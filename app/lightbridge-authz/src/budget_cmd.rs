//! `lightbridge-authz budget grant` — the operator surface for booking a single budget grant
//! against the configured database, one-shot, with no server and no bearer token.
//!
//! ## Why this exists when `grantBudget` already does
//!
//! The RPC procedure `grantBudget` (`authz.cstack`) is the normal path and this command delegates
//! to the *same* [`BudgetRepo::grant`] transaction it does — ledger insert, balance projection,
//! and the ADR-0034 §15 snapshot delta, atomically, under the same per-(account, period) row lock.
//! What the RPC cannot do is run unattended: its `@allow` requires `auth().permBudgetGrant`, which
//! comes from a platform role on a *human* subject, and ADR-0030 is explicit that a
//! `client_credentials` service token carries no `roles` claim and therefore holds zero permissions
//! against every RPC op-id. So a Job — the `hack/jobs` pattern `rbac grant` already uses — has no
//! credential that can call it.
//!
//! This is the `rbac grant` argument applied to money: a bootstrap path that writes through the
//! domain layer rather than around it. It is emphatically **not** a licence to `UPDATE
//! budget_balances` — ADR-0009's whole point is that the ledger is the only writer, and this
//! command adds a caller, not a second writer.
//!
//! ## What it refuses to do
//!
//! - **Grant to an account that is not a budget account.** The `accounts ⋈ users` existence check
//!   is the same predicate `lightbridge-authz-budget`'s `known_account` uses for `GET
//!   /budget/v1/remaining`, so a typo'd id is refused here rather than becoming a ledger row
//!   nothing will ever read.
//! - **Grant a non-positive amount.** Only `correction` may be negative (ADR-0009's
//!   `budget_grants_amount_sign_chk`), and a reset-down is the scheduler's job, not an operator's.
//! - **Invent a period.** `--period` is required and parsed; there is no "current month" default,
//!   because the month a grant lands in is exactly the thing an operator running this at 23:58 UTC
//!   must state rather than inherit.
//!
//! Exposed from the crate's lib target rather than kept bin-private so integration tests can call
//! [`dispatch`] directly instead of spawning the built binary — the same arrangement `rbac_cmd` and
//! `jwk_cmd` have.

use std::str::FromStr;
use std::sync::Arc;

use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::{Error, Result};

/// The `budget` operations, decoupled from `cli.rs`'s clap `Subcommand` shape so this module's
/// public API does not depend on how the binary happens to parse its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetAction {
    /// Book one grant. `idempotency_key` makes a re-run — a retried Job, a re-applied manifest —
    /// return the grant that already exists instead of booking a second one.
    Grant {
        account: String,
        amount_micros: i64,
        period: String,
        source: String,
        reason: Option<String>,
        idempotency_key: Option<String>,
    },
}

/// The same `accounts ⋈ users` predicate `lightbridge_authz_budget::known_account` applies before
/// answering `GET /budget/v1/remaining`. Kept identical on purpose: an id this command will grant
/// to and an id that endpoint will report on must be the same set, or a grant lands somewhere
/// nothing reads.
const ACCOUNT_EXISTS_SQL: &str = "SELECT 1 FROM accounts a JOIN users u ON u.id = a.user_id \
     WHERE a.id = $1";

/// Entry point: loads config, connects to Postgres (no Redis — grants are DB-only), and dispatches.
pub async fn run(config_path: &str, action: BudgetAction) -> Result<()> {
    let config = load_from_path(config_path)?;
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);
    dispatch(pool, action).await
}

/// The part of [`run`] that touches the database, taking an already-built pool rather than a config
/// path — so integration tests can exercise it against a real test database with no config file on
/// disk.
pub async fn dispatch(pool: Arc<dyn DbPoolTrait>, action: BudgetAction) -> Result<()> {
    match action {
        BudgetAction::Grant {
            account,
            amount_micros,
            period,
            source,
            reason,
            idempotency_key,
        } => {
            grant(
                pool,
                &account,
                amount_micros,
                &period,
                &source,
                reason,
                idempotency_key,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn grant(
    pool: Arc<dyn DbPoolTrait>,
    account: &str,
    amount_micros: i64,
    period: &str,
    source: &str,
    reason: Option<String>,
    idempotency_key: Option<String>,
) -> Result<()> {
    if amount_micros <= 0 {
        return Err(Error::BadRequest(format!(
            "--amount-micros must be positive, got {amount_micros}; only a `correction` may be \
             negative (ADR-0009), and booking one is the reset scheduler's job"
        )));
    }
    let parsed_period = Period::parse(period).map_err(|err| {
        Error::BadRequest(format!("--period {period} is not a valid period: {err}"))
    })?;
    let parsed_source = GrantSource::from_str(source).map_err(|err| {
        Error::BadRequest(format!("--source {source} is not a grant source: {err}"))
    })?;

    let exists: Option<(i32,)> = sqlx::query_as(ACCOUNT_EXISTS_SQL)
        .bind(account)
        .fetch_optional(pool.pool())
        .await
        .map_err(|err| Error::Server(err.to_string()))?;
    if exists.is_none() {
        // `Error::NotFound` is a unit variant and would say nothing about WHICH id was wrong, so
        // this refusal is a `BadRequest` carrying the id -- the operator reading a failed Job's
        // logs needs to know which of seven arguments was the typo.
        return Err(Error::BadRequest(format!(
            "no budget account {account} (an `accounts` row whose user_id resolves to a `users` \
             row); refusing to book a grant nothing will ever read"
        )));
    }

    let repo = BudgetRepo::new(pool);
    let booked = repo
        .grant(GrantRequest {
            budget_account_id: account.to_string(),
            account_id: account.to_string(),
            project_id: None,
            period: parsed_period,
            amount_micros,
            source: parsed_source,
            actor_id: None,
            reason,
            policy_revision: None,
            matched_rule_ids: None,
            idempotency_key,
            trigger_key: None,
            expires_at: None,
        })
        .await
        .map_err(|err| Error::Server(err.to_string()))?;

    println!(
        "granted id={} account={} period={} amount_micros={} source={}",
        booked.id, booked.budget_account_id, booked.period, booked.amount_micros, booked.source
    );
    Ok(())
}
