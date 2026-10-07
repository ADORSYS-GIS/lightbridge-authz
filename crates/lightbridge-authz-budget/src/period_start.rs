//! The month-start pass: every real account holds its starting grant for the CURRENT period.
//!
//! ## The defect this closes
//!
//! The gateway's ceiling is `SUM(budget_grants WHERE period = <current UTC month>)`
//! ([`crate::repo::BudgetRepo::effective_balance`]). A grant belongs to ONE calendar month, and
//! nothing booked the next month's: [`crate::starting_grant::StartingGrantService::book`] ran only
//! at account creation, and a reset schedule fires on its own cadence (production's is weekly). So
//! at 00:00 UTC on the 1st every account's ceiling was `0` and the gateway answered `402` to
//! everyone until the next schedule window — up to six days.
//!
//! ## What a pass does
//!
//! One `SELECT` finds the accounts that do not yet hold `budget-start-<period>-<account_id>`
//! (an anti-join on [`crate::starting_grant_amount::starting_grant_key_prefix`]); each is booked
//! through [`StartingGrantService::book_period_start`], never a raw `INSERT` — the ledger has one
//! writer (ADR-0009). In steady state the `SELECT` returns nothing, so a tick takes no row lock.
//!
//! The key is the whole contract. A grant already under it — an account created this month, or
//! funded by an operator's Job under the same key — drops out of the `SELECT`, and if it were
//! booked anyway [`crate::repo::BudgetRepo::grant`]'s `ON CONFLICT` replay returns the existing row.
//! Presence of the key is what counts, not whether the row is revoked: a revocation is a decision
//! this pass must not undo.
//!
//! ## Replicas and races
//!
//! Several `authz-budget` replicas run this concurrently, and two can pick the same account. That
//! is safe without a lock: `BudgetRepo::grant` locks the `(account, period)` balance row
//! `FOR UPDATE` before inserting, so the loser waits, its insert hits the unique index on
//! `idempotency_key`, `DO NOTHING` returns zero rows, and the already-committed grant is read back
//! — a unique violation can never surface as an error. Each grant is its own transaction on one
//! balance row, so two replicas walking the same list cannot deadlock either.
//!
//! ## Failure handling
//!
//! One account failing (say its schedule read errors) is counted and the pass moves on: stopping at
//! the first failure would let one bad account leave every account behind it at a ceiling of `0`.
//! Only a failure to enumerate the missing accounts is an `Err`. Nothing here ever grants more on
//! failure — an account that could not be funded stays at `0` and is retried on the next tick.
//!
//! The amount is [`StartingGrantService::resolve_amount`]'s, so after this pass the reset schedule
//! that produced it is a `delta = 0` no-op (the `$8`-vs-`$15` rule, [`crate::starting_grant_amount`]).
//! Resetting an account whose spend is unavailable is still deferred by the scheduler, unchanged.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;

use crate::error::BudgetError;
use crate::period::Period;
use crate::starting_grant::StartingGrantService;
use crate::starting_grant_amount::starting_grant_key_prefix;

/// Same predicate as `known_account` and the `global` schedule scope: an `accounts` row whose
/// owner resolves to a `users` row. `$1` is the key prefix, so the key's shape stays defined once.
const MISSING_START_GRANTS_SQL: &str = "SELECT a.id FROM accounts a \
     JOIN users u ON u.id = a.user_id \
     WHERE NOT EXISTS ( \
         SELECT 1 FROM budget_grants g WHERE g.idempotency_key = $1::text || a.id \
     ) \
     ORDER BY a.created_at ASC";

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeriodStartReport {
    /// Accounts without this period's grant when the pass looked.
    pub missing: usize,
    /// Accounts that now hold it — including any a concurrent replica funded first.
    pub funded: usize,
    /// Accounts that could not be funded; the next tick retries them.
    pub failed: usize,
    /// The first failure's message, so a summary log line can name a cause without N lines.
    pub first_error: Option<String>,
}

/// Books the month-start grant for every account that lacks one. Stateless over the pool, so every
/// replica builds its own.
#[derive(Debug, Clone)]
pub struct PeriodStartGrants {
    pool: Arc<dyn DbPoolTrait>,
    starting: StartingGrantService,
}

impl PeriodStartGrants {
    pub fn new(pool: Arc<dyn DbPoolTrait>, starting: StartingGrantService) -> Self {
        Self { pool, starting }
    }

    /// The accounts with no grant under this period's starting-grant key, oldest first.
    pub async fn missing_accounts(&self, period: &Period) -> Result<Vec<String>, BudgetError> {
        sqlx::query_scalar(MISSING_START_GRANTS_SQL)
            .bind(starting_grant_key_prefix(period))
            .fetch_all(self.pool.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))
    }

    /// One pass for the period `now` falls in. `now` is a parameter, not a clock read, and is the
    /// same instant [`StartingGrantService::book_period_start`] derives its period and key from,
    /// so the `SELECT` and the writes can never disagree about which month is meant.
    pub async fn run(&self, now: DateTime<Utc>) -> Result<PeriodStartReport, BudgetError> {
        let missing = self.missing_accounts(&Period::current(now)).await?;
        let mut report = PeriodStartReport {
            missing: missing.len(),
            ..PeriodStartReport::default()
        };

        for account_id in &missing {
            match self.starting.book_period_start(account_id, now).await {
                Ok(_) => report.funded += 1,
                Err(err) => {
                    report.failed += 1;
                    if report.first_error.is_none() {
                        tracing::warn!(
                            budget_account_id = %account_id,
                            error = %err,
                            "could not book the month-start grant; retrying on the next tick"
                        );
                        report.first_error = Some(err.to_string());
                    }
                }
            }
        }
        Ok(report)
    }
}
