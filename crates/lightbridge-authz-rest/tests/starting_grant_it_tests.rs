// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml) does
// not reach their free helper functions. Unwrapping in a test is a deliberate assertion that the
// setup held; the workspace gate stays `deny` for shipping code.
#![allow(clippy::unwrap_used)]

//! `createAccount` funds the account it creates (#697), end to end through the handler every
//! caller reaches — the RPC procedure, the MCP `create-account` tool, and the console's bootstrap
//! flow all delegate to `AuthzStoreImpl::create_account`.
//!
//! What the budget crate's own `starting_grant_tests` cannot prove is exactly what is asserted
//! here: that the handler actually calls it. That seam is where #697 lived for three months — the
//! grant path existed, the schedule existed, and nothing connected them to account creation.
//!
//! Gated behind `it-tests` (needs a migrated Postgres via `DATABASE_URL`), same harness as
//! `account_name_it_tests.rs`.
#![cfg(feature = "it-tests")]

use std::sync::Arc;

use chrono::Utc;
use lightbridge_authz_budget::repo::BudgetRepo;
use lightbridge_authz_budget::starting_grant_amount::starting_grant_idempotency_key;
use lightbridge_authz_budget::{
    BudgetError, Period, Remaining, RemainingReader, RemainingService, ResetScheduler, Spend,
    SpendReader,
};
use lightbridge_authz_core::CreateAccount;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;

/// ADR-0015's shipped `starting_amount_micros` — what an account no reset schedule covers gets.
const POLICY_STARTING_AMOUNT_MICROS: i64 = 15_000_000;

fn core_pool(pool: PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool))
}

/// The usage service says "nothing spent". A brand-new account genuinely has spent nothing — it
/// has no API key yet — so this is the honest answer, not a convenience.
#[derive(Debug)]
struct NoSpend;

#[lightbridge_authz_core::async_trait]
impl SpendReader for NoSpend {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(Spend::Known(0))
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_books_the_starting_grant_and_introspection_reads_it(pool: PgPool) {
    let core = core_pool(pool.clone());
    let store = AuthzStoreImpl::with_pool(core.clone());
    let subject = cuid2();

    let account = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .expect("createAccount should succeed");

    let now = Utc::now();
    let period = Period::current(now);

    // 1. Exactly one `automatic` grant, booked under the starting-grant key.
    let rows: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT amount_micros, source, idempotency_key FROM budget_grants \
         WHERE budget_account_id = $1",
    )
    .bind(&account.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "exactly one starting grant: {rows:?}");
    assert_eq!(rows[0].0, POLICY_STARTING_AMOUNT_MICROS);
    assert_eq!(rows[0].1, "automatic");
    assert_eq!(
        rows[0].2.as_deref(),
        Some(starting_grant_idempotency_key(&period, &account.id).as_str())
    );

    // 2. The account is in the snapshot working set, so the gateway stops reading `known: false`
    //    on the refresher's next tick rather than on the account's first metered request.
    let (snapshot_rows,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM budget_remaining_snapshots WHERE budget_account_id = $1",
    )
    .bind(&account.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(snapshot_rows, 1);

    // 3. Introspection reports the grant as spendable budget -- `remaining == grant`, which is
    //    the acceptance criterion.
    let budget_repo = Arc::new(BudgetRepo::new(core.clone()));
    let spend: Arc<dyn SpendReader> = Arc::new(NoSpend);
    let scheduler = Arc::new(ResetScheduler::new(
        core.clone(),
        budget_repo.clone(),
        spend.clone(),
    ));
    let remaining = RemainingService::new(budget_repo, spend, scheduler)
        .remaining_for_account(&account.id, &period, now)
        .await
        .unwrap();

    match remaining {
        Remaining::Known(budget) => {
            assert_eq!(budget.ceiling_micros, POLICY_STARTING_AMOUNT_MICROS);
            assert_eq!(budget.spent_micros, 0);
            assert_eq!(budget.remaining_micros, POLICY_STARTING_AMOUNT_MICROS);
        }
        other => panic!("a freshly created account must read Known, got {other:?}"),
    }
}

/// A second `createAccount` for the same identity mints a SECOND account (ADR-0026), and that one
/// is funded too — the starting grant is per account, not per person.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_account_for_the_same_identity_is_funded_as_well(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool.clone()));
    let subject = cuid2();

    let first = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
    let second = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();

    assert_ne!(first.id, second.id);
    for account_id in [&first.id, &second.id] {
        let (total,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(amount_micros), 0)::bigint FROM budget_grants \
             WHERE budget_account_id = $1",
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(total, POLICY_STARTING_AMOUNT_MICROS, "account {account_id}");
    }
}
