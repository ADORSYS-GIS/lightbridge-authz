// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml) does
// not reach their free helper functions. Unwrapping in a test is a deliberate assertion that the
// setup held; the workspace gate stays `deny` for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! Tests for `lightbridge-authz budget grant`.
//!
//! This command writes MONEY into an append-only ledger from an unattended Job, so the tests that
//! matter are the refusals and the idempotency — not the happy path, which is `BudgetRepo::grant`'s
//! own well-tested transaction.
//!
//! What each one is defending:
//!
//! - **Idempotency.** A Job can be retried, a manifest re-applied. Booking twice would silently
//!   double an account's budget, and ADR-0009 makes the ledger append-only, so there is no undo —
//!   only a compensating `correction` row somebody has to notice is needed.
//! - **The unknown-account refusal.** A typo'd id would otherwise become a real `budget_grants` row
//!   that no reader ever resolves, because `GET /budget/v1/remaining` filters on `accounts ⋈ users`
//!   and would answer `UnknownAccount` for it. Money written where nothing reads is worse than an
//!   error.
//! - **The non-positive refusal.** Only `correction` may be negative (ADR-0009's
//!   `budget_grants_amount_sign_chk`); a reset-down belongs to the scheduler, not to an operator
//!   with a minus sign.

use std::sync::Arc;

use lightbridge_authz::budget_cmd::{BudgetAction, dispatch};
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::BudgetRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

const PERIOD: &str = "2026-09";

fn pool_of(pool: &PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool.clone()))
}

async fn account(pool: &PgPool) -> String {
    let id = cuid2();
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    id
}

fn grant_action(account: &str, amount_micros: i64, key: Option<&str>) -> BudgetAction {
    BudgetAction::Grant {
        account: account.to_string(),
        amount_micros,
        period: PERIOD.to_string(),
        source: "automatic".to_string(),
        reason: Some("budget-cmd test".to_string()),
        idempotency_key: key.map(str::to_string),
    }
}

async fn ledger_total(pool: &PgPool, account: &str) -> i64 {
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount_micros), 0)::bigint FROM budget_grants \
         WHERE budget_account_id = $1 AND period = $2",
    )
    .bind(account)
    .bind(PERIOD)
    .fetch_one(pool)
    .await
    .unwrap();
    total
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_lands_in_the_ledger_and_the_balance_projection(pool: PgPool) {
    let id = account(&pool).await;

    dispatch(pool_of(&pool), grant_action(&id, 8_000_000, None))
        .await
        .expect("granting to a real budget account must succeed");

    assert_eq!(ledger_total(&pool, &id).await, 8_000_000);
    let repo = BudgetRepo::new(pool_of(&pool));
    assert_eq!(
        repo.effective_balance(&id, &Period::parse(PERIOD).unwrap(), chrono::Utc::now())
            .await
            .unwrap(),
        8_000_000,
        "the ceiling the gateway enforces on must move, not just the raw ledger"
    );
}

/// The property a retried Job depends on. Same key twice must leave ONE row and ONE balance.
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_idempotency_key_never_books_twice(pool: PgPool) {
    let id = account(&pool).await;
    let key = format!("test-{}", cuid2());

    dispatch(pool_of(&pool), grant_action(&id, 8_000_000, Some(&key)))
        .await
        .expect("first grant");
    dispatch(pool_of(&pool), grant_action(&id, 8_000_000, Some(&key)))
        .await
        .expect("a replay must succeed, not error");

    let (rows,): (i64,) = sqlx::query_as(
        "SELECT count(*)::bigint FROM budget_grants WHERE budget_account_id = $1 AND period = $2",
    )
    .bind(&id)
    .bind(PERIOD)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows, 1,
        "a replayed key must not append a second ledger row"
    );
    assert_eq!(
        ledger_total(&pool, &id).await,
        8_000_000,
        "and it must not double the money either"
    );
}

/// Without a key, two runs DO book twice — stated as a test so nobody reads the idempotency test
/// above as "this command is safe to re-run unconditionally". It is safe to re-run *with a key*.
#[sqlx::test(migrations = "../../migrations")]
async fn without_an_idempotency_key_a_rerun_books_again(pool: PgPool) {
    let id = account(&pool).await;

    dispatch(pool_of(&pool), grant_action(&id, 8_000_000, None))
        .await
        .expect("first grant");
    dispatch(pool_of(&pool), grant_action(&id, 8_000_000, None))
        .await
        .expect("second grant");

    assert_eq!(
        ledger_total(&pool, &id).await,
        16_000_000,
        "no key means no idempotency -- every Job must pass one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_that_does_not_exist_is_refused_before_anything_is_written(pool: PgPool) {
    let ghost = cuid2();

    let err = dispatch(pool_of(&pool), grant_action(&ghost, 8_000_000, None))
        .await
        .expect_err("granting to an id nothing has heard of must be refused");
    assert!(
        err.to_string().contains(&ghost),
        "the refusal must name the id an operator mistyped: {err}"
    );
    assert_eq!(
        ledger_total(&pool, &ghost).await,
        0,
        "and it must have written nothing"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_positive_amount_is_refused(pool: PgPool) {
    let id = account(&pool).await;

    for amount in [0_i64, -8_000_000] {
        dispatch(pool_of(&pool), grant_action(&id, amount, None))
            .await
            .expect_err("only a correction may be non-positive, and that is the scheduler's job");
    }
    assert_eq!(ledger_total(&pool, &id).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unparseable_period_or_source_is_refused(pool: PgPool) {
    let id = account(&pool).await;

    let bad_period = BudgetAction::Grant {
        account: id.clone(),
        amount_micros: 8_000_000,
        period: "September".to_string(),
        source: "automatic".to_string(),
        reason: None,
        idempotency_key: None,
    };
    dispatch(pool_of(&pool), bad_period)
        .await
        .expect_err("a period that is not YYYY-MM must be refused, never coerced");

    let bad_source = BudgetAction::Grant {
        account: id.clone(),
        amount_micros: 8_000_000,
        period: PERIOD.to_string(),
        source: "generous".to_string(),
        reason: None,
        idempotency_key: None,
    };
    dispatch(pool_of(&pool), bad_source)
        .await
        .expect_err("an unknown source must be refused -- the CHECK would reject it anyway");

    assert_eq!(ledger_total(&pool, &id).await, 0);
}

/// The §15.6 tie-in: a grant moves the precomputed snapshot inside its own transaction, so the
/// seeded row these seven accounts now have becomes `known: true, remaining > 0` immediately rather
/// than one refresher tick later.
#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_moves_an_existing_snapshot_reading_in_the_same_transaction(pool: PgPool) {
    use lightbridge_authz_budget::snapshot::BudgetSnapshotReader;
    use lightbridge_authz_budget::snapshot_store::SnapshotStore;

    let id = account(&pool).await;
    let store = SnapshotStore::new(pool_of(&pool));
    let period = Period::parse(PERIOD).unwrap();
    store.touch(&id).await.unwrap();
    store
        .store_reading(&id, &period, 0, 0, chrono::Utc::now())
        .await
        .unwrap();

    dispatch(pool_of(&pool), grant_action(&id, 8_000_000, None))
        .await
        .expect("grant");

    assert_eq!(
        store
            .read(&id)
            .await
            .unwrap()
            .unwrap()
            .remaining_for(&period),
        Some(8_000_000),
        "the gateway must see the money on the very next request, not after a tick"
    );
}
