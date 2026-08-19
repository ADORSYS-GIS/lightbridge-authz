#![cfg(feature = "it-tests")]

use std::sync::Arc;

use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::tier::BudgetTier;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

const PERIOD: &str = "2026-08";
const OTHER_PERIOD: &str = "2026-07";

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

fn base_request(
    account_id: &str,
    period: &str,
    source: GrantSource,
    amount_micros: i64,
) -> GrantRequest {
    GrantRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(period).expect("valid period"),
        amount_micros,
        source,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_grant_by_id_returns_the_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    let created = repo
        .grant(base_request(
            &account_id,
            PERIOD,
            GrantSource::Admin,
            5_000_000,
        ))
        .await
        .expect("grant must succeed");

    let fetched = repo
        .get_grant_by_id(&created.id)
        .await
        .expect("the grant just created must be fetchable by id");

    assert_eq!(fetched, created);
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_grant_by_id_not_found_is_a_typed_error(pool: PgPool) {
    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));

    let result = repo.get_grant_by_id("no-such-grant-id").await;

    assert!(
        matches!(result, Err(BudgetError::NotFound(_))),
        "an unknown grant id must be a typed NotFound, not a panic or a default value: {result:?}"
    );
}

/// Proves the ledger's audit-read path returns entries newest-first by `created_at`, and that
/// paginating with the returned `before` cursor actually advances through the ledger rather than
/// repeating or skipping rows -- the exact bug a test that never calls `list_grants` a second time
/// would miss entirely.
#[sqlx::test(migrations = "../../migrations")]
async fn list_grants_pages_newest_first_by_created_at(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));

    let mut inserted_ids = Vec::new();
    for i in 0..5 {
        let grant = repo
            .grant(base_request(
                &account_id,
                PERIOD,
                GrantSource::Admin,
                1_000_000 * (i + 1),
            ))
            .await
            .expect("grant must succeed");
        inserted_ids.push(grant.id);
    }
    // `budget_grants` has no sub-transaction ordering guarantee finer than `created_at`'s actual
    // stored precision across five separate `grant()` calls issued in sequence -- but each is its
    // own transaction/`now()` read, so insertion order is expected to match `created_at` order in
    // practice. Newest-first means the LAST id inserted must be the FIRST one returned.
    let newest_to_oldest: Vec<String> = inserted_ids.into_iter().rev().collect();

    let period = Period::parse(PERIOD).expect("valid period");

    let page1 = repo
        .list_grants(&account_id, Some(&period), None, 2)
        .await
        .expect("first page must succeed");
    assert_eq!(page1.len(), 2, "page size must be respected");
    assert_eq!(
        page1.iter().map(|g| g.id.clone()).collect::<Vec<_>>(),
        newest_to_oldest[0..2],
        "the first page must be the two newest grants, newest first"
    );
    assert!(
        page1[0].created_at >= page1[1].created_at,
        "page must be ordered newest-first by created_at"
    );

    let cursor = page1[1].created_at;
    let page2 = repo
        .list_grants(&account_id, Some(&period), Some(cursor), 2)
        .await
        .expect("second page must succeed");
    assert_eq!(
        page2.iter().map(|g| g.id.clone()).collect::<Vec<_>>(),
        newest_to_oldest[2..4],
        "the second page must continue strictly after the cursor, not repeat or skip rows"
    );

    let cursor2 = page2[1].created_at;
    let page3 = repo
        .list_grants(&account_id, Some(&period), Some(cursor2), 2)
        .await
        .expect("third page must succeed");
    assert_eq!(
        page3.iter().map(|g| g.id.clone()).collect::<Vec<_>>(),
        newest_to_oldest[4..5],
        "the final page must return exactly the one remaining, oldest grant"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_grants_filters_by_period(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::Admin,
        1_000_000,
    ))
    .await
    .expect("grant in PERIOD must succeed");
    repo.grant(base_request(
        &account_id,
        OTHER_PERIOD,
        GrantSource::Admin,
        2_000_000,
    ))
    .await
    .expect("grant in OTHER_PERIOD must succeed");

    let period = Period::parse(PERIOD).expect("valid period");
    let scoped = repo
        .list_grants(&account_id, Some(&period), None, 10)
        .await
        .expect("scoped listing must succeed");
    assert_eq!(scoped.len(), 1, "only the PERIOD grant must be returned");
    assert_eq!(scoped[0].period, period);

    let all_periods = repo
        .list_grants(&account_id, None, None, 10)
        .await
        .expect("unscoped listing must succeed");
    assert_eq!(
        all_periods.len(),
        2,
        "omitting the period filter must return grants across every period"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_grants_does_not_leak_another_accounts_entries(pool: PgPool) {
    let account_id = cuid2();
    let other_account_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_account(&pool, &other_account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::Admin,
        1_000_000,
    ))
    .await
    .expect("grant for account must succeed");
    repo.grant(base_request(
        &other_account_id,
        PERIOD,
        GrantSource::Admin,
        9_000_000,
    ))
    .await
    .expect("grant for other_account must succeed");

    let entries = repo
        .list_grants(&account_id, None, None, 10)
        .await
        .expect("listing must succeed");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].budget_account_id, account_id);
}

/// ADR-0014 (the token-mint budget-tier claim) reuses this exact resolver, so its fallback
/// behavior on a brand-new account/period must be `B15`, the lowest rung -- never an error,
/// never a permissive default.
#[sqlx::test(migrations = "../../migrations")]
async fn current_tier_defaults_to_b15_with_no_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    let period = Period::parse(PERIOD).expect("valid period");

    let tier = repo
        .current_tier(&account_id, &period)
        .await
        .expect("current_tier must succeed even with zero grants");

    assert_eq!(tier, BudgetTier::B15);
}

/// The primary correctness case: a real grant on the ledger must be the tier reported back,
/// proving `current_tier` genuinely reads the ledger rather than always returning its `B15`
/// default.
#[sqlx::test(migrations = "../../migrations")]
async fn current_tier_resolves_the_most_recent_qualifying_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::SelfService,
        BudgetTier::B120.amount().get(),
    ))
    .await
    .expect("grant must succeed");

    let period = Period::parse(PERIOD).expect("valid period");
    let tier = repo
        .current_tier(&account_id, &period)
        .await
        .expect("current_tier must succeed");

    assert_eq!(tier, BudgetTier::B120);
}

/// `correction`/`refund` grants must NOT be read as "the tier this account is on" -- see
/// [`GrantSource`]'s own doc comment on `current_tier` for why. A correction here deliberately
/// carries an amount that doesn't even match a known rung, so if it were wrongly counted this
/// test would fail via the "unrecognized amount" fallback rather than silently passing.
#[sqlx::test(migrations = "../../migrations")]
async fn current_tier_ignores_correction_and_refund_sources(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::SelfService,
        BudgetTier::B60.amount().get(),
    ))
    .await
    .expect("base grant must succeed");
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::Correction,
        1_234_567,
    ))
    .await
    .expect("correction grant must succeed");
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::Refund,
        500_000,
    ))
    .await
    .expect("refund grant must succeed");

    let period = Period::parse(PERIOD).expect("valid period");
    let tier = repo
        .current_tier(&account_id, &period)
        .await
        .expect("current_tier must succeed");

    assert_eq!(
        tier,
        BudgetTier::B60,
        "the correction/refund rows landed after the tier grant but must not be read as the \
         account's current tier"
    );
}

/// A qualifying grant whose `amount_micros` doesn't match any known rung (data this service
/// doesn't expect in practice, e.g. a hand-edited or historically-imported row) must fall back to
/// `B15` rather than propagating a lookup failure or silently rounding to the nearest rung.
#[sqlx::test(migrations = "../../migrations")]
async fn current_tier_falls_back_to_b15_on_unrecognized_amount(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    repo.grant(base_request(
        &account_id,
        PERIOD,
        GrantSource::Admin,
        42_000_000,
    ))
    .await
    .expect("grant must succeed");

    let period = Period::parse(PERIOD).expect("valid period");
    let tier = repo
        .current_tier(&account_id, &period)
        .await
        .expect("current_tier must succeed even on an unrecognized amount");

    assert_eq!(tier, BudgetTier::B15);
}

/// A genuine storage failure is NOT swallowed into `B15` inside `BudgetRepo::current_tier`
/// itself -- see that method's doc comment for why (a caller that wants to distinguish "new
/// account" from "ledger unavailable" still can). The token-mint path
/// (`TokenExchangeOpStore::resolve_budget_tier`, `lightbridge-authz-rest`) is the layer that
/// downgrades this `Err` to `B15`; this test pins that `current_tier` itself still surfaces the
/// error rather than pre-emptively hiding it.
#[tokio::test]
async fn current_tier_propagates_a_genuine_storage_failure() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    let period = Period::parse(PERIOD).expect("valid period");

    let result = repo.current_tier("unreachable-account", &period).await;

    assert!(
        matches!(result, Err(BudgetError::StorageFailed(_))),
        "an unreachable database must surface as a typed StorageFailed error, not a silent \
         default: {result:?}"
    );
}
