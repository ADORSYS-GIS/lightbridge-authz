#![cfg(feature = "it-tests")]

use std::sync::Arc;

use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::source::GrantSource;
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
