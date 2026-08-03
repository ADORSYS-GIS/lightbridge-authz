#![cfg(feature = "it-tests")]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_budget::{Period, Spend, SpendReader, TimescaleSpendReader};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

const PERIOD: &str = "2026-08";

async fn insert_usage_event(
    pool: &PgPool,
    account_id: &str,
    observed_at: DateTime<Utc>,
    total_cost: f64,
) {
    sqlx::query(
        "INSERT INTO usage_events (observed_at, signal_type, account_id, total_cost)
         VALUES ($1, 'test', $2, $3)",
    )
    .bind(observed_at)
    .bind(account_id)
    .bind(total_cost)
    .execute(pool)
    .await
    .expect("inserting a test usage_events row must succeed");
}

fn reader_for(pool: PgPool) -> TimescaleSpendReader {
    TimescaleSpendReader::new(Arc::new(DbPool::from_pool(pool)))
}

fn mid_period() -> DateTime<Utc> {
    "2026-08-15T12:00:00Z"
        .parse()
        .expect("valid timestamp literal")
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_is_unavailable_when_no_matching_rows(pool: PgPool) {
    let account_id = cuid2();
    let reader = reader_for(pool);
    let period = Period::parse(PERIOD).expect("valid period");

    let spend = reader
        .spend_for_account(&account_id, &period)
        .await
        .expect("query must succeed");

    assert_eq!(
        spend,
        Spend::Unavailable,
        "an account with zero matching rows must read as Unavailable, not Known(0)"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_is_known_zero_when_a_zero_cost_row_exists(pool: PgPool) {
    let account_id = cuid2();
    insert_usage_event(&pool, &account_id, mid_period(), 0.0).await;

    let reader = reader_for(pool);
    let period = Period::parse(PERIOD).expect("valid period");

    let spend = reader
        .spend_for_account(&account_id, &period)
        .await
        .expect("query must succeed");

    assert_eq!(
        spend,
        Spend::Known(0),
        "a row that costs nothing must read as Known(0), distinct from Unavailable"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_sums_multiple_rows_and_converts_to_micros(pool: PgPool) {
    let account_id = cuid2();
    insert_usage_event(&pool, &account_id, mid_period(), 1.5).await;
    insert_usage_event(&pool, &account_id, mid_period(), 2.25).await;

    let reader = reader_for(pool);
    let period = Period::parse(PERIOD).expect("valid period");

    let spend = reader
        .spend_for_account(&account_id, &period)
        .await
        .expect("query must succeed");

    assert_eq!(spend, Spend::Known(3_750_000));
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_excludes_rows_outside_the_period(pool: PgPool) {
    let account_id = cuid2();
    let adjacent_month: DateTime<Utc> = "2026-09-01T00:00:01Z"
        .parse()
        .expect("valid timestamp literal");
    insert_usage_event(&pool, &account_id, adjacent_month, 5.0).await;

    let reader = reader_for(pool);
    let period = Period::parse(PERIOD).expect("valid period");

    let spend = reader
        .spend_for_account(&account_id, &period)
        .await
        .expect("query must succeed");

    assert_eq!(
        spend,
        Spend::Unavailable,
        "a row outside the target period must not count toward it"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_excludes_other_accounts(pool: PgPool) {
    let target_account_id = cuid2();
    let other_account_id = cuid2();
    insert_usage_event(&pool, &other_account_id, mid_period(), 9.0).await;

    let reader = reader_for(pool);
    let period = Period::parse(PERIOD).expect("valid period");

    let spend = reader
        .spend_for_account(&target_account_id, &period)
        .await
        .expect("query must succeed");

    assert_eq!(
        spend,
        Spend::Unavailable,
        "a row belonging to a different account must not count toward this account's spend"
    );
}
