#![cfg(feature = "it-tests")]

//! Retention/rollup integration tests (#549 AC2/AC3).
//!
//! `rollup_and_purge` moves raw `usage_events` rows older than a retention window into the
//! `usage_events_daily` aggregate and deletes them, in one transaction. These tests prove:
//!
//!   * old rows leave `usage_events` and land, aggregated, in `usage_events_daily`;
//!   * recent rows stay in `usage_events`;
//!   * `spend_for_account` returns the SAME sum before and after the rollup -- AC3's "budget
//!     decisions must not shift because data aged" -- for both the current (raw) period and a
//!     period that has aged into the rollup.

use chrono::{Duration, Utc};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_usage_rest::repo::{StoreRepo, UsageEvent};
use lightbridge_authz_usage_rest::retention::rollup_and_purge;
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

fn event_with_cost(
    account_id: &str,
    observed_at: chrono::DateTime<Utc>,
    total_cost: f64,
) -> UsageEvent {
    UsageEvent {
        observed_at,
        signal_type: "trace".to_string(),
        account_id: Some(account_id.to_string()),
        project_id: Some("proj_1".to_string()),
        api_key_id: None,
        user_id: None,
        user_name: None,
        model: Some("gpt-4.1".to_string()),
        metric_name: None,
        azp: None,
        operation: None,
        billing_plan: None,
        usage_value: 1.0,
        request_count: 1,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        total_cost: Some(total_cost),
        latency_ms: None,
    }
}

/// The rollup moves old rows out of `usage_events` into `usage_events_daily`, leaves recent rows
/// alone, and `spend_for_account` is unchanged across the boundary (AC3).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn rollup_and_purge_moves_old_rows_and_spend_is_unchanged(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();
    let raw_days = 90;

    // A COMPLETE day, well older than the retention window: its rows must be rolled up.
    let old_day = (now - Duration::days(raw_days + 10))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    let old_events = vec![
        event_with_cost("acct_1", old_day, 10.0),
        event_with_cost("acct_1", old_day + Duration::hours(1), 20.0),
    ];

    // A recent day, well inside the window: its rows must stay raw.
    let recent_day = (now - Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    let recent_events = vec![event_with_cost("acct_1", recent_day, 100.0)];

    repo.insert_usage_events(&old_events)
        .await
        .expect("insert old");
    repo.insert_usage_events(&recent_events)
        .await
        .expect("insert recent");

    let old_period_start = old_day;
    let old_period_end = old_day + Duration::days(1);
    let recent_period_start = recent_day;
    let recent_period_end = recent_day + Duration::days(1);

    // Spend before the rollup.
    let s_old_before = repo
        .spend_for_account("acct_1", old_period_start, old_period_end)
        .await
        .expect("spend old before");
    let s_recent_before = repo
        .spend_for_account("acct_1", recent_period_start, recent_period_end)
        .await
        .expect("spend recent before");
    assert_eq!(s_old_before, Some(30.0));
    assert_eq!(s_recent_before, Some(100.0));

    // Run the retention job.
    let purged = rollup_and_purge(&pool, raw_days)
        .await
        .expect("rollup should run");
    assert!(
        purged >= 2,
        "the two old rows must be purged from raw, got {purged}"
    );

    // Old rows are gone from raw.
    let old_raw: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_events WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3",
    )
    .bind("acct_1")
    .bind(old_period_start)
    .bind(old_period_end)
    .fetch_one(&pool)
    .await
    .expect("count old raw");
    assert_eq!(old_raw, 0, "old rows must be deleted from usage_events");

    // Old rows are aggregated in the rollup.
    let rollup_cost: Option<f64> = sqlx::query_scalar(
        "SELECT SUM(total_cost) FROM usage_events_daily WHERE account_id = $1 AND bucket_start >= $2 AND bucket_start < $3",
    )
    .bind("acct_1")
    .bind(old_period_start)
    .bind(old_period_end)
    .fetch_one(&pool)
    .await
    .expect("sum rollup");
    assert_eq!(rollup_cost, Some(30.0), "old cost must land in the rollup");

    // Recent rows stay raw.
    let recent_raw: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_events WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3",
    )
    .bind("acct_1")
    .bind(recent_period_start)
    .bind(recent_period_end)
    .fetch_one(&pool)
    .await
    .expect("count recent raw");
    assert_eq!(recent_raw, 1, "recent rows must stay in usage_events");

    // AC3: spend is unchanged across the retention boundary, for BOTH the current (raw) period
    // and the period that has aged into the rollup.
    let s_old_after = repo
        .spend_for_account("acct_1", old_period_start, old_period_end)
        .await
        .expect("spend old after");
    let s_recent_after = repo
        .spend_for_account("acct_1", recent_period_start, recent_period_end)
        .await
        .expect("spend recent after");
    assert_eq!(
        s_old_after, s_old_before,
        "spend for the aged period must not shift after rollup"
    );
    assert_eq!(
        s_recent_after, s_recent_before,
        "spend for the current period must not shift after rollup"
    );
}

/// A second run of the retention job is a no-op: the old rows are already gone, so nothing is
/// re-rolled-up and nothing is double-counted.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn rollup_and_purge_is_idempotent(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();
    let raw_days = 90;

    let old_day = (now - Duration::days(raw_days + 10))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day, 5.0)])
        .await
        .expect("insert");

    let first = rollup_and_purge(&pool, raw_days).await.expect("first run");
    assert_eq!(first, 1, "first run purges the one old row");

    let second = rollup_and_purge(&pool, raw_days).await.expect("second run");
    assert_eq!(second, 0, "second run has nothing left to purge");

    let rollup_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events_daily")
        .fetch_one(&pool)
        .await
        .expect("count rollup");
    assert_eq!(rollup_count, 1, "the day must be rolled up exactly once");
}
