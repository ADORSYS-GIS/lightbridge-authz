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
    let rollup_days = 365;

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
    let purged = rollup_and_purge(&pool, raw_days, rollup_days)
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
    let rollup_days = 365;

    let old_day = (now - Duration::days(raw_days + 10))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day, 5.0)])
        .await
        .expect("insert");

    let first = rollup_and_purge(&pool, raw_days, rollup_days)
        .await
        .expect("first run");
    assert_eq!(first, 1, "first run purges the one old row");

    let second = rollup_and_purge(&pool, raw_days, rollup_days)
        .await
        .expect("second run");
    assert_eq!(second, 0, "second run has nothing left to purge");

    let rollup_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events_daily")
        .fetch_one(&pool)
        .await
        .expect("count rollup");
    assert_eq!(rollup_count, 1, "the day must be rolled up exactly once");
}

/// A late-arriving raw event -- one whose `observed_at` falls in a day a PREVIOUS run already
/// rolled up -- must not wedge the retention job, AND its cost must be folded into the existing
/// rollup row rather than dropped. Without `ON CONFLICT DO UPDATE` on the rollup INSERT, that
/// event's `(bucket_start, dimensions)` group already exists in `usage_events_daily`, the INSERT
/// would either raise a unique violation (wedging the job forever) or, with `DO NOTHING`, silently
/// discard the late event's cost. `DO UPDATE` folds the late cost in, so spend for a closed
/// historical period is stable: it never jumps up while the late row is still raw and then
/// collapses when the row is purged.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn late_arriving_event_for_an_already_rolled_up_day_is_folded_in_not_dropped(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();
    let raw_days = 90;
    let rollup_days = 365;

    let old_day = (now - Duration::days(raw_days + 10))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();

    // First run: roll up + purge the old day ($10).
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day, 10.0)])
        .await
        .expect("insert original");
    let first = rollup_and_purge(&pool, raw_days, rollup_days)
        .await
        .expect("first run");
    assert_eq!(first, 1, "first run purges the one old row");

    // A late event ($99) for the SAME day arrives after that day was already rolled up.
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day, 99.0)])
        .await
        .expect("insert late event");

    // Second run must SUCCEED (not raise a unique violation), purge the late raw row, AND fold the
    // late cost into the existing rollup row: 10 + 99 = 109.
    let second = rollup_and_purge(&pool, raw_days, rollup_days)
        .await
        .expect("second run must not wedge on the late event");
    assert_eq!(second, 1, "the late raw row must still be purged");

    let late_raw: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_events WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3",
    )
    .bind("acct_1")
    .bind(old_day)
    .bind(old_day + Duration::days(1))
    .fetch_one(&pool)
    .await
    .expect("count late raw");
    assert_eq!(
        late_raw, 0,
        "the late raw row must be deleted from usage_events"
    );

    let rollup_cost: Option<f64> = sqlx::query_scalar(
        "SELECT SUM(total_cost) FROM usage_events_daily WHERE account_id = $1 AND bucket_start = $2",
    )
    .bind("acct_1")
    .bind(old_day)
    .fetch_one(&pool)
    .await
    .expect("sum rollup");
    assert_eq!(
        rollup_cost,
        Some(109.0),
        "the late cost must be folded into the rollup (10 + 99), not dropped"
    );

    // AC3: spend for the closed period is stable and reflects the folded-in late cost.
    let spend = repo
        .spend_for_account("acct_1", old_day, old_day + Duration::days(1))
        .await
        .expect("spend after fold-in");
    assert_eq!(
        spend,
        Some(109.0),
        "spend must reflect the folded-in late cost, not collapse back to 10"
    );
}

/// The rollup table is itself bounded: a rolled-up day older than `rollup_days` is deleted from
/// `usage_events_daily` too, so the long-term store does not grow without bound. A day that is
/// both rolled up (past `raw_days`) and past `rollup_days` must leave BOTH tables.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn rollup_rows_older_than_rollup_days_are_purged_from_the_rollup(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();
    let raw_days = 90;
    // A tiny rollup window so the rolled-up day is immediately past it.
    let rollup_days = 1;

    let old_day = (now - Duration::days(raw_days + 10))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day, 10.0)])
        .await
        .expect("insert");

    let purged = rollup_and_purge(&pool, raw_days, rollup_days)
        .await
        .expect("rollup should run");
    assert_eq!(purged, 1, "the old raw row must be purged");

    let raw_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events")
        .fetch_one(&pool)
        .await
        .expect("count raw");
    assert_eq!(raw_count, 0, "the raw row must be gone");

    let rollup_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events_daily")
        .fetch_one(&pool)
        .await
        .expect("count rollup");
    assert_eq!(
        rollup_count, 0,
        "the rolled-up day must be purged from the rollup once it is past rollup_days"
    );
}

/// The advisory lock is the replica-safety invariant: only one replica may run the rollup at a
/// time. When another transaction already holds the lock, a run must SKIP (return 0) rather than
/// race. This test fails if the `pg_try_advisory_xact_lock(549000001)` guard is removed.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn second_concurrent_run_skips_while_the_advisory_lock_is_held(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();
    let old_day = (now - Duration::days(100))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    // A row that WOULD be rolled up if the run proceeded -- so a lock-removal mutation is caught.
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day, 10.0)])
        .await
        .expect("insert old row");

    // Hold the advisory lock in a separate transaction on a separate connection.
    let mut holder = pool.begin().await.expect("begin holder");
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(549000001)")
        .fetch_one(&mut *holder)
        .await
        .expect("acquire lock");
    assert!(acquired, "the test must acquire the lock first");

    // A run while the lock is held must skip, not race.
    let purged = rollup_and_purge(&pool, 90, 365)
        .await
        .expect("rollup should skip cleanly");
    assert_eq!(
        purged, 0,
        "a run while another replica holds the advisory lock must skip (return 0)"
    );

    // The old row must still be raw -- it was not rolled up because the run skipped.
    let raw: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events")
        .fetch_one(&pool)
        .await
        .expect("count raw");
    assert_eq!(raw, 1, "the old row must stay raw when the run skips");

    holder.rollback().await.expect("rollback holder");
}

/// Only COMPLETE days are rolled up: the cutoff is rounded DOWN to the day boundary, so the whole
/// boundary day (the day that is `raw_days` old) stays raw -- which is what keeps the dashboard's
/// full 90-day window served from raw. This test fails if the `date_trunc('day', ...)` on the
/// cutoff is removed, which would roll up the partial, still-in-flight portion of the boundary day.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn boundary_day_is_not_partially_rolled_up(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();

    // A row at the very START of the boundary day (the day that is `raw_days` old). With the
    // `date_trunc` cutoff this row is NOT older than the cutoff (the cutoff is the start of this
    // day), so it must stay raw. Without `date_trunc`, the cutoff is the instant `now - raw_days`,
    // which is later in this day, so this row WOULD be rolled up -- the mutation this test catches.
    let boundary_day_start = (now - Duration::days(90))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    repo.insert_usage_events(&[event_with_cost("acct_1", boundary_day_start, 50.0)])
        .await
        .expect("insert boundary-day row");

    let purged = rollup_and_purge(&pool, 90, 365)
        .await
        .expect("rollup should run");
    assert_eq!(
        purged, 0,
        "the boundary day must not be rolled up -- only complete days are"
    );

    let raw: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events")
        .fetch_one(&pool)
        .await
        .expect("count raw");
    assert_eq!(raw, 1, "the boundary-day row must stay raw");

    let rollup: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_events_daily")
        .fetch_one(&pool)
        .await
        .expect("count rollup");
    assert_eq!(
        rollup, 0,
        "no rollup row may be created for the boundary day"
    );
}

/// Day bucketing is pinned to UTC: `date_trunc('day', <timestamptz>)` is session-timezone-dependent,
/// so without the transaction's `SET LOCAL TimeZone = 'UTC'` a non-UTC session would shift the day
/// boundary. This test sets a non-UTC session and asserts the rollup still buckets by the UTC day.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn rollup_buckets_by_utc_regardless_of_session_timezone(pool: PgPool) {
    // Set the session to a non-UTC zone (UTC-3). The pool may hand this connection to the rollup.
    sqlx::query("SET TimeZone = 'America/Sao_Paulo'")
        .execute(&pool)
        .await
        .expect("set session timezone");
    let repo = build_repo(pool.clone());
    let now = Utc::now();

    // A complete past day at 02:00 UTC. Under Sao Paulo (UTC-3) that is 23:00 the PREVIOUS local
    // day, so a local-timezone bucketing would shift the bucket one day earlier than UTC.
    let old_day_utc = (now - Duration::days(100))
        .date_naive()
        .and_hms_opt(2, 0, 0)
        .expect("valid time")
        .and_utc();
    repo.insert_usage_events(&[event_with_cost("acct_1", old_day_utc, 10.0)])
        .await
        .expect("insert");

    rollup_and_purge(&pool, 90, 365)
        .await
        .expect("rollup should run");

    // The rollup bucket must be the UTC day boundary, not the Sao Paulo local day.
    let expected = old_day_utc
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();
    let bucket: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT bucket_start FROM usage_events_daily")
            .fetch_one(&pool)
            .await
            .expect("read bucket");
    assert_eq!(
        bucket, expected,
        "the rollup must bucket by UTC, not the session timezone"
    );
}

/// P0-1 regression guard: a backdated row committed by a CONCURRENT ingest while the rollup runs
/// must never be lost. The rollup+purge is a single statement (DELETE ... RETURNING feeding the
/// INSERT), so the two share one snapshot: a concurrent row is either rolled up (if visible to the
/// statement) or stays raw (if committed after) -- never deleted without being rolled up. If the
/// two were separate statements, a row committed between them would be deleted but not rolled up,
/// and spend would silently drop. This test asserts total spend is preserved across the race.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn concurrent_backdated_insert_is_not_lost_by_the_rollup(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let now = Utc::now();
    let old_day = (now - Duration::days(100))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc();

    // A batch of old rows so the rollup has real work and a window for the concurrent insert.
    let mut events = Vec::new();
    for i in 0..2000 {
        events.push(event_with_cost(
            "acct_1",
            old_day + Duration::seconds(i),
            1.0,
        ));
    }
    repo.insert_usage_events(&events)
        .await
        .expect("insert batch");

    // A concurrent ingest inserts a backdated row while the rollup runs.
    let pool2 = pool.clone();
    let insert_task = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let repo2 = build_repo(pool2);
        repo2
            .insert_usage_events(&[event_with_cost(
                "acct_1",
                old_day + Duration::seconds(3000),
                777.0,
            )])
            .await
            .expect("concurrent insert");
    });

    let purged = rollup_and_purge(&pool, 90, 365)
        .await
        .expect("rollup should run");
    insert_task.await.expect("concurrent insert task");

    // Total spend must be preserved: 2000 * 1.0 + 777.0 = 2777.0. The concurrent row is either
    // rolled up or still raw, but never lost.
    assert!(purged >= 2000, "the old batch must be purged, got {purged}");
    let spend = repo
        .spend_for_account("acct_1", old_day, old_day + Duration::days(1))
        .await
        .expect("spend after race");
    assert_eq!(
        spend,
        Some(2777.0),
        "no row may be lost by the rollup under a concurrent backdated insert"
    );
}
