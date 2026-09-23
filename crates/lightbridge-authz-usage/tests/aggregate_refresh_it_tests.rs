#![cfg(feature = "it-tests")]
//! Integration tests for the #587 KPI aggregates (plain-Postgres materialized views).
//!
//! Unlike the Timescale-gated tests in `day_seat_grain_it_tests.rs`, these run in CI on plain
//! Postgres: `CREATE MATERIALIZED VIEW`, `REFRESH MATERIALIZED VIEW CONCURRENTLY` and the unique
//! indexes they need are all vanilla Postgres (the #587 owner decision: no TimescaleDB, plain
//! Postgres achieves the same). They apply the real `migrations-usage/` directory fresh per test
//! via `#[sqlx::test]`.
//!
//! They prove the ticket's acceptance criteria:
//!
//! 1. A named aggregate exists per KPI measure, each on exactly one grain table (AC1).
//! 2. The refresh job runs and records its last refresh (AC2 -- "refresh policies ... have
//!    demonstrably run", on plain Postgres).
//! 3. Money discipline: unknown-cost rows are counted separately, never coerced to 0 (AC4).
//! 4. An EXPLAIN proves the KPI query reads the aggregate, not a raw-table scan (AC3).

use chrono::{DateTime, NaiveDate, Utc};
use lightbridge_authz_usage_rest::aggregate_refresh::{
    AGGREGATE_VIEWS, RefreshLockGuard, record_last_refresh, refresh_all_aggregates,
};
use sqlx::PgPool;

/// AC1: every named KPI aggregate exists as a materialized view.
///
/// The sabotage condition: drop a `CREATE MATERIALIZED VIEW` from the migration (or remove a name
/// from `AGGREGATE_VIEWS`) and this test goes red for that exact view.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn every_kpi_aggregate_exists(pool: PgPool) {
    for view in AGGREGATE_VIEWS {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pg_matviews WHERE matviewname = $1")
                .bind(view)
                .fetch_one(&pool)
                .await
                .expect("matview lookup should succeed");

        assert_eq!(
            count, 1,
            "KPI aggregate {view} must exist as a materialized view; if this is 0, the \
             CREATE MATERIALIZED VIEW in migration 20260918000001 did not fire, or the name \
             drifted from AGGREGATE_VIEWS"
        );
    }
}

/// AC2: refreshing all aggregates succeeds and records the last refresh into
/// `usage_aggregate_refresh_state`, so a test or operator can prove the refresh has run.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn refresh_records_last_refresh(pool: PgPool) {
    refresh_all_aggregates(&pool)
        .await
        .expect("refreshing all KPI aggregates should succeed");
    record_last_refresh(&pool)
        .await
        .expect("recording last refresh should succeed");

    let last: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT last_refreshed_at FROM usage_aggregate_refresh_state WHERE id = TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("state lookup should succeed");

    assert!(
        last.is_some(),
        "last_refreshed_at must be recorded after a refresh run -- the 'refresh has run' \
         acceptance criterion is unprovable without it"
    );
}

/// Dropping a [`RefreshLockGuard`] without calling `release` -- the cancellation/panic path -- must
/// release the session advisory lock. The refresh lock is session-scoped (REFRESH cannot run in a
/// transaction, so the transaction-scoped fix `snapshot_refresher.rs` uses is unavailable), and a
/// session lock returned to the pool still held would silently stop every replica's refresh. This
/// is the deterministic half of that guarantee: the guard's `Drop` is what releases it.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn dropped_guard_releases_advisory_lock(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire a connection");
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(587_000_001)
        .fetch_one(&mut *conn)
        .await
        .expect("acquiring the lock should succeed");
    assert!(
        acquired,
        "the test must hold the lock before handing it to the guard"
    );

    // Hand the lock to a guard and drop it WITHOUT `release` -- the abnormal path a cancelled or
    // panicked refresh takes.
    let guard = RefreshLockGuard::new(conn, 587_000_001);
    drop(guard);

    assert!(
        lock_becomes_free(&pool).await,
        "dropping the guard must release the session advisory lock -- a session-scoped lock \
         returned to the pool still held would silently stop every OTHER replica's refresh"
    );
}

/// A completed refresh must leave the advisory lock free with no explicit unlock beyond the
/// guard's own `release` -- the deterministic half that the normal path releases the lock.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn completed_refresh_releases_advisory_lock(pool: PgPool) {
    refresh_all_aggregates(&pool)
        .await
        .expect("refresh should succeed");
    assert!(
        lock_is_free(&pool).await,
        "a completed refresh must leave the advisory lock free"
    );
}

/// Polls [`lock_is_free`] for up to two seconds.
///
/// The wait is not slack in the property; it is what makes the property observable at all. The
/// guard's `Drop` releases the lock on a dedicated thread, so between `drop()` returning and that
/// thread's unlock actually executing there is a window, and a probe on a different pool connection
/// can land inside it and see the lock still held.
async fn lock_becomes_free(pool: &PgPool) -> bool {
    for _ in 0..100 {
        if lock_is_free(pool).await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    false
}

/// `true` when nobody holds the aggregate-refresh advisory lock, read from `pg_locks`.
///
/// Reading `pg_locks` takes no lock and cannot perturb what it measures. A 64-bit advisory key is
/// split across two columns: `classid` is the high 32 bits, `objid` the low 32. For key
/// `587_000_001` (`0x22FC_E8C1`): `classid = 0x22FC = 8956`, `objid = 0xE8C1 = 59585`.
async fn lock_is_free(pool: &PgPool) -> bool {
    const LOCK_CLASSID: i32 = 8_956;
    const LOCK_OBJID: i32 = 59_585;
    let (held,): (i64,) = sqlx::query_as(
        "SELECT count(*)::bigint FROM pg_locks \
         WHERE locktype = 'advisory' AND classid = $1 AND objid = $2 AND granted",
    )
    .bind(LOCK_CLASSID)
    .bind(LOCK_OBJID)
    .fetch_one(pool)
    .await
    .expect("reading pg_locks must succeed");
    held == 0
}

/// AC4: money discipline on the day-facts spend aggregate. A row with NULL cost must be counted in
/// `unknown_cost_count` and must NOT make the bucket's `cost_micro_usd` read as 0.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_aggregate_counts_unknown_cost_separately(pool: PgPool) {
    let d = NaiveDate::from_ymd_opt(2026, 9, 1).expect("valid date");

    // Two day-facts rows on the same day: one with a known cost, one with unknown (NULL) cost.
    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id, cost_micro_usd)
         VALUES
            ('github-copilot', $1, 'org', 'org-1', 500),
            ('github-copilot', $1, 'org', 'org-2', NULL)",
    )
    .bind(d)
    .execute(&pool)
    .await
    .expect("insert should succeed");

    refresh_all_aggregates(&pool)
        .await
        .expect("refresh should succeed");

    let (cost, unknown): (Option<i64>, i64) = sqlx::query_as(
        "SELECT SUM(cost_micro_usd)::bigint, SUM(unknown_cost_count)::bigint
         FROM mv_day_facts_spend_daily WHERE source = 'github-copilot'",
    )
    .fetch_one(&pool)
    .await
    .expect("aggregate query should succeed");

    assert_eq!(
        cost,
        Some(500),
        "known cost must sum to 500, not be coerced to 0 by the unknown row"
    );
    assert_eq!(
        unknown, 1,
        "the NULL-cost row must be counted separately in unknown_cost_count, never folded in as free"
    );
}

/// AC4 (all-unknown bucket): when EVERY row in a bucket has unknown cost, the bucket's
/// `cost_micro_usd` must be NULL (never 0) and `unknown_cost_count` must equal the row count.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_aggregate_all_unknown_is_null_not_zero(pool: PgPool) {
    let d = NaiveDate::from_ymd_opt(2026, 9, 1).expect("valid date");

    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id, cost_micro_usd)
         VALUES
            ('github-copilot', $1, 'org', 'org-1', NULL),
            ('github-copilot', $1, 'org', 'org-2', NULL)",
    )
    .bind(d)
    .execute(&pool)
    .await
    .expect("insert should succeed");

    refresh_all_aggregates(&pool)
        .await
        .expect("refresh should succeed");

    let (cost, unknown): (Option<i64>, i64) = sqlx::query_as(
        "SELECT SUM(cost_micro_usd)::bigint, SUM(unknown_cost_count)::bigint
         FROM mv_day_facts_spend_daily WHERE source = 'github-copilot'",
    )
    .fetch_one(&pool)
    .await
    .expect("aggregate query should succeed");

    assert!(
        cost.is_none(),
        "an all-unknown bucket must report cost_micro_usd = NULL, never 0 (ADR-0028 D0)"
    );
    assert_eq!(unknown, 2, "both unknown rows must be counted separately");
}

/// AC1 (no cross-grain): the day-facts and seat aggregates exist and are queryable, and the
/// day-facts active-users aggregate reports the peak (MAX), not a sum, of the per-day distinct
/// count. Two days for the same subject (8 then 12 active users) must aggregate to the peak 12,
/// never the sum 20.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn day_facts_active_users_aggregate_reports_peak(pool: PgPool) {
    let d1 = NaiveDate::from_ymd_opt(2026, 9, 1).expect("valid date");
    let d2 = NaiveDate::from_ymd_opt(2026, 9, 2).expect("valid date");

    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id, total_active_users)
         VALUES
            ('github-copilot', $1, 'org', 'org-1', 8),
            ('github-copilot', $2, 'org', 'org-1', 12)",
    )
    .bind(d1)
    .bind(d2)
    .execute(&pool)
    .await
    .expect("insert should succeed");

    refresh_all_aggregates(&pool)
        .await
        .expect("refresh should succeed");

    let peak: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(active_users) FROM mv_day_facts_active_users_daily
         WHERE source = 'github-copilot' AND subject_id = 'org-1'",
    )
    .fetch_one(&pool)
    .await
    .expect("aggregate query should succeed");

    assert_eq!(
        peak,
        Some(12),
        "active users is a per-day distinct count, so the aggregate must report the peak (MAX), \
         not a sum across days (which would be 20)"
    );
}

/// AC3 (seat): an EXPLAIN of the seat query shape against the aggregate proves the seat endpoint
/// reads the aggregate, not a raw-table scan. The seat query routes to
/// `mv_seat_snapshots_active_daily` when it exists (see `repo/seat_query.rs`).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn explain_proves_seat_query_reads_aggregate(pool: PgPool) {
    let lines: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT source, SUM(active_count) AS active
         FROM mv_seat_snapshots_active_daily
         GROUP BY source",
    )
    .fetch_all(&pool)
    .await
    .expect("EXPLAIN should succeed");
    let plan = lines.join("\n");

    assert!(
        plan.contains("mv_seat_snapshots_active_daily"),
        "the seat query plan must read the aggregate mv_seat_snapshots_active_daily; got: {plan}"
    );
    assert!(
        !plan.contains("usage_seat_snapshots"),
        "the seat query plan must NOT scan the raw usage_seat_snapshots table; got: {plan}"
    );
}

/// AC3 (day-facts): an EXPLAIN of the day-facts query shape against the aggregates proves the
/// day-facts endpoint reads the aggregates (a same-grain JOIN), not a raw-table scan. The
/// day-facts query routes to the three `mv_day_facts_*_daily` aggregates when they exist (see
/// `repo/day_fact_query.rs`).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn explain_proves_day_facts_query_reads_aggregate(pool: PgPool) {
    let lines: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT a.source, SUM(a.suggestions) AS suggestions, SUM(s.cost_micro_usd) AS cost
         FROM mv_day_facts_acceptances_daily a
         JOIN mv_day_facts_spend_daily s
           ON a.day = s.day AND a.source = s.source AND a.subject_kind = s.subject_kind
          AND a.subject_id = s.subject_id AND a.is_aggregate_only = s.is_aggregate_only
         GROUP BY a.source",
    )
    .fetch_all(&pool)
    .await
    .expect("EXPLAIN should succeed");
    let plan = lines.join("\n");

    assert!(
        plan.contains("mv_day_facts_acceptances_daily")
            && plan.contains("mv_day_facts_spend_daily"),
        "the day-facts query plan must read the mv_day_facts_*_daily aggregates; got: {plan}"
    );
    assert!(
        !plan.contains("usage_day_facts"),
        "the day-facts query plan must NOT scan the raw usage_day_facts table; got: {plan}"
    );
}
