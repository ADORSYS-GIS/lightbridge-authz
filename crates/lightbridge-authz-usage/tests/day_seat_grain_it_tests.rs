#![cfg(feature = "it-tests")]
//! Integration tests for the day-grain (`usage_day_facts`) and seat-grain (`usage_seat_snapshots`)
//! tables introduced in #583.
//!
//! These tests run against a real Timescale-enabled Postgres via `#[sqlx::test]` (migrations are
//! applied fresh per test). They prove:
//!
//! 1. Both tables exist as hypertables in `timescaledb_information.hypertables`.
//! 2. Retention and compression policies are present in `timescaledb_information.jobs`.
//! 3. Upsert on the natural key is idempotent — reprocessing a day changes no counts.
//! 4. Money columns survive a NULL round-trip exactly as NULL, never 0.
//! 5. A second source (`m365-copilot`) lands with zero DDL changes (governance#167's criterion).
//! 6. Aggregate-only rows are stored and distinguishable from per-entity rows.

use chrono::NaiveDate;
use sqlx::PgPool;

fn copilot_day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 9, 1).expect("valid date")
}

fn m365_day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 9, 2).expect("valid date")
}

/// Asserts that `usage_day_facts` is registered as a hypertable.
///
/// If `create_hypertable` is removed or silently falls back, this test fails with a clear message
/// rather than silently leaving a plain Postgres table that looks like it works until retention
/// never drops a chunk. The sabotage condition: comment out `SELECT create_hypertable(...)` in
/// the migration and run this test — it must go red for this exact assertion.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn usage_day_facts_is_a_hypertable(pool: PgPool) {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM timescaledb_information.hypertables
         WHERE hypertable_name = 'usage_day_facts'",
    )
    .fetch_one(&pool)
    .await
    .expect("query should succeed");

    assert_eq!(
        count, 1,
        "usage_day_facts must be registered as a hypertable in timescaledb_information.hypertables; \
         if this is 0, the create_hypertable call in the migration did not fire — \
         check that the Timescale extension is loaded and that the migration has no EXCEPTION WHEN OTHERS"
    );
}

/// Same assertion for `usage_seat_snapshots`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn usage_seat_snapshots_is_a_hypertable(pool: PgPool) {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM timescaledb_information.hypertables
         WHERE hypertable_name = 'usage_seat_snapshots'",
    )
    .fetch_one(&pool)
    .await
    .expect("query should succeed");

    assert_eq!(
        count, 1,
        "usage_seat_snapshots must be registered as a hypertable in timescaledb_information.hypertables"
    );
}

/// Asserts that both tables have a retention policy attached (ADR-0028 D6: 25 months).
///
/// A retention policy that was never successfully attached is indistinguishable from no policy —
/// storage grows forever and the F2 lesson repeats.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn both_tables_have_retention_policies(pool: PgPool) {
    for table in ["usage_day_facts", "usage_seat_snapshots"] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM timescaledb_information.jobs
             WHERE application_name LIKE 'Retention Policy%'
               AND hypertable_name = $1",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|_| panic!("retention policy query failed for {table}"));

        assert!(
            count >= 1,
            "{table} must have a retention policy in timescaledb_information.jobs; \
             if this is 0, add_retention_policy did not succeed — \
             check migration output for errors"
        );
    }
}

/// Asserts that both tables have a compression policy attached (ADR-0028 D6: 30 days).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn both_tables_have_compression_policies(pool: PgPool) {
    for table in ["usage_day_facts", "usage_seat_snapshots"] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM timescaledb_information.jobs
             WHERE application_name LIKE 'Compression Policy%'
               AND hypertable_name = $1",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|_| panic!("compression policy query failed for {table}"));

        assert!(
            count >= 1,
            "{table} must have a compression policy in timescaledb_information.jobs"
        );
    }
}

/// Upsert on the natural key (`source`, `day`, `subject_kind`, `subject_id`) is idempotent.
///
/// Inserting the same fact twice must produce ONE row, not two. The test proves the UNIQUE index
/// `idx_usage_day_facts_natural_key` and the `ON CONFLICT DO UPDATE` path both work.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn insert_day_fact_is_idempotent_on_natural_key(pool: PgPool) {
    let day = copilot_day();

    let insert = r"
        INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_suggestions_count, total_acceptances_count, cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (source, day, subject_kind, subject_id)
        DO UPDATE SET
            total_suggestions_count = EXCLUDED.total_suggestions_count,
            total_acceptances_count = EXCLUDED.total_acceptances_count,
            cost_micro_usd = EXCLUDED.cost_micro_usd
    ";

    sqlx::query(insert)
        .bind("github-copilot")
        .bind(day)
        .bind("org")
        .bind("org-42")
        .bind(1000_i64)
        .bind(800_i64)
        .bind(150_000_i64)
        .execute(&pool)
        .await
        .expect("first insert should succeed");

    sqlx::query(insert)
        .bind("github-copilot")
        .bind(day)
        .bind("org")
        .bind("org-42")
        .bind(1000_i64)
        .bind(800_i64)
        .bind(150_000_i64)
        .execute(&pool)
        .await
        .expect("second insert (same key) should succeed via ON CONFLICT");

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM usage_day_facts WHERE source = $1 AND day = $2")
            .bind("github-copilot")
            .bind(day)
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");

    assert_eq!(
        row_count, 1,
        "reprocessing the same (source, day, subject_kind, subject_id) must produce exactly one row, \
         not {row_count} — the ON CONFLICT upsert on the natural key did not fire"
    );
}

/// Upsert on the natural key for `usage_seat_snapshots`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn insert_seat_snapshot_is_idempotent_on_natural_key(pool: PgPool) {
    let day = copilot_day();

    let insert = r"
        INSERT INTO usage_seat_snapshots
            (source, snapshot_day, subject_kind, subject_id, provider_user_id, assignee_login, plan_type)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (source, snapshot_day, subject_kind, subject_id, provider_user_id)
        DO UPDATE SET
            assignee_login = EXCLUDED.assignee_login,
            plan_type = EXCLUDED.plan_type
    ";

    for _ in 0..2 {
        sqlx::query(insert)
            .bind("github-copilot")
            .bind(day)
            .bind("org")
            .bind("org-42")
            .bind("user-999")
            .bind("ada")
            .bind("business")
            .execute(&pool)
            .await
            .expect("insert should succeed");
    }

    let row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_seat_snapshots WHERE source = $1 AND snapshot_day = $2",
    )
    .bind("github-copilot")
    .bind(day)
    .fetch_one(&pool)
    .await
    .expect("count query should succeed");

    assert_eq!(
        row_count, 1,
        "reprocessing the same seat snapshot must produce exactly one row, not {row_count}"
    );
}

/// NULL money round-trip: `cost_micro_usd = NULL` must come back as NULL, never 0.
///
/// ADR-0028 D0: NULL = unknown, NEVER zero. `Some(0)` and `None` are different facts.
/// This test proves the column's NULL semantics are preserved end-to-end through the Postgres type
/// system and sqlx's `Option<i64>` binding.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn null_money_round_trips_as_null(pool: PgPool) {
    let day = NaiveDate::from_ymd_opt(2026, 9, 3).expect("valid date");

    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id, cost_micro_usd)
         VALUES ('github-copilot', $1, 'user', 'user-1', NULL)",
    )
    .bind(day)
    .execute(&pool)
    .await
    .expect("insert should succeed");

    let cost: Option<i64> =
        sqlx::query_scalar("SELECT cost_micro_usd FROM usage_day_facts WHERE day = $1")
            .bind(day)
            .fetch_one(&pool)
            .await
            .expect("select should succeed");

    assert!(
        cost.is_none(),
        "cost_micro_usd = NULL must round-trip as None, not Some({:?}) — \
         NULL means unknown, not zero (ADR-0028 D0)",
        cost
    );
}

/// Non-NULL money round-trip: a specific micro-USD value must survive exactly.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn non_null_money_round_trips_exactly(pool: PgPool) {
    let day = NaiveDate::from_ymd_opt(2026, 9, 4).expect("valid date");
    let cost_micros: i64 = 1_500_000;

    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id, cost_micro_usd)
         VALUES ('github-copilot', $1, 'user', 'user-2', $2)",
    )
    .bind(day)
    .bind(cost_micros)
    .execute(&pool)
    .await
    .expect("insert should succeed");

    let stored: Option<i64> =
        sqlx::query_scalar("SELECT cost_micro_usd FROM usage_day_facts WHERE day = $1")
            .bind(day)
            .fetch_one(&pool)
            .await
            .expect("select should succeed");

    assert_eq!(
        stored,
        Some(cost_micros),
        "cost_micro_usd must round-trip exactly — expected Some({cost_micros}), got {stored:?}"
    );
}

/// AC5: Zero-DDL second-source demonstration.
///
/// governance#167's acceptance criterion: a second source lands in an existing grain table with
/// only a normalizer + registry row — zero schema changes. This test proves it at the SQL level
/// by inserting rows from two different sources (`github-copilot` and `m365-copilot`) into the
/// SAME table and asserting both are queryable, per-source, with no DDL between the inserts.
///
/// The `m365-copilot` rows are fixture data (the M365 spike data from governance#158 is the
/// intended eventual occupant; fixture data proves the SQL property independent of data
/// availability).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn second_source_lands_with_zero_ddl(pool: PgPool) {
    let copilot_day = copilot_day();
    let m365_day = m365_day();

    sqlx::query(
        "INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_active_users, cost_micro_usd)
         VALUES ('github-copilot', $1, 'org', 'org-10', 50, 5_000_000)",
    )
    .bind(copilot_day)
    .execute(&pool)
    .await
    .expect("github-copilot insert should succeed");

    sqlx::query(
        "INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_active_users, cost_micro_usd)
         VALUES ('m365-copilot', $1, 'org', 'tenant-abc', 120, 12_000_000)",
    )
    .bind(m365_day)
    .execute(&pool)
    .await
    .expect("m365-copilot insert should succeed — no DDL needed for a second source");

    let copilot_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM usage_day_facts WHERE source = 'github-copilot'")
            .fetch_one(&pool)
            .await
            .expect("copilot count query should succeed");

    let m365_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM usage_day_facts WHERE source = 'm365-copilot'")
            .fetch_one(&pool)
            .await
            .expect("m365 count query should succeed");

    assert_eq!(copilot_count, 1, "github-copilot row must be present");
    assert_eq!(
        m365_count, 1,
        "m365-copilot row must be present — a second source must land with zero DDL changes \
         (governance#167's acceptance criterion); if this fails, the schema is vendor-coupled"
    );

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_day_facts")
        .fetch_one(&pool)
        .await
        .expect("total count should succeed");

    assert_eq!(
        total, 2,
        "both sources must coexist in the same table — total rows should be 2, got {total}"
    );
}

/// AC6: Aggregate-only rows are stored and distinguishable.
///
/// The `is_aggregate_only` flag marks rows from sources that enforce a reporting floor
/// (e.g. GitHub Copilot's 5-seat minimum in the Metrics API). These rows must be queryable
/// and must be distinguishable from per-entity rows so callers can exclude them from
/// per-user averages.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn aggregate_only_flag_is_stored_and_queryable(pool: PgPool) {
    let day = NaiveDate::from_ymd_opt(2026, 9, 5).expect("valid date");

    sqlx::query(
        "INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_active_users, is_aggregate_only)
         VALUES ('github-copilot', $1, 'org', 'org-small', 8, TRUE)",
    )
    .bind(day)
    .execute(&pool)
    .await
    .expect("aggregate-only insert should succeed");

    sqlx::query(
        "INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_active_users, is_aggregate_only)
         VALUES ('github-copilot', $1, 'user', 'user-100', 1, FALSE)",
    )
    .bind(day)
    .execute(&pool)
    .await
    .expect("per-user insert should succeed");

    let agg_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_day_facts WHERE day = $1 AND is_aggregate_only = TRUE",
    )
    .bind(day)
    .fetch_one(&pool)
    .await
    .expect("aggregate count should succeed");

    let per_user_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_day_facts WHERE day = $1 AND is_aggregate_only = FALSE",
    )
    .bind(day)
    .fetch_one(&pool)
    .await
    .expect("per-user count should succeed");

    assert_eq!(agg_count, 1, "one aggregate-only row must be present");
    assert_eq!(per_user_count, 1, "one per-user row must be present");
}

/// Subject_kind CHECK constraint rejects unknown values.
///
/// The constraint `CHECK (subject_kind IN ('org', 'user', 'repo', 'user_team'))` must fire on
/// an unknown value. This test proves the constraint is present and active — not just in the
/// migration text but in the actual applied schema.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn unknown_subject_kind_is_rejected(pool: PgPool) {
    let day = NaiveDate::from_ymd_opt(2026, 9, 6).expect("valid date");

    let result = sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id)
         VALUES ('github-copilot', $1, 'enterprise', 'ent-1')",
    )
    .bind(day)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "inserting an unknown subject_kind must be rejected by the CHECK constraint; \
         if this passes, the constraint is missing from the schema"
    );
}

/// Same for `usage_seat_snapshots`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn unknown_subject_kind_is_rejected_in_seat_snapshots(pool: PgPool) {
    let day = copilot_day();

    let result = sqlx::query(
        "INSERT INTO usage_seat_snapshots
            (source, snapshot_day, subject_kind, subject_id, provider_user_id)
         VALUES ('github-copilot', $1, 'enterprise', 'ent-1', 'user-1')",
    )
    .bind(day)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "inserting an unknown subject_kind into usage_seat_snapshots must be rejected"
    );
}

/// Empty source is rejected by the CHECK constraint.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn empty_source_is_rejected(pool: PgPool) {
    let day = copilot_day();

    let result = sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id)
         VALUES ('', $1, 'org', 'org-1')",
    )
    .bind(day)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "an empty source string must be rejected by the CHECK constraint"
    );
}
