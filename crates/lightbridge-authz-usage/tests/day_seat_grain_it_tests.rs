#![cfg(feature = "it-tests")]
//! Integration tests for the day-grain (`usage_day_facts`) and seat-grain (`usage_seat_snapshots`)
//! tables introduced in #583.
//!
//! These tests run against a real Timescale-enabled Postgres via `#[sqlx::test]` (migrations are
//! applied fresh per test). They prove:
//!
//! 1. Both tables exist as hypertables in `timescaledb_information.hypertables`.
//! 2. Retention and compression policies are present in `timescaledb_information.jobs`.
//! 3. Upsert on the natural key **is the primary key** — replaying a day changes no counts.
//! 4. Money columns survive a NULL round-trip exactly as NULL, never 0.
//! 5. A second source (`m365-copilot`) lands with zero DDL changes (governance#167's criterion).
//! 6. Aggregate-only rows are stored and distinguishable from per-entity rows.
//! 7. Every `SubjectKind` variant round-trips serde ↔ `as_str()` ↔ a live INSERT (the parity the
//!    SQL CHECK constraints, the serde names, and `SubjectKind` must keep).
//! 8. Seat-state columns round-trip (AC1: seat *state* and *activity* columns).
//! 9. D22's compressed-chunk replay: a row replayed into a chunk that has already been compressed
//!    is absorbed by the PK conflict — still exactly one row, never a duplicate.

use chrono::NaiveDate;
use lightbridge_authz_usage_rest::models::SubjectKind;
use sqlx::PgPool;

fn copilot_day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 9, 1).expect("valid date")
}

fn m365_day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 9, 2).expect("valid date")
}

/// Asserts that both grain tables are registered as hypertables.
///
/// If `create_hypertable` is removed or silently falls back, this test fails with a clear message
/// rather than silently leaving a plain Postgres table that looks like it works until retention
/// never drops a chunk. The sabotage condition: comment out `SELECT create_hypertable(...)` in
/// the migration and run this test — it must go red for this exact assertion.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn both_grain_tables_are_hypertables(pool: PgPool) {
    for table in ["usage_day_facts", "usage_seat_snapshots"] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM timescaledb_information.hypertables
             WHERE hypertable_name = $1",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("query should succeed");

        assert_eq!(
            count, 1,
            "{table} must be registered as a hypertable in timescaledb_information.hypertables; \
             if this is 0, the create_hypertable call in the migration did not fire — \
             check that the Timescale extension is loaded and that the migration has no EXCEPTION WHEN OTHERS"
        );
    }
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
/// Inserting the same fact twice must produce ONE row, not two. The natural key IS the primary
/// key (`PRIMARY KEY (source, day, subject_kind, subject_id)`), so the `ON CONFLICT` here
/// targets the PK. The sabotage condition: widen the PK (e.g. add `total_suggestions_count`) or
/// drop any of its columns — the insert must then FAIL to conflict and double instead.
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

/// Upsert on the natural key for `usage_seat_snapshots` — which is that table's primary key,
/// including the seat-state column's NOT NULL host.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn insert_seat_snapshot_is_idempotent_on_natural_key(pool: PgPool) {
    let day = copilot_day();

    let insert = r"
        INSERT INTO usage_seat_snapshots
            (source, snapshot_day, subject_kind, subject_id, provider_user_id, seat_state, assignee_login, plan_type)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (source, snapshot_day, subject_kind, subject_id, provider_user_id)
        DO UPDATE SET
            seat_state = EXCLUDED.seat_state,
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
            .bind("assigned")
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
            (source, snapshot_day, subject_kind, subject_id, provider_user_id, seat_state)
         VALUES ('github-copilot', $1, 'enterprise', 'ent-1', 'user-1', 'assigned')",
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

/// Test 7a: every `SubjectKind` variant is accepted by the CHECK constraint — via a live INSERT.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn all_subject_kind_variants_are_accepted(pool: PgPool) {
    let day = copilot_day();

    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id)
         VALUES
            ('github-copilot', $1, 'org', 'subject-0'),
            ('github-copilot', $1, 'user', 'subject-1'),
            ('github-copilot', $1, 'repo', 'subject-2'),
            ('github-copilot', $1, 'user_team', 'subject-3')",
    )
    .bind(day)
    .execute(&pool)
    .await
    .expect("all four subject_kind variants must be accepted by the CHECK");

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM usage_day_facts WHERE source = 'github-copilot'")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");

    assert_eq!(count, 4, "all four subject_kind variants must land");
}

/// Test 7b: the three presentations of the vocabulary cannot drift apart — the enum's `as_str()`
/// tokens, the CHECK-constraint body as read back from the LIVE database, and
/// `SubjectKind::check_vocabulary()` must be the same four tokens in the same order. Adding a
/// variant to the enum without amending the migrations' CHECK (or vice versa) fails here, at
/// test time, not at first ingest.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn subject_kind_vocabulary_stays_in_lockstep_with_the_live_check(pool: PgPool) {
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(c.oid)
         FROM pg_constraint c
         JOIN pg_class t ON t.oid = c.conrelid
         WHERE c.conname = 'chk_usage_day_facts_subject_kind'
           AND t.relname = 'usage_day_facts'",
    )
    .fetch_one(&pool)
    .await
    .expect("the CHECK constraint must exist on the live table");

    for kind in SubjectKind::ALL {
        let token = kind.as_str();
        assert!(
            def.contains(token),
            "CHECK definition {def:?} must contain the enum token {token:?}"
        );
    }

    for token in SubjectKind::check_vocabulary() {
        assert!(
            def.contains(token),
            "CHECK vocabulary {token:?} must be in the live definition {def:?}"
        );
    }

    assert_eq!(
        SubjectKind::ALL
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>(),
        SubjectKind::check_vocabulary().to_vec(),
        "enum as_str() order and check_vocabulary() must agree — they are two copies of the \
         schema-side tokens and must never drift"
    );
}

/// Test 8: AC1's "seat state *and* activity columns" — seat_state round-trips verbatim, and the
/// state column is distinct from the activity columns. A source that reports some other state
/// token must store it, not guess.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn seat_state_round_trips_verbatim(pool: PgPool) {
    let day = copilot_day();

    sqlx::query(
        "INSERT INTO usage_seat_snapshots
            (source, snapshot_day, subject_kind, subject_id, provider_user_id, seat_state, last_activity_at)
         VALUES ('github-copilot', $1, 'org', 'org-1', 'user-77', $2, NOW())",
    )
    .bind(day)
    .bind("pending_cancellation")
    .execute(&pool)
    .await
    .expect("insert should succeed");

    let state: String = sqlx::query_scalar(
        "SELECT seat_state FROM usage_seat_snapshots WHERE source = 'github-copilot' AND snapshot_day = $1",
    )
    .bind(day)
    .fetch_one(&pool)
    .await
    .expect("select should succeed");

    assert_eq!(
        state, "pending_cancellation",
        "seat_state must round-trip verbatim"
    );
}

/// Test 9 (D22): a row replayed into a chunk that has already compressed must be absorbed by the
/// natural-key PK — never a silent duplicate. Several co-located rows (same `source`/`subject_kind`
/// segment) are inserted first so `compress_segmentby`/`compress_orderby` are actually exercised,
/// the chunk holding the past month is compressed manually, then one fact is re-sent through the
/// upsert and the table still holds the original row count with the replayed values.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn dedup_holds_when_replaying_into_a_compressed_chunk(pool: PgPool) {
    let day = NaiveDate::from_ymd_opt(2026, 1, 15).expect("valid date");

    sqlx::query(
        "INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_suggestions_count, cost_micro_usd)
         VALUES
            ('github-copilot', $1, 'org', 'org-a', 10, 1_000),
            ('github-copilot', $1, 'org', 'org-b', 20, 2_000),
            ('github-copilot', $1, 'org', 'org-c', 30, 3_000)",
    )
    .bind(day)
    .execute(&pool)
    .await
    .expect("initial multi-row insert should succeed");

    sqlx::query(
        "SELECT compress_chunk(c)
         FROM show_chunks('usage_day_facts') AS c",
    )
    .execute(&pool)
    .await
    .expect("manual chunk compression should succeed");

    let compressed = sqlx::query_scalar::<_, bool>(
        "SELECT is_compressed
         FROM timescaledb_information.chunks
         WHERE hypertable_name = 'usage_day_facts'
           AND chunk_name = (SELECT chunk_name
                             FROM timescaledb_information.chunks
                             WHERE hypertable_name = 'usage_day_facts'
                             ORDER BY range_start
                             LIMIT 1)",
    )
    .fetch_one(&pool)
    .await
    .expect("chunk lookup should succeed");

    assert!(
        compressed,
        "the January chunk must be compressed for this test to be meaningful"
    );

    sqlx::query(
        "INSERT INTO usage_day_facts
            (source, day, subject_kind, subject_id, total_suggestions_count, cost_micro_usd)
         VALUES ('github-copilot', $1, 'org', 'org-b', 900, 2_000)
         ON CONFLICT (source, day, subject_kind, subject_id)
         DO UPDATE SET total_suggestions_count = EXCLUDED.total_suggestions_count,
                       cost_micro_usd = EXCLUDED.cost_micro_usd",
    )
    .bind(day)
    .execute(&pool)
    .await
    .expect(
        "replay into the compressed chunk must succeed — if TimescaleDB refuses an \
             ON CONFLICT DO UPDATE against a compressed chunk, D22's dedup contract must be \
             carried by a decompress-replay-refuse policy, not silently",
    );

    let rows: (i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), MIN(total_suggestions_count) FROM usage_day_facts WHERE day = $1",
    )
    .bind(day)
    .fetch_one(&pool)
    .await
    .expect("count query should succeed");

    assert_eq!(
        rows.0,
        3,
        "replay into a compressed chunk must not duplicate the row — expected the original 3 \
         co-located rows to survive, got {rows_count}",
        rows_count = rows.0
    );
    assert_eq!(
        rows.1,
        Some(10),
        "the untouched segment rows must survive; only the replayed subject is updated"
    );

    let replayed: Option<i64> = sqlx::query_scalar(
        "SELECT total_suggestions_count FROM usage_day_facts
         WHERE source = 'github-copilot' AND day = $1 AND subject_id = 'org-b'",
    )
    .bind(day)
    .fetch_one(&pool)
    .await
    .expect("replayed row lookup should succeed");

    assert_eq!(
        replayed,
        Some(900),
        "the replayed measures must replace the stored ones for the replayed subject only"
    );
}
