#![cfg(feature = "it-tests")]

//! Execution-grain integration tests (#582): `usage_executions` / `usage_model_calls` /
//! `usage_tool_calls` / `usage_identities`.
//!
//! Ingest wiring and query endpoints are separate stories (out of scope for #582), so these
//! tests exercise the tables directly through SQL. They prove the properties the ticket and
//! the schema make load-bearing:
//!   * one execution can carry N model calls and M tool calls (each child is its own span);
//!   * idempotent replay -- replaying the same batch (same `source`, `trace_id`, `span_id`)
//!     changes no counts (AC #4), while a later priced cost fills a NULL (the
//!     `ON CONFLICT DO UPDATE ... COALESCE` correction path);
//!   * a later report CORRECTS a wrong non-NULL cost and token count (the upsert updates the
//!     mutable fields, not just NULLs);
//!   * child-before-parent -- OTLP exports children before their parent, so ingest mints a
//!     stub `usage_executions` row (NULL `duration_ms`/`raw_schema_version`) on first sight of
//!     a child; the real execution span later fills the stub via the upsert;
//!   * the id is globally unique -- the same `span_id` across different traces, and the same
//!     `(trace_id, span_id)` across different `source` values, both insert distinct rows;
//!   * NULL-cost round-trip -- a NULL money column survives a write/read as NULL, and a
//!     genuine 0 (a truly free run) is storable and distinct from NULL (AC #3);
//!   * `usage_identities` mint/dedup and single-UPDATE erasure (ADR-0028 D7).
//!
//! The hypertable-assertion sabotage test from the ticket's Test Expectations is deliberately
//! absent: TimescaleDB is not deployed on the usage tenant and is not required for this grain
//! (see the ticket note and the migration headers), so there is no hypertable assertion to
//! sabotage.

use chrono::{Duration, Utc};
use sqlx::PgPool;

const SOURCE: &str = "claude_code";

async fn insert_execution(
    pool: &PgPool,
    observed_at: chrono::DateTime<Utc>,
    trace_id: &str,
    span_id: &str,
    identity_id: Option<&str>,
    cost: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_executions
            (id, observed_at, source, provider, trace_id, span_id, identity_id, duration_ms, raw_schema_version, estimated_cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (source, trace_id, span_id) DO UPDATE SET
            -- observed_at is last-write-wins ONLY when filling a stub (existing duration is
            -- NULL); a pure replay of a completed execution keeps the first observed_at so an
            -- idempotent redelivery is a true no-op on the time column.
            observed_at = CASE
                WHEN usage_executions.duration_ms IS NULL THEN EXCLUDED.observed_at
                ELSE usage_executions.observed_at
            END,
            provider = EXCLUDED.provider,
            identity_id = COALESCE(EXCLUDED.identity_id, usage_executions.identity_id),
            duration_ms = COALESCE(EXCLUDED.duration_ms, usage_executions.duration_ms),
            raw_backend = COALESCE(EXCLUDED.raw_backend, usage_executions.raw_backend),
            raw_schema_version = COALESCE(EXCLUDED.raw_schema_version, usage_executions.raw_schema_version),
            estimated_cost_micro_usd = COALESCE(EXCLUDED.estimated_cost_micro_usd, usage_executions.estimated_cost_micro_usd),
            updated_at = now()
        "#,
    )
    .bind(format!("exec_{SOURCE}_{trace_id}_{span_id}"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind("anthropic")
    .bind(trace_id)
    .bind(span_id)
    .bind(identity_id)
    .bind(1200i64)
    .bind(1i64)
    .bind(cost)
    .execute(pool)
    .await?;
    Ok(())
}

// A stub execution: minted by ingest on first sight of a child span, before the real execution
// span arrives (OTLP exports children before their parent). `duration_ms`/`raw_schema_version`
// are NULL because a stub has neither; the real execution span fills them via the upsert.
async fn insert_execution_stub(
    pool: &PgPool,
    observed_at: chrono::DateTime<Utc>,
    trace_id: &str,
    span_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_executions
            (id, observed_at, source, provider, trace_id, span_id, duration_ms, raw_schema_version)
        VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL)
        ON CONFLICT (source, trace_id, span_id) DO NOTHING
        "#,
    )
    .bind(format!("exec_{SOURCE}_{trace_id}_{span_id}"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind("anthropic")
    .bind(trace_id)
    .bind(span_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper binding the fixed set of usage_model_calls columns"
)]
async fn insert_model_call(
    pool: &PgPool,
    observed_at: chrono::DateTime<Utc>,
    trace_id: &str,
    child_span_id: &str,
    execution_id: &str,
    model: &str,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cost: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_model_calls
            (id, observed_at, source, execution_id, trace_id, span_id, model, input_tokens, output_tokens, cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (source, trace_id, span_id) DO UPDATE SET
            input_tokens = COALESCE(EXCLUDED.input_tokens, usage_model_calls.input_tokens),
            output_tokens = COALESCE(EXCLUDED.output_tokens, usage_model_calls.output_tokens),
            cost_micro_usd = COALESCE(EXCLUDED.cost_micro_usd, usage_model_calls.cost_micro_usd),
            updated_at = now()
        "#,
    )
    .bind(format!("{SOURCE}_{trace_id}_{child_span_id}:mc"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind(execution_id)
    .bind(trace_id)
    .bind(child_span_id)
    .bind(model)
    .bind(input_tokens)
    .bind(output_tokens)
    .bind(cost)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_tool_call(
    pool: &PgPool,
    observed_at: chrono::DateTime<Utc>,
    trace_id: &str,
    child_span_id: &str,
    execution_id: &str,
    tool_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_tool_calls
            (id, observed_at, source, execution_id, trace_id, span_id, tool_name, duration_ms)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (source, trace_id, span_id) DO NOTHING
        "#,
    )
    .bind(format!("{SOURCE}_{trace_id}_{child_span_id}:tc"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind(execution_id)
    .bind(trace_id)
    .bind(child_span_id)
    .bind(tool_name)
    .bind(90i64)
    .execute(pool)
    .await?;
    Ok(())
}

async fn count_executions(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM usage_executions")
        .fetch_one(pool)
        .await
        .expect("count usage_executions")
}

async fn count_model_calls(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM usage_model_calls")
        .fetch_one(pool)
        .await
        .expect("count usage_model_calls")
}

async fn count_tool_calls(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM usage_tool_calls")
        .fetch_one(pool)
        .await
        .expect("count usage_tool_calls")
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn one_execution_can_carry_multiple_model_and_tool_calls(pool: PgPool) {
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-multi";
    let exec_span = "span-exec-multi";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("insert execution");

    // Two model calls, each its own span.
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-mc-1",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        Some(1000),
    )
    .await
    .expect("insert model call 1");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-mc-2",
        &exec_id,
        "claude-opus-4-1",
        Some(1200),
        Some(400),
        Some(2000),
    )
    .await
    .expect("insert model call 2");

    // Two tool calls, each its own span.
    insert_tool_call(&pool, observed_at, trace_id, "span-tc-1", &exec_id, "bash")
        .await
        .expect("insert tool call 1");
    insert_tool_call(&pool, observed_at, trace_id, "span-tc-2", &exec_id, "grep")
        .await
        .expect("insert tool call 2");

    assert_eq!(count_executions(&pool).await, 1);
    assert_eq!(count_model_calls(&pool).await, 2);
    assert_eq!(count_tool_calls(&pool).await, 2);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn replaying_the_same_batch_twice_changes_no_counts(pool: PgPool) {
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-replay-1";
    let exec_span = "span-replay-1";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("first insert should succeed");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-replay-1-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        Some(1000),
    )
    .await
    .expect("first model call");
    insert_tool_call(
        &pool,
        observed_at,
        trace_id,
        "span-replay-1-tc",
        &exec_id,
        "bash",
    )
    .await
    .expect("first tool call");

    let exec_before = count_executions(&pool).await;
    let mc_before = count_model_calls(&pool).await;
    let tc_before = count_tool_calls(&pool).await;
    assert_eq!((exec_before, mc_before, tc_before), (1, 1, 1));

    // Replay the exact same batch (same trace_id, span_id).
    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("replay should be absorbed, not error");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-replay-1-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        Some(1000),
    )
    .await
    .expect("replay model call");
    insert_tool_call(
        &pool,
        observed_at,
        trace_id,
        "span-replay-1-tc",
        &exec_id,
        "bash",
    )
    .await
    .expect("replay tool call");

    let exec_after = count_executions(&pool).await;
    let mc_after = count_model_calls(&pool).await;
    let tc_after = count_tool_calls(&pool).await;

    assert_eq!(
        (exec_after, mc_after, tc_after),
        (exec_before, mc_before, tc_before),
        "replaying the same OTLP batch must not change any grain's row count"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn replay_with_drifted_observed_at_is_still_absorbed(pool: PgPool) {
    // The dedup key is (source, trace_id, span_id), bijective with the derived id, so a
    // redelivery with a different observed_at must be absorbed -- not a 23505 on the PK.
    // And because the existing row is a completed execution (duration NOT NULL), the upsert
    // keeps the FIRST observed_at: an idempotent replay is a true no-op on the time column.
    let trace_id = "trace-drift";
    let exec_span = "span-drift";
    let first_observed_at = Utc::now() - Duration::minutes(5);

    insert_execution(
        &pool,
        first_observed_at,
        trace_id,
        exec_span,
        None,
        Some(5000),
    )
    .await
    .expect("first delivery");

    insert_execution(
        &pool,
        Utc::now() - Duration::minutes(4),
        trace_id,
        exec_span,
        None,
        Some(5000),
    )
    .await
    .expect("redelivery with a drifted observed_at must be absorbed, not a 23505");

    assert_eq!(count_executions(&pool).await, 1);

    let stored: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT observed_at FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read stored observed_at");
    // Postgres TIMESTAMPTZ stores microsecond precision, so compare within a tolerance well
    // below the 1-minute drift -- this proves the replay kept the FIRST observed_at.
    assert!(
        (stored - first_observed_at).num_milliseconds().abs() < 1000,
        "an idempotent replay of a completed execution must not mutate observed_at (stored {stored}, first {first_observed_at})"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn same_span_id_across_different_traces_does_not_collide(pool: PgPool) {
    // An OTLP span_id is only unique within a trace, not globally. The id embeds source,
    // trace_id and span_id (`exec_{source}_{trace_id}_{span_id}`), so two executions that
    // happen to share a span_id across unrelated traces must both insert -- not a 23505 on
    // the PK.
    let observed_at = Utc::now() - Duration::minutes(5);
    let shared_span = "span-shared";

    insert_execution(&pool, observed_at, "trace-a", shared_span, None, Some(1000))
        .await
        .expect("execution in trace-a");
    insert_execution(&pool, observed_at, "trace-b", shared_span, None, Some(2000))
        .await
        .expect("execution in trace-b with the same span_id must not collide on the PK");

    assert_eq!(count_executions(&pool).await, 2);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn same_trace_and_span_across_different_sources_does_not_collide(pool: PgPool) {
    // The `source` dimension is in the dedup key and the id, so two origins that emit the
    // same (trace_id, span_id) must both be stored -- not silently absorbed or overwritten
    // (a multi-tenant gateway and a CLI can legitimately share a trace/span id space).
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-shared";
    let span_id = "span-shared";

    // source = claude_code (the helper's SOURCE constant).
    insert_execution(&pool, observed_at, trace_id, span_id, None, Some(1000))
        .await
        .expect("execution from claude_code");

    // source = opencode, same (trace_id, span_id) -- must be a distinct row.
    sqlx::query(
        r#"
        INSERT INTO usage_executions
            (id, observed_at, source, provider, trace_id, span_id, duration_ms, raw_schema_version, estimated_cost_micro_usd)
        VALUES ($1, $2, 'opencode', 'anthropic', $3, $4, 1200, 1, 2000)
        "#,
    )
    .bind(format!("exec_opencode_{trace_id}_{span_id}"))
    .bind(observed_at)
    .bind(trace_id)
    .bind(span_id)
    .execute(&pool)
    .await
    .expect("execution from opencode with the same trace/span must not collide");

    assert_eq!(
        count_executions(&pool).await,
        2,
        "the same (trace_id, span_id) from two sources must be two rows"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn child_can_be_inserted_before_its_parent_execution(pool: PgPool) {
    // OTLP exports child spans before the parent execution span (a child ends before its
    // parent, and BatchSpanProcessor flushes every ~5s). Ingest mints a STUB usage_executions
    // row (id from the child's parent_span_id, duration_ms/raw_schema_version NULL) on first
    // sight of a child, in the same transaction, so the NOT NULL execution_id FK is
    // satisfiable. The real execution span later fills the stub via the upsert.
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-child-first";
    let exec_span = "span-child-first-exec";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    // Child arrives first: ingest creates the stub execution, then the model call.
    insert_execution_stub(&pool, observed_at, trace_id, exec_span)
        .await
        .expect("stub execution on first sight of a child");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-child-first-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        Some(1000),
    )
    .await
    .expect("model call referencing the stub execution");

    // The stub has no duration or schema version yet.
    let stub_duration: Option<i64> = sqlx::query_scalar(
        "SELECT duration_ms FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read stub duration");
    assert_eq!(stub_duration, None, "a stub execution has no duration yet");

    // The real execution span arrives later and fills the stub via the upsert.
    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("real execution fills the stub");

    let filled_duration: Option<i64> = sqlx::query_scalar(
        "SELECT duration_ms FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read filled duration");
    assert_eq!(
        filled_duration,
        Some(1200),
        "the real execution must fill the stub's duration"
    );

    assert_eq!(
        count_executions(&pool).await,
        1,
        "stub + real execution must be one row"
    );
    assert_eq!(count_model_calls(&pool).await, 1);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn null_cost_survives_round_trip_as_unknown_never_zero(pool: PgPool) {
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-null-cost";
    let exec_span = "span-null-cost";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(&pool, observed_at, trace_id, exec_span, None, None)
        .await
        .expect("insert execution with NULL cost");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-null-cost-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        None,
    )
    .await
    .expect("insert model call with NULL cost");

    let exec_cost: Option<i64> = sqlx::query_scalar(
        "SELECT estimated_cost_micro_usd FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read execution cost");

    let mc_cost: Option<i64> = sqlx::query_scalar(
        "SELECT cost_micro_usd FROM usage_model_calls WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind("span-null-cost-mc")
    .fetch_one(&pool)
    .await
    .expect("read model call cost");

    assert_eq!(
        exec_cost, None,
        "NULL execution cost must round-trip as unknown (None), never 0"
    );
    assert_eq!(
        mc_cost, None,
        "NULL model-call cost must round-trip as unknown (None), never 0"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn genuine_zero_cost_is_storable_and_distinct_from_null(pool: PgPool) {
    // A truly free run (cost rounds to 0 micro-USD) is a legitimate value and must be storable
    // -- the NULL-vs-0 discipline is about unknown being written as NULL, not about forbidding
    // a real 0. The donor ships no CHECK for this reason.
    let observed_at = Utc::now() - Duration::minutes(5);

    insert_execution(&pool, observed_at, "trace-zero", "span-zero", None, Some(0))
        .await
        .expect("a genuine 0 cost must be storable");

    let zero_cost: Option<i64> = sqlx::query_scalar(
        "SELECT estimated_cost_micro_usd FROM usage_executions WHERE trace_id = 'trace-zero'",
    )
    .fetch_one(&pool)
    .await
    .expect("read zero cost");
    assert_eq!(zero_cost, Some(0), "a genuine 0 must round-trip as Some(0)");

    // And it stays distinct from NULL (unknown).
    insert_execution(
        &pool,
        observed_at,
        "trace-unknown",
        "span-unknown",
        None,
        None,
    )
    .await
    .expect("insert unknown cost");
    let unknown_cost: Option<i64> = sqlx::query_scalar(
        "SELECT estimated_cost_micro_usd FROM usage_executions WHERE trace_id = 'trace-unknown'",
    )
    .fetch_one(&pool)
    .await
    .expect("read unknown cost");
    assert_eq!(
        unknown_cost, None,
        "unknown must round-trip as None, distinct from Some(0)"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn later_priced_cost_fills_a_null_on_replay(pool: PgPool) {
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-correction";
    let exec_span = "span-correction";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    // First report: cost unknown (NULL).
    insert_execution(&pool, observed_at, trace_id, exec_span, None, None)
        .await
        .expect("first report with NULL cost");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-correction-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        None,
    )
    .await
    .expect("first model call with NULL cost");

    // Later report: the priced cost arrives. DO UPDATE ... COALESCE must fill the NULL.
    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(7777))
        .await
        .expect("later report with priced cost");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-correction-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
        Some(3333),
    )
    .await
    .expect("later model call with priced cost");

    let exec_cost: Option<i64> = sqlx::query_scalar(
        "SELECT estimated_cost_micro_usd FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read corrected execution cost");

    let mc_cost: Option<i64> = sqlx::query_scalar(
        "SELECT cost_micro_usd FROM usage_model_calls WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind("span-correction-mc")
    .fetch_one(&pool)
    .await
    .expect("read corrected model call cost");

    assert_eq!(
        exec_cost,
        Some(7777),
        "a later priced cost must fill a NULL execution cost"
    );
    assert_eq!(
        mc_cost,
        Some(3333),
        "a later priced cost must fill a NULL model-call cost"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn later_report_corrects_a_non_null_cost_and_tokens(pool: PgPool) {
    // A later report must be able to CORRECT a wrong non-NULL cost and token count, not just
    // fill a NULL. The upsert updates the mutable fields (COALESCE: a non-NULL EXCLUDED value
    // wins; a NULL EXCLUDED value preserves the existing one, so a partial replay never wipes
    // a priced cost).
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-correct-fields";
    let exec_span = "span-correct-fields";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    // First report: a wrong (too-low) cost and partial token count.
    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(1000))
        .await
        .expect("first execution report");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-correct-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(100),
        Some(50),
        Some(500),
    )
    .await
    .expect("first model-call report");

    // Later report: the corrected cost and full token count arrive.
    insert_execution(&pool, observed_at, trace_id, exec_span, None, Some(2000))
        .await
        .expect("corrected execution report");
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-correct-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(200),
        Some(100),
        Some(900),
    )
    .await
    .expect("corrected model-call report");

    let exec_cost: Option<i64> = sqlx::query_scalar(
        "SELECT estimated_cost_micro_usd FROM usage_executions WHERE trace_id = $1",
    )
    .bind(trace_id)
    .fetch_one(&pool)
    .await
    .expect("read corrected execution cost");
    assert_eq!(
        exec_cost,
        Some(2000),
        "a later priced cost must correct a non-NULL execution cost"
    );

    let (mc_cost, mc_in, mc_out): (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT cost_micro_usd, input_tokens, output_tokens FROM usage_model_calls WHERE trace_id = $1",
    )
    .bind(trace_id)
    .fetch_one(&pool)
    .await
    .expect("read corrected model-call fields");
    assert_eq!(
        mc_cost,
        Some(900),
        "a later priced cost must correct a non-NULL model-call cost"
    );
    assert_eq!(
        mc_in,
        Some(200),
        "a later report must correct the input token count"
    );
    assert_eq!(
        mc_out,
        Some(100),
        "a later report must correct the output token count"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn usage_identities_mint_dedup_and_single_update_erasure(pool: PgPool) {
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-identity";
    let exec_span = "span-identity";
    let identity_a = "identity_ada_0001";
    let identity_b = "identity_bob_0001";

    async fn mint(pool: &PgPool, id: &str, subject_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO usage_identities (id, source, subject_kind, subject_id)
            VALUES ($1, $2, 'user', $3)
            ON CONFLICT (source, subject_kind, subject_id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(SOURCE)
        .bind(subject_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    // Mint: insert an identity, then re-assert the same (source, subject_kind, subject_id)
    // with ON CONFLICT DO NOTHING -- must not mint a duplicate.
    mint(&pool, identity_a, "ada@example.com")
        .await
        .expect("mint identity A");
    mint(&pool, "identity_ada_0002", "ada@example.com")
        .await
        .expect("re-assert identity A");

    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_identities WHERE subject_id = 'ada@example.com'",
    )
    .fetch_one(&pool)
    .await
    .expect("count identities");
    assert_eq!(
        identity_count, 1,
        "re-asserting the same identity must not mint a duplicate"
    );

    // Reference identity A from an execution (exercises the FK).
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        Some(identity_a),
        Some(5000),
    )
    .await
    .expect("insert execution referencing the identity");

    let resolved: String = sqlx::query_scalar(
        "SELECT ui.subject_id FROM usage_executions e JOIN usage_identities ui ON ui.id = e.identity_id WHERE e.trace_id = $1",
    )
    .bind(trace_id)
    .fetch_one(&pool)
    .await
    .expect("resolve execution identity");
    assert_eq!(
        resolved, "ada@example.com",
        "execution must resolve to the referenced identity"
    );

    // Single-UPDATE erasure: one UPDATE on usage_identities removes the PII everywhere,
    // because every grain table references this row by id, not by the PII value. The sentinel
    // embeds the row's own id (`erased:<id>`) so erasing a SECOND identity of the same
    // (source, subject_kind) does not collide with the UNIQUE natural key.
    sqlx::query("UPDATE usage_identities SET subject_id = 'erased:' || id WHERE id = $1")
        .bind(identity_a)
        .execute(&pool)
        .await
        .expect("erase identity A");

    // Mint a second identity of the same (source, subject_kind) and erase it too -- a constant
    // sentinel would collide here (23505); the row-unique sentinel must not.
    mint(&pool, identity_b, "bob@example.com")
        .await
        .expect("mint identity B");
    sqlx::query("UPDATE usage_identities SET subject_id = 'erased:' || id WHERE id = $1")
        .bind(identity_b)
        .execute(&pool)
        .await
        .expect("erasing a second identity of the same (source, subject_kind) must not collide");

    let erased: String = sqlx::query_scalar(
        "SELECT ui.subject_id FROM usage_executions e JOIN usage_identities ui ON ui.id = e.identity_id WHERE e.trace_id = $1",
    )
    .bind(trace_id)
    .fetch_one(&pool)
    .await
    .expect("resolve erased identity");
    assert_eq!(
        erased,
        format!("erased:{identity_a}"),
        "one UPDATE on usage_identities must erase the PII everywhere"
    );
}
