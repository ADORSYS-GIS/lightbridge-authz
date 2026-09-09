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
//!     mutable fields, not just NULLs) -- and the same correction applies to
//!     `usage_model_calls.model` and to `usage_tool_calls.tool_name`/`duration_ms`, which are
//!     NOT NULL but not immutable either;
//!   * child-before-parent -- OTLP exports children before their parent, so ingest mints a
//!     stub `usage_executions` row (NULL `duration_ms`/`raw_schema_version`) on first sight of
//!     a child; the real execution span later fills the stub via the upsert. While still a
//!     stub, multiple children arriving out of processing order converge the stub's
//!     `observed_at` on the EARLIEST child observation (`LEAST`), never a later one;
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
    provider: Option<&str>,
    cost: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_executions
            (id, observed_at, source, provider, trace_id, span_id, identity_id, duration_ms, raw_schema_version, estimated_cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (source, trace_id, span_id) DO UPDATE SET
            -- observed_at only moves EARLIER while filling a stub (existing duration is NULL),
            -- via LEAST -- never later. Children of one execution can arrive out of processing
            -- order (network jitter), so a plain last-write-wins here would let observed_at
            -- drift non-monotonically (even backward) depending on arrival order; LEAST makes
            -- the stub converge on the earliest-known observation, which is the closest proxy
            -- for the execution's true start time. A pure replay of a completed execution keeps
            -- the first observed_at so an idempotent redelivery is a true no-op on the time
            -- column.
            observed_at = CASE
                WHEN usage_executions.duration_ms IS NULL
                    THEN LEAST(usage_executions.observed_at, EXCLUDED.observed_at)
                ELSE usage_executions.observed_at
            END,
            -- provider is nullable (for the tool-call-first stub path), so it gets the same
            -- COALESCE guard as every other correctable column: a delivery that cannot
            -- resolve a provider must never wipe one already known on a completed execution.
            provider = COALESCE(EXCLUDED.provider, usage_executions.provider),
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
    .bind(provider)
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
            -- model is NOT NULL, so COALESCE always takes EXCLUDED's value here -- this is a
            -- corrigible field like input_tokens/output_tokens/cost_micro_usd below, not an
            -- omission: a later report that resolves a more specific model id (e.g. after an
            -- alias/snapshot is finalized) must correct it, matching every other mutable column
            -- on this row.
            model = COALESCE(EXCLUDED.model, usage_model_calls.model),
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
    duration_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_tool_calls
            (id, observed_at, source, execution_id, trace_id, span_id, tool_name, duration_ms)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (source, trace_id, span_id) DO UPDATE SET
            -- tool_name/duration_ms are NOT NULL, so a redelivery always carries a real value --
            -- unconditional overwrite (not COALESCE) matches the donor and lets a later,
            -- corrected report replace an interim/estimated value instead of freezing the row
            -- at whatever arrived first.
            tool_name = EXCLUDED.tool_name,
            duration_ms = EXCLUDED.duration_ms,
            updated_at = now()
        "#,
    )
    .bind(format!("{SOURCE}_{trace_id}_{child_span_id}:tc"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind(execution_id)
    .bind(trace_id)
    .bind(child_span_id)
    .bind(tool_name)
    .bind(duration_ms)
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

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(5000),
    )
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
    insert_tool_call(
        &pool,
        observed_at,
        trace_id,
        "span-tc-1",
        &exec_id,
        "bash",
        90,
    )
    .await
    .expect("insert tool call 1");
    insert_tool_call(
        &pool,
        observed_at,
        trace_id,
        "span-tc-2",
        &exec_id,
        "grep",
        90,
    )
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

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(5000),
    )
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
        90,
    )
    .await
    .expect("first tool call");

    let exec_before = count_executions(&pool).await;
    let mc_before = count_model_calls(&pool).await;
    let tc_before = count_tool_calls(&pool).await;
    assert_eq!((exec_before, mc_before, tc_before), (1, 1, 1));

    // Replay the exact same batch (same trace_id, span_id).
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(5000),
    )
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
        90,
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
        Some("anthropic"),
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
        Some("anthropic"),
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

    insert_execution(
        &pool,
        observed_at,
        "trace-a",
        shared_span,
        None,
        Some("anthropic"),
        Some(1000),
    )
    .await
    .expect("execution in trace-a");
    insert_execution(
        &pool,
        observed_at,
        "trace-b",
        shared_span,
        None,
        Some("anthropic"),
        Some(2000),
    )
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
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        span_id,
        None,
        Some("anthropic"),
        Some(1000),
    )
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
    // parent, and BatchSpanProcessor flushes every ~5s). Within a single ingest transaction
    // the child is inserted BEFORE the parent row exists, and the DEFERRABLE INITIALLY
    // DEFERRED execution_id FK defers the check to commit time -- so a child can reference a
    // parent that is only created later in the same transaction. This is the actual wire
    // ordering, and it is what the deferrable FK exists to permit.
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-child-first";
    let exec_span = "span-child-first-exec";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    let mut tx = pool.begin().await.expect("begin transaction");

    // Child first: the model call references an execution that does not exist yet. The
    // DEFERRABLE INITIALLY DEFERRED FK must not reject this until commit.
    sqlx::query(
        r#"
        INSERT INTO usage_model_calls
            (id, observed_at, source, execution_id, trace_id, span_id, model, input_tokens, output_tokens, cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(format!("{SOURCE}_{trace_id}_span-child-first-mc:mc"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind(&exec_id)
    .bind(trace_id)
    .bind("span-child-first-mc")
    .bind("claude-sonnet-4-5")
    .bind(1200i64)
    .bind(400i64)
    .bind(1000i64)
    .execute(&mut *tx)
    .await
    .expect("model call referencing a not-yet-existing execution");

    // The stub execution (parent) is created later in the same transaction. It is a stub, so
    // provider/duration_ms/raw_schema_version are NULL (a tool-call-first stub has no model
    // provider to set).
    sqlx::query(
        r#"
        INSERT INTO usage_executions
            (id, observed_at, source, provider, trace_id, span_id, duration_ms, raw_schema_version)
        VALUES ($1, $2, $3, NULL, $4, $5, NULL, NULL)
        "#,
    )
    .bind(&exec_id)
    .bind(observed_at)
    .bind(SOURCE)
    .bind(trace_id)
    .bind(exec_span)
    .execute(&mut *tx)
    .await
    .expect("stub execution created after the child");

    // Commit: the deferred FK check now passes because the stub exists.
    tx.commit().await.expect("commit transaction");

    // The stub has no duration or provider yet.
    let stub_duration: Option<i64> = sqlx::query_scalar(
        "SELECT duration_ms FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read stub duration");
    assert_eq!(stub_duration, None, "a stub execution has no duration yet");
    let stub_provider: Option<String> = sqlx::query_scalar(
        "SELECT provider FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read stub provider");
    assert_eq!(stub_provider, None, "a stub execution has no provider yet");

    // The real execution span arrives later and fills the stub via the upsert.
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(5000),
    )
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
    let filled_provider: Option<String> = sqlx::query_scalar(
        "SELECT provider FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(exec_span)
    .fetch_one(&pool)
    .await
    .expect("read filled provider");
    assert_eq!(
        filled_provider.as_deref(),
        Some("anthropic"),
        "the real execution must fill the stub's provider"
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

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        None,
    )
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

    insert_execution(
        &pool,
        observed_at,
        "trace-zero",
        "span-zero",
        None,
        Some("anthropic"),
        Some(0),
    )
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
        Some("anthropic"),
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
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        None,
    )
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
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(7777),
    )
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
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(1000),
    )
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
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(2000),
    )
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
async fn later_report_corrects_the_model_call_s_model(pool: PgPool) {
    // model is NOT NULL on usage_model_calls, but that does not mean it is immutable: a later
    // report that resolves a more specific model id (e.g. a snapshot alias finalized after the
    // interim report) must correct the stored value, matching every other mutable column on
    // this row (input_tokens/output_tokens/cost_micro_usd already prove this pattern).
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-correct-model";
    let exec_span = "span-correct-model-exec";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(1000),
    )
    .await
    .expect("execution report");

    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-correct-model-mc",
        &exec_id,
        "claude-sonnet-4-5-interim",
        Some(100),
        Some(50),
        Some(500),
    )
    .await
    .expect("first model-call report with an interim model id");

    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "span-correct-model-mc",
        &exec_id,
        "claude-sonnet-4-5-20260901",
        Some(100),
        Some(50),
        Some(500),
    )
    .await
    .expect("corrected model-call report with the finalized model id");

    let model: String =
        sqlx::query_scalar("SELECT model FROM usage_model_calls WHERE trace_id = $1")
            .bind(trace_id)
            .fetch_one(&pool)
            .await
            .expect("read corrected model");
    assert_eq!(
        model, "claude-sonnet-4-5-20260901",
        "a later report must correct the model id, not freeze it at the first-seen value"
    );
    assert_eq!(
        count_model_calls(&pool).await,
        1,
        "correcting the model must not create a second row"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn later_report_corrects_tool_call_fields(pool: PgPool) {
    // tool_name/duration_ms are NOT NULL on usage_tool_calls, so unlike the money/token columns
    // there is no NULL to fill -- but a later, more accurate report must still be able to
    // CORRECT them, not be silently dropped. This is the tool-call analogue of
    // `later_report_corrects_a_non_null_cost_and_tokens` above.
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-correct-tool-call";
    let exec_span = "span-correct-tool-call-exec";
    let child_span = "span-correct-tool-call-tc";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(1000),
    )
    .await
    .expect("execution report");

    // First report: an interim tool name and an estimated (too-low) duration.
    insert_tool_call(
        &pool,
        observed_at,
        trace_id,
        child_span,
        &exec_id,
        "bash-interim",
        10,
    )
    .await
    .expect("first tool-call report");

    // Later report: the corrected tool name and final duration arrive.
    insert_tool_call(
        &pool,
        observed_at,
        trace_id,
        child_span,
        &exec_id,
        "bash",
        250,
    )
    .await
    .expect("corrected tool-call report");

    let (tool_name, duration_ms): (String, i64) =
        sqlx::query_as("SELECT tool_name, duration_ms FROM usage_tool_calls WHERE trace_id = $1")
            .bind(trace_id)
            .fetch_one(&pool)
            .await
            .expect("read corrected tool call");
    assert_eq!(
        tool_name, "bash",
        "a later report must correct tool_name, not freeze it at the first-seen value"
    );
    assert_eq!(
        duration_ms, 250,
        "a later report must correct duration_ms, not freeze it at the first-seen (estimated) value"
    );
    assert_eq!(
        count_tool_calls(&pool).await,
        1,
        "correcting the tool call must not create a second row"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn a_stub_execution_s_observed_at_converges_on_the_earliest_child(pool: PgPool) {
    // Multiple children of one still-open execution can arrive out of processing order (network
    // jitter). While the execution is still a stub (duration_ms IS NULL), observed_at must move
    // only EARLIER (LEAST), never later -- a plain last-write-wins would let a late-processed
    // but early-observed child regress the stub's observed_at backward, or let a
    // later-observed-but-earlier-processed child overwrite a truly-earlier timestamp with a
    // later one.
    let earliest = Utc::now() - Duration::minutes(10);
    let middle = Utc::now() - Duration::minutes(7);
    let latest = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-stub-observed-at";
    let exec_span = "span-stub-observed-at-exec";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    // A stub-minting upsert, matching the shape ingest uses when a child arrives before its
    // parent execution span (see `child_can_be_inserted_before_its_parent_execution`):
    // duration_ms stays NULL, so the row remains a stub across every call in this test -- unlike
    // `insert_execution`, which always writes a non-NULL duration_ms and would "complete" the
    // stub on the very first call.
    async fn upsert_stub(pool: &PgPool, id: &str, observed_at: chrono::DateTime<Utc>) {
        sqlx::query(
            r#"
            INSERT INTO usage_executions (id, observed_at, source, trace_id, span_id)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (source, trace_id, span_id) DO UPDATE SET
                observed_at = CASE
                    WHEN usage_executions.duration_ms IS NULL
                        THEN LEAST(usage_executions.observed_at, EXCLUDED.observed_at)
                    ELSE usage_executions.observed_at
                END
            "#,
        )
        .bind(id)
        .bind(observed_at)
        .bind(SOURCE)
        .bind("trace-stub-observed-at")
        .bind("span-stub-observed-at-exec")
        .execute(pool)
        .await
        .expect("stub upsert");
    }

    // First child observed at the LATEST time processed FIRST.
    upsert_stub(&pool, &exec_id, latest).await;

    // A second child, observed EARLIER, processed SECOND -- must pull observed_at backward.
    upsert_stub(&pool, &exec_id, earliest).await;

    // A third child, observed in the MIDDLE, processed THIRD -- must not push observed_at
    // forward past the earliest already recorded.
    upsert_stub(&pool, &exec_id, middle).await;

    let stub_duration: Option<i64> =
        sqlx::query_scalar("SELECT duration_ms FROM usage_executions WHERE trace_id = $1")
            .bind(trace_id)
            .fetch_one(&pool)
            .await
            .expect("read stub duration");
    assert_eq!(
        stub_duration, None,
        "sanity check: the row must still be a stub for this test to be exercising the LEAST() \
         branch at all"
    );

    let stored: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT observed_at FROM usage_executions WHERE trace_id = $1")
            .bind(trace_id)
            .fetch_one(&pool)
            .await
            .expect("read stub observed_at");
    assert!(
        (stored - earliest).num_milliseconds().abs() < 1000,
        "a still-open stub's observed_at must converge on the earliest-known child observation \
         (stored {stored}, earliest {earliest})"
    );
    assert_eq!(
        count_executions(&pool).await,
        1,
        "children of one execution must be absorbed into one stub row"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn null_provider_replay_does_not_erase_a_known_provider(pool: PgPool) {
    // provider is nullable (for the tool-call-first stub path), so the upsert must guard it
    // with COALESCE like every other correctable column: a delivery that cannot resolve a
    // provider (a retry, a duplicate export, or a payload where provider resolution failed)
    // must never wipe a provider already known on a completed execution.
    let observed_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-provider";
    let span_id = "span-provider";

    // First delivery: provider known.
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        span_id,
        None,
        Some("anthropic"),
        Some(5000),
    )
    .await
    .expect("first delivery with provider");

    // Replay with provider = NULL (provider resolution failed on this delivery), same
    // (source, trace_id, span_id). The upsert must keep 'anthropic'.
    insert_execution(
        &pool,
        observed_at,
        trace_id,
        span_id,
        None,
        None,
        Some(5000),
    )
    .await
    .expect("replay with NULL provider");

    let provider: Option<String> = sqlx::query_scalar(
        "SELECT provider FROM usage_executions WHERE trace_id = $1 AND span_id = $2",
    )
    .bind(trace_id)
    .bind(span_id)
    .fetch_one(&pool)
    .await
    .expect("read provider");
    assert_eq!(
        provider.as_deref(),
        Some("anthropic"),
        "a NULL-provider replay must not erase a known provider"
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
        Some("anthropic"),
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
