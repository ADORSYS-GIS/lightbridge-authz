#![cfg(feature = "it-tests")]

//! Execution-grain integration tests (#582): `usage_executions` / `usage_model_calls` /
//! `usage_tool_calls` / `usage_identities`.
//!
//! Ingest wiring and query endpoints are separate stories (out of scope for #582), so these
//! tests exercise the tables directly through SQL. They prove the properties the ticket and
//! the schema make load-bearing:
//!   * one execution can carry N model calls and M tool calls (each child is its own span);
//!   * idempotent replay -- replaying the same batch (same `started_at`, `trace_id`,
//!     `span_id`) changes no counts (AC #4), while a later priced cost fills a NULL (the
//!     `ON CONFLICT DO UPDATE ... COALESCE` correction path);
//!   * NULL-cost round-trip -- a NULL money column survives a write/read as NULL, never 0
//!     (AC #3), and 0 is rejected outright by the CHECK constraint;
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
    started_at: chrono::DateTime<Utc>,
    trace_id: &str,
    span_id: &str,
    identity_id: Option<&str>,
    cost: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_executions
            (id, started_at, source, provider, trace_id, span_id, identity_id, duration_ms, raw_schema_version, estimated_cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (started_at, trace_id, span_id) DO UPDATE SET
            estimated_cost_micro_usd = COALESCE(EXCLUDED.estimated_cost_micro_usd, usage_executions.estimated_cost_micro_usd)
        "#,
    )
    .bind(format!("exec_{span_id}"))
    .bind(started_at)
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

async fn insert_model_call(
    pool: &PgPool,
    started_at: chrono::DateTime<Utc>,
    trace_id: &str,
    child_span_id: &str,
    execution_id: &str,
    model: &str,
    cost: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_model_calls
            (id, started_at, source, execution_id, trace_id, span_id, model, input_tokens, output_tokens, cost_micro_usd)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (started_at, trace_id, span_id) DO UPDATE SET
            cost_micro_usd = COALESCE(EXCLUDED.cost_micro_usd, usage_model_calls.cost_micro_usd)
        "#,
    )
    .bind(format!("{child_span_id}:mc"))
    .bind(started_at)
    .bind(SOURCE)
    .bind(execution_id)
    .bind(trace_id)
    .bind(child_span_id)
    .bind(model)
    .bind(1200i64)
    .bind(400i64)
    .bind(cost)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_tool_call(
    pool: &PgPool,
    started_at: chrono::DateTime<Utc>,
    trace_id: &str,
    child_span_id: &str,
    execution_id: &str,
    tool_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO usage_tool_calls
            (id, started_at, source, execution_id, trace_id, span_id, tool_name, duration_ms)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (started_at, trace_id, span_id) DO NOTHING
        "#,
    )
    .bind(format!("{child_span_id}:tc"))
    .bind(started_at)
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
    let started_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-multi";
    let exec_span = "span-exec-multi";
    let exec_id = format!("exec_{exec_span}");

    insert_execution(&pool, started_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("insert execution");

    // Two model calls, each its own span.
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-mc-1",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1000),
    )
    .await
    .expect("insert model call 1");
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-mc-2",
        &exec_id,
        "claude-opus-4-1",
        Some(2000),
    )
    .await
    .expect("insert model call 2");

    // Two tool calls, each its own span.
    insert_tool_call(&pool, started_at, trace_id, "span-tc-1", &exec_id, "bash")
        .await
        .expect("insert tool call 1");
    insert_tool_call(&pool, started_at, trace_id, "span-tc-2", &exec_id, "grep")
        .await
        .expect("insert tool call 2");

    assert_eq!(count_executions(&pool).await, 1);
    assert_eq!(count_model_calls(&pool).await, 2);
    assert_eq!(count_tool_calls(&pool).await, 2);
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn replaying_the_same_batch_twice_changes_no_counts(pool: PgPool) {
    let started_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-replay-1";
    let exec_span = "span-replay-1";
    let exec_id = format!("exec_{exec_span}");

    insert_execution(&pool, started_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("first insert should succeed");
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-replay-1-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1000),
    )
    .await
    .expect("first model call");
    insert_tool_call(
        &pool,
        started_at,
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

    // Replay the exact same batch (same started_at, trace_id, span_id).
    insert_execution(&pool, started_at, trace_id, exec_span, None, Some(5000))
        .await
        .expect("replay should be absorbed, not error");
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-replay-1-mc",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1000),
    )
    .await
    .expect("replay model call");
    insert_tool_call(
        &pool,
        started_at,
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
async fn null_cost_survives_round_trip_as_unknown_never_zero(pool: PgPool) {
    let started_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-null-cost";
    let exec_span = "span-null-cost";
    let exec_id = format!("exec_{exec_span}");

    insert_execution(&pool, started_at, trace_id, exec_span, None, None)
        .await
        .expect("insert execution with NULL cost");
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-null-cost-mc",
        &exec_id,
        "claude-sonnet-4-5",
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
async fn zero_cost_is_rejected_by_the_check_constraint(pool: PgPool) {
    let started_at = Utc::now() - Duration::minutes(5);

    let exec_err = insert_execution(
        &pool,
        started_at,
        "trace-zero-exec",
        "span-zero-exec",
        None,
        Some(0),
    )
    .await;
    assert!(
        exec_err.is_err(),
        "a 0 execution cost must be rejected, not silently read as 'free'"
    );

    let exec_id = "exec_span-zero-mc";
    insert_execution(
        &pool,
        started_at,
        "trace-zero-mc",
        "span-zero-mc",
        None,
        Some(1000),
    )
    .await
    .expect("seed execution for model-call check");
    let mc_err = insert_model_call(
        &pool,
        started_at,
        "trace-zero-mc",
        "span-zero-mc-child",
        exec_id,
        "claude-sonnet-4-5",
        Some(0),
    )
    .await;
    assert!(
        mc_err.is_err(),
        "a 0 model-call cost must be rejected, not silently read as 'free'"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn later_priced_cost_fills_a_null_on_replay(pool: PgPool) {
    let started_at = Utc::now() - Duration::minutes(5);
    let trace_id = "trace-correction";
    let exec_span = "span-correction";
    let exec_id = format!("exec_{exec_span}");

    // First report: cost unknown (NULL).
    insert_execution(&pool, started_at, trace_id, exec_span, None, None)
        .await
        .expect("first report with NULL cost");
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-correction-mc",
        &exec_id,
        "claude-sonnet-4-5",
        None,
    )
    .await
    .expect("first model call with NULL cost");

    // Later report: the priced cost arrives. DO UPDATE ... COALESCE must fill the NULL.
    insert_execution(&pool, started_at, trace_id, exec_span, None, Some(7777))
        .await
        .expect("later report with priced cost");
    insert_model_call(
        &pool,
        started_at,
        trace_id,
        "span-correction-mc",
        &exec_id,
        "claude-sonnet-4-5",
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
async fn usage_identities_mint_dedup_and_single_update_erasure(pool: PgPool) {
    let started_at = Utc::now() - Duration::minutes(5);
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
        started_at,
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
