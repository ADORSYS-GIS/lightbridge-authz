#![cfg(feature = "it-tests")]
//! Integration tests for the execution-grain receiver (#588, AC2): repo upserts (dedup,
//! stub-before-parent, identity minting) and the end-to-end ingest path
//! (`/v1/otel/traces` with `X-Source: claude-code` → `usage_executions`/`usage_model_calls`/
//! `usage_tool_calls`).
//!
//! These apply the real `migrations-usage/` directory fresh per test via `#[sqlx::test]` and run
//! in CI unconditionally (plain Postgres).

use std::sync::Arc;

mod support;

use axum::{
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::{
    UsageRepoTrait, UsageState, build_ingest_router,
    models::execution_ingest::{
        ExecutionGrainBatch, ExecutionRecord, ModelCallRecord, ToolCallRecord,
    },
    repo::StoreRepo,
};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

fn repo(pool: &PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
}

fn app(pool: PgPool) -> axum::Router {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState {
        repo,
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_auth: None,
        raw_days: Some(90),
    });
    build_ingest_router(state, readiness_pool, false)
}

fn ts(nanos: u64) -> DateTime<Utc> {
    DateTime::from_timestamp(
        (nanos / 1_000_000_000) as i64,
        (nanos % 1_000_000_000) as u32,
    )
    .expect("valid timestamp")
}

fn exec(source: &str, trace: &str, span: &str, user: Option<&str>) -> ExecutionRecord {
    ExecutionRecord {
        source: source.into(),
        trace_id: trace.into(),
        span_id: span.into(),
        observed_at: ts(1_735_689_600_000_000_000),
        provider: Some("anthropic".into()),
        provider_user_id: user.map(|u| u.into()),
        duration_ms: Some(5000),
        estimated_cost_micro_usd: Some(1234),
        raw_backend: None,
        raw_schema_version: None,
    }
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn upsert_execution_grain_is_idempotent_on_dedup_key(pool: PgPool) {
    let r = repo(&pool);
    let batch = ExecutionGrainBatch {
        executions: vec![exec("claude-code", "t1", "e1", Some("user-1"))],
        model_calls: vec![ModelCallRecord {
            source: "claude-code".into(),
            trace_id: "t1".into(),
            span_id: "m1".into(),
            execution_id: "exec_claude-code_t1_e1".into(),
            observed_at: ts(1_735_689_600_000_000_000),
            model: "gpt-4.1".into(),
            input_tokens: Some(10),
            output_tokens: Some(5),
            cost_micro_usd: Some(100),
        }],
        tool_calls: vec![ToolCallRecord {
            source: "claude-code".into(),
            trace_id: "t1".into(),
            span_id: "tc1".into(),
            execution_id: "exec_claude-code_t1_e1".into(),
            observed_at: ts(1_735_689_600_000_000_000),
            tool_name: "bash".into(),
            duration_ms: 200,
        }],
    };
    r.upsert_execution_grain(&batch).await.expect("first");
    r.upsert_execution_grain(&batch).await.expect("replay");

    let execs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_executions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mcs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_model_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    let tcs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_tool_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (execs, mcs, tcs),
        (1, 1, 1),
        "replay must not change counts"
    );
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn stub_before_parent_then_real_execution_fills_it(pool: PgPool) {
    let r = repo(&pool);
    // Child-only batch: the parent execution is absent, so the normalizer would have minted a
    // stub execution (provider/duration/identity NULL) alongside the child. The repo upserts the
    // batch as given — stub-before-parent is a normalizer concern.
    let child_only = ExecutionGrainBatch {
        executions: vec![ExecutionRecord {
            source: "claude-code".into(),
            trace_id: "t1".into(),
            span_id: "e1".into(),
            observed_at: ts(1_735_689_600_000_000_000),
            provider: None,
            provider_user_id: None,
            duration_ms: None,
            estimated_cost_micro_usd: None,
            raw_backend: None,
            raw_schema_version: None,
        }],
        model_calls: vec![ModelCallRecord {
            source: "claude-code".into(),
            trace_id: "t1".into(),
            span_id: "m1".into(),
            execution_id: "exec_claude-code_t1_e1".into(),
            observed_at: ts(1_735_689_600_000_000_000),
            model: "gpt-4.1".into(),
            input_tokens: Some(10),
            output_tokens: Some(5),
            cost_micro_usd: Some(100),
        }],
        tool_calls: vec![],
    };
    r.upsert_execution_grain(&child_only)
        .await
        .expect("child only");

    let stub_provider: Option<String> = sqlx::query_scalar(
        "SELECT provider FROM usage_executions WHERE id = 'exec_claude-code_t1_e1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stub_provider, None, "a stub has no provider yet");

    // Now the real execution arrives and fills the stub.
    let real = ExecutionGrainBatch {
        executions: vec![exec("claude-code", "t1", "e1", Some("user-1"))],
        model_calls: vec![],
        tool_calls: vec![],
    };
    r.upsert_execution_grain(&real).await.expect("real");

    let (provider, duration, identity): (Option<String>, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT provider, duration_ms, identity_id FROM usage_executions WHERE id = 'exec_claude-code_t1_e1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        provider.as_deref(),
        Some("anthropic"),
        "real span fills provider"
    );
    assert_eq!(duration, Some(5000), "real span fills duration");
    assert!(identity.is_some(), "real span resolves an identity");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn duplicate_execution_in_one_batch_does_not_21000(pool: PgPool) {
    let r = repo(&pool);
    // A single OTLP export can carry the same (source, trace_id, span_id) twice (e.g. a
    // BatchSpanProcessor flush that duplicates a span into two resource_spans). A multi-row
    // `ON CONFLICT DO UPDATE` refuses a row that appears twice in the SAME statement (Postgres
    // 21000), so the repo must dedup before building the statement.
    let batch = ExecutionGrainBatch {
        executions: vec![
            exec("claude-code", "t1", "e1", Some("user-1")),
            exec("claude-code", "t1", "e1", Some("user-1")),
        ],
        model_calls: vec![],
        tool_calls: vec![],
    };
    r.upsert_execution_grain(&batch)
        .await
        .expect("a duplicate span in one batch must not 21000");
    let execs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_executions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(execs, 1, "the duplicate collapses to one row");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn identity_is_minted_once_and_reused(pool: PgPool) {
    let r = repo(&pool);
    let batch = ExecutionGrainBatch {
        executions: vec![
            exec("claude-code", "t1", "e1", Some("user-1")),
            exec("claude-code", "t2", "e2", Some("user-1")),
        ],
        model_calls: vec![],
        tool_calls: vec![],
    };
    r.upsert_execution_grain(&batch).await.expect("ok");

    let identities: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_identities WHERE source='claude-code'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(identities, 1, "same provider user id mints one identity");

    let distinct: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT identity_id) FROM usage_executions WHERE source='claude-code'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(distinct, 1, "both executions reference the same identity");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn ingest_execution_grain_traces_end_to_end(pool: PgPool) {
    let router = app(pool.clone());
    let body = json!({
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": "00000000000000000000000000000001",
                        "spanId": "0000000000000001",
                        "name": "agent.run",
                        "startTimeUnixNano": "1735689600000000000",
                        "endTimeUnixNano": "1735689605000000000",
                        "attributes": [
                            {"key":"user_id","value":{"stringValue":"user-1"}},
                            {"key":"provider","value":{"stringValue":"anthropic"}}
                        ]
                    },
                    {
                        "traceId": "00000000000000000000000000000001",
                        "spanId": "0000000000000002",
                        "parentSpanId": "0000000000000001",
                        "name": "chat.completion",
                        "startTimeUnixNano": "1735689600000000000",
                        "endTimeUnixNano": "1735689601000000000",
                        "attributes": [
                            {"key":"gen_ai.request.model","value":{"stringValue":"gpt-4.1"}},
                            {"key":"gen_ai.usage.input_tokens","value":{"intValue":"10"}},
                            {"key":"gen_ai.usage.output_tokens","value":{"intValue":"5"}}
                        ]
                    },
                    {
                        "traceId": "00000000000000000000000000000001",
                        "spanId": "0000000000000003",
                        "parentSpanId": "0000000000000001",
                        "name": "tool.use",
                        "startTimeUnixNano": "1735689600000000000",
                        "endTimeUnixNano": "1735689600200000000",
                        "attributes": [
                            {"key":"gen_ai.tool.name","value":{"stringValue":"bash"}}
                        ]
                    }
                ]
            }]
        }]
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/traces")
                .header("x-source", "opencode")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let execs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_executions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mcs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_model_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    let tcs: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_tool_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((execs, mcs, tcs), (1, 1, 1), "one of each grain must land");

    // The execution is the REAL one from the root span, not a stub minted for its children --
    // the two are indistinguishable by count alone (#769).
    let provider: Option<String> = sqlx::query_scalar("SELECT provider FROM usage_executions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(provider.as_deref(), Some("anthropic"));
}

/// #769, end to end: a VS Code Copilot Chat turn labelled `claude-code` (shape from a real
/// capture, values synthetic) is ACCEPTED -- its parentless model-bearing spans no longer reject
/// the batch -- and stores no real execution: only the stub its one parented model call needs.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn a_copilot_turn_labelled_claude_code_is_accepted_and_stores_only_a_stub(pool: PgPool) {
    let router = app(pool.clone());
    let span = |id: &str, parent: &str, name: &str, attrs: serde_json::Value| {
        json!({
            "traceId": "000000000000000000000000000000c1", "spanId": id, "parentSpanId": parent,
            "name": name, "startTimeUnixNano": "1735689600000000000",
            "endTimeUnixNano": "1735689601000000000", "attributes": attrs
        })
    };
    let kv = |k: &str, v: &str| json!({"key": k, "value": {"stringValue": v}});
    let body = json!({"resourceSpans": [{"scopeSpans": [{"spans": [
        span("00000000000000a1", "", "invoke_agent GitHub Copilot Chat",
            json!([kv("gen_ai.operation.name", "invoke_agent"), kv("gen_ai.request.model", "model-x")])),
        span("00000000000000a2", "00000000000000a1", "execute_tool list_dir",
            json!([kv("gen_ai.tool.name", "list_dir")])),
        span("00000000000000a3", "00000000000000a1", "embeddings text-embedding-x",
            json!([kv("gen_ai.request.model", "text-embedding-x")])),
        span("00000000000000a4", "", "chat model-y", json!([kv("gen_ai.request.model", "model-y")])),
        span("00000000000000a5", "", "vscode.chat.user_perceived_time_to_first_progress", json!([]))
    ]}]}]});

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/traces")
                .header("x-source", "claude-code")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let (execs, real, mcs, tcs): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM usage_executions), \
                (SELECT count(*) FROM usage_executions WHERE duration_ms IS NOT NULL), \
                (SELECT count(*) FROM usage_model_calls), (SELECT count(*) FROM usage_tool_calls)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (execs, real, mcs, tcs),
        (1, 0, 1, 0),
        "one stub, no real execution, no tool row"
    );
}
