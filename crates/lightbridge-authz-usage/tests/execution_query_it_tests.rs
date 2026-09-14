#![cfg(feature = "it-tests")]

//! DB-backed integration tests for the execution-grain query endpoint (#726):
//! `StoreRepo::query_executions` against a real Postgres, plus the full-router authorization
//! gate (`POST /usage/v1/usage/executions/query`).
//!
//! These seed `usage_executions` / `usage_model_calls` / `usage_tool_calls` / `usage_identities`
//! directly through SQL (there is no execution-grain ingest yet -- #582 shipped tables only,
//! matching `execution_grain_it_tests.rs`).

#[path = "support/mod.rs"]
mod support;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_query_router;
use lightbridge_authz_usage_rest::models::UsageScope;
use lightbridge_authz_usage_rest::models::execution::{
    ExecutionGroupBy, ExecutionQueryFilters, ExecutionQueryRequest, ExecutionQueryResponse,
};
use lightbridge_authz_usage_rest::repo::StoreRepo;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const SOURCE: &str = "claude_code";
const ISSUER: &str = "https://issuer.test";

fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
}

fn ts_midnight(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

async fn insert_identity(pool: &PgPool, id: &str, subject_id: &str) {
    sqlx::query(
        "INSERT INTO usage_identities (id, source, subject_kind, subject_id) \
         VALUES ($1, $2, 'user', $3) ON CONFLICT (source, subject_kind, subject_id) DO NOTHING",
    )
    .bind(id)
    .bind(SOURCE)
    .bind(subject_id)
    .execute(pool)
    .await
    .expect("insert identity");
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper binding the fixed set of usage_executions columns"
)]
async fn insert_execution(
    pool: &PgPool,
    observed_at: DateTime<Utc>,
    trace_id: &str,
    span_id: &str,
    identity_id: Option<&str>,
    provider: Option<&str>,
    duration_ms: Option<i64>,
    cost: Option<i64>,
) {
    sqlx::query(
        "INSERT INTO usage_executions \
         (id, observed_at, source, provider, trace_id, span_id, identity_id, duration_ms, raw_schema_version, estimated_cost_micro_usd) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(format!("exec_{SOURCE}_{trace_id}_{span_id}"))
    .bind(observed_at)
    .bind(SOURCE)
    .bind(provider)
    .bind(trace_id)
    .bind(span_id)
    .bind(identity_id)
    .bind(duration_ms)
    .bind(1i64)
    .bind(cost)
    .execute(pool)
    .await
    .expect("insert execution");
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper binding the fixed set of usage_model_calls columns"
)]
async fn insert_model_call(
    pool: &PgPool,
    observed_at: DateTime<Utc>,
    trace_id: &str,
    child_span_id: &str,
    execution_id: &str,
    model: &str,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
) {
    sqlx::query(
        "INSERT INTO usage_model_calls \
         (id, observed_at, source, execution_id, trace_id, span_id, model, input_tokens, output_tokens, cost_micro_usd) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
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
    .bind(0i64)
    .execute(pool)
    .await
    .expect("insert model call");
}

async fn insert_tool_call(
    pool: &PgPool,
    observed_at: DateTime<Utc>,
    trace_id: &str,
    child_span_id: &str,
    execution_id: &str,
    tool_name: &str,
    duration_ms: i64,
) {
    sqlx::query(
        "INSERT INTO usage_tool_calls \
         (id, observed_at, source, execution_id, trace_id, span_id, tool_name, duration_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
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
    .await
    .expect("insert tool call");
}

fn repo(pool: &PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
}

fn request(
    scope: UsageScope,
    scope_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    group_by: Vec<ExecutionGroupBy>,
    limit: u32,
) -> ExecutionQueryRequest {
    ExecutionQueryRequest {
        scope,
        scope_id: scope_id.to_string(),
        start_time: start,
        end_time: end,
        bucket: "1 day".to_string(),
        filters: ExecutionQueryFilters::default(),
        group_by,
        limit,
    }
}

/// Seed an execution with two model calls and two tool calls, then query and assert the children
/// are aggregated correctly (tokens, tool count) without multiplying the execution-level counts.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn execution_query_aggregates_children_without_fan_out(pool: PgPool) {
    let observed_at = ts(2026, 8, 15);
    let trace_id = "trace-agg";
    let exec_span = "span-agg";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(1200),
        Some(5000),
    )
    .await;
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "mc-1",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
    )
    .await;
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "mc-2",
        &exec_id,
        "claude-opus-4-1",
        Some(1200),
        Some(400),
    )
    .await;
    insert_tool_call(&pool, observed_at, trace_id, "tc-1", &exec_id, "bash", 90).await;
    insert_tool_call(&pool, observed_at, trace_id, "tc-2", &exec_id, "grep", 90).await;

    let (points, truncated) = repo(&pool)
        .query_executions(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert!(!truncated);
    assert_eq!(points.len(), 1, "one bucket for one execution");
    let point = &points[0];
    assert_eq!(
        point.executions_count, 1,
        "one execution, not multiplied by children"
    );
    assert_eq!(point.total_duration_ms, 1200);
    assert_eq!(point.total_cost, Some(5000));
    assert_eq!(point.total_input_tokens, 2400, "1200 + 1200");
    assert_eq!(point.total_output_tokens, 800, "400 + 400");
    assert_eq!(point.tool_call_count, 2);
}

/// A stub execution (no children) still appears, with `NULL` cost and `0` tokens/tool count.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn stub_execution_appears_with_null_cost_and_zero_children(pool: PgPool) {
    insert_execution(
        &pool,
        ts(2026, 8, 15),
        "trace-stub",
        "span-stub",
        None,
        None,
        None,
        None,
    )
    .await;

    let (points, _) = repo(&pool)
        .query_executions(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1);
    let point = &points[0];
    assert_eq!(point.executions_count, 1);
    assert_eq!(
        point.total_cost, None,
        "a stub with no cost is unknown, never 0"
    );
    assert_eq!(point.total_duration_ms, 0);
    assert_eq!(point.total_input_tokens, 0);
    assert_eq!(point.total_output_tokens, 0);
    assert_eq!(point.tool_call_count, 0);
}

/// A bucket where no execution carried a cost returns `total_cost: None`, never `0`
/// (governance#188).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn null_cost_round_trips_as_none_never_zero(pool: PgPool) {
    insert_execution(
        &pool,
        ts(2026, 8, 15),
        "trace-nc",
        "span-nc",
        None,
        Some("anthropic"),
        Some(100),
        None,
    )
    .await;

    let (points, _) = repo(&pool)
        .query_executions(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 1);
    assert_eq!(
        points[0].total_cost, None,
        "NULL cost must round-trip as None, never 0"
    );
}

/// Bucket-scoped truncation (#578): 15 distinct days, limit 10 -> `truncated: true` and the 10
/// NEWEST buckets survive (the oldest 5 are dropped whole).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn bucket_truncation_drops_the_oldest_buckets(pool: PgPool) {
    for day in 1..=15 {
        insert_execution(
            &pool,
            ts(2026, 8, day),
            &format!("trace-{day}"),
            &format!("span-{day}"),
            None,
            Some("anthropic"),
            Some(100),
            Some(1000),
        )
        .await;
    }

    let (points, truncated) = repo(&pool)
        .query_executions(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 8, 16),
            vec![],
            10,
        ))
        .await
        .expect("query must succeed");

    assert!(
        truncated,
        "15 distinct buckets with limit 10 must be truncated"
    );
    assert_eq!(points.len(), 10, "exactly 10 whole buckets survive");
    // Newest-kept: the surviving buckets are days 6..15 (ascending order). `date_bin` with a
    // 1-day bucket anchored at epoch truncates to midnight UTC.
    assert_eq!(points[0].bucket_start, ts_midnight(2026, 8, 6));
    assert_eq!(points[9].bucket_start, ts_midnight(2026, 8, 15));
}

/// Option A fan-out: an execution with two distinct models appears in BOTH model groups, and the
/// execution-level aggregates are counted once per model it touched.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn model_group_by_fan_out_counts_the_execution_per_model(pool: PgPool) {
    let observed_at = ts(2026, 8, 15);
    let trace_id = "trace-fanout";
    let exec_span = "span-fanout";
    let exec_id = format!("exec_{SOURCE}_{trace_id}_{exec_span}");

    insert_execution(
        &pool,
        observed_at,
        trace_id,
        exec_span,
        None,
        Some("anthropic"),
        Some(1200),
        Some(5000),
    )
    .await;
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "mc-1",
        &exec_id,
        "claude-sonnet-4-5",
        Some(1200),
        Some(400),
    )
    .await;
    insert_model_call(
        &pool,
        observed_at,
        trace_id,
        "mc-2",
        &exec_id,
        "claude-opus-4-1",
        Some(600),
        Some(200),
    )
    .await;

    let (points, _) = repo(&pool)
        .query_executions(&request(
            UsageScope::All,
            "",
            ts(2026, 8, 1),
            ts(2026, 9, 1),
            vec![ExecutionGroupBy::Model],
            100,
        ))
        .await
        .expect("query must succeed");

    assert_eq!(points.len(), 2, "one group per distinct model");
    let sonnet = points
        .iter()
        .find(|p| p.model.as_deref() == Some("claude-sonnet-4-5"))
        .expect("sonnet group");
    let opus = points
        .iter()
        .find(|p| p.model.as_deref() == Some("claude-opus-4-1"))
        .expect("opus group");

    // The single execution is counted once per model it touched (the documented fan-out).
    assert_eq!(sonnet.executions_count, 1);
    assert_eq!(opus.executions_count, 1);
    assert_eq!(sonnet.total_input_tokens, 1200);
    assert_eq!(opus.total_input_tokens, 600);
    assert_eq!(
        sonnet.total_cost,
        Some(5000),
        "execution cost is not split across models"
    );
    assert_eq!(opus.total_cost, Some(5000));
}

// ---------------------------------------------------------------------------------------------
// Full-router authorization gate (the shared ownership gate, GrainScope::Execution)
// ---------------------------------------------------------------------------------------------

fn app(
    pool: PgPool,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
) -> axum::Router {
    app_with_authority(pool, bearer, support::refuse_everything_scope_authority())
}

/// Same as [`app`], but with an explicit scope authority -- tests that must prove a refusal comes
/// from the ownership gate itself (not from a refusing authority) pass an authorizing one.
fn app_with_authority(
    pool: PgPool,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
    scope_authority: Arc<dyn lightbridge_authz_usage_rest::scope_authority::ScopeAuthority>,
) -> axum::Router {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState {
        repo,
        bearer,
        scope_authority,
        raw_days: Some(90),
    });
    build_query_router(state, readiness_pool, false)
}

async fn post_executions(
    router: axum::Router,
    bearer_header: Option<&str>,
    scope: &str,
    scope_id: &str,
) -> (StatusCode, serde_json::Value) {
    let body = json!({
        "scope": scope,
        "scope_id": scope_id,
        "start_time": "2026-08-01T00:00:00Z",
        "end_time": "2026-09-01T00:00:00Z",
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/usage/v1/usage/executions/query")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(bearer) = bearer_header {
        request = request.header(header::AUTHORIZATION, bearer);
    }
    let request = request
        .body(Body::from(
            serde_json::to_vec(&body).expect("request body must serialize"),
        ))
        .expect("request must build");

    let response = router
        .oneshot(request)
        .await
        .expect("router must produce a response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must be readable");
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

/// `scope=user` self-ownership: the caller reading their OWN subject sees their seeded executions.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn own_user_scope_returns_200_with_seeded_executions(pool: PgPool) {
    insert_identity(&pool, "identity-a", "sub-a").await;
    insert_execution(
        &pool,
        ts(2026, 8, 15),
        "trace-own",
        "span-own",
        Some("identity-a"),
        Some("anthropic"),
        Some(100),
        Some(1000),
    )
    .await;

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, body) =
        post_executions(app(pool, bearer), Some("Bearer token-a"), "user", "sub-a").await;

    assert_eq!(status, StatusCode::OK);
    let response: ExecutionQueryResponse =
        serde_json::from_value(body).expect("response must be an ExecutionQueryResponse");
    assert_eq!(response.points.len(), 1);
    assert_eq!(response.points[0].executions_count, 1);
}

/// Two-tenant 403 (fail-first per the epic): a caller asking for a DIFFERENT subject's
/// `scope=user` data is refused with 403 and no data.
///
/// The scope authority here is deliberately AUTHORIZING for exactly this `(sub-b, user, sub-a)`
/// combination: if the authority were refusing, the 403 could come from it rather than the
/// self-ownership gate. With an authorizing authority, the only thing that can still refuse is
/// the ownership check itself -- which is the property under test.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn other_subjects_user_scope_is_refused_with_403(pool: PgPool) {
    insert_identity(&pool, "identity-a", "sub-a").await;
    insert_execution(
        &pool,
        ts(2026, 8, 15),
        "trace-victim",
        "span-victim",
        Some("identity-a"),
        Some("anthropic"),
        Some(100),
        Some(1000),
    )
    .await;

    let authority =
        support::FakeScopeAuthority::new().authorizing(ISSUER, "sub-b", &UsageScope::User, "sub-a");
    let bearer = support::bearer_with("token-b", ISSUER, "sub-b");
    let (status, body) = post_executions(
        app_with_authority(pool, bearer, Arc::new(authority)),
        Some("Bearer token-b"),
        "user",
        "sub-a",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        serde_json::Value::Null,
        "a refused query must never leak data"
    );
}

/// `scope=account` is not applicable to the execution grain and is rejected with `400`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn account_scope_is_rejected_with_400(pool: PgPool) {
    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, _) = post_executions(
        app(pool, bearer),
        Some("Bearer token-a"),
        "account",
        "acct-1",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A missing bearer token is `401`.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn missing_bearer_is_refused_with_401(pool: PgPool) {
    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let (status, _) = post_executions(app(pool, bearer), None, "user", "sub-a").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
