#![cfg(feature = "it-tests")]

#[path = "support/mod.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_ingest_router;
use lightbridge_authz_usage_rest::models::{
    UsageGroupBy, UsageQueryFilters, UsageQueryRequest, UsageScope,
};
use lightbridge_authz_usage_rest::repo::StoreRepo;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

/// Build a `UsageState` wired to the real repo, with a bearer that trusts nothing and a scope
/// authority that refuses everything (the ingest path never reads either).
fn build_state(pool: PgPool) -> Arc<UsageState> {
    let repo = Arc::new(build_repo(pool));
    Arc::new(UsageState {
        repo,
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_principals: std::collections::HashMap::default(),
    })
}

/// Build one OTLP trace span in the protobuf-JSON shape the ingest handler decodes. Mirrors the
/// Python seed script's `make_span` so the two stay in lockstep.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct usage_events dimension the seed must control"
)]
fn make_span(
    observed_at: chrono::DateTime<Utc>,
    account_id: &str,
    project_id: &str,
    api_key_id: &str,
    user_id: &str,
    user_name: &str,
    model: &str,
    metric_name: &str,
    prompt: i64,
    completion: i64,
    cost: f64,
    latency_ms: f64,
    index: u64,
) -> serde_json::Value {
    let total = prompt + completion;
    let start_nanos = observed_at.timestamp_nanos_opt().expect("in range");
    let end_nanos = start_nanos + (latency_ms * 1_000_000.0) as i64;

    json!({
        "traceId": format!("{index:032x}"),
        "spanId": format!("{index:016x}"),
        "name": metric_name,
        "startTimeUnixNano": start_nanos.to_string(),
        "endTimeUnixNano": end_nanos.to_string(),
        "attributes": [
            {"key": "account_id", "value": {"stringValue": account_id}},
            {"key": "project_id", "value": {"stringValue": project_id}},
            {"key": "api_key_id", "value": {"stringValue": api_key_id}},
            {"key": "lc_user_id", "value": {"stringValue": user_id}},
            {"key": "lc_user_name", "value": {"stringValue": user_name}},
            {"key": "model", "value": {"stringValue": model}},
            {"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": prompt.to_string()}},
            {"key": "gen_ai.usage.completion_tokens", "value": {"intValue": completion.to_string()}},
            {"key": "gen_ai.usage.total_tokens", "value": {"intValue": total.to_string()}},
            {"key": "io.envoy.ai_gateway.llm_custom_total_cost", "value": {"doubleValue": cost}},
            {"key": "gen_ai.server.request.duration", "value": {"doubleValue": latency_ms / 1000.0}},
        ],
    })
}

/// Wrap spans into an `ExportTraceServiceRequest` JSON body.
fn build_payload(spans: Vec<serde_json::Value>) -> serde_json::Value {
    json!({
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "ai-gateway"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "seed", "version": "1.0"},
                        "spans": spans,
                    }
                ]
            }
        ]
    })
}

/// POST an OTLP trace payload through the real ingest handler and assert it returns 202.
///
/// `x-source` is required by `resolve_source` (lightbridge-authz#584) -- every ingest request is
/// rejected with 400 without it. `eaig` matches this payload's attribute shape
/// (`io.envoy.ai_gateway.llm_custom_total_cost`), same as `usage_tests.rs`/`repo_it_tests.rs`.
async fn post_traces(app: &axum::Router, payload: serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/otel/traces")
                .header("content-type", "application/json")
                .header("x-source", "eaig")
                .body(Body::from(payload.to_string()))
                .expect("request must build"),
        )
        .await
        .expect("router must produce a response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// The seed path end-to-end: drive the real OTLP ingest handler with a small deterministic
/// dataset, then query through the repo and assert the returned totals equal what was seeded.
///
/// This is the automated proof for lightbridge-authz#528's Test Plan ("seed, then query through
/// the API and assert returned totals equal what was seeded"). It exercises the true write path
/// (extraction + validation + insert), not a direct repo insert.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn seed_then_query_returns_totals_equal_to_what_was_seeded(pool: PgPool) {
    let state = build_state(pool.clone());
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let app = build_ingest_router(state, readiness_pool, false, false);

    let now = Utc::now();
    let start = now - Duration::days(3);

    // Deterministic dataset: 3 projects x 2 models x 2 hours. Each event has known tokens/cost.
    let projects = ["proj_001", "proj_002", "proj_003"];
    let models = ["gpt-4.1", "claude-sonnet-4"];
    let mut spans = Vec::new();
    let mut index = 0u64;
    let mut expected_total_cost = 0.0f64;
    let mut expected_total_tokens = 0i64;
    let mut expected_requests = 0i64;

    for hour in 0..2 {
        let observed = start + Duration::hours(hour);
        for (pi, project) in projects.iter().enumerate() {
            for (mi, model) in models.iter().enumerate() {
                let prompt = 100 + (pi * 10 + mi) as i64;
                let completion = 50 + (pi * 5 + mi) as i64;
                // Micro-USD, matching the gateway's llm_custom_total_cost unit
                // (spend_units.rs, #488) -- dollars would be the 10^6 error.
                let cost = 1_000.0 + (pi as f64 * 2_000.0) + (mi as f64 * 1_000.0);
                let latency_ms = 100.0 + (pi * 10 + mi) as f64;
                spans.push(make_span(
                    observed,
                    "acct_001",
                    project,
                    "key_001",
                    "user_alice",
                    "Alice",
                    model,
                    "chat.completion",
                    prompt,
                    completion,
                    cost,
                    latency_ms,
                    index,
                ));
                index += 1;
                // `cost` above is micro-USD, the wire unit; merge_norm_tokens_and_cost (ingest.rs)
                // divides by 1e6 before storing/returning total_cost in dollars -- match that here,
                // or this reproduces the exact "F1" 10^6 unit bug the comment above warns about.
                expected_total_cost += cost / 1_000_000.0;
                expected_total_tokens += prompt + completion;
                expected_requests += 1;
            }
        }
    }

    post_traces(&app, build_payload(spans)).await;

    // Query across the whole window, grouped by project, and assert the aggregate totals match.
    let repo = build_repo(pool);
    let request = UsageQueryRequest {
        scope: UsageScope::All,
        scope_id: String::new(),
        start_time: start - Duration::hours(1),
        end_time: now + Duration::hours(1),
        bucket: "1 hour".to_string(),
        metrics: None,
        filters: UsageQueryFilters::default(),
        group_by: vec![UsageGroupBy::ProjectId],
        limit: 100,
    };

    let (points, _truncated) = repo
        .query_usage(&request)
        .await
        .expect("query should succeed");

    // 2 hours x 3 projects = 6 points (one per project per bucket).
    assert_eq!(points.len(), 6);

    let total_cost: f64 = points.iter().map(|p| p.total_cost).sum();
    let total_tokens: i64 = points.iter().map(|p| p.total_tokens).sum();
    let total_requests: i64 = points.iter().map(|p| p.requests).sum();

    assert!(
        (total_cost - expected_total_cost).abs() < 1e-9,
        "total_cost mismatch: got {total_cost}, expected {expected_total_cost}"
    );
    assert_eq!(total_tokens, expected_total_tokens);
    assert_eq!(total_requests, expected_requests);

    // Grouping is exercised: every project appears in the results.
    let mut projects_seen: Vec<&str> = points
        .iter()
        .filter_map(|p| p.project_id.as_deref())
        .collect();
    projects_seen.sort_unstable();
    projects_seen.dedup();
    assert_eq!(projects_seen, vec!["proj_001", "proj_002", "proj_003"]);
}
