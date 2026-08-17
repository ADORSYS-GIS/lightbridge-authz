#![cfg(feature = "it-tests")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_query_router;
use lightbridge_authz_usage_rest::models::SpendQueryResponse;
use lightbridge_authz_usage_rest::repo::{StoreRepo, UsageEvent};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

fn parse_timestamp(value: &str) -> DateTime<Utc> {
    value
        .parse()
        .expect("test timestamp literal must be a valid RFC3339 timestamp")
}

/// Builds the query listener's router directly (`build_query_router`), bypassing TLS entirely via
/// `.oneshot()` -- these tests exercise `/usage/v1/spend/query`/`/usage/v1/usage/query`'s
/// application logic in isolation, same as before #347. The mTLS client-certificate requirement
/// (#347) lives at the TLS layer (`Tls::client_ca_bundle_path`,
/// `lightbridge_authz_core::server::serve_tls`'s `build_mtls_config`), not in this router or its
/// handlers, so it is proven separately -- see
/// `crates/lightbridge-authz-core/tests/server_tests.rs` and
/// `crates/lightbridge-authz-budget/tests/usage_service_client_identity_tests.rs` for the real
/// TLS-handshake-level coverage.
async fn app(pool: PgPool) -> axum::Router {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState { repo });
    build_query_router(state, readiness_pool, false)
}

fn sample_event(account_id: &str, observed_at: DateTime<Utc>, total_cost: f64) -> UsageEvent {
    UsageEvent {
        observed_at,
        signal_type: "trace".to_string(),
        account_id: Some(account_id.to_string()),
        project_id: None,
        api_key_id: None,
        user_id: None,
        user_name: None,
        model: None,
        metric_name: None,
        usage_value: 0.0,
        request_count: 1,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        total_cost: Some(total_cost),
        attributes: json!({}),
    }
}

async fn insert(pool: &PgPool, event: &UsageEvent) {
    sqlx::query(
        "INSERT INTO usage_events (observed_at, signal_type, account_id, total_cost) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(event.observed_at)
    .bind(&event.signal_type)
    .bind(&event.account_id)
    .bind(event.total_cost)
    .execute(pool)
    .await
    .expect("inserting a test usage_events row must succeed");
}

/// This test helper sends no client certificate -- irrelevant here since `.oneshot()` never opens
/// a real TLS connection (see `app`'s doc comment above for where the mTLS requirement actually
/// lives and is actually tested).
async fn query_spend(
    router: axum::Router,
    account_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> (StatusCode, serde_json::Value) {
    let body = json!({
        "account_id": account_id,
        "start": start.to_rfc3339(),
        "end": end.to_rfc3339(),
    });
    let request = Request::builder()
        .method("POST")
        .uri("/usage/v1/spend/query")
        .header(header::CONTENT_TYPE, "application/json")
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

/// Test 1 (minimum test list): the endpoint must return the same figure the direct SQL query
/// returns for identical seeded data. `TimescaleSpendReader` ran
/// `SELECT SUM(total_cost)::double precision FROM usage_events WHERE account_id = $1 AND
/// observed_at >= $2 AND observed_at < $3` directly; this endpoint runs the exact same SQL
/// (`StoreRepo::spend_for_account`) -- this test proves the HTTP roundtrip doesn't drift from it.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_matches_direct_sql_sum_for_seeded_data(pool: PgPool) {
    let account_id = cuid2();
    let mid_period = parse_timestamp("2026-08-15T12:00:00Z");
    insert(&pool, &sample_event(&account_id, mid_period, 1.5)).await;
    insert(&pool, &sample_event(&account_id, mid_period, 2.25)).await;

    let expected: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(total_cost)::double precision FROM usage_events \
         WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3",
    )
    .bind(&account_id)
    .bind(parse_timestamp("2026-08-01T00:00:00Z"))
    .bind(parse_timestamp("2026-09-01T00:00:00Z"))
    .fetch_one(&pool)
    .await
    .expect("direct sql sum must succeed");

    let start = parse_timestamp("2026-08-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");
    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(response.total_cost, expected);
    assert_eq!(response.total_cost, Some(3.75));
}

/// Test 2: a row exactly at `start` is included, a row exactly at `end` is excluded -- the
/// half-open `[start, end)` interval `TimescaleSpendReader` relied on.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_half_open_interval_includes_start_excludes_end(pool: PgPool) {
    let account_id = cuid2();
    let start = parse_timestamp("2026-08-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");

    insert(&pool, &sample_event(&account_id, start, 1.0)).await;
    insert(&pool, &sample_event(&account_id, end, 100.0)).await;

    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(
        response.total_cost,
        Some(1.0),
        "a row at `start` must be included and a row at `end` must be excluded"
    );
}

/// Test 5 (minimum test list): a genuinely-zero spend must read back as `Some(0.0)`, never as
/// `None` -- the SQL-NULL-vs-zero distinction the budget domain's `Spend::Known`/`Unavailable`
/// split depends on.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_reports_known_zero_not_null_for_a_zero_cost_row(pool: PgPool) {
    let account_id = cuid2();
    let mid_period = parse_timestamp("2026-08-15T12:00:00Z");
    insert(&pool, &sample_event(&account_id, mid_period, 0.0)).await;

    let start = parse_timestamp("2026-08-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");
    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(response.total_cost, Some(0.0));
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_reports_null_when_no_rows_match(pool: PgPool) {
    let account_id = cuid2();
    let start = parse_timestamp("2026-08-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");

    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(response.total_cost, None);
}

/// `/usage/v1/usage/query`'s application logic is unaffected by #347's mTLS requirement -- that
/// requirement lives at the TLS layer, not in this handler, so exercising it directly via
/// `.oneshot()` (no TLS, no client certificate) must still succeed. See `app`'s doc comment.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn usage_query_endpoint_application_logic_is_unaffected_by_mtls(pool: PgPool) {
    let router = app(pool).await;
    let body = json!({
        "scope": "account",
        "scope_id": "acct_1",
        "start_time": "2026-08-01T00:00:00Z",
        "end_time": "2026-09-01T00:00:00Z",
    });
    let request = Request::builder()
        .method("POST")
        .uri("/usage/v1/usage/query")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("request body must serialize"),
        ))
        .expect("request must build");

    let response = router
        .oneshot(request)
        .await
        .expect("router must produce a response");
    assert_eq!(response.status(), StatusCode::OK);
}
