#![cfg(feature = "it-tests")]

#[path = "support/mod.rs"]
mod support;

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::{
    cuid::cuid2,
    db::{DbPool, DbPoolTrait},
};
use lightbridge_authz_usage_rest::{
    UsageState, build_query_router,
    models::SpendQueryResponse,
    repo::{StoreRepo, UsageEvent},
};
use serde_json::json;
use sqlx::PgPool;
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
    let state = Arc::new(UsageState {
        repo,
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_auth: None,
        raw_days: Some(90),
    });
    build_query_router(state, readiness_pool, false)
}

fn sample_event(account_id: &str, observed_at: DateTime<Utc>, total_cost: f64) -> UsageEvent {
    UsageEvent {
        dedup_key: None,
        observed_at,
        signal_type: "trace".to_string(),
        source: Some("eaig".to_string()),
        account_id: Some(account_id.to_string()),
        project_id: None,
        api_key_id: None,
        user_id: None,
        user_name: None,
        model: None,
        metric_name: None,
        azp: None,
        operation: None,
        billing_plan: None,
        usage_value: 0.0,
        request_count: 1,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        total_cost: Some(total_cost),
        latency_ms: None,
    }
}

async fn insert(pool: &PgPool, event: &UsageEvent) {
    sqlx::query(
        "INSERT INTO usage_events (observed_at, signal_type, account_id, source, total_cost) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(event.observed_at)
    .bind(&event.signal_type)
    .bind(&event.account_id)
    .bind(&event.source)
    .bind(event.total_cost)
    .execute(pool)
    .await
    .expect("inserting a test usage_events row must succeed");
}

/// Inserts directly into the daily rollup table -- `usage_events_daily` is never written by the
/// ingest handlers, only by the retention job's `ROLLUP_AND_PURGE_SQL`, so a test that wants a
/// row already "aged into the rollup" has to seed it here rather than through `insert` + a real
/// rollup run.
async fn insert_daily(
    pool: &PgPool,
    account_id: &str,
    bucket_start: DateTime<Utc>,
    source: Option<&str>,
    total_cost: f64,
) {
    sqlx::query(
        "INSERT INTO usage_events_daily (bucket_start, account_id, source, total_cost) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(bucket_start)
    .bind(account_id)
    .bind(source)
    .bind(total_cost)
    .execute(pool)
    .await
    .expect("inserting a test usage_events_daily row must succeed");
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
/// `.oneshot()` (no TLS, no client certificate) must still succeed once the #570 bearer/ownership
/// gate this handler now applies is satisfied. See `app`'s doc comment.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn usage_query_endpoint_application_logic_is_unaffected_by_mtls(pool: PgPool) {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState {
        repo,
        bearer: support::bearer_with("valid-token", "https://issuer.test", "sub-1"),
        scope_authority: Arc::new(support::FakeScopeAuthority::new().authorizing(
            "https://issuer.test",
            "sub-1",
            &lightbridge_authz_usage_rest::models::UsageScope::Account,
            "acct_1",
        )),
        ingest_auth: None,
        raw_days: Some(90),
    });
    let router = build_query_router(state, readiness_pool, false);

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
        .header(header::AUTHORIZATION, "Bearer valid-token")
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

/// governance#358 / ADR-0028 D8: EAIG is the sole spend authority. A public IDE collector may
/// observe the same model call EAIG already billed through the gateway, so its rows must never
/// add to spend -- summing both would double-bill the account.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_excludes_ide_sourced_raw_rows(pool: PgPool) {
    let account_id = cuid2();
    let mid_period = parse_timestamp("2026-08-15T12:00:00Z");
    let mut eaig_event = sample_event(&account_id, mid_period, 1.0);
    eaig_event.source = Some("eaig".to_string());
    insert(&pool, &eaig_event).await;
    let mut claude_code_event = sample_event(&account_id, mid_period, 100.0);
    claude_code_event.source = Some("claude-code".to_string());
    insert(&pool, &claude_code_event).await;

    let start = parse_timestamp("2026-08-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");
    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(
        response.total_cost,
        Some(1.0),
        "the claude-code row must not be added to EAIG spend"
    );
}

/// Same guarantee once a day has aged into the rollup -- the rollup arm needs the identical
/// exclusion, or spend correctness would depend on how old the data is.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_excludes_ide_sourced_rollup_rows(pool: PgPool) {
    let account_id = cuid2();
    let bucket_start = parse_timestamp("2026-07-15T00:00:00Z");
    insert_daily(&pool, &account_id, bucket_start, Some("eaig"), 2.0).await;
    insert_daily(&pool, &account_id, bucket_start, Some("codex"), 250.0).await;

    let start = parse_timestamp("2026-07-01T00:00:00Z");
    let end = parse_timestamp("2026-08-01T00:00:00Z");
    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(
        response.total_cost,
        Some(2.0),
        "the codex rollup row must not be added to EAIG spend"
    );
}

/// A row from before `source` tracking existed carries `NULL`, not `'eaig'` -- but every such row
/// is, in substance, 100% EAIG traffic (the IDE ingest leg didn't exist yet). Excluding `NULL`
/// would silently undercount that legacy spend, so it must be treated as EAIG.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_treats_null_source_as_eaig_for_backward_compatibility(pool: PgPool) {
    let account_id = cuid2();
    let mid_period = parse_timestamp("2026-08-15T12:00:00Z");
    let mut legacy_event = sample_event(&account_id, mid_period, 5.0);
    legacy_event.source = None;
    insert(&pool, &legacy_event).await;
    let bucket_start = parse_timestamp("2026-07-15T00:00:00Z");
    insert_daily(&pool, &account_id, bucket_start, None, 3.0).await;

    let start = parse_timestamp("2026-07-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");
    let (status, body) = query_spend(app(pool).await, &account_id, start, end).await;

    assert_eq!(status, StatusCode::OK);
    let response: SpendQueryResponse =
        serde_json::from_value(body).expect("response body must be a SpendQueryResponse");
    assert_eq!(response.total_cost, Some(8.0));
}

/// #570: `/usage/v1/spend/query` is a service-to-service route with no per-caller ownership
/// check -- it now refuses outright any request carrying an `Authorization` header, closing the
/// "console catch-all-proxy" hole where a misrouted browser bearer token could otherwise reach
/// this ownerless cross-account read.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_query_refuses_a_request_carrying_an_authorization_header(pool: PgPool) {
    let account_id = cuid2();
    let start = parse_timestamp("2026-08-01T00:00:00Z");
    let end = parse_timestamp("2026-09-01T00:00:00Z");

    let body = json!({
        "account_id": account_id,
        "start": start.to_rfc3339(),
        "end": end.to_rfc3339(),
    });
    let request = Request::builder()
        .method("POST")
        .uri("/usage/v1/spend/query")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer some-users-token")
        .body(Body::from(
            serde_json::to_vec(&body).expect("request body must serialize"),
        ))
        .expect("request must build");

    let response = app(pool)
        .await
        .oneshot(request)
        .await
        .expect("router must produce a response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a spend query carrying an Authorization header must be refused, not answered"
    );
}
