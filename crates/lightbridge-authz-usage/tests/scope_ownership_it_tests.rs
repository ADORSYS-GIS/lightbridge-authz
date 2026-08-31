#![cfg(feature = "it-tests")]

//! #570: end-to-end coverage for `/usage/v1/usage/query`'s bearer + ownership gate
//! (`handlers::query::query_usage`), against a real Postgres-backed `StoreRepo` so the seeded
//! `usage_events` rows are what proves "200 + data" versus "403, no data" -- not just a mocked
//! repo that would happily return data regardless of whether the gate ran.

#[path = "support/mod.rs"]
mod support;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, Utc};
use httpmock::Method::POST;
use httpmock::MockServer;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::build_query_router;
use lightbridge_authz_usage_rest::config::ScopeAuthorityConfig;
use lightbridge_authz_usage_rest::models::{UsageQueryResponse, UsageScope};
use lightbridge_authz_usage_rest::repo::{StoreRepo, UsageEvent};
use lightbridge_authz_usage_rest::scope_authority::RemoteScopeAuthority;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const ISSUER: &str = "https://issuer.test";

fn remote_authority_config(base_url: impl Into<String>) -> ScopeAuthorityConfig {
    ScopeAuthorityConfig {
        base_url: base_url.into(),
        username: "authorino".to_string(),
        password: "change-me".to_string(),
        insecure_skip_verify: true,
        ca_bundle_path: None,
        client_cert_path: None,
        client_key_path: None,
        timeout_ms: 1_000,
    }
}

fn parse_timestamp(value: &str) -> DateTime<Utc> {
    value
        .parse()
        .expect("test timestamp literal must be a valid RFC3339 timestamp")
}

fn sample_event(account_id: &str, project_id: &str, observed_at: DateTime<Utc>) -> UsageEvent {
    UsageEvent {
        observed_at,
        signal_type: "trace".to_string(),
        account_id: Some(account_id.to_string()),
        project_id: Some(project_id.to_string()),
        api_key_id: Some("key_1".to_string()),
        user_id: Some("user_1".to_string()),
        user_name: None,
        model: None,
        metric_name: None,
        usage_value: 1.0,
        request_count: 1,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        total_cost: Some(1.0),
        latency_ms: None,
        attributes: json!({}),
    }
}

async fn seed(pool: &PgPool, account_id: &str, project_id: &str) {
    let repo = StoreRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    repo.insert_usage_events(&[sample_event(
        account_id,
        project_id,
        parse_timestamp("2026-08-15T12:00:00Z"),
    )])
    .await
    .expect("seeding a usage_events row must succeed");
}

fn app(
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
    });
    build_query_router(state, readiness_pool, false)
}

async fn query(
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
        .uri("/usage/v1/usage/query")
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

/// Test 1: the owning tenant's account scope returns 200 with the seeded data.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn own_account_scope_returns_200_with_data(pool: PgPool) {
    let account_id = "acct-tenant-a";
    seed(&pool, account_id, "proj-tenant-a").await;

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let scope_authority = Arc::new(support::FakeScopeAuthority::new().authorizing(
        ISSUER,
        "sub-a",
        &UsageScope::Account,
        account_id,
    ));

    let (status, body) = query(
        app(pool, bearer, scope_authority),
        Some("Bearer token-a"),
        "account",
        account_id,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: UsageQueryResponse =
        serde_json::from_value(body).expect("response must be a UsageQueryResponse");
    assert_eq!(
        response.points.len(),
        1,
        "the owning tenant must see their own seeded data"
    );
}

/// Test 2 (the decisive #570 negative case): a DIFFERENT tenant's bearer token, asking for
/// tenant A's account scope, must be refused with 403 and NO data -- proves this is a real
/// ownership check wired into the handler, not a permissive stub.
///
/// FAIL-FIRST EVIDENCE: with the ownership gate removed (e.g. deleting the
/// `match &input.scope { ... }` block in `handlers::query::query_usage` so every request falls
/// straight through to `state.repo.query_usage`), this test observes `200` with tenant A's data
/// instead of `403` -- see this crate's PR description / commit history for the actual before/
/// after run used to prove this before the fix landed.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn other_tenants_account_scope_is_refused_with_no_data(pool: PgPool) {
    let account_a = "acct-tenant-a";
    seed(&pool, account_a, "proj-tenant-a").await;

    // tenant B's bearer never authorizes tenant A's account scope.
    let bearer = support::bearer_with("token-b", ISSUER, "sub-b");
    let scope_authority = support::refuse_everything_scope_authority();

    let (status, body) = query(
        app(pool, bearer, scope_authority),
        Some("Bearer token-b"),
        "account",
        account_a,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        serde_json::Value::Null,
        "a refused query must never leak tenant A's data in the body"
    );
}

/// Test 3: the project-scope mirror of tests 1/2 above.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn own_project_scope_returns_200_and_other_tenants_is_refused(pool: PgPool) {
    let project_a = "proj-tenant-a";
    seed(&pool, "acct-tenant-a", project_a).await;

    let owning_bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let owning_authority = Arc::new(support::FakeScopeAuthority::new().authorizing(
        ISSUER,
        "sub-a",
        &UsageScope::Project,
        project_a,
    ));
    let (status, body) = query(
        app(pool.clone(), owning_bearer, owning_authority),
        Some("Bearer token-a"),
        "project",
        project_a,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: UsageQueryResponse =
        serde_json::from_value(body).expect("response must be a UsageQueryResponse");
    assert_eq!(response.points.len(), 1);

    let other_bearer = support::bearer_with("token-b", ISSUER, "sub-b");
    let other_authority = support::refuse_everything_scope_authority();
    let (status, body) = query(
        app(pool, other_bearer, other_authority),
        Some("Bearer token-b"),
        "project",
        project_a,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, serde_json::Value::Null);
}

/// Test 4: `user`/`api_key` scopes have no resolvable ownership authority and are refused
/// unconditionally -- never reaching `scope_authority` at all, so authorizing EVERYTHING there
/// still must not let these scopes through.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn user_and_api_key_scopes_are_refused_unconditionally(pool: PgPool) {
    seed(&pool, "acct-tenant-a", "proj-tenant-a").await;

    struct AuthorizeEverything;
    #[lightbridge_authz_core::async_trait]
    impl lightbridge_authz_usage_rest::scope_authority::ScopeAuthority for AuthorizeEverything {
        async fn authorize(
            &self,
            _issuer: &str,
            _subject: &str,
            _scope: &UsageScope,
            _scope_id: &str,
        ) -> lightbridge_authz_core::Result<bool> {
            Ok(true)
        }
    }

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    for (scope, scope_id) in [("user", "user_1"), ("api_key", "key_1")] {
        let (status, body) = query(
            app(pool.clone(), bearer.clone(), Arc::new(AuthorizeEverything)),
            Some("Bearer token-a"),
            scope,
            scope_id,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "scope '{scope}' must be refused even when the authority would authorize everything"
        );
        assert_eq!(body, serde_json::Value::Null);
    }
}

/// Test 5: a missing bearer token is 401; a garbage/unrecognized one is also 401 -- both before
/// `scope_authority` is ever consulted.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn missing_or_garbage_bearer_is_refused_with_401(pool: PgPool) {
    let account_id = "acct-tenant-a";
    seed(&pool, account_id, "proj-tenant-a").await;

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let scope_authority = Arc::new(support::FakeScopeAuthority::new().authorizing(
        ISSUER,
        "sub-a",
        &UsageScope::Account,
        account_id,
    ));

    let (status, body) = query(
        app(pool.clone(), bearer.clone(), scope_authority.clone()),
        None,
        "account",
        account_id,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing bearer must be 401"
    );
    assert_eq!(body, serde_json::Value::Null);

    let (status, body) = query(
        app(pool, bearer, scope_authority),
        Some("Bearer this-token-does-not-exist"),
        "account",
        account_id,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "garbage bearer must be 401"
    );
    assert_eq!(body, serde_json::Value::Null);
}

/// Test 6: the authority being unreachable/erroring must NEVER be treated as authorized -- proves
/// `RemoteScopeAuthority`'s fail-closed contract end to end through the real router, not just in
/// `scope_authority`'s own unit tests.
///
/// FAIL-FIRST EVIDENCE: temporarily flip the refusal branch in `RemoteScopeAuthority::authorize`
/// to `status => { ...; Ok(true) }` (i.e. treat a non-200/404 status as authorized) and this test
/// goes from `403` to `200` with tenant A's data leaked -- exactly the permissive-default failure
/// mode this endpoint must never have.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn authority_returning_server_error_never_authorizes(pool: PgPool) {
    let account_id = "acct-tenant-a";
    seed(&pool, account_id, "proj-tenant-a").await;

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/idp/v1/authorize-usage-scope");
        then.status(500);
    });

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let scope_authority: Arc<dyn lightbridge_authz_usage_rest::scope_authority::ScopeAuthority> =
        Arc::new(
            RemoteScopeAuthority::new(&remote_authority_config(server.base_url()))
                .expect("authority should construct"),
        );

    let (status, body) = query(
        app(pool, bearer, scope_authority),
        Some("Bearer token-a"),
        "account",
        account_id,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        serde_json::Value::Null,
        "a server-error authority response must never leak data"
    );
}

/// The same fail-closed proof against a genuinely unreachable authority (connection refused), not
/// merely a non-200 response.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn authority_unreachable_never_authorizes(pool: PgPool) {
    let account_id = "acct-tenant-a";
    seed(&pool, account_id, "proj-tenant-a").await;

    let bearer = support::bearer_with("token-a", ISSUER, "sub-a");
    let scope_authority: Arc<dyn lightbridge_authz_usage_rest::scope_authority::ScopeAuthority> =
        Arc::new(
            RemoteScopeAuthority::new(&remote_authority_config("https://127.0.0.1:1"))
                .expect("authority should construct"),
        );

    let (status, body) = query(
        app(pool, bearer, scope_authority),
        Some("Bearer token-a"),
        "account",
        account_id,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, serde_json::Value::Null);
}

/// Test 7: `/usage/v1/spend/query` refuses any request carrying an `Authorization` header --
/// the sibling assertion to the same test in `spend_query_it_tests.rs`, kept here too since #570's
/// task list names it explicitly for this file.
#[sqlx::test(migrations = "../../migrations-usage")]
async fn spend_endpoint_refuses_bearer_carrying_requests(pool: PgPool) {
    let readiness_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
    let repo = Arc::new(StoreRepo::new(Arc::new(DbPool::from_pool(pool))));
    let state = Arc::new(UsageState {
        repo,
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });
    let router = build_query_router(state, readiness_pool, false);

    let body = json!({
        "account_id": "acct-tenant-a",
        "start": "2026-08-01T00:00:00Z",
        "end": "2026-09-01T00:00:00Z",
    });
    let request = Request::builder()
        .method("POST")
        .uri("/usage/v1/spend/query")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer whatever")
        .body(Body::from(
            serde_json::to_vec(&body).expect("request body must serialize"),
        ))
        .expect("request must build");

    let response = router
        .oneshot(request)
        .await
        .expect("router must produce a response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
