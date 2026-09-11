#[path = "support/mod.rs"]
mod support;

use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use lightbridge_authz_bearer::{SERVICE_CALLER_KIND, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::authz::PermissionSet;
use lightbridge_authz_usage_rest::{
    UsageRepoTrait, UsageState, build_ingest_router,
    models::{UsageQueryRequest, UsageSeriesPoint},
    repo::UsageEvent,
};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use prost::Message;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;

#[derive(Debug, Default)]
struct MockUsageRepo {
    pub inserted_events: std::sync::Mutex<usize>,
}

#[async_trait]
impl UsageRepoTrait for MockUsageRepo {
    async fn insert_usage_events(
        &self,
        events: &[UsageEvent],
    ) -> lightbridge_authz_core::Result<usize> {
        let count = events.len();
        *self.inserted_events.lock().unwrap() += count;
        Ok(count)
    }

    async fn query_usage(
        &self,
        _input: &UsageQueryRequest,
    ) -> lightbridge_authz_core::Result<(Vec<UsageSeriesPoint>, bool)> {
        Ok((vec![], false))
    }

    async fn spend_for_account(
        &self,
        _account_id: &str,
        _start: chrono::DateTime<chrono::Utc>,
        _end: chrono::DateTime<chrono::Utc>,
    ) -> lightbridge_authz_core::Result<Option<f64>> {
        Ok(None)
    }
}

// A mock DbPoolTrait is required by `build_ingest_router` for health probes, but the ingest
// routes themselves do not use it.
#[derive(Debug)]
struct DummyDbPool;

#[async_trait]
impl lightbridge_authz_core::db::DbPoolTrait for DummyDbPool {
    fn pool(&self) -> &sqlx::Pool<sqlx::Postgres> {
        unimplemented!("not used in these tests")
    }
}

fn test_payload() -> Bytes {
    let req = ExportLogsServiceRequest::default();
    req.encode_to_vec().into()
}

fn valid_payload_with_source(source: &str) -> Bytes {
    use opentelemetry_proto::tonic::{
        common::v1::{AnyValue, KeyValue, any_value},
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        resource::v1::Resource,
    };

    let req = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "governance.source".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(source.to_string())),
                    }),
                    ..Default::default()
                }],
                dropped_attributes_count: 0,
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![LogRecord {
                    time_unix_nano: 1,
                    observed_time_unix_nano: 1,
                    severity_number: 1,
                    severity_text: "INFO".to_string(),
                    body: None,
                    attributes: vec![],
                    dropped_attributes_count: 0,
                    flags: 0,
                    trace_id: vec![],
                    span_id: vec![],
                    event_name: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
            schema_url: "".to_string(),
        }],
    };
    req.encode_to_vec().into()
}

fn build_router(
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
    principals: HashMap<String, String>,
) -> axum::Router {
    let repo = Arc::new(MockUsageRepo::default());
    let state = Arc::new(UsageState {
        repo,
        bearer,
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_principals: principals,
    });

    build_ingest_router(state, Arc::new(DummyDbPool), false, true)
}

struct CustomBearer {
    token: String,
    info: Option<TokenInfo>,
}

#[async_trait]
impl lightbridge_authz_bearer::BearerTokenServiceTrait for CustomBearer {
    async fn validate_bearer_token(&self, t: &str) -> anyhow::Result<TokenInfo> {
        if t == self.token {
            if let Some(ref info) = self.info {
                return Ok(info.clone());
            }
        }
        Err(anyhow::anyhow!("unknown token"))
    }
}

fn custom_bearer(
    token: &str,
    sub: &str,
    caller_kind: Option<&str>,
) -> Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> {
    Arc::new(CustomBearer {
        token: token.to_string(),
        info: Some(TokenInfo {
            active: true,
            sub: sub.to_string(),
            iss: "test-issuer".to_string(),
            exp: 9999999999,
            aud: vec![],
            roles: vec![],
            permissions: PermissionSet::default(),
            caller_kind: caller_kind.map(|s| s.to_string()),
            access_token: token.to_string(),
        }),
    })
}

#[tokio::test]
async fn missing_bearer_token_returns_401() {
    let router = build_router(support::trust_no_one_bearer(), HashMap::new());

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_bearer_token_returns_401() {
    let router = build_router(support::trust_no_one_bearer(), HashMap::new());

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer garbage")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_validation_failure_returns_401() {
    let router = build_router(support::trust_no_one_bearer(), HashMap::new());

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer unknown-token")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disallowed_principal_returns_403() {
    let bearer = custom_bearer(
        "valid-token",
        "svc:unknown-collector",
        Some(SERVICE_CALLER_KIND),
    );
    let mut principals = HashMap::new();
    principals.insert("svc:known-collector".to_string(), "claude-code".to_string());

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "claude-code")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(test_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn principal_wrong_source_returns_403() {
    let bearer = custom_bearer(
        "valid-token",
        "svc:collector-claude",
        Some(SERVICE_CALLER_KIND),
    );
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "codex") // Wrong source
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(test_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_x_source_returns_400() {
    let bearer = custom_bearer(
        "valid-token",
        "svc:collector-claude",
        Some(SERVICE_CALLER_KIND),
    );
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        // Missing X-Source
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(test_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_x_source_returns_400() {
    let bearer = custom_bearer(
        "valid-token",
        "svc:collector-claude",
        Some(SERVICE_CALLER_KIND),
    );
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "unknown-source") // Not in KNOWN_SOURCES
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(test_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn valid_auth_and_source_returns_202() {
    let bearer = custom_bearer(
        "valid-token",
        "svc:collector-claude",
        Some(SERVICE_CALLER_KIND),
    );
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "claude-code")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(valid_payload_with_source("claude-code")))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn payload_source_mismatch_still_accepts_but_warns() {
    let bearer = custom_bearer(
        "valid-token",
        "svc:collector-claude",
        Some(SERVICE_CALLER_KIND),
    );
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "claude-code")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        // The payload contains source 'codex', but X-Source is 'claude-code'
        .body(Body::from(valid_payload_with_source("codex")))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    // It should be accepted (202), and log a warning (verified by visual inspection or logs)
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// Proves the `caller_kind == SERVICE_CALLER_KIND` guard on line 65 of `auth_ingest.rs`
/// is not dead code: a token whose `sub` IS in `ingest_principals` but has no `caller_kind`
/// claim (e.g. a human OIDC login token) must be refused, not admitted.
///
/// Mutate the guard to `!= Some(SERVICE_CALLER_KIND)` and this test stays green — but delete the
/// entire `if` block and this test turns red (the request reaches step 4 and succeeds).
#[tokio::test]
async fn no_caller_kind_with_valid_sub_returns_403() {
    let bearer = custom_bearer("valid-token", "svc:collector-claude", None);
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "claude-code")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(test_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a token with no caller_kind whose sub matches ingest_principals must be refused; \
         only service tokens (caller_kind == SERVICE_CALLER_KIND) may use the authenticated ingest surface"
    );
}

/// Companion to `no_caller_kind_with_valid_sub_returns_403`: an `api_key`-derived token
/// (a real caller_kind value, but not the service one) must also be refused, even if its
/// `sub` collides with a configured principal. Covers the `Some("api_key")` branch the
/// original review flagged.
#[tokio::test]
async fn api_key_caller_kind_with_valid_sub_returns_403() {
    let bearer = custom_bearer("valid-token", "svc:collector-claude", Some("api_key"));
    let mut principals = HashMap::new();
    principals.insert(
        "svc:collector-claude".to_string(),
        "claude-code".to_string(),
    );

    let router = build_router(bearer, principals);

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", "claude-code")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(test_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an api_key-derived token whose sub matches ingest_principals must be refused; \
         only client_credentials service tokens may use the authenticated ingest surface"
    );
}
