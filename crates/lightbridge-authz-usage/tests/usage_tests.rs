#[path = "support/mod.rs"]
mod support;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use axum::{Json, body::Bytes, http::HeaderMap};
use chrono::{Duration, Utc};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{Error, Result, async_trait};
use lightbridge_authz_usage_rest::UsageRepoTrait;
use lightbridge_authz_usage_rest::UsageState;
use lightbridge_authz_usage_rest::handlers::ingest::{ingest_logs, ingest_metrics, ingest_traces};
use lightbridge_authz_usage_rest::handlers::query::query_usage;
use lightbridge_authz_usage_rest::models::{
    UsageGroupBy, UsageQueryFilters, UsageQueryRequest, UsageQueryResponse, UsageScope,
    UsageSeriesPoint,
};
use lightbridge_authz_usage_rest::repo::{StoreRepo, UsageEvent};
use lightbridge_authz_usage_rest::{build_ingest_router, build_query_router};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::metrics::v1::{
    Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Debug, Default)]
struct MockUsageRepo {
    points: Vec<UsageSeriesPoint>,
    inserted_events: usize,
    spend: Option<f64>,
    truncated: bool,
}

#[async_trait]
impl UsageRepoTrait for MockUsageRepo {
    async fn insert_usage_events(&self, _events: &[UsageEvent]) -> Result<usize> {
        Ok(self.inserted_events)
    }

    async fn query_usage(
        &self,
        _input: &UsageQueryRequest,
    ) -> Result<(Vec<UsageSeriesPoint>, bool)> {
        Ok((self.points.clone(), self.truncated))
    }

    async fn spend_for_account(
        &self,
        _account_id: &str,
        _start: chrono::DateTime<Utc>,
        _end: chrono::DateTime<Utc>,
    ) -> Result<Option<f64>> {
        Ok(self.spend)
    }
}

fn base_request() -> UsageQueryRequest {
    let start = Utc::now() - Duration::hours(1);
    let end = Utc::now();

    UsageQueryRequest {
        scope: UsageScope::Project,
        scope_id: "proj_1".to_string(),
        start_time: start,
        end_time: end,
        bucket: "5 minutes".to_string(),
        filters: UsageQueryFilters::default(),
        group_by: vec![UsageGroupBy::Model],
        limit: 100,
    }
}

fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz_usage")
        .expect("lazy pool should be constructible");
    Arc::new(DbPool::from_pool(pool))
}

fn mock_state() -> Arc<UsageState> {
    Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: Arc::new(support::FakeScopeAuthority::new().authorizing(
            TEST_ISSUER,
            TEST_SUBJECT,
            &UsageScope::Project,
            "proj_1",
        )),
    })
}

const TEST_TOKEN: &str = "test-bearer-token";
const TEST_ISSUER: &str = "https://issuer.test";
const TEST_SUBJECT: &str = "sub-1";

/// The ingest listener's router (#347 split): probes, Swagger docs, `/v1/otel/*` only --
/// `/usage/v1/usage/query`/`/usage/v1/spend/query` moved to `query_app` below.
fn usage_app(dev_cors: bool) -> axum::Router {
    build_ingest_router(mock_state(), lazy_pool(), dev_cors)
}

/// The mTLS-required query listener's router (#347 split): `/usage/v1/usage/query` +
/// `/usage/v1/spend/query`, plus its own probes. No TLS/client-cert layer here -- these tests
/// exercise the router in isolation over plain HTTP, exactly like `usage_app` above; the
/// client-certificate requirement is proven separately against a real TLS handshake in
/// `crates/lightbridge-authz-usage/tests/spend_query_it_tests.rs`.
fn query_app(dev_cors: bool) -> axum::Router {
    build_query_router(mock_state(), lazy_pool(), dev_cors)
}

#[tokio::test]
async fn build_ingest_router_serves_probes() {
    let response = usage_app(false)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn build_query_router_serves_probes() {
    let response = query_app(false)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the query listener must serve its own health probes independently of the ingest listener"
    );
}

#[tokio::test]
async fn build_query_router_with_dev_cors_answers_preflight_with_any_origin() {
    let preflight = query_app(true)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/usage/v1/usage/query")
                .header(header::ORIGIN, "https://spa.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(preflight.status(), StatusCode::OK);
    assert_eq!(
        preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("dev-cors preflight must carry a CORS allow-origin header"),
        "*"
    );
}

#[tokio::test]
async fn build_ingest_router_without_dev_cors_omits_cors_headers() {
    let response = usage_app(false)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header(header::ORIGIN, "https://spa.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "CORS headers must stay off unless AUTHZ_DEV_CORS enables them"
    );
}

#[tokio::test]
async fn build_ingest_router_no_longer_serves_the_query_routes() {
    let response = usage_app(false)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/usage/v1/usage/query")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "scope": "project",
                        "scope_id": "proj_1",
                        "start_time": "2026-01-01T00:00:00Z",
                        "end_time": "2026-01-01T01:00:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "#347 moved /usage/v1/usage/query off the unauthenticated ingest listener onto the \
         mTLS-required query listener -- it must not still answer here"
    );
}

fn authorized_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {TEST_TOKEN}")
            .parse()
            .expect("bearer header value should be a valid header value"),
    );
    headers
}

async fn call_query_usage(
    state: Arc<UsageState>,
    headers: HeaderMap,
    req: UsageQueryRequest,
) -> axum::response::Response {
    query_usage(axum::extract::State(state), headers, Json(req))
        .await
        .expect("handler should not propagate an Err for an auth refusal")
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }
}

#[tokio::test]
async fn query_usage_returns_bad_request_when_time_window_is_invalid() {
    let req = UsageQueryRequest {
        start_time: Utc::now(),
        end_time: Utc::now() - Duration::hours(1),
        ..base_request()
    };

    let state = mock_state();

    let result = query_usage(axum::extract::State(state), authorized_headers(), Json(req)).await;

    assert!(matches!(
        result,
        Err(Error::BadRequest(message)) if message == "start_time must be before end_time"
    ));
}

#[tokio::test]
async fn query_usage_returns_timeseries_points_when_query_is_valid() {
    let now = Utc::now();
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            inserted_events: 1,
            points: vec![UsageSeriesPoint {
                bucket_start: now,
                account_id: Some("acct_1".to_string()),
                project_id: Some("proj_1".to_string()),
                api_key_id: Some("key_1".to_string()),
                user_id: Some("user_1".to_string()),
                user_name: Some("Ada Lovelace".to_string()),
                model: Some("gpt-4.1".to_string()),
                metric_name: Some("gen_ai.usage.total_tokens".to_string()),
                signal_type: Some("metric".to_string()),
                requests: 3,
                total_cost: 42.0,
                usage_value: 120.0,
                prompt_tokens: 80,
                completion_tokens: 40,
                total_tokens: 120,
                latency_samples: 3,
                latency_p50_ms: Some(410.0),
                latency_p95_ms: Some(1_180.0),
                latency_p99_ms: Some(1_240.0),
            }],
            spend: None,
            truncated: false,
        }),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: Arc::new(support::FakeScopeAuthority::new().authorizing(
            TEST_ISSUER,
            TEST_SUBJECT,
            &UsageScope::Project,
            "proj_1",
        )),
    });

    let req = base_request();
    let response = call_query_usage(state, authorized_headers(), req).await;

    assert_eq!(response.status(), StatusCode::OK);
    let payload: UsageQueryResponse = serde_json::from_value(body_json(response).await)
        .expect("response body must decode as UsageQueryResponse");
    assert_eq!(payload.points.len(), 1);
    assert_eq!(payload.points[0].project_id.as_deref(), Some("proj_1"));
    assert!(!payload.truncated);
}

/// #570: no `Authorization` header at all -- 401, no data.
#[tokio::test]
async fn query_usage_refuses_missing_bearer_with_401() {
    let response = call_query_usage(mock_state(), HeaderMap::new(), base_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Auth-before-validation, proved directly: an unauthenticated caller sending a BOTH-invalid
/// request (malformed time window, no bearer token) must get 401, never a differentiated 400 --
/// a 400 here would itself be a signal ("your bearer would have been checked, but your body was
/// bad first") that an unauthenticated caller must never receive. Pairs with
/// `query_usage_returns_bad_request_when_time_window_is_invalid` above (same malformed body, but
/// WITH a valid bearer) so validation coverage isn't lost by moving the auth check first.
#[tokio::test]
async fn query_usage_refuses_malformed_body_with_401_when_bearer_is_also_missing() {
    let req = UsageQueryRequest {
        start_time: Utc::now(),
        end_time: Utc::now() - Duration::hours(1),
        ..base_request()
    };

    let response = call_query_usage(mock_state(), HeaderMap::new(), req).await;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "authentication must be checked before body validation, so a malformed body from an \
         unauthenticated caller must still be refused with 401, not a differentiated 400"
    );
}

/// #570: a bearer token the fake service does not recognize -- 401, no data.
#[tokio::test]
async fn query_usage_refuses_unrecognized_bearer_with_401() {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, "Bearer garbage".parse().unwrap());
    let response = call_query_usage(mock_state(), headers, base_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// #570 decisive negative case: a validly-authenticated caller whose `scope_authority` refuses
/// the requested scope must get 403, never the underlying repo's data.
#[tokio::test]
async fn query_usage_refuses_when_scope_authority_declines() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![UsageSeriesPoint {
                bucket_start: Utc::now(),
                account_id: None,
                project_id: Some("proj_1".to_string()),
                api_key_id: None,
                user_id: None,
                user_name: None,
                model: None,
                metric_name: None,
                signal_type: None,
                requests: 1,
                total_cost: 1.0,
                usage_value: 1.0,
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
                latency_samples: 0,
                latency_p50_ms: None,
                latency_p95_ms: None,
                latency_p99_ms: None,
            }],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let response = call_query_usage(state, authorized_headers(), base_request()).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await, serde_json::Value::Null);
}

struct AuthorizeEverything;
#[async_trait]
impl lightbridge_authz_usage_rest::scope_authority::ScopeAuthority for AuthorizeEverything {
    async fn authorize(
        &self,
        _issuer: &str,
        _subject: &str,
        _scope: &UsageScope,
        _scope_id: &str,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// `api_key` has no resolvable ownership predicate at all (no `accounts`/`projects` row is ever
/// keyed by a raw `api_key_id`, and unlike `user` there is no caller-subject shortcut either) --
/// refused unconditionally, even when `scope_authority` would authorize everything.
#[tokio::test]
async fn query_usage_refuses_api_key_scope_unconditionally() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo::default()),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: Arc::new(AuthorizeEverything),
    });

    let req = UsageQueryRequest {
        scope: UsageScope::ApiKey,
        scope_id: "whatever".to_string(),
        ..base_request()
    };
    let response = call_query_usage(state, authorized_headers(), req).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "scope=api_key must be refused unconditionally"
    );
}

/// `scope=user` self-ownership: the caller asking for THEIR OWN subject's usage is allowed, with
/// no `scope_authority` round trip at all -- `refuse_everything_scope_authority` proves the point
/// (the request still succeeds even though the authority refuses everything, because `scope=user`
/// self never reaches it).
#[tokio::test]
async fn query_usage_allows_own_user_scope() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let req = UsageQueryRequest {
        scope: UsageScope::User,
        scope_id: TEST_SUBJECT.to_string(),
        ..base_request()
    };
    let response = call_query_usage(state, authorized_headers(), req).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// `scope=user` for any subject OTHER than the caller's own is still refused, even when
/// `scope_authority` would authorize everything -- proving self-ownership is decided from the
/// token, never delegated to the authority for this scope.
#[tokio::test]
async fn query_usage_refuses_other_subjects_user_scope() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo::default()),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: Arc::new(AuthorizeEverything),
    });

    let req = UsageQueryRequest {
        scope: UsageScope::User,
        scope_id: "someone-else".to_string(),
        ..base_request()
    };
    let response = call_query_usage(state, authorized_headers(), req).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await, serde_json::Value::Null);
}

/// `scope=all` requires `Permission::UsageReadAll` -- a caller without it is refused, even when
/// `scope_authority` would authorize everything (there is no "all" predicate on that authority at
/// all; this is a coarse RBAC gate, decided entirely from the token's own permissions).
#[tokio::test]
async fn query_usage_refuses_all_scope_without_permission() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo::default()),
        bearer: support::bearer_with(TEST_TOKEN, TEST_ISSUER, TEST_SUBJECT),
        scope_authority: Arc::new(AuthorizeEverything),
    });

    let req = UsageQueryRequest {
        scope: UsageScope::All,
        scope_id: String::new(),
        ..base_request()
    };
    let response = call_query_usage(state, authorized_headers(), req).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await, serde_json::Value::Null);
}

/// `scope=all` for a caller holding `Permission::UsageReadAll` is allowed, with an empty
/// `scope_id` (the documented "ignored" shape) and no `scope_authority` round trip at all.
#[tokio::test]
async fn query_usage_allows_all_scope_with_permission() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo::default()),
        bearer: support::bearer_with_permissions(
            TEST_TOKEN,
            TEST_ISSUER,
            TEST_SUBJECT,
            lightbridge_authz_core::authz::PermissionSet::from_iter([
                lightbridge_authz_core::Permission::UsageReadAll,
            ]),
        ),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let req = UsageQueryRequest {
        scope: UsageScope::All,
        scope_id: String::new(),
        ..base_request()
    };
    let response = call_query_usage(state, authorized_headers(), req).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// `scope_id` stays required for every scope except `all`, which has none to validate.
#[tokio::test]
async fn query_usage_all_scope_does_not_require_scope_id() {
    let req = UsageQueryRequest {
        scope: UsageScope::All,
        scope_id: String::new(),
        ..base_request()
    };
    let result = query_usage(
        axum::extract::State(Arc::new(UsageState {
            repo: Arc::new(MockUsageRepo::default()),
            bearer: support::bearer_with_permissions(
                TEST_TOKEN,
                TEST_ISSUER,
                TEST_SUBJECT,
                lightbridge_authz_core::authz::PermissionSet::from_iter([
                    lightbridge_authz_core::Permission::UsageReadAll,
                ]),
            ),
            scope_authority: support::refuse_everything_scope_authority(),
        })),
        authorized_headers(),
        Json(req),
    )
    .await;
    assert!(
        result.is_ok(),
        "scope=all with an empty scope_id must not be rejected as a bad request"
    );
}

/// Serde round-trip for `UsageScope::All` -- the wire representation is `"all"`.
#[test]
fn usage_scope_all_serializes_as_lowercase_all() {
    let json = serde_json::to_string(&UsageScope::All).expect("UsageScope::All must serialize");
    assert_eq!(json, "\"all\"");
    let parsed: UsageScope =
        serde_json::from_str("\"all\"").expect("\"all\" must deserialize to UsageScope::All");
    assert!(matches!(parsed, UsageScope::All));
}

#[tokio::test]
async fn ingest_logs_treats_noop_insert_as_success() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let response = ingest_logs(
        axum::extract::State(state),
        HeaderMap::new(),
        encoded_log_request(),
    )
    .await
    .expect("noop insert should still acknowledge OTLP logs");

    assert_eq!(response.0, StatusCode::ACCEPTED);
    assert_eq!(response.1.0.accepted_events, 1);
}

#[tokio::test]
async fn ingest_logs_rejects_invalid_protobuf_as_bad_request() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let result = ingest_logs(
        axum::extract::State(state),
        HeaderMap::new(),
        Bytes::from_static(b"not protobuf"),
    )
    .await;

    assert!(matches!(
        result,
        Err(Error::BadRequest(message))
            if message.contains("invalid OTLP logs protobuf payload")
    ));
}

fn encoded_log_request() -> Bytes {
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: None,
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![LogRecord {
                    time_unix_nano: 1_700_000_000_000_000_000,
                    severity_text: "INFO".to_string(),
                    attributes: vec![
                        string_attr("account_id", "acct_1"),
                        string_attr("project_id", "proj_1"),
                        int_attr("prompt_tokens", 8),
                        int_attr("completion_tokens", 4),
                    ],
                    ..Default::default()
                }],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };

    let mut encoded = Vec::new();
    request
        .encode(&mut encoded)
        .expect("log request should encode");
    Bytes::from(encoded)
}

fn string_attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        key_strindex: 0,
    }
}

fn int_attr(key: &str, value: i64) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::IntValue(value)),
        }),
        key_strindex: 0,
    }
}

fn encoded_trace_request() -> Bytes {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![string_attr("account_id", "acct_1")],
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    name: "chat.completion".to_string(),
                    start_time_unix_nano: 1_700_000_000_000_000_000,
                    end_time_unix_nano: 1_700_000_001_000_000_000,
                    attributes: vec![
                        string_attr("project_id", "proj_1"),
                        int_attr("prompt_tokens", 3),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let mut encoded = Vec::new();
    request
        .encode(&mut encoded)
        .expect("trace request should encode");
    Bytes::from(encoded)
}

fn encoded_metrics_request() -> Bytes {
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![string_attr("account_id", "acct_1")],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![Metric {
                    name: "gen_ai.usage.total_tokens".to_string(),
                    data: Some(metric::Data::Sum(Sum {
                        data_points: vec![NumberDataPoint {
                            time_unix_nano: 1_700_000_000_000_000_000,
                            value: Some(number_data_point::Value::AsInt(42)),
                            ..Default::default()
                        }],
                        aggregation_temporality: 0,
                        is_monotonic: true,
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let mut encoded = Vec::new();
    request
        .encode(&mut encoded)
        .expect("metrics request should encode");
    Bytes::from(encoded)
}

#[tokio::test]
async fn ingest_traces_treats_noop_insert_as_success() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let response = ingest_traces(
        axum::extract::State(state),
        HeaderMap::new(),
        encoded_trace_request(),
    )
    .await
    .expect("noop insert should still acknowledge OTLP traces");

    assert_eq!(response.0, StatusCode::ACCEPTED);
    assert_eq!(response.1.0.accepted_events, 1);
}

#[tokio::test]
async fn ingest_traces_rejects_invalid_protobuf_as_bad_request() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let result = ingest_traces(
        axum::extract::State(state),
        HeaderMap::new(),
        Bytes::from_static(b"not protobuf"),
    )
    .await;

    assert!(matches!(
        result,
        Err(Error::BadRequest(message))
            if message.contains("invalid OTLP trace protobuf payload")
    ));
}

#[tokio::test]
async fn ingest_metrics_treats_noop_insert_as_success() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let response = ingest_metrics(
        axum::extract::State(state),
        HeaderMap::new(),
        encoded_metrics_request(),
    )
    .await
    .expect("noop insert should still acknowledge OTLP metrics");

    assert_eq!(response.0, StatusCode::ACCEPTED);
    assert_eq!(response.1.0.accepted_events, 1);
}

#[tokio::test]
async fn ingest_metrics_rejects_invalid_protobuf_as_bad_request() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let result = ingest_metrics(
        axum::extract::State(state),
        HeaderMap::new(),
        Bytes::from_static(b"not protobuf"),
    )
    .await;

    assert!(matches!(
        result,
        Err(Error::BadRequest(message))
            if message.contains("invalid OTLP metrics protobuf payload")
    ));
}

#[tokio::test]
async fn ingest_logs_accepts_json_content_type_payload() {
    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let body = serde_json::json!({
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": "1700000000000000000",
                                "severityText": "INFO"
                            }
                        ]
                    }
                ]
            }
        ]
    })
    .to_string();

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

    let response = ingest_logs(
        axum::extract::State(state),
        headers,
        Bytes::from(body.into_bytes()),
    )
    .await
    .expect("json OTLP logs payload should be accepted");

    assert_eq!(response.0, StatusCode::ACCEPTED);
    assert_eq!(response.1.0.accepted_events, 1);
}

#[tokio::test]
async fn ingest_logs_accepts_gzip_encoded_body() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let state = Arc::new(UsageState {
        repo: Arc::new(MockUsageRepo {
            points: vec![],
            inserted_events: 0,
            spend: None,
            truncated: false,
        }),
        bearer: support::trust_no_one_bearer(),
        scope_authority: support::refuse_everything_scope_authority(),
    });

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&encoded_log_request())
        .expect("write should succeed");
    let compressed = encoder.finish().expect("gzip encoding should succeed");

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());

    let response = ingest_logs(
        axum::extract::State(state),
        headers,
        Bytes::from(compressed),
    )
    .await
    .expect("gzip encoded OTLP logs payload should be accepted");

    assert_eq!(response.0, StatusCode::ACCEPTED);
    assert_eq!(response.1.0.accepted_events, 1);
}

#[tokio::test]
async fn root_route_reports_a_welcome_message() {
    let response = usage_app(false)
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn healthz_ready_route_reports_unavailable_when_database_is_down() {
    let response = usage_app(false)
        .oneshot(
            Request::builder()
                .uri("/healthz/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn store_repo_insert_usage_events_is_a_noop_for_empty_batch_without_a_live_pool() {
    let repo: Arc<dyn UsageRepoTrait> = Arc::new(StoreRepo::new(lazy_pool()));

    let persisted = repo
        .insert_usage_events(&[])
        .await
        .expect("empty insert should succeed without touching the pool");

    assert_eq!(persisted, 0);
}

#[tokio::test]
async fn store_repo_query_usage_rejects_invalid_bucket_without_a_live_pool() {
    let repo: Arc<dyn UsageRepoTrait> = Arc::new(StoreRepo::new(lazy_pool()));
    let request = UsageQueryRequest {
        bucket: "1 fortnight".to_string(),
        ..base_request()
    };

    let result = repo.query_usage(&request).await;

    assert!(matches!(result, Err(Error::BadRequest(_))));
}

#[test]
fn usage_query_request_deserializes_default_bucket_and_limit() {
    let request: UsageQueryRequest = serde_json::from_value(serde_json::json!({
        "scope": "project",
        "scope_id": "proj_1",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T01:00:00Z"
    }))
    .expect("minimal usage query request should deserialize");

    assert_eq!(request.bucket, "1 hour");
    assert_eq!(request.limit, 1_000);
}
