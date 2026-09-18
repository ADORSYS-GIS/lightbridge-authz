//! Behavioural tests for the authenticated ingest surface (#585):
//! `POST /auth/v1/otel/{traces,metrics,logs}`.
//!
//! Two things this file is deliberately built around:
//!
//! 1. **Every signal gets covered.** The three handlers share one generic body
//!    (`handlers::auth_ingest::ingest`), but "shared body" is only true while nothing
//!    signal-specific creeps back in -- so each of traces/metrics/logs gets a happy path AND a
//!    refusal case, rather than a single `/logs` case standing in for all three.
//! 2. **Each guard has a test that fails when the guard is weakened or deleted.** A test that
//!    passes for an unrelated reason does not pin anything; the doc comment on each test says
//!    which mutation it is there to catch.

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
    config::IngestAuthConfig,
    handlers::payload_identity::find_identity_mismatch,
    models::{
        UsageQueryRequest, UsageSeriesPoint,
        execution::{ExecutionQueryRequest, ExecutionSeriesPoint},
    },
    repo::UsageEvent,
};
use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
    trace::v1::ExportTraceServiceRequest,
};
use prost::Message;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

/// The audience every test credential is minted for, matching the value
/// `config/usage.yaml`/`.docker/usage/container.yaml` configure.
const AUDIENCE: &str = "lightbridge-usage-ingest";

/// The source the tests' one configured principal is allowed to assert.
///
/// Deliberately a request-grain source (`eaig`), not `github-copilot` or `claude-code`: since
/// #588, `github-copilot` logs are routed to the day-grain receiver and `claude-code` traces are
/// routed to the execution-grain receiver, so neither can stand in for the generic request-grain
/// authenticated path these tests exercise. `eaig` (the AI gateway) is request-grain for every
/// signal.
const TRUSTED_SOURCE: &str = "eaig";
/// A different, equally-valid source, used to prove the credential -- not the caller -- decides.
const OTHER_SOURCE: &str = "codex";
/// The `sub` of the tests' one configured principal.
const PRINCIPAL: &str = "svc:collector-eaig";

// ---------------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MockUsageRepo {
    pub inserted_events: Mutex<usize>,
    /// Every event handed to `insert_usage_events`, so a test can assert what was actually STORED
    /// rather than only the status code it got back.
    pub captured: Mutex<Vec<UsageEvent>>,
}

#[async_trait]
impl UsageRepoTrait for MockUsageRepo {
    async fn insert_usage_events(
        &self,
        events: &[UsageEvent],
    ) -> lightbridge_authz_core::Result<usize> {
        let count = events.len();
        *self
            .inserted_events
            .lock()
            .expect("mutex should not be poisoned") += count;
        self.captured
            .lock()
            .expect("mutex should not be poisoned")
            .extend_from_slice(events);
        Ok(count)
    }

    async fn upsert_day_facts(
        &self,
        _facts: &[lightbridge_authz_usage_rest::models::day_seat::DayFact],
    ) -> lightbridge_authz_core::Result<usize> {
        Ok(0)
    }

    async fn upsert_seat_snapshots(
        &self,
        _snapshots: &[lightbridge_authz_usage_rest::models::day_seat::SeatSnapshot],
    ) -> lightbridge_authz_core::Result<usize> {
        Ok(0)
    }

    async fn upsert_execution_grain(
        &self,
        _batch: &lightbridge_authz_usage_rest::models::execution_ingest::ExecutionGrainBatch,
    ) -> lightbridge_authz_core::Result<usize> {
        Ok(0)
    }

    async fn query_usage(
        &self,
        _input: &UsageQueryRequest,
    ) -> lightbridge_authz_core::Result<(Vec<UsageSeriesPoint>, bool)> {
        Ok((vec![], false))
    }

    async fn query_executions(
        &self,
        _input: &ExecutionQueryRequest,
    ) -> lightbridge_authz_core::Result<(Vec<ExecutionSeriesPoint>, bool)> {
        Ok((vec![], false))
    }

    async fn query_seat_snapshots(
        &self,
        _input: &lightbridge_authz_usage_rest::models::seat::SeatSnapshotQueryRequest,
    ) -> lightbridge_authz_core::Result<(
        Vec<lightbridge_authz_usage_rest::models::seat::SeatSnapshotSeriesPoint>,
        bool,
    )> {
        Ok((vec![], false))
    }

    async fn query_day_facts(
        &self,
        _input: &lightbridge_authz_usage_rest::models::day_fact::DayFactQueryRequest,
    ) -> lightbridge_authz_core::Result<(
        Vec<lightbridge_authz_usage_rest::models::day_fact::DayFactSeriesPoint>,
        bool,
    )> {
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

    async fn last_purge_cutoff(
        &self,
    ) -> lightbridge_authz_core::Result<Option<chrono::DateTime<chrono::Utc>>> {
        Ok(None)
    }
}

/// A mock `DbPoolTrait` is required by `build_ingest_router` for health probes, but the ingest
/// routes themselves do not use it.
#[derive(Debug)]
struct DummyDbPool;

#[async_trait]
impl lightbridge_authz_core::db::DbPoolTrait for DummyDbPool {
    #[expect(clippy::unimplemented, reason = "test double — never called")]
    fn pool(&self) -> &sqlx::Pool<sqlx::Postgres> {
        unimplemented!("not used in these tests")
    }
}

// ---------------------------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------------------------

/// An empty export: decodes fine, produces zero events.
fn empty_logs_payload() -> Bytes {
    ExportLogsServiceRequest::default().encode_to_vec().into()
}

/// A logs export whose resource attributes assert `asserted_source` as `governance.source`.
fn logs_payload(asserted_source: &str) -> Bytes {
    let req: ExportLogsServiceRequest = serde_json::from_value(json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    { "key": "governance.source", "value": { "stringValue": asserted_source } }
                ]
            },
            "scopeLogs": [{
                "logRecords": [{
                    "timeUnixNano": "1735689600000000000",
                    "severityText": "INFO"
                }]
            }]
        }]
    }))
    .expect("valid logs payload");
    req.encode_to_vec().into()
}

fn traces_payload() -> Bytes {
    let req: ExportTraceServiceRequest = serde_json::from_value(json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    { "key": "account_id", "value": { "stringValue": "acct_1" } }
                ]
            },
            "scopeSpans": [{
                "spans": [{
                    "traceId": "00000000000000000000000000000001",
                    "spanId": "0000000000000001",
                    "name": "chat.completion",
                    "startTimeUnixNano": "1735689600000000000",
                    "endTimeUnixNano": "1735689601000000000"
                }]
            }]
        }]
    }))
    .expect("valid trace payload");
    req.encode_to_vec().into()
}

fn metrics_payload() -> Bytes {
    let req: ExportMetricsServiceRequest = serde_json::from_value(json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    { "key": "account_id", "value": { "stringValue": "acct_1" } }
                ]
            },
            "scopeMetrics": [{
                "metrics": [{
                    "name": "gen_ai.usage.total_tokens",
                    "sum": {
                        "aggregationTemporality": 1,
                        "isMonotonic": true,
                        "dataPoints": [{
                            "timeUnixNano": "1735689601000000000",
                            "asInt": "99"
                        }]
                    }
                }]
            }]
        }]
    }))
    .expect("valid metrics payload");
    req.encode_to_vec().into()
}

// ---------------------------------------------------------------------------------------------
// Router + credential helpers
// ---------------------------------------------------------------------------------------------

/// The config the tests' router is built with: one principal, allowed to assert
/// [`TRUSTED_SOURCE`], and the AC4 audience.
fn ingest_config() -> IngestAuthConfig {
    let mut principals = HashMap::new();
    principals.insert(PRINCIPAL.to_string(), TRUSTED_SOURCE.to_string());
    IngestAuthConfig {
        principals,
        audience: AUDIENCE.to_string(),
    }
}

fn build_router(
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
    auth: Option<IngestAuthConfig>,
) -> axum::Router {
    build_router_with_capture(bearer, auth).0
}

/// Like `build_router` but also returns the `Arc<MockUsageRepo>` so a test can inspect the events
/// stored during the request. Mounting of `/auth/v1/otel/*` is derived from `auth` being `Some` --
/// exactly as `build_ingest_router` does it in production.
fn build_router_with_capture(
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
    auth: Option<IngestAuthConfig>,
) -> (axum::Router, Arc<MockUsageRepo>) {
    let repo = Arc::new(MockUsageRepo::default());
    let repo_ref = Arc::clone(&repo);
    let state = Arc::new(UsageState {
        repo,
        bearer,
        scope_authority: support::refuse_everything_scope_authority(),
        ingest_auth: auth,
        raw_days: Some(90),
    });
    (
        build_ingest_router(state, Arc::new(DummyDbPool), false),
        repo_ref,
    )
}

/// A bearer service that resolves exactly one token to a fixed [`TokenInfo`].
struct CustomBearer {
    token: String,
    info: Option<TokenInfo>,
}

#[async_trait]
impl lightbridge_authz_bearer::BearerTokenServiceTrait for CustomBearer {
    async fn validate_bearer_token(&self, t: &str) -> anyhow::Result<TokenInfo> {
        if t == self.token
            && let Some(ref info) = self.info
        {
            return Ok(info.clone());
        }
        Err(anyhow::anyhow!("unknown token"))
    }
}

fn token_info(sub: &str, caller_kind: Option<&str>, aud: &[&str], token: &str) -> TokenInfo {
    TokenInfo {
        active: true,
        sub: sub.to_string(),
        iss: "test-issuer".to_string(),
        exp: 9999999999,
        aud: aud.iter().map(|a| a.to_string()).collect(),
        roles: vec![],
        permissions: PermissionSet::default(),
        caller_kind: caller_kind.map(|s| s.to_string()),
        access_token: token.to_string(),
    }
}

/// The ordinary case: a `client_credentials` token with the right `sub` and the right `aud`.
fn service_bearer(sub: &str) -> Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> {
    bearer(sub, Some(SERVICE_CALLER_KIND), &[AUDIENCE])
}

fn bearer(
    sub: &str,
    caller_kind: Option<&str>,
    aud: &[&str],
) -> Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> {
    Arc::new(CustomBearer {
        token: "valid-token".to_string(),
        info: Some(token_info(sub, caller_kind, aud, "valid-token")),
    })
}

/// A `POST /auth/v1/otel/{signal}` request with the given `X-Source` (omit for none).
fn ingest_request(signal: &str, x_source: Option<&str>, body: Bytes) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/auth/v1/otel/{signal}"))
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header(header::CONTENT_TYPE, "application/x-protobuf");
    if let Some(source) = x_source {
        builder = builder.header("X-Source", source);
    }
    builder
        .body(Body::from(body))
        .expect("the request should build")
}

// ---------------------------------------------------------------------------------------------
// Gate 1/2: credential presence and validation -> 401
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn missing_bearer_token_returns_401() {
    let router = build_router(support::trust_no_one_bearer(), Some(ingest_config()));

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
    let router = build_router(support::trust_no_one_bearer(), Some(ingest_config()));

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer garbage")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// AC4's "auth-dependency unreachable ⇒ refusal, never accept" case. The bearer service here
/// fails every token, which is what an unreachable JWKS resolves to (`validate_bearer_token`
/// returns `Err`, never a permissive default). Mutation this catches: any `unwrap_or(true)` /
/// `unwrap_or_default()` on the validation result, which would turn a JWKS outage into an open
/// door.
#[tokio::test]
async fn bearer_validation_failure_returns_401() {
    let router = build_router(support::trust_no_one_bearer(), Some(ingest_config()));

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer unknown-token")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 7235 makes the auth scheme name case-insensitive, and some OTel exporter HTTP clients send
/// `bearer`. Mutation this catches: reverting to a case-sensitive `starts_with("Bearer ")`, which
/// silently 401s every such client while all other tests stay green.
#[tokio::test]
async fn lowercase_bearer_scheme_is_accepted() {
    let router = build_router(service_bearer(PRINCIPAL), Some(ingest_config()));

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "bearer valid-token")
        .header("X-Source", TRUSTED_SOURCE)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(empty_logs_payload()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "a lowercase `bearer` scheme must be accepted -- RFC 7235 treats it as case-insensitive"
    );
}

// ---------------------------------------------------------------------------------------------
// Gate 3: caller_kind -> 403
// ---------------------------------------------------------------------------------------------

/// Proves the `caller_kind == SERVICE_CALLER_KIND` guard is not dead code: a token whose `sub` IS
/// in `principals` but has no `caller_kind` claim (e.g. a human OIDC login) must be refused.
/// Mutation this catches: deleting the whole guard -- every other test still passes without it,
/// because they either fail earlier (token) or later (principals mapping).
#[tokio::test]
async fn no_caller_kind_with_valid_sub_returns_403() {
    let router = build_router(bearer(PRINCIPAL, None, &[AUDIENCE]), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a token with no caller_kind whose sub matches a principal must be refused"
    );
}

/// Companion to the above: an `api_key`-derived token is a real `caller_kind` value, but not the
/// service one, and must be refused even when its `sub` collides with a configured principal.
#[tokio::test]
async fn api_key_caller_kind_with_valid_sub_returns_403() {
    let router = build_router(
        bearer(PRINCIPAL, Some("api_key"), &[AUDIENCE]),
        Some(ingest_config()),
    );

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an api_key-derived token whose sub matches a principal must be refused"
    );
}

// ---------------------------------------------------------------------------------------------
// Gate 4 (AC4): audience -> 403
// ---------------------------------------------------------------------------------------------

/// AC4's wrong-audience refusal. Without this gate, ANY valid `client_credentials` token from any
/// client whose `sub` happened to be mapped would be admitted, whatever resource it was minted
/// for -- the audience is what binds the credential to this endpoint.
///
/// Mutation this catches: deleting the `aud` check, or comparing it with the wrong expectation
/// (e.g. `!iter().any(...)`, which admits exactly the tokens that should be refused).
#[tokio::test]
async fn wrong_audience_returns_403() {
    let router = build_router(
        bearer(
            PRINCIPAL,
            Some(SERVICE_CALLER_KIND),
            &["some-other-service"],
        ),
        Some(ingest_config()),
    );

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a service token whose `aud` does not name this endpoint must be refused, even with a \
         mapped sub and the expected caller_kind"
    );
}

/// The other half of the audience gate: a token carrying NO `aud` at all must be refused.
///
/// This is not the same case as `wrong_audience_returns_403`. `lightbridge-authz-bearer`'s own
/// `validate_aud` path skips entirely when a token carries no `aud` claim, so an implementation
/// that relied on the JWKS validator's audience enforcement instead of checking here would admit
/// an audience-less token.
#[tokio::test]
async fn missing_audience_returns_403() {
    let router = build_router(
        bearer(PRINCIPAL, Some(SERVICE_CALLER_KIND), &[]),
        Some(ingest_config()),
    );

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a token carrying no `aud` must be refused -- `validate_aud` alone does not catch this case"
    );
}

/// The positive control for the audience gate: a token that names this endpoint among several
/// audiences is admitted. Without this, `wrong_audience_returns_403` could pass by refusing
/// everything.
#[tokio::test]
async fn multiple_audiences_including_this_endpoint_is_accepted() {
    let router = build_router(
        bearer(
            PRINCIPAL,
            Some(SERVICE_CALLER_KIND),
            &["another-service", AUDIENCE],
        ),
        Some(ingest_config()),
    );

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

// ---------------------------------------------------------------------------------------------
// Gate 5: principal -> X-Source binding -> 403 / 400
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn disallowed_principal_returns_403() {
    let router = build_router(
        service_bearer("svc:unknown-collector"),
        Some(ingest_config()),
    );

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn principal_wrong_source_returns_403() {
    let router = build_router(service_bearer(PRINCIPAL), Some(ingest_config()));

    // The principal is mapped to TRUSTED_SOURCE but asserts OTHER_SOURCE.
    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(OTHER_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_x_source_returns_400() {
    let router = build_router(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request("logs", None, empty_logs_payload()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_x_source_returns_400() {
    let router = build_router(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some("not-a-known-source"),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Defensive: the handlers refuse when `ingest_auth` is absent, even though `build_ingest_router`
/// does not mount these routes in that case. Mutation this catches: an `unwrap()` on
/// `state.ingest_auth`, which would turn a mis-composed router into a panic (and, if ever
/// softened to a default, into an open door).
#[tokio::test]
async fn unmounted_surface_refuses_when_reached() {
    let (router, repo) = build_router_with_capture(service_bearer(PRINCIPAL), None);

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            empty_logs_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "with no ingest_auth configured the route is not mounted at all"
    );
    assert_eq!(
        repo.captured.lock().expect("mutex").len(),
        0,
        "nothing may be stored through an unmounted surface"
    );
}

// ---------------------------------------------------------------------------------------------
// Happy paths, one per signal
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn valid_logs_ingest_returns_202_and_stores_the_trusted_source() {
    let (router, repo) =
        build_router_with_capture(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            logs_payload(TRUSTED_SOURCE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let captured = repo.captured.lock().expect("mutex");
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].signal_type, "log");
    assert_eq!(captured[0].source.as_deref(), Some(TRUSTED_SOURCE));
}

#[tokio::test]
async fn valid_traces_ingest_returns_202_and_stores_the_trusted_source() {
    let (router, repo) =
        build_router_with_capture(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "traces",
            Some(TRUSTED_SOURCE),
            traces_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let captured = repo.captured.lock().expect("mutex");
    assert_eq!(captured.len(), 1, "the trace must be stored");
    assert_eq!(captured[0].signal_type, "trace");
    assert_eq!(captured[0].account_id.as_deref(), Some("acct_1"));
    assert_eq!(captured[0].source.as_deref(), Some(TRUSTED_SOURCE));
}

#[tokio::test]
async fn valid_metrics_ingest_returns_202_and_stores_the_trusted_source() {
    let (router, repo) =
        build_router_with_capture(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "metrics",
            Some(TRUSTED_SOURCE),
            metrics_payload(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let captured = repo.captured.lock().expect("mutex");
    assert_eq!(captured.len(), 1, "the metric must be stored");
    assert_eq!(captured[0].signal_type, "metric");
    assert_eq!(
        captured[0].metric_name.as_deref(),
        Some("gen_ai.usage.total_tokens"),
        "the authenticated route must reach the metric extractor"
    );
    assert_eq!(captured[0].account_id.as_deref(), Some("acct_1"));
    assert_eq!(captured[0].source.as_deref(), Some(TRUSTED_SOURCE));
}

/// Refusal coverage for the two signals the previous revision never exercised. The generic body
/// makes these likely redundant today; they exist so that if a signal-specific branch is ever
/// reintroduced, it cannot ship unauthenticated.
#[tokio::test]
async fn traces_and_metrics_refuse_an_unmapped_principal() {
    for signal in ["traces", "metrics"] {
        let router = build_router(
            service_bearer("svc:unknown-collector"),
            Some(ingest_config()),
        );
        let body = if signal == "traces" {
            traces_payload()
        } else {
            metrics_payload()
        };

        let response = router
            .oneshot(ingest_request(signal, Some(TRUSTED_SOURCE), body))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{signal} must enforce the same principal binding as logs"
        );
    }
}

/// A gzip-encoded body must be accepted on the authenticated surface too.
///
/// Mutation this catches: reverting the handlers to a raw `T::decode(body)` instead of
/// `decode_otlp_request_async`, which drops gzip support (and the 64 MiB decompressed cap) from
/// this path only -- exactly the regression the first review round found.
#[tokio::test]
async fn gzip_encoded_body_is_accepted() {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&logs_payload(TRUSTED_SOURCE))
        .expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");

    let router = build_router(service_bearer(PRINCIPAL), Some(ingest_config()));

    let request = Request::builder()
        .method("POST")
        .uri("/auth/v1/otel/logs")
        .header(header::AUTHORIZATION, "Bearer valid-token")
        .header("X-Source", TRUSTED_SOURCE)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from(compressed))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "a gzip-encoded export must be accepted on the authenticated surface"
    );
}

// ---------------------------------------------------------------------------------------------
// The payload-identity cross-check, moved upstream by #549
// ---------------------------------------------------------------------------------------------

/// The pure predicate, driven directly.
///
/// `check_identity_mismatch` only logs, so this is where the *decision* is pinned: which keys are
/// consulted, which values count as a disagreement, and that agreement and absence are both
/// silent. Mutation this catches: inverting the comparison, scanning the wrong key list, or
/// treating a missing attribute as a mismatch.
#[test]
fn find_identity_mismatch_detects_only_disagreement() {
    let mismatching = HashMap::from([("governance.source".to_string(), json!("codex"))]);
    assert_eq!(
        find_identity_mismatch(&mismatching, TRUSTED_SOURCE),
        Some(("governance.source", "codex"))
    );

    let agreeing = HashMap::from([("governance.source".to_string(), json!(TRUSTED_SOURCE))]);
    assert_eq!(find_identity_mismatch(&agreeing, TRUSTED_SOURCE), None);

    let absent = HashMap::new();
    assert_eq!(find_identity_mismatch(&absent, TRUSTED_SOURCE), None);

    let other_key = HashMap::from([(
        "service.namespace".to_string(),
        json!("some-other-namespace"),
    )]);
    assert_eq!(
        find_identity_mismatch(&other_key, TRUSTED_SOURCE),
        Some(("service.namespace", "some-other-namespace")),
        "both identity keys must be consulted, not just the first"
    );

    let non_string = HashMap::from([("governance.source".to_string(), json!(42))]);
    assert_eq!(
        find_identity_mismatch(&non_string, TRUSTED_SOURCE),
        None,
        "only a string assertion is a disagreement; a non-string is not comparable and must not \
         be reported as one"
    );
}

/// The end-to-end contract for the mismatch path: a payload asserting a DIFFERENT source is
/// accepted, stored, stamped with the TRUSTED source, and produces exactly one warning naming
/// both values.
///
/// Four separate failure modes go red here, which is the point:
///
/// - the batch is rejected because of the mismatch      -> status != 202
/// - the batch is silently dropped                      -> captured is empty
/// - the payload's asserted source is applied           -> `event.source == "codex"`
/// - the check never fires (dead control)               -> no warning captured
/// - the check fires on agreement instead               -> warning captured on the happy path
#[tokio::test]
async fn payload_source_mismatch_warns_but_stores_the_trusted_source() {
    use tracing_subscriber::layer::SubscriberExt;

    let capture = WarningCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    // `#[tokio::test]`'s runtime is current-thread, so the thread-local default set here stays in
    // force across the whole await chain.
    let _guard = tracing::subscriber::set_default(subscriber);

    let (router, repo) =
        build_router_with_capture(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            logs_payload(OTHER_SOURCE),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "a payload asserting a different source must be ACCEPTED -- the control alerts, it does \
         not refuse"
    );

    let captured = repo.captured.lock().expect("mutex");
    assert_eq!(
        captured.len(),
        1,
        "the mismatching batch must be stored, not silently dropped"
    );
    assert_eq!(
        captured[0].source.as_deref(),
        Some(TRUSTED_SOURCE),
        "the credential-established source must win over the payload's assertion"
    );

    let warnings = capture.0.lock().expect("capture mutex");
    assert_eq!(
        warnings.len(),
        1,
        "exactly one mismatch warning must be emitted, got: {warnings:?}"
    );
    let warning = &warnings[0];
    assert!(
        warning.contains(OTHER_SOURCE),
        "the warning must name the payload's asserted source, got: {warning}"
    );
    assert!(
        warning.contains(TRUSTED_SOURCE),
        "the warning must name the trusted source, got: {warning}"
    );
}

/// The negative control for the test above: a payload that AGREES must produce no warning at all.
/// Without this, a `check_identity_mismatch` that warned unconditionally would pass the mismatch
/// test.
#[tokio::test]
async fn payload_source_agreement_emits_no_warning() {
    use tracing_subscriber::layer::SubscriberExt;

    let capture = WarningCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let router = build_router(service_bearer(PRINCIPAL), Some(ingest_config()));

    let response = router
        .oneshot(ingest_request(
            "logs",
            Some(TRUSTED_SOURCE),
            logs_payload(TRUSTED_SOURCE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        capture.0.lock().expect("capture mutex").len(),
        0,
        "an agreeing payload must not warn"
    );
}

/// Collects the rendered `warn!` messages emitted on this thread.
#[derive(Clone, Default)]
struct WarningCapture(Arc<Mutex<Vec<String>>>);

#[derive(Default)]
struct MessageVisitor(String);

impl MessageVisitor {
    fn push(&mut self, field: &tracing::field::Field, value: String) {
        if field.name() == "message" {
            self.0 = value;
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={value}", field.name()));
        }
    }
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.push(field, format!("{value:?}").trim_matches('"').to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field, value.to_string());
    }
}

impl<S> tracing_subscriber::Layer<S> for WarningCapture
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.0
            .lock()
            .expect("capture mutex")
            .push(visitor.0.trim().to_string());
    }
}
