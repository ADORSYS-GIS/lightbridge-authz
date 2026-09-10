use crate::UsageState;
use crate::handlers::ingest::{ingest_logs, ingest_metrics, ingest_traces};
use crate::handlers::query::query_usage;
use crate::handlers::spend::query_spend;
use axum::{Router, routing::post};
use std::sync::Arc;

/// Ingest-only routes, mounted on `UsageServerGroup::usage` (see its doc comment). Deliberately
/// left unauthenticated: the caller here is an AI Envoy/OpenTelemetry exporter outside this
/// repo's deploy surface (`docs/usage-api.md`), which cannot be given a client certificate
/// without a coordinated change to that caller -- out of #347's scope. Safe only under the
/// existing ClusterIP-only/no-ingress condition (see `AGENTS.md`'s Security Notes).
///
/// The gateway's existing `/v1/otel/*` path is the one deliberate exception to the authenticated
/// ingest requirement (#585 AC5). It remains unauthenticated, safe under the existing
/// ClusterIP-only/no-ingress condition plus the deployment topology that pins its sole emitter
/// (the AI gateway's Envoy access-log sink) to the same cluster. Its source is always `eaig`.
pub fn ingest_router() -> Router<Arc<UsageState>> {
    Router::new()
        .route("/v1/otel/traces", post(ingest_traces))
        .route("/v1/otel/metrics", post(ingest_metrics))
        .route("/v1/otel/logs", post(ingest_logs))
}

pub fn auth_ingest_router() -> Router<Arc<UsageState>> {
    use crate::handlers::auth_ingest::{auth_ingest_logs, auth_ingest_metrics, auth_ingest_traces};
    Router::new()
        .route("/auth/v1/otel/traces", post(auth_ingest_traces))
        .route("/auth/v1/otel/metrics", post(auth_ingest_metrics))
        .route("/auth/v1/otel/logs", post(auth_ingest_logs))
}

/// The internal query routes (#347): `/usage/v1/usage/query` and `/usage/v1/spend/query`, mounted
/// on `UsageServerGroup::query` -- the listener that requires and verifies a client certificate
/// via `Tls::client_ca_bundle_path` (see `lightbridge_authz_core::server::serve_tls`'s
/// `build_mtls_config`). Both routes moved off the shared `usage` listener above rather than
/// growing a second, in-app authorization mechanism, because `axum-server`'s rustls integration
/// enforces client-cert verification per-listener, not per-route.
///
/// The two routes diverge above the TLS layer, though (#570): `/usage/v1/spend/query`
/// (`handlers::spend::query_spend`) applies no further app-level check -- it is `authz-budget`'s
/// legitimate cross-account service reader and now REFUSES any request carrying an `Authorization`
/// header, since it has no business ever receiving one. `/usage/v1/usage/query`
/// (`handlers::query::query_usage`) is no longer "no auth check of its own": it additionally
/// requires and validates an end-user bearer token via JWKS, then calls `UsageState::
/// scope_authority` to check that the token's subject actually owns the requested `account`/
/// `project` scope (`user`/`api_key` scopes are refused unconditionally, having no resolvable
/// ownership authority at all) -- see `query_usage`'s own doc comment for the full gate.
pub fn query_router() -> Router<Arc<UsageState>> {
    Router::new()
        .route("/usage/v1/usage/query", post(query_usage))
        .route("/usage/v1/spend/query", post(query_spend))
}
