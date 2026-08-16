use crate::UsageState;
use crate::handlers::ingest::{ingest_logs, ingest_metrics, ingest_traces};
use crate::handlers::query::query_usage;
use crate::handlers::spend::query_spend;
use axum::{Router, routing::post};
use std::sync::Arc;

/// Every route here is unauthenticated -- see `AGENTS.md`'s Security Notes for the documented
/// risk this carries (ClusterIP-only, no ingress, no auth). `spend_router` below carries the same
/// risk -- see its own doc comment.
pub fn usage_router() -> Router<Arc<UsageState>> {
    Router::new()
        .route("/v1/otel/traces", post(ingest_traces))
        .route("/v1/otel/metrics", post(ingest_metrics))
        .route("/v1/otel/logs", post(ingest_logs))
        .route("/usage/v1/usage/query", post(query_usage))
}

/// The internal spend-query route, kept as its own function so its risk is documented in one
/// place. Deliberately unauthenticated -- no Basic auth, no mTLS yet. Safe only under the same
/// condition that already makes `usage_router`'s routes acceptable: this service is ClusterIP-only
/// with no ingress. If that ever changes, both this route and `/usage/v1/usage/query` leak
/// per-account spend/usage figures to anything that can reach the service. mTLS between the api/
/// budget domain and this service is tracked as a follow-up, not implemented here.
pub fn spend_router() -> Router<Arc<UsageState>> {
    Router::new().route("/usage/v1/spend/query", post(query_spend))
}
