use crate::UsageState;
use crate::handlers::ingest::{ingest_logs, ingest_metrics, ingest_traces};
use crate::handlers::query::query_usage;
use crate::handlers::spend::query_spend;
use axum::{Router, routing::post};
use std::sync::Arc;

/// Every route here is unauthenticated -- see `AGENTS.md`'s Security Notes for the documented
/// risk this carries (ClusterIP-only, no ingress, no auth). `spend_router` below is the one
/// exception, gated by Basic auth.
pub fn usage_router() -> Router<Arc<UsageState>> {
    Router::new()
        .route("/v1/otel/traces", post(ingest_traces))
        .route("/v1/otel/metrics", post(ingest_metrics))
        .route("/v1/otel/logs", post(ingest_logs))
        .route("/usage/v1/usage/query", post(query_usage))
}

/// The internal spend-query route, kept separate from `usage_router` so `build_usage_router` can
/// layer Basic-auth middleware onto this route only.
pub fn spend_router() -> Router<Arc<UsageState>> {
    Router::new().route("/usage/v1/spend/query", post(query_spend))
}
