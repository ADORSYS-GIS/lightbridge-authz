use crate::UsageState;
use crate::handlers::ingest::{ingest_metrics, ingest_traces};
use crate::handlers::query::query_usage;
use axum::{Router, routing::post};
use std::sync::Arc;

pub fn usage_router() -> Router<Arc<UsageState>> {
    Router::new()
        .route("/v1/otel/traces", post(ingest_traces))
        .route("/v1/otel/metrics", post(ingest_metrics))
        .route("/usage/v1/usage/query", post(query_usage))
}
