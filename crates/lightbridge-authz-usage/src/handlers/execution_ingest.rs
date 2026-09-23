//! The execution-grain ingest handler (#588, AC2): receives OTLP trace exports for the agent
//! sources and upserts them into `usage_executions` / `usage_model_calls` / `usage_tool_calls`
//! (plus `usage_identities`).
//!
//! This handler is dispatched to from the OTLP trace ingest paths (`/v1/otel/traces` and
//! `/auth/v1/otel/traces`) when the request's source is an execution-grain source
//! (`claude-code`/`codex`/`opencode`/`microsoft-foundry`). Authentication/source resolution
//! happens in the caller; this handler only decodes, parses the execution-grain contract, and
//! upserts in one transaction.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use lightbridge_authz_core::Result;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;

use crate::{
    UsageState, handlers::ingest::decode_otlp_request_async, models::IngestResponse,
    normalizer::execution_grain::parse_execution_grain,
};

/// Decode an OTLP trace export, parse it into the execution grain, and upsert in one transaction.
pub async fn ingest_execution_grain_traces(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
    source: &'static str,
) -> Result<(StatusCode, Json<IngestResponse>)> {
    let payload =
        decode_otlp_request_async::<ExportTraceServiceRequest>(headers, body, "trace").await?;
    let batch = parse_execution_grain(payload, source)?;
    let accepted = state.repo.upsert_execution_grain(&batch).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            accepted_events: accepted,
        }),
    ))
}
