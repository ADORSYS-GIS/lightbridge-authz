//! The authenticated ingest surface (#585): `POST /auth/v1/otel/{traces,metrics,logs}`.
//!
//! Mounted on the same listener as the unauthenticated `/v1/otel/*` routes, and distinct from them
//! by path so the two doors can never be confused for one another. The gateway's legacy path stays
//! as the one documented exception (AC5).
//!
//! ## The binding this surface exists to enforce
//!
//! The stored `source` must come from the *credential*, never from the payload. That binding is
//! built by the gates in [`credential::authenticate_and_authorize`] -- listed in full there --
//! which between them require a validating machine token whose audience names this endpoint, and
//! then require `X-Source` to match the source that token's `sub` is mapped to.
//!
//! ## Shape of this module
//!
//! The three signals are one generic body ([`ingest`]) with three one-line wrappers: the
//! authenticate -> decode -> extract -> persist sequence is identical for traces, metrics and
//! logs, and three near-identical copies meant only the `/logs` route was ever covered by a test.
//! One body means one thing to test, and one thing to review.
//!
//! The payload's own source assertion is cross-checked separately, and *upstream of extraction* --
//! see `handlers::payload_identity` for why it cannot live here any more (#549).

mod credential;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use prost::Message;
use std::sync::Arc;

use crate::{
    UsageState,
    handlers::ingest::{
        decode_otlp_request_async, extract_log_events, extract_metric_events, extract_trace_events,
        persist_events,
    },
    models::IngestResponse,
    repo::UsageEvent,
};

use credential::authenticate_and_authorize;

/// The single body shared by all three authenticated handlers: authorize, decode, extract,
/// persist.
///
/// `decode_signal` names the payload format in decode errors (`trace`/`metrics`/`logs`);
/// `persist_signal` is the stored `signal_type`, which this store writes in the singular
/// (`trace`/`metric`/`log`). They are separate arguments because they genuinely differ -- deriving
/// one from the other by trimming a trailing `s` would be a silent trap the day a signal is named
/// without one.
///
/// `P` is inferred from `extract`, so the three wrappers below name no request type at all.
async fn ingest<P>(
    state: Arc<UsageState>,
    headers: HeaderMap,
    body: Bytes,
    decode_signal: &'static str,
    persist_signal: &'static str,
    extract: fn(P, &str) -> Vec<UsageEvent>,
) -> Response
where
    P: Message + Default + serde::de::DeserializeOwned + Send + 'static,
{
    let source = match authenticate_and_authorize(&state, &headers).await {
        Ok(source) => source,
        Err(refusal) => return (*refusal).into_response(),
    };

    let payload = match decode_otlp_request_async::<P>(headers, body, decode_signal).await {
        Ok(payload) => payload,
        Err(e) => return e.into_response(),
    };

    let events = extract(payload, source);

    match persist_events(&state, persist_signal, &events).await {
        Ok(inserted) => (
            StatusCode::ACCEPTED,
            Json(IngestResponse {
                accepted_events: inserted,
            }),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn auth_ingest_traces(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ingest(state, headers, body, "trace", "trace", extract_trace_events).await
}

pub async fn auth_ingest_metrics(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ingest(
        state,
        headers,
        body,
        "metrics",
        "metric",
        extract_metric_events,
    )
    .await
}

pub async fn auth_ingest_logs(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ingest(state, headers, body, "logs", "log", extract_log_events).await
}
