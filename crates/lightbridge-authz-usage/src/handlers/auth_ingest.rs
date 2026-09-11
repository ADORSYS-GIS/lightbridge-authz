use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use lightbridge_authz_bearer::SERVICE_CALLER_KIND;
use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
    trace::v1::ExportTraceServiceRequest,
};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    UsageState,
    handlers::ingest::{
        decode_otlp_request_async, extract_log_events, extract_metric_events, extract_trace_events,
        persist_events,
    },
    models::IngestResponse,
    repo::UsageEvent,
};

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

/// Authenticates the request using the bearer token, ensures it's a machine token,
/// resolves the `X-Source`, and verifies the token's subject is mapped to that source.
async fn authenticate_and_authorize(
    state: &UsageState,
    headers: &HeaderMap,
) -> std::result::Result<String, Response> {
    // 1. Extract bearer token — RFC 7235 treats the scheme name as case-insensitive,
    //    so lowercase before matching and extract the token from the original string
    //    (same pattern as handlers/query.rs and lightbridge-authz-rest middleware).
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|s| s.to_ascii_lowercase().starts_with("bearer "))
        .map(|s| s["bearer ".len()..].trim());

    let token = match auth_header {
        Some(token) if !token.is_empty() => token,
        _ => return Err(unauthorized()),
    };

    // 2. Validate token
    let token_info = state
        .bearer
        .validate_bearer_token(token)
        .await
        .map_err(|_| unauthorized())?;

    // 3. Check caller_kind
    if token_info.caller_kind.as_deref() != Some(SERVICE_CALLER_KIND) {
        debug!(
            "rejecting token with caller_kind {:?} (expected service)",
            token_info.caller_kind
        );
        return Err(forbidden());
    }

    // 4. Resolve X-Source
    let source = crate::normalizer::resolve_source(headers).map_err(|e| e.into_response())?;

    // 5. Enforce strict principal -> source mapping
    let allowed_source = state.ingest_principals.get(&token_info.sub);
    match allowed_source {
        Some(allowed) if allowed == source => {
            debug!(
                "principal {} authorized for source {}",
                token_info.sub, source
            );
        }
        Some(allowed) => {
            debug!(
                "principal {} is mapped to {}, but asserted source {}",
                token_info.sub, allowed, source
            );
            return Err(forbidden());
        }
        None => {
            debug!(
                "principal {} is not authorized for any source",
                token_info.sub
            );
            return Err(forbidden());
        }
    }

    Ok(source.to_string())
}

fn check_payload_identity_mismatch(events: &[UsageEvent], trusted_source: &str) {
    for event in events {
        if let serde_json::Value::Object(attrs) = &event.attributes {
            for key in ["governance.source", "service.namespace"] {
                if let Some(serde_json::Value::String(val)) = attrs.get(key)
                    && val != trusted_source
                {
                    warn!(
                        "payload source attribute '{}' differs from trusted X-Source '{}'",
                        val, trusted_source
                    );
                    return; // log once per batch
                }
            }
        }
    }
}

pub async fn auth_ingest_traces(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let source = match authenticate_and_authorize(&state, &headers).await {
        Ok(s) => s,
        Err(e) => return e,
    };

    let payload = match decode_otlp_request_async::<ExportTraceServiceRequest>(
        headers, body, "trace",
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let events = extract_trace_events(payload, &source);
    check_payload_identity_mismatch(&events, &source);
    match persist_events(&state, "trace", &events).await {
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

pub async fn auth_ingest_metrics(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let source = match authenticate_and_authorize(&state, &headers).await {
        Ok(s) => s,
        Err(e) => return e,
    };

    let payload =
        match decode_otlp_request_async::<ExportMetricsServiceRequest>(headers, body, "metrics")
            .await
        {
            Ok(p) => p,
            Err(e) => return e.into_response(),
        };

    let events = extract_metric_events(payload, &source);
    check_payload_identity_mismatch(&events, &source);
    match persist_events(&state, "metric", &events).await {
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

pub async fn auth_ingest_logs(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let source = match authenticate_and_authorize(&state, &headers).await {
        Ok(s) => s,
        Err(e) => return e,
    };

    let payload =
        match decode_otlp_request_async::<ExportLogsServiceRequest>(headers, body, "logs").await {
            Ok(p) => p,
            Err(e) => return e.into_response(),
        };

    let events = extract_log_events(payload, &source);
    check_payload_identity_mismatch(&events, &source);
    match persist_events(&state, "log", &events).await {
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
