use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::Result;
use lightbridge_authz_core::{ResolveContextRequest, ResolvedContext};
use tracing::instrument;

use crate::OpaState;

/// Resolves and consumes a single-use `request_id`, enforcing the bound subject, TTL, and single use.
/// Any failure (unknown / expired / already consumed / subject mismatch) is a uniform 404.
#[utoipa::path(
    post,
    path = "/idp/v1/resolve-context",
    request_body = ResolveContextRequest,
    responses(
        (status = 200, body = ResolvedContext),
        (status = 404, description = "Unknown, expired, consumed, or subject mismatch")
    ),
    tag = "idp"
)]
#[instrument(skip(state, input))]
pub async fn resolve_context(
    State(state): State<Arc<OpaState>>,
    Json(input): Json<ResolveContextRequest>,
) -> Result<axum::response::Response> {
    let request_id = input.request_id.unwrap_or_default();
    let subject = input.subject.unwrap_or_default();
    let context: ResolvedContext = state
        .repo
        .consume_identity_request(&request_id, &subject)
        .await?;
    Ok((StatusCode::OK, Json(context)).into_response())
}
