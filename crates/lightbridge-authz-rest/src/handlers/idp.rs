use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::Result;
use lightbridge_authz_core::{ResolveContextRequest, ResolvedContext};
use tracing::instrument;

use crate::OpaState;

/// Resolves the tenant context (`account_id`/`project_id`) for an authenticated subject scoped to a
/// project. Membership is enforced: a subject that is not a member of the project's account, or an
/// unknown project, is a uniform 404. Basic-auth protected — the IdP adapter presents the OPA
/// credentials.
#[utoipa::path(
    post,
    path = "/idp/v1/resolve-context",
    request_body = ResolveContextRequest,
    responses(
        (status = 200, body = ResolvedContext),
        (status = 404, description = "Unknown project or subject is not a member")
    ),
    tag = "idp"
)]
#[instrument(skip(state, input))]
pub async fn resolve_context(
    State(state): State<Arc<OpaState>>,
    Json(input): Json<ResolveContextRequest>,
) -> Result<axum::response::Response> {
    let subject = input.subject.unwrap_or_default();
    let project_id = input.project_id.unwrap_or_default();
    let context: ResolvedContext = state.repo.resolve_context(&subject, &project_id).await?;
    tracing::info!(
        subject = %subject,
        project_id = %project_id,
        account_id = %context.account_id,
        "resolved tenant context"
    );
    Ok((StatusCode::OK, Json(context)).into_response())
}
