use std::sync::Arc;

use axum::{Form, Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::Result;
use tracing::instrument;

use crate::OpaState;
use crate::handlers::opa::validate_api_key_context;
use crate::models::{IntrospectRequest, IntrospectResponse};

/// RFC 7662 token introspection for opaque API keys. Authorino's `oauth2Introspection`
/// identity calls this to authenticate a presented key and read its context in one call;
/// a deleted or revoked key returns `{"active": false}` on the next request, since the
/// `api_keys` row is the source of truth.
#[utoipa::path(
    post,
    path = "/v1/authorino/validate/introspect",
    request_body = IntrospectRequest,
    responses(
        (status = 200, body = IntrospectResponse)
    ),
    tag = "authorino"
)]
#[instrument(skip(state, input))]
pub async fn introspect_api_key(
    State(state): State<Arc<OpaState>>,
    Form(input): Form<IntrospectRequest>,
) -> Result<axum::response::Response> {
    let Some(validated) = validate_api_key_context(&state, &input.token, None).await? else {
        tracing::info!(active = false, "api key introspection resolved inactive");
        return Ok((StatusCode::OK, Json(IntrospectResponse::inactive())).into_response());
    };

    tracing::info!(
        active = true,
        api_key_id = %validated.api_key.id,
        account_id = %validated.account.id,
        project_id = %validated.project.id,
        "api key introspection resolved active"
    );

    let plan = state.billing.get(&validated.api_key.billing_plan);
    let response = IntrospectResponse {
        active: true,
        sub: Some(validated.api_key.id.clone()),
        account_id: Some(validated.account.id.clone()),
        project_id: Some(validated.project.id.clone()),
        api_key_id: Some(validated.api_key.id.clone()),
        api_key_status: Some(validated.api_key.status.to_string()),
        billing_plan: Some(validated.api_key.billing_plan.clone()),
        billing_plan_name: plan.map(|p| p.name.clone()),
        billing_plan_limits: plan.and_then(|p| p.limits.clone()),
        allowed_models: validated.project.allowed_models.clone(),
        exp: validated.api_key.expires_at.map(|value| value.timestamp()),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
