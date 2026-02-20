use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use lightbridge_authz_core::Result;

use crate::OpaState;
use crate::handlers::opa::validate_api_key_context;
use crate::models::OpaErrorResponse;
use crate::models::authorino::{
    AuthorinoCheckRequest, AuthorinoCheckResponse, AuthorinoMetadata,
};

/// Authorino validation handler.
#[utoipa::path(
    post,
    path = "/v1/authorino/validate",
    request_body = AuthorinoCheckRequest,
    responses(
        (status = 200, body = AuthorinoCheckResponse),
        (status = 401, body = OpaErrorResponse)
    ),
    tag = "authorino"
)]
pub async fn validate_authorino_api_key(
    State(state): State<Arc<OpaState>>,
    Json(input): Json<AuthorinoCheckRequest>,
) -> Result<axum::response::Response> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(OpaErrorResponse {
                error: "unauthorized".to_string(),
            }),
        )
            .into_response()
    };

    let Some(validated) = validate_api_key_context(&state, &input.api_key, input.ip).await? else {
        return Ok(unauthorized());
    };

    let dynamic_metadata = AuthorinoMetadata {
        account_id: validated.account.id.clone(),
        project_id: validated.project.id.clone(),
        api_key_id: validated.api_key.id.clone(),
        api_key_status: validated.api_key.status.to_string(),
        extra: input.metadata,
    };

    Ok((
        StatusCode::OK,
        Json(AuthorinoCheckResponse {
            api_key: validated.api_key,
            project: validated.project,
            account: validated.account,
            dynamic_metadata,
        }),
    )
        .into_response())
}
