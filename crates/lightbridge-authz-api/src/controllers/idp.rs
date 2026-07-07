use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateIdentityRequest, IdentityRequest};
use tracing::instrument;

#[instrument(skip(state, token_info))]
#[utoipa::path(
    post,
    path = "/api/v1/idp/requests",
    request_body = CreateIdentityRequest,
    responses(
        (status = 201, body = IdentityRequest)
    ),
    tag = "idp"
)]
pub async fn create_identity_request(
    State(state): State<Arc<crate::AppState>>,
    Extension(token_info): Extension<TokenInfo>,
    Json(input): Json<CreateIdentityRequest>,
) -> Result<impl IntoResponse, Error> {
    let subject = token_info.sub.clone();
    let request = state.store.create_identity_request(&subject, input).await?;
    Ok((StatusCode::CREATED, Json(request)))
}
