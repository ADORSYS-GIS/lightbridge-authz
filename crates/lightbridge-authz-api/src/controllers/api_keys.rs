use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_core::{
    ApiKey,
    ApiKeySecret,
    CreateApiKey,
    RotateApiKey,
    UpdateApiKey,
};
use lightbridge_authz_core::error::Error;
use tracing::instrument;

#[instrument]
#[utoipa::path(
    post,
    path = "/api/v1/projects/{project_id}/api-keys",
    request_body = CreateApiKey,
    params(
        ("project_id" = String, Path, description = "Project ID")
    ),
    responses(
        (status = 201, body = ApiKeySecret)
    ),
    tag = "api_keys"
)]
pub async fn create_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
    Json(input): Json<CreateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.create_api_key(&project_id, input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}

#[instrument]
#[utoipa::path(
    get,
    path = "/api/v1/projects/{project_id}/api-keys",
    params(
        ("project_id" = String, Path, description = "Project ID")
    ),
    responses(
        (status = 200, body = Vec<ApiKey>)
    ),
    tag = "api_keys"
)]
pub async fn list_api_keys(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_keys = state.store.list_api_keys(&project_id).await?;
    Ok((StatusCode::OK, Json(api_keys)))
}

#[instrument]
#[utoipa::path(
    get,
    path = "/api/v1/api-keys/{key_id}",
    params(
        ("key_id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 200, body = ApiKey)
    ),
    tag = "api_keys"
)]
pub async fn get_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.get_api_key(&key_id).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

#[instrument]
#[utoipa::path(
    patch,
    path = "/api/v1/api-keys/{key_id}",
    request_body = UpdateApiKey,
    params(
        ("key_id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 200, body = ApiKey)
    ),
    tag = "api_keys"
)]
pub async fn update_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
    Json(input): Json<UpdateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.update_api_key(&key_id, input).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

#[instrument]
#[utoipa::path(
    delete,
    path = "/api/v1/api-keys/{key_id}",
    params(
        ("key_id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 204, description = "No Content")
    ),
    tag = "api_keys"
)]
pub async fn delete_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.store.delete_api_key(&key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[instrument]
#[utoipa::path(
    post,
    path = "/api/v1/api-keys/{key_id}/revoke",
    params(
        ("key_id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 200, body = ApiKey)
    ),
    tag = "api_keys"
)]
pub async fn revoke_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.revoke_api_key(&key_id).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

#[instrument]
#[utoipa::path(
    post,
    path = "/api/v1/api-keys/{key_id}/rotate",
    request_body = RotateApiKey,
    params(
        ("key_id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 201, body = ApiKeySecret)
    ),
    tag = "api_keys"
)]
pub async fn rotate_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
    Json(input): Json<RotateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.rotate_api_key(&key_id, input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}
