use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_core::{CreateApiKey, RotateApiKey, UpdateApiKey};
use lightbridge_authz_core::error::Error;
use tracing::instrument;

#[instrument]
pub async fn create_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
    Json(input): Json<CreateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.create_api_key(&project_id, input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}

#[instrument]
pub async fn list_api_keys(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_keys = state.store.list_api_keys(&project_id).await?;
    Ok((StatusCode::OK, Json(api_keys)))
}

#[instrument]
pub async fn get_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.get_api_key(&key_id).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

#[instrument]
pub async fn update_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
    Json(input): Json<UpdateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.update_api_key(&key_id, input).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

#[instrument]
pub async fn delete_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.store.delete_api_key(&key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[instrument]
pub async fn revoke_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.revoke_api_key(&key_id).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

#[instrument]
pub async fn rotate_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key_id): Path<String>,
    Json(input): Json<RotateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.store.rotate_api_key(&key_id, input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}
