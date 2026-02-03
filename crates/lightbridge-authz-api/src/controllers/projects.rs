use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_core::{CreateProject, UpdateProject};
use lightbridge_authz_core::error::Error;
use tracing::instrument;

#[instrument]
pub async fn create_project(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
    Json(input): Json<CreateProject>,
) -> Result<impl IntoResponse, Error> {
    let project = state.store.create_project(&account_id, input).await?;
    Ok((StatusCode::CREATED, Json(project)))
}

#[instrument]
pub async fn list_projects(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let projects = state.store.list_projects(&account_id).await?;
    Ok((StatusCode::OK, Json(projects)))
}

#[instrument]
pub async fn get_project(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let project = state.store.get_project(&project_id).await?;
    Ok((StatusCode::OK, Json(project)))
}

#[instrument]
pub async fn update_project(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
    Json(input): Json<UpdateProject>,
) -> Result<impl IntoResponse, Error> {
    let project = state.store.update_project(&project_id, input).await?;
    Ok((StatusCode::OK, Json(project)))
}

#[instrument]
pub async fn delete_project(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.store.delete_project(&project_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
