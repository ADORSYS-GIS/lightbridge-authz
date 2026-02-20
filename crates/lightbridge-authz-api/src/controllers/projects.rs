use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateProject, Project, UpdateProject};
use tracing::instrument;

#[instrument(skip(state))]
#[utoipa::path(
    post,
    path = "/api/v1/accounts/{account_id}/projects",
    request_body = CreateProject,
    params(
        ("account_id" = String, Path, description = "Account ID")
    ),
    responses(
        (status = 201, body = Project)
    ),
    tag = "projects"
)]
pub async fn create_project(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
    Json(input): Json<CreateProject>,
) -> Result<impl IntoResponse, Error> {
    let project = state.store.create_project(&account_id, input).await?;
    Ok((StatusCode::CREATED, Json(project)))
}

#[instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/api/v1/accounts/{account_id}/projects",
    params(
        ("account_id" = String, Path, description = "Account ID")
    ),
    responses(
        (status = 200, body = Vec<Project>)
    ),
    tag = "projects"
)]
pub async fn list_projects(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let projects = state.store.list_projects(&account_id).await?;
    Ok((StatusCode::OK, Json(projects)))
}

#[instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/api/v1/projects/{project_id}",
    params(
        ("project_id" = String, Path, description = "Project ID")
    ),
    responses(
        (status = 200, body = Project)
    ),
    tag = "projects"
)]
pub async fn get_project(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let project = state.store.get_project(&project_id).await?;
    Ok((StatusCode::OK, Json(project)))
}

#[instrument(skip(state))]
#[utoipa::path(
    patch,
    path = "/api/v1/projects/{project_id}",
    request_body = UpdateProject,
    params(
        ("project_id" = String, Path, description = "Project ID")
    ),
    responses(
        (status = 200, body = Project)
    ),
    tag = "projects"
)]
pub async fn update_project(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
    Json(input): Json<UpdateProject>,
) -> Result<impl IntoResponse, Error> {
    let project = state.store.update_project(&project_id, input).await?;
    Ok((StatusCode::OK, Json(project)))
}

#[instrument(skip(state))]
#[utoipa::path(
    delete,
    path = "/api/v1/projects/{project_id}",
    params(
        ("project_id" = String, Path, description = "Project ID")
    ),
    responses(
        (status = 204, description = "No Content")
    ),
    tag = "projects"
)]
pub async fn delete_project(
    State(state): State<Arc<crate::AppState>>,
    Path(project_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.store.delete_project(&project_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
