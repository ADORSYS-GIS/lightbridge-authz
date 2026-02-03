use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_core::{CreateAccount, UpdateAccount};
use lightbridge_authz_core::error::Error;
use tracing::instrument;

#[instrument]
pub async fn create_account(
    State(state): State<Arc<crate::AppState>>,
    Json(input): Json<CreateAccount>,
) -> Result<impl IntoResponse, Error> {
    let account = state.store.create_account(input).await?;
    Ok((StatusCode::CREATED, Json(account)))
}

#[instrument]
pub async fn list_accounts(
    State(state): State<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, Error> {
    let accounts = state.store.list_accounts().await?;
    Ok((StatusCode::OK, Json(accounts)))
}

#[instrument]
pub async fn get_account(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let account = state.store.get_account(&account_id).await?;
    Ok((StatusCode::OK, Json(account)))
}

#[instrument]
pub async fn update_account(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
    Json(input): Json<UpdateAccount>,
) -> Result<impl IntoResponse, Error> {
    let account = state.store.update_account(&account_id, input).await?;
    Ok((StatusCode::OK, Json(account)))
}

#[instrument]
pub async fn delete_account(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.store.delete_account(&account_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
