use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_core::{Account, CreateAccount, UpdateAccount};
use lightbridge_authz_core::error::Error;
use tracing::instrument;

#[instrument]
#[utoipa::path(
    post,
    path = "/api/v1/accounts",
    request_body = CreateAccount,
    responses(
        (status = 201, body = Account)
    ),
    tag = "accounts"
)]
pub async fn create_account(
    State(state): State<Arc<crate::AppState>>,
    Json(input): Json<CreateAccount>,
) -> Result<impl IntoResponse, Error> {
    let account = state.store.create_account(input).await?;
    Ok((StatusCode::CREATED, Json(account)))
}

#[instrument]
#[utoipa::path(
    get,
    path = "/api/v1/accounts",
    responses(
        (status = 200, body = Vec<Account>)
    ),
    tag = "accounts"
)]
pub async fn list_accounts(
    State(state): State<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, Error> {
    let accounts = state.store.list_accounts().await?;
    Ok((StatusCode::OK, Json(accounts)))
}

#[instrument]
#[utoipa::path(
    get,
    path = "/api/v1/accounts/{account_id}",
    params(
        ("account_id" = String, Path, description = "Account ID")
    ),
    responses(
        (status = 200, body = Account)
    ),
    tag = "accounts"
)]
pub async fn get_account(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let account = state.store.get_account(&account_id).await?;
    Ok((StatusCode::OK, Json(account)))
}

#[instrument]
#[utoipa::path(
    patch,
    path = "/api/v1/accounts/{account_id}",
    request_body = UpdateAccount,
    params(
        ("account_id" = String, Path, description = "Account ID")
    ),
    responses(
        (status = 200, body = Account)
    ),
    tag = "accounts"
)]
pub async fn update_account(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
    Json(input): Json<UpdateAccount>,
) -> Result<impl IntoResponse, Error> {
    let account = state.store.update_account(&account_id, input).await?;
    Ok((StatusCode::OK, Json(account)))
}

#[instrument]
#[utoipa::path(
    delete,
    path = "/api/v1/accounts/{account_id}",
    params(
        ("account_id" = String, Path, description = "Account ID")
    ),
    responses(
        (status = 204, description = "No Content")
    ),
    tag = "accounts"
)]
pub async fn delete_account(
    State(state): State<Arc<crate::AppState>>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.store.delete_account(&account_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
