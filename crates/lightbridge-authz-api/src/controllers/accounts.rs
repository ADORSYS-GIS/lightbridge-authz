use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{Account, CreateAccount, UpdateAccount};
use tracing::instrument;

#[instrument(skip(state))]
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
    Extension(token_info): Extension<TokenInfo>,
    Json(input): Json<CreateAccount>,
) -> Result<impl IntoResponse, Error> {
    let subject = token_info.sub.clone();
    let account = state.store.create_account(&subject, input).await?;
    Ok((StatusCode::CREATED, Json(account)))
}

#[instrument(skip(state))]
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
    Extension(token_info): Extension<TokenInfo>,
) -> Result<impl IntoResponse, Error> {
    let subject = token_info.sub.clone();
    let accounts = state.store.list_accounts(&subject).await?;
    Ok((StatusCode::OK, Json(accounts)))
}

#[instrument(skip(state))]
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
    Extension(token_info): Extension<TokenInfo>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let subject = token_info.sub.clone();
    let account = state.store.get_account(&subject, &account_id).await?;
    Ok((StatusCode::OK, Json(account)))
}

#[instrument(skip(state))]
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
    Extension(token_info): Extension<TokenInfo>,
    Path(account_id): Path<String>,
    Json(input): Json<UpdateAccount>,
) -> Result<impl IntoResponse, Error> {
    let subject = token_info.sub.clone();
    let account = state
        .store
        .update_account(&subject, &account_id, input)
        .await?;
    Ok((StatusCode::OK, Json(account)))
}

#[instrument(skip(state))]
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
    Extension(token_info): Extension<TokenInfo>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let subject = token_info.sub.clone();
    state.store.delete_account(&subject, &account_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
