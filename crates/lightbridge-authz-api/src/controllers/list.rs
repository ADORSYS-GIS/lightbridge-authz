use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};

use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::error::Error;
use tracing::instrument;

/// Handles the listing of all API keys.
///
/// This function extracts the `APIKeyCrud` handler from the application state.
/// It then calls the `list_api_keys` method on the handler to retrieve all API keys.
///
/// # Arguments
///
/// * `State(state)` - The application state containing the `APIKeyCrud` implementation.
///
/// # Returns
///
/// A `Result` containing a `Json` response with a vector of `ApiKey` on success,
/// or an `Error` if the listing fails.
#[instrument]
#[axum::debug_handler]
pub async fn list_api_keys(
    State(state): State<Arc<crate::AppState>>,
    Extension(TokenInfo { sub: user_id, .. }): Extension<TokenInfo>,
) -> Result<impl IntoResponse, Error> {
    let api_keys = state.handler.list_api_keys(user_id).await?;
    Ok((StatusCode::OK, Json(api_keys)))
}
