use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::error::Error;
use tracing::instrument;

/// Handles the deletion of an API key by its key string.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `key` from the request path. It then calls the `delete_api_key`
/// method on the handler to delete the API key.
///
/// # Arguments
///
/// * `State(state)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(key)` - The API key string extracted from the request path.
///
/// # Returns
///
/// A `Result` indicating success or failure of the deletion operation.
#[instrument]
#[axum::debug_handler]
pub async fn delete_api_key(
    State(state): State<Arc<crate::AppState>>,
    Extension(TokenInfo { sub: user_id, .. }): Extension<TokenInfo>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.handler.delete_api_key(user_id, key).await?;
    Ok(StatusCode::NO_CONTENT)
}
