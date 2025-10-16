use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::error::Error;
use tracing::instrument;

/// Handles the retrieval of an API key by its ID.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `key` (API key ID) from the request path. It then calls the
/// `get_api_key` method on the handler to retrieve the API key.
///
/// # Arguments
///
/// * `State(state)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(key)` - The API key ID extracted from the request path.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the retrieved `ApiKey` on success,
/// or an `Error` if the API key is not found or an issue occurs.
#[instrument]
#[axum::debug_handler]
pub async fn get_api_key(
    State(state): State<Arc<crate::AppState>>,
    Extension(TokenInfo { sub: user_id, .. }): Extension<TokenInfo>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.handler.get_api_key(user_id, key).await?;
    Ok((StatusCode::OK, Json(api_key)))
}
