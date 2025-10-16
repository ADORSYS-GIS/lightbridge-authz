use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::PatchApiKey;
use lightbridge_authz_core::error::Error;
use tracing::instrument;

/// Handles the update of an existing API key.
///
/// This function extracts the `APIKeyHandler` from the application state,
/// the `key` (API key ID) from the request path, and the `PatchApiKey` payload
/// from the request body. It then calls the `patch_api_key` method on the handler
/// to update the API key.
///
/// # Arguments
///
/// * `State(state)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(key)` - The API key ID extracted from the request path.
/// * `Json(input)` - The JSON payload containing the data to patch the API key with.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the updated `ApiKey` on success,
/// or an `Error` if the update fails.
#[instrument]
#[axum::debug_handler]
pub async fn patch_api_key(
    State(state): State<Arc<crate::AppState>>,
    Extension(TokenInfo { sub: user_id, .. }): Extension<TokenInfo>,
    Path(key): Path<String>,
    Json(input): Json<PatchApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.handler.patch_api_key(user_id, key, input).await?;
    Ok((StatusCode::OK, Json(api_key)))
}
