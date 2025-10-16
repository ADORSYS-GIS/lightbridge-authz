use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};

use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::CreateApiKey;
use lightbridge_authz_core::error::Error;
use tracing::instrument;

/// Handles the creation of a new API key.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `CreateApiKey` payload from the request body. It then calls
/// the `create_api_key` method on the handler to perform the actual creation.
///
/// # Arguments
///
/// * `State(state)` - The application state containing the `APIKeyHandler` implementation.
/// * `Json(input)` - The JSON payload containing the data for the new API key.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the created `ApiKey` on success,
/// or an `Error` if the creation fails.
#[instrument]
#[axum::debug_handler]
pub async fn create_api_key(
    State(state): State<Arc<crate::AppState>>,
    Extension(TokenInfo { sub: user_id, .. }): Extension<TokenInfo>,
    Json(input): Json<CreateApiKey>,
) -> Result<impl IntoResponse, Error> {
    // Call the handler with the updated input.
    let api_key = state.handler.create_api_key(user_id, input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}
