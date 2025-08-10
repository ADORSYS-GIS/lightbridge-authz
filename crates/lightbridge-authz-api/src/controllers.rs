use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateApiKey, PatchApiKey};
use tracing::instrument;

/// Handles the creation of a new API key.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `CreateApiKey` payload from the request body. It then calls
/// the `create_api_key` method on the handler to perform the actual creation.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
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
    Extension(token_info): Extension<lightbridge_authz_bearer::TokenInfo>,
    Json(mut input): Json<CreateApiKey>,
) -> Result<impl IntoResponse, Error> {
    // Ensure token contains a subject (user id)
    let user_id = token_info.sub.ok_or_else(|| {
        // Translate into an Unauthorized response for axum via core Error -> IntoResponse
        // Using Any to wrap an anyhow::Error so it becomes 500/UNAUTHORIZED mapping is handled by caller.
        // Instead construct an Io error with simple message to keep Error variants limited.
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Missing sub in token")
    })?;

    // Populate the DTO's user_id so downstream handlers/repos receive it.
    input.user_id = user_id.clone();

    // Call the handler with the updated input.
    let api_key = state.handler.create_api_key(input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}

/// Handles the retrieval of an API key by its key string.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `key` from the request path. It then calls the `get_api_key`
/// method on the handler to retrieve the API key.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(key)` - The API key string extracted from the request path.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the retrieved `ApiKey` on success,
/// or an `Error` if the API key is not found or an issue occurs.
#[instrument]
#[axum::debug_handler]
pub async fn get_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.handler.get_api_key(key).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

/// Handles the update of an existing API key.
///
/// This function extracts the `APIKeyHandler` from the application state,
/// the `key` from the request path, and the `PatchApiKey` payload
/// from the request body. It then calls the `patch_api_key` method on the handler
/// to update the API key.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(key)` - The API key string extracted from the request path.
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
    Path(key): Path<String>,
    Json(input): Json<PatchApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = state.handler.patch_api_key(key, input).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

/// Handles the deletion of an API key by its key string.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `key` from the request path. It then calls the `delete_api_key`
/// method on the handler to delete the API key.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(key)` - The API key string extracted from the request path.
///
/// # Returns
///
/// A `Result` indicating success or failure of the deletion operation.
#[instrument]
#[axum::debug_handler]
pub async fn delete_api_key(
    State(state): State<Arc<crate::AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    state.handler.delete_api_key(key).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Handles the listing of all API keys.
///
/// This function extracts the `APIKeyCrud` handler from the application state.
/// It then calls the `list_api_keys` method on the handler to retrieve all API keys.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyCrud` implementation.
///
/// # Returns
///
/// A `Result` containing a `Json` response with a vector of `ApiKey` on success,
/// or an `Error` if the listing fails.
#[instrument]
#[axum::debug_handler]
pub async fn list_api_keys(
    State(state): State<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, Error> {
    let api_keys = state.handler.list_api_keys().await?;
    Ok((StatusCode::OK, Json(api_keys)))
}
