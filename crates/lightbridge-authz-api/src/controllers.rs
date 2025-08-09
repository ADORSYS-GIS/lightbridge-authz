use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
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
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Json(input): Json<CreateApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = handler.create_api_key(input).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}

/// Handles the retrieval of an API key by its ID.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `api_key_id` from the request path. It then calls the `get_api_key`
/// method on the handler to retrieve the API key.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(api_key_id)` - The API key ID extracted from the request path.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the retrieved `ApiKey` on success,
/// or an `Error` if the API key is not found or an issue occurs.
#[instrument]
#[axum::debug_handler]
pub async fn get_api_key(
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Path(api_key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = handler.get_api_key(api_key_id).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

/// Handles the update of an existing API key.
///
/// This function extracts the `APIKeyHandler` from the application state,
/// the `api_key_id` from the request path, and the `PatchApiKey` payload
/// from the request body. It then calls the `patch_api_key` method on the handler
/// to update the API key.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(api_key_id)` - The API key ID extracted from the request path.
/// * `Json(input)` - The JSON payload containing the data to patch the API key with.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the updated `ApiKey` on success,
/// or an `Error` if the update fails.
#[instrument]
#[axum::debug_handler]
pub async fn patch_api_key(
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Path(api_key_id): Path<String>,
    Json(input): Json<PatchApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = handler.patch_api_key(api_key_id, input).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

/// Handles the deletion of an API key by its ID.
///
/// This function extracts the `APIKeyHandler` from the application state
/// and the `api_key_id` from the request path. It then calls the `delete_api_key`
/// method on the handler to delete the API key.
///
/// # Arguments
///
/// * `State(handler)` - The application state containing the `APIKeyHandler` implementation.
/// * `Path(api_key_id)` - The API key ID extracted from the request path.
///
/// # Returns
///
/// A `Result` indicating success or failure of the deletion operation.
#[instrument]
#[axum::debug_handler]
pub async fn delete_api_key(
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Path(api_key_id): Path<String>,
) -> Result<impl IntoResponse, Error> {
    handler.delete_api_key(api_key_id).await?;
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
    State(handler): State<Arc<dyn crate::APIKeyService>>,
) -> Result<impl IntoResponse, Error> {
    let api_keys = handler.list_api_keys().await?;
    Ok((StatusCode::OK, Json(api_keys)))
}
