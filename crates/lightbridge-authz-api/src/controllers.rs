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
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = handler.get_api_key(key).await?;
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
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Path(key): Path<String>,
    Json(input): Json<PatchApiKey>,
) -> Result<impl IntoResponse, Error> {
    let api_key = handler.patch_api_key(key, input).await?;
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
    State(handler): State<Arc<dyn crate::APIKeyService>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    handler.delete_api_key(key).await?;
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

/// Handles the creation of a new API key using the lightbridge-authz-api-key crate.
///
/// This function extracts the `DbPool` from the application state
/// and the `CreateApiKey` payload from the request body. It then calls
/// the `create_api_key` function from the lightbridge-authz-api-key crate
/// to perform the actual creation.
///
/// # Arguments
///
/// * `State(pool)` - The application state containing the `DbPool`.
/// * `Json(input)` - The JSON payload containing the data for the new API key.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the created `ApiKey` on success,
/// or an `Error` if the creation fails.
#[instrument]
#[axum::debug_handler]
pub async fn create_api_key_via_crate(
    State(pool): State<Arc<lightbridge_authz_core::db::DbPool>>,
    Json(input): Json<CreateApiKey>,
) -> Result<impl IntoResponse, Error> {
    // Extract ACL from input or use default
    let acl = input.acl.unwrap_or_default();

    // TODO: Extract user_id from request context
    let user_id = "default_user";

    let api_key = lightbridge_authz_api_key::create_api_key(&pool, user_id, acl).await?;
    Ok((StatusCode::CREATED, Json(api_key)))
}

/// Handles the retrieval of an API key by its key string using the lightbridge-authz-api-key crate.
///
/// This function extracts the `DbPool` from the application state
/// and the `key` from the request path. It then calls the `get_api_key`
/// function from the lightbridge-authz-api-key crate to retrieve the API key.
///
/// # Arguments
///
/// * `State(pool)` - The application state containing the `DbPool`.
/// * `Path(key)` - The API key string extracted from the request path.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the retrieved `ApiKey` on success,
/// or an `Error` if the API key is not found or an issue occurs.
#[instrument]
#[axum::debug_handler]
pub async fn get_api_key_via_crate(
    State(pool): State<Arc<lightbridge_authz_core::db::DbPool>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    let api_key = lightbridge_authz_api_key::get_api_key(&pool, &key)
        .await?
        .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
    Ok((StatusCode::OK, Json(api_key)))
}

/// Handles the update of an existing API key using the lightbridge-authz-api-key crate.
///
/// This function extracts the `DbPool` from the application state,
/// the `key` from the request path, and the `PatchApiKey` payload
/// from the request body. It then calls the `update_api_key` function
/// from the lightbridge-authz-api-key crate to update the API key.
///
/// # Arguments
///
/// * `State(pool)` - The application state containing the `DbPool`.
/// * `Path(key)` - The API key string extracted from the request path.
/// * `Json(input)` - The JSON payload containing the data to patch the API key with.
///
/// # Returns
///
/// A `Result` containing a `Json` response with the updated `ApiKey` on success,
/// or an `Error` if the update fails.
#[instrument]
#[axum::debug_handler]
pub async fn update_api_key_via_crate(
    State(pool): State<Arc<lightbridge_authz_core::db::DbPool>>,
    Path(key): Path<String>,
    Json(input): Json<PatchApiKey>,
) -> Result<impl IntoResponse, Error> {
    // Extract ACL from input or return error if not provided
    let acl = input.acl.ok_or_else(|| {
        use std::io;
        lightbridge_authz_core::error::Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACL is required for updating an API key",
        ))
    })?;

    let api_key = lightbridge_authz_api_key::update_api_key(&pool, &key, acl).await?;
    Ok((StatusCode::OK, Json(api_key)))
}

/// Handles the deletion of an API key by its key string using the lightbridge-authz-api-key crate.
///
/// This function extracts the `DbPool` from the application state
/// and the `key` from the request path. It then calls the `delete_api_key`
/// function from the lightbridge-authz-api-key crate to delete the API key.
///
/// # Arguments
///
/// * `State(pool)` - The application state containing the `DbPool`.
/// * `Path(key)` - The API key string extracted from the request path.
///
/// # Returns
///
/// A `Result` indicating success or failure of the deletion operation.
#[instrument]
#[axum::debug_handler]
pub async fn delete_api_key_via_crate(
    State(pool): State<Arc<lightbridge_authz_core::db::DbPool>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, Error> {
    lightbridge_authz_api_key::delete_api_key(&pool, &key).await?;
    Ok(StatusCode::NO_CONTENT)
}
