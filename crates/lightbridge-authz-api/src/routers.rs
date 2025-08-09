use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    APIKeyService,
    controllers::{create_api_key, delete_api_key, get_api_key, list_api_keys, patch_api_key},
};

use crate::controllers::{
    create_api_key_via_crate, delete_api_key_via_crate, get_api_key_via_crate,
    update_api_key_via_crate,
};
use lightbridge_authz_core::db::DbPool;

/// Creates an Axum router for API key management.
///
/// This function sets up the routes for creating, retrieving, updating,
/// deleting, and listing API keys. It takes an `Arc` to an object that
/// implements both `APIKeyHandler` and `APIKeyCrud` traits, allowing
/// for flexible dependency injection.
///
/// # Arguments
///
/// * `handler` - An `Arc` to an object implementing `APIKeyHandler` and `APIKeyCrud`.
///
/// # Returns
///
/// An `Axum` `Router` configured with the API key routes.
pub fn api_key_router(handler: Arc<dyn APIKeyService>) -> Router {
    Router::new()
        .route("/api-keys", post(create_api_key).get(list_api_keys))
        .route(
            "/api-keys/:key",
            get(get_api_key).put(patch_api_key).delete(delete_api_key),
        )
        .with_state(handler)
}

/// Creates an Axum router for API key management using the lightbridge-authz-api-key crate.
///
/// This function sets up the routes for creating, retrieving, updating,
/// and deleting API keys using functions from the lightbridge-authz-api-key crate.
/// It takes a `DbPool` for database operations.
///
/// # Arguments
///
/// * `pool` - A `DbPool` for database operations.
///
/// # Returns
///
/// An `Axum` `Router` configured with the API key routes.
pub fn api_key_router_via_crate(pool: Arc<DbPool>) -> Router {
    Router::new()
        .route("/api-keys", post(create_api_key_via_crate))
        .route(
            "/api-keys/:key",
            get(get_api_key_via_crate)
                .put(update_api_key_via_crate)
                .delete(delete_api_key_via_crate),
        )
        .with_state(pool)
}
