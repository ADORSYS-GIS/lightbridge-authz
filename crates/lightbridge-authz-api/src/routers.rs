use crate::AppState;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::controllers::{
    create::create_api_key, delete::delete_api_key, get::get_api_key, list::list_api_keys,
    patch::patch_api_key,
};

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
pub fn api_key_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api-keys", post(create_api_key).get(list_api_keys))
        .route(
            "/api-keys/{key}",
            get(get_api_key).put(patch_api_key).delete(delete_api_key),
        )
}
