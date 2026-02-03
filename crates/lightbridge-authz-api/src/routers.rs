use crate::AppState;
use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, patch, post},
};

use crate::controllers::{
    accounts::{
        create_account, delete_account, get_account, list_accounts, update_account,
    },
    api_keys::{
        create_api_key, delete_api_key, get_api_key, list_api_keys, revoke_api_key, rotate_api_key,
        update_api_key,
    },
    projects::{create_project, delete_project, get_project, list_projects, update_project},
};

/// Creates an Axum router for the CRUD API.
pub fn api_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounts", post(create_account).get(list_accounts))
        .route(
            "/accounts/{account_id}",
            get(get_account).patch(update_account).delete(delete_account),
        )
        .route(
            "/accounts/{account_id}/projects",
            post(create_project).get(list_projects),
        )
        .route(
            "/projects/{project_id}",
            get(get_project).patch(update_project).delete(delete_project),
        )
        .route(
            "/projects/{project_id}/api-keys",
            post(create_api_key).get(list_api_keys),
        )
        .route(
            "/api-keys/{key_id}",
            get(get_api_key)
                .patch(update_api_key)
                .delete(delete_api_key),
        )
        .route("/api-keys/{key_id}/revoke", post(revoke_api_key))
        .route("/api-keys/{key_id}/rotate", post(rotate_api_key))
}
