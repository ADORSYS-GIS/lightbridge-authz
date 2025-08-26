use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_api::routers::api_key_router;
use lightbridge_authz_core::{
    config::{Oauth2, Rest},
    db::DbPoolTrait,
    error::Result,
};

mod handlers;
mod middleware;
use handlers::APIKeyHandlerImpl;
use middleware::bearer_auth;

use lightbridge_authz_bearer::BearerTokenService;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

/// Start the REST server.
///
/// This function now takes the `oauth2` configuration so the BearerTokenService can be
/// instantiated using the application's OAuth2 settings (jwks_url etc).
pub async fn start_rest_server(
    rest: &Rest,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
) -> Result<()> {
    let api_key_handler = Arc::new(APIKeyHandlerImpl::with_pool(pool));

    // Instantiate BearerTokenService using oauth2 configuration passed from the caller.
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

    // Build shared application state containing both the API key handler and the bearer service.
    let app_state = Arc::new(lightbridge_authz_api::AppState {
        handler: api_key_handler.clone(),
        bearer: bearer_service.clone(),
    });

    // Build the router. The nested api router uses the shared AppState (router-level state).
    let app = Router::new()
        .route("/", get(root_handler))
        .nest("/api/v1", api_key_router())
        // Attach the shared application state to the top-level router.
        .with_state(app_state.clone())
        // Apply the bearer_auth middleware using the same shared state.
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            bearer_auth,
        ));

    let addr = format!("{}:{}", rest.address, rest.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Starting REST server on {}", addr);
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn root_handler() -> (StatusCode, Json<RootResponse>) {
    let response = RootResponse {
        status: "ok".to_string(),
        message: "Welcome to Lightbridge Authz API".to_string(),
    };
    (StatusCode::OK, Json(response))
}
