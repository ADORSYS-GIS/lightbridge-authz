use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_api::routers::api_key_router;
use lightbridge_authz_core::{
    config::{Database, Rest},
    db::DbPool,
    error::Result,
};

mod handlers;
use handlers::APIKeyHandlerImpl;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

pub async fn start_rest_server(rest: &Rest, db: &Database) -> Result<()> {
    let pool = Arc::new(DbPool::new(&db.url).await?);
    let api_key_handler = Arc::new(APIKeyHandlerImpl::with_pool(pool));

    let app = Router::new()
        .route("/", get(root_handler))
        .nest("/api/v1", api_key_router(api_key_handler));

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
