use axum::{Router, routing::get};
use lightbridge_authz_api::routers::api_key_router;
use lightbridge_authz_core::{config::Config, db::DbPool, error::Result};

mod handlers;
use handlers::APIKeyHandlerImpl;

use std::sync::Arc;

pub async fn start_rest_server(config: &Config) -> Result<()> {
    let pool = Arc::new(DbPool::new(&config.database.url).await?);
    let api_key_handler = Arc::new(APIKeyHandlerImpl::with_pool(pool));

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .nest("/api/v1", api_key_router(api_key_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
