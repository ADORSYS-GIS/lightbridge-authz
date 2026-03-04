use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_core::{
    Result, async_trait,
    config::Database,
    db::{DbPool, DbPoolTrait, is_database_ready},
    server::serve_tls,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod config;
pub mod handlers;
pub mod models;
pub mod repo;
pub mod routers;
pub mod tracing;

pub use config::{UsageConfig, UsageServer, load_from_path};
use models::{UsageQueryRequest, UsageSeriesPoint};
use repo::{StoreRepo, UsageEvent};

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

pub struct UsageState {
    pub repo: Arc<dyn UsageRepoTrait>,
}

#[async_trait]
pub trait UsageRepoTrait: Send + Sync {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize>;
    async fn query_usage(&self, input: &UsageQueryRequest) -> Result<Vec<UsageSeriesPoint>>;
}

#[async_trait]
impl UsageRepoTrait for StoreRepo {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize> {
        StoreRepo::insert_usage_events(self, events).await
    }

    async fn query_usage(&self, input: &UsageQueryRequest) -> Result<Vec<UsageSeriesPoint>> {
        StoreRepo::query_usage(self, input).await
    }
}

pub async fn start_usage_server(usage: &UsageServer, database: &Database) -> Result<()> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(database).await?);
    let readiness_pool = pool.clone();
    let repo: Arc<dyn UsageRepoTrait> = Arc::new(StoreRepo::new(pool));
    let state = Arc::new(UsageState { repo });

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/health/startup", get(startup_handler))
        .route(
            "/health/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        )
        .merge(SwaggerUi::new("/v1/usage/docs").url("/v1/usage/openapi.json", UsageDoc::openapi()))
        .merge(routers::usage_router())
        .with_state(state);

    serve_tls("USAGE", &usage.address, usage.port, &usage.tls, app).await
}

async fn root_handler() -> (StatusCode, Json<RootResponse>) {
    (
        StatusCode::OK,
        Json(RootResponse {
            status: "ok".to_string(),
            message: "Welcome to Lightbridge Authz Usage API".to_string(),
        }),
    )
}

async fn health_handler() -> StatusCode {
    StatusCode::OK
}

async fn startup_handler() -> StatusCode {
    StatusCode::OK
}

async fn readiness_handler(pool: Arc<dyn DbPoolTrait>) -> StatusCode {
    if is_database_ready(pool.as_ref()).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::ingest::ingest_traces,
        crate::handlers::ingest::ingest_metrics,
        crate::handlers::query::query_usage
    ),
    components(
        schemas(
            crate::models::IngestResponse,
            crate::models::UsageErrorResponse,
            crate::models::UsageQueryRequest,
            crate::models::UsageQueryResponse,
            crate::models::UsageQueryFilters,
            crate::models::UsageSeriesPoint,
            crate::models::UsageScope,
            crate::models::UsageGroupBy
        )
    ),
    tags(
        (name = "ingest", description = "OTEL ingest endpoints"),
        (name = "usage", description = "Timeseries usage query endpoint")
    )
)]
struct UsageDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;

    fn usage_openapi() -> Value {
        serde_json::to_value(UsageDoc::openapi()).expect("openapi should serialize")
    }

    #[test]
    fn usage_openapi_should_expose_usage_paths() {
        let doc = usage_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/v1/usage/query"),
            "expected usage query endpoint in openapi paths"
        );
        assert!(
            paths.contains_key("/v1/otel/traces"),
            "expected traces ingest endpoint in openapi paths"
        );
        assert!(
            paths.contains_key("/v1/otel/metrics"),
            "expected metrics ingest endpoint in openapi paths"
        );
    }

    #[test]
    fn usage_openapi_should_be_openapi_3() {
        let doc = usage_openapi();
        let version = doc["openapi"]
            .as_str()
            .expect("openapi version should be a string");
        assert!(
            version.starts_with("3."),
            "expected an OpenAPI 3.x document, got {version}"
        );
    }

    #[tokio::test]
    async fn health_and_startup_endpoints_report_ok() {
        assert_eq!(health_handler().await, StatusCode::OK);
        assert_eq!(startup_handler().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_when_database_is_down() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz_usage")
            .expect("lazy pool should be constructible");
        let pool: Arc<dyn DbPoolTrait> =
            Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool));

        assert_eq!(
            readiness_handler(pool).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
