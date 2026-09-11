use axum::{Json, Router, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait};
use lightbridge_authz_core::{
    Error, Result, async_trait,
    build_info::log_build_info,
    config::{Database, Oauth2},
    db::{DbPool, DbPoolTrait, is_database_ready},
    server::{dev_cors_enabled, serve_tls},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod config;
pub mod handlers;
pub mod instrumentation;
pub mod models;
pub mod normalizer;
pub mod repo;
pub mod routers;
pub mod scope_authority;

pub use config::{ScopeAuthorityConfig, UsageConfig, UsageServer, load_from_path};
use models::execution::{ExecutionQueryRequest, ExecutionSeriesPoint};
use models::{UsageQueryRequest, UsageSeriesPoint};
use repo::{StoreRepo, UsageEvent};
use scope_authority::{RemoteScopeAuthority, ScopeAuthority};

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

/// Shared between both listeners `start_usage_server` binds (#347): the unauthenticated ingest
/// listener (`UsageServerGroup::usage`) and the mTLS-required query listener
/// (`UsageServerGroup::query`, `/usage/v1/usage/query` + `/usage/v1/spend/query`).
///
/// The ingest listener carries no auth gate of its own beyond the ClusterIP-only mitigation
/// (`AGENTS.md`'s Security Notes) -- it never reads `bearer`/`scope_authority`. The query
/// listener's mTLS requirement is enforced at the TLS layer (`Tls::client_ca_bundle_path`) before
/// any handler here runs, but `/usage/v1/usage/query` additionally requires and validates an
/// end-user bearer token (#570, `handlers::query::query_usage`) -- `bearer`/`scope_authority`
/// below back that check. `/usage/v1/spend/query` (`handlers::spend::query_spend`) stays exempt
/// (mTLS-only, no bearer -- it is `authz-budget`'s legitimate cross-account service reader).
pub struct UsageState {
    pub repo: Arc<dyn UsageRepoTrait>,
    /// Validates the end-user bearer token `/usage/v1/usage/query` requires (#570).
    pub bearer: Arc<dyn BearerTokenServiceTrait>,
    /// Ownership authority for `/usage/v1/usage/query`'s `account`/`project` scopes (#570).
    pub scope_authority: Arc<dyn ScopeAuthority>,
}

#[async_trait]
pub trait UsageRepoTrait: Send + Sync {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize>;
    /// Returns `(points, truncated)` -- see `StoreRepo::query_usage`'s doc comment for the #578
    /// truncation contract `truncated` documents.
    async fn query_usage(&self, input: &UsageQueryRequest)
    -> Result<(Vec<UsageSeriesPoint>, bool)>;
    /// Returns `(points, truncated)` for the execution grain (#726) -- see
    /// `StoreRepo::query_executions`'s doc comment for the #578 truncation contract `truncated`
    /// documents.
    async fn query_executions(
        &self,
        input: &ExecutionQueryRequest,
    ) -> Result<(Vec<ExecutionSeriesPoint>, bool)>;
    async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>>;
}

#[async_trait]
impl UsageRepoTrait for StoreRepo {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize> {
        StoreRepo::insert_usage_events(self, events).await
    }

    async fn query_usage(
        &self,
        input: &UsageQueryRequest,
    ) -> Result<(Vec<UsageSeriesPoint>, bool)> {
        StoreRepo::query_usage(self, input).await
    }

    async fn query_executions(
        &self,
        input: &ExecutionQueryRequest,
    ) -> Result<(Vec<ExecutionSeriesPoint>, bool)> {
        StoreRepo::query_executions(self, input).await
    }

    async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>> {
        StoreRepo::spend_for_account(self, account_id, start, end).await
    }
}

/// Service names reported by `GET /version` and the `service.build` startup log line (#573).
///
/// The usage binary binds TWO listeners on two ports (#347) with different auth postures, so they
/// report as two distinct services: a support engineer asking "which one am I hitting?" gets an
/// answer, rather than one ambiguous `authz-usage` for both.
pub const SERVICE_USAGE_INGEST: &str = "authz-usage";
/// See [`SERVICE_USAGE_INGEST`]. The mTLS-required query listener.
pub const SERVICE_USAGE_QUERY: &str = "authz-usage-query";

/// `GET /version` (#573): the build stamp of the process answering, as JSON.
///
/// Unauthenticated for the same reason `/healthz` is (see `lightbridge-authz-rest`'s
/// `probe_router`): it names the running build and nothing else. On the ingest listener that
/// matters more than elsewhere — that listener has no auth gate at all beyond being ClusterIP-only,
/// and a version string is exactly the kind of non-secret an operator needs from it.
async fn version_handler(service: &'static str) -> Json<lightbridge_authz_core::BuildInfo> {
    Json(lightbridge_authz_core::build_info(service))
}

fn health_routes(
    readiness_pool: Arc<dyn DbPoolTrait>,
    service: &'static str,
) -> Router<Arc<UsageState>> {
    Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(health_handler))
        .route("/healthz/startup", get(startup_handler))
        .route("/version", get(move || version_handler(service)))
        .route(
            "/healthz/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        )
}

/// Assembles the ingest listener's router (public probes, Swagger docs, OTEL ingest only --
/// `/usage/v1/usage/query` and `/usage/v1/spend/query` moved to `build_query_router` below,
/// #347). Separated from `start_usage_server` so the composition can be tested without binding a
/// socket. `dev_cors` (driven by `AUTHZ_DEV_CORS` in `start_usage_server`) layers a wide-open CORS
/// policy over the whole router — preflights included — so browser SPAs on other origins can call
/// the API in local dev; never enable it in production.
pub fn build_ingest_router(
    state: Arc<UsageState>,
    readiness_pool: Arc<dyn DbPoolTrait>,
    dev_cors: bool,
) -> Router {
    let router = health_routes(readiness_pool, SERVICE_USAGE_INGEST)
        .merge(
            SwaggerUi::new("/usage/v1/usage/docs")
                .url("/usage/v1/usage/openapi.json", UsageDoc::openapi()),
        )
        .merge(routers::ingest_router())
        .with_state(state);

    if dev_cors {
        router.layer(CorsLayer::permissive())
    } else {
        router
    }
}

/// Assembles the mTLS-required query listener's router (#347): `/usage/v1/usage/query` +
/// `/usage/v1/spend/query`, plus its own health probes so it can be readiness-checked
/// independently of the ingest listener. No auth middleware here -- the client-certificate
/// requirement is enforced at the TLS layer by `Tls::client_ca_bundle_path`
/// (`UsageServerGroup::query`), before any handler in this router runs.
pub fn build_query_router(
    state: Arc<UsageState>,
    readiness_pool: Arc<dyn DbPoolTrait>,
    dev_cors: bool,
) -> Router {
    let router = health_routes(readiness_pool, SERVICE_USAGE_QUERY)
        .merge(routers::query_router())
        .with_state(state);

    if dev_cors {
        router.layer(CorsLayer::permissive())
    } else {
        router
    }
}

/// Binds both usage-service listeners concurrently (#347): the unauthenticated ingest listener
/// (`usage`) and the mTLS-required query listener (`query`, `/usage/v1/usage/query` +
/// `/usage/v1/spend/query`) -- see `UsageServerGroup`'s doc comment for why these are two ports,
/// not one. Either listener failing to bind/serve fails this function; `tokio::try_join!` runs
/// them concurrently rather than sequentially so one listener's lifetime never blocks the other's.
pub async fn start_usage_server(
    usage: &UsageServer,
    query: &UsageServer,
    database: &Database,
    oauth2: &Oauth2,
    scope_authority: &ScopeAuthorityConfig,
) -> Result<()> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(database).await?);
    let repo: Arc<dyn UsageRepoTrait> = Arc::new(StoreRepo::new(pool.clone()));
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        BearerTokenService::new(oauth2.clone())
            .map_err(|e| Error::Server(format!("failed to build bearer JWKS client: {e}")))?,
    );
    let scope_authority: Arc<dyn ScopeAuthority> =
        Arc::new(RemoteScopeAuthority::new(scope_authority)?);
    let state = Arc::new(UsageState {
        repo,
        bearer,
        scope_authority,
    });

    let dev_cors = dev_cors_enabled();
    if dev_cors {
        warn!("AUTHZ_DEV_CORS is set — usage server allows any CORS origin (dev only)");
    }

    let ingest_app = build_ingest_router(state.clone(), pool.clone(), dev_cors);
    let query_app = build_query_router(state, pool, dev_cors);

    log_build_info(SERVICE_USAGE_INGEST);
    log_build_info(SERVICE_USAGE_QUERY);
    info!(
        "starting usage ingest listener on {}:{}",
        &usage.address, usage.port
    );
    info!(
        "starting usage query listener (mTLS) on {}:{}",
        &query.address, query.port
    );
    let ingest = serve_tls(
        "USAGE-INGEST",
        &usage.address,
        usage.port,
        &usage.tls,
        ingest_app,
    );
    let query = serve_tls(
        "USAGE-QUERY",
        &query.address,
        query.port,
        &query.tls,
        query_app,
    );
    tokio::try_join!(ingest, query)?;
    Ok(())
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
        warn!("database is not ready for usage server");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::ingest::ingest_traces,
        crate::handlers::ingest::ingest_metrics,
        crate::handlers::ingest::ingest_logs,
        crate::handlers::query::query_usage,
        crate::handlers::execution::query_executions,
        crate::handlers::spend::query_spend
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
            crate::models::UsageGroupBy,
            crate::models::UsageMetric,
            crate::models::execution::ExecutionQueryRequest,
            crate::models::execution::ExecutionQueryResponse,
            crate::models::execution::ExecutionQueryFilters,
            crate::models::execution::ExecutionSeriesPoint,
            crate::models::execution::ExecutionGroupBy,
            crate::models::SpendQueryRequest,
            crate::models::SpendQueryResponse
        )
    ),
    tags(
        (name = "ingest", description = "OTEL ingest endpoints (unauthenticated, ClusterIP-only -- see AGENTS.md's Security Notes)"),
        (name = "usage", description = "Timeseries usage query endpoint -- mTLS-required listener (#347) plus an end-user bearer token and ownership check (#570); scope=user is self-ownership-only and scope=all requires the usage:read-all permission, see UsageServerGroup::query"),
        (name = "spend", description = "Internal spend-query endpoint used by the budget domain -- mTLS-required listener (#347), see UsageServerGroup::query")
    )
)]
struct UsageDoc;

/// The generated OpenAPI document, exposed so the contract tests can live in the integration-test
/// tree (`tests/openapi_contract_tests.rs`) rather than inflating this grandfathered file past its
/// LoC-gate ceiling (lightbridge-governance#172).
pub fn usage_openapi_doc() -> utoipa::openapi::OpenApi {
    UsageDoc::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn health_and_startup_endpoints_report_ok() {
        assert_eq!(health_handler().await, StatusCode::OK);
        assert_eq!(startup_handler().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_when_database_is_down() {
        let pool = PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
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
