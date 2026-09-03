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
pub mod repo;
pub mod retention;
pub mod routers;
pub mod scope_authority;

pub use config::{RetentionConfig, ScopeAuthorityConfig, UsageConfig, UsageServer, load_from_path};
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
    retention: &RetentionConfig,
) -> Result<()> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(database).await?);

    // Assert deploy sequencing: new schema (migrations 03 and 04) must exist before we serve traffic.
    // Since SQLx handles queries dynamically, failing here prevents obscure runtime errors later.
    let migration_check = sqlx::query("SELECT 1 FROM usage_events_daily LIMIT 1")
        .fetch_optional(pool.pool())
        .await;
    if migration_check.is_err() {
        return Err(Error::Database(
            "usage_events_daily table missing. Ensure migrations 20260903000003 and 04 have run before starting.".to_string(),
        ));
    }

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

    // #549 AC2: the retention/rollup background job. It owns its own `PgPool` clone (the shared
    // pool is behind a `dyn DbPoolTrait`), and runs independently of both listeners -- a retention
    // failure is logged and retried, never fatal.
    tokio::spawn(retention::run_retention_loop(
        Arc::new(pool.pool().clone()),
        retention.clone(),
    ));

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
            paths.contains_key("/usage/v1/usage/query"),
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
        assert!(
            paths.contains_key("/v1/otel/logs"),
            "expected logs ingest endpoint in openapi paths"
        );
        assert!(
            paths.contains_key("/usage/v1/spend/query"),
            "expected spend query endpoint in openapi paths"
        );
    }

    /// Guards the seam between this service and the console. `converse-frontends` hand-maintains
    /// `openapi/usage.backend.yaml` and generates its typed client from it, so a latency field
    /// that silently stops being published here would surface over there as a chart of nothing --
    /// exactly the "permanent apology" state this whole change exists to remove. Asserting the
    /// published schema, not just the Rust struct, is what makes that drift fail here first.
    #[test]
    fn usage_openapi_should_publish_the_latency_percentile_contract() {
        let doc = usage_openapi();
        let point = &doc["components"]["schemas"]["UsageSeriesPoint"]["properties"];

        for field in [
            "latency_samples",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ] {
            assert!(
                point.get(field).is_some(),
                "expected UsageSeriesPoint.{field} in the published schema"
            );
        }

        let required: Vec<&str> = doc["components"]["schemas"]["UsageSeriesPoint"]["required"]
            .as_array()
            .expect("UsageSeriesPoint should declare required fields")
            .iter()
            .filter_map(|value| value.as_str())
            .collect();

        assert!(
            required.contains(&"latency_samples"),
            "latency_samples is always present and must be required, got {required:?}"
        );
    }

    /// The 2026-09-03 query-cost work: `metrics` is the console's lever for skipping the
    /// latency percentiles, so both halves of the contract -- the request field and the response
    /// echo -- are pinned in the published schema. A caller that cannot see the field cannot use
    /// it, and a caller that cannot see the echo cannot tell "no latency samples" from "I did not
    /// ask for percentiles".
    #[test]
    fn usage_openapi_should_publish_the_metrics_selection_contract() {
        let doc = usage_openapi();

        let metrics: Vec<&str> = doc["components"]["schemas"]["UsageMetric"]["enum"]
            .as_array()
            .expect("UsageMetric should publish an enum")
            .iter()
            .map(|v| v.as_str().expect("enum values are strings"))
            .collect();
        assert_eq!(metrics, vec!["totals", "latency_percentiles"]);

        assert!(
            doc["components"]["schemas"]["UsageQueryRequest"]["properties"]["metrics"].is_object(),
            "expected UsageQueryRequest.metrics in the published schema"
        );
        let required: Vec<&str> = doc["components"]["schemas"]["UsageQueryRequest"]["required"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert!(
            !required.contains(&"metrics"),
            "metrics must stay optional -- every caller written before it existed omits it"
        );

        assert!(
            doc["components"]["schemas"]["UsageQueryResponse"]["properties"]["metrics"].is_object(),
            "expected UsageQueryResponse.metrics in the published schema"
        );
    }

    /// #578: pins `UsageQueryResponse.truncated` in the published schema, the same seam
    /// `usage_openapi_should_publish_the_latency_percentile_contract` above guards for the
    /// latency fields -- a client generated from `openapi/usage.backend.yaml` needs this field to
    /// exist and be required to ever render a truncation notice at all.
    #[test]
    fn usage_openapi_should_publish_the_truncated_field() {
        let doc = usage_openapi();
        let response = &doc["components"]["schemas"]["UsageQueryResponse"];

        assert!(
            response["properties"].get("truncated").is_some(),
            "expected UsageQueryResponse.truncated in the published schema"
        );

        let required: Vec<&str> = response["required"]
            .as_array()
            .expect("UsageQueryResponse should declare required fields")
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        assert!(
            required.contains(&"truncated"),
            "truncated is always present and must be required, got {required:?}"
        );
    }

    /// #570: pins the 401/403 responses `/usage/v1/usage/query` now documents (bearer
    /// authentication + ownership check), so a silent regression back to "no auth check
    /// documented" fails here first.
    #[test]
    fn usage_openapi_should_publish_query_endpoint_auth_responses() {
        let doc = usage_openapi();
        let responses = &doc["paths"]["/usage/v1/usage/query"]["post"]["responses"];

        assert!(
            responses.get("401").is_some(),
            "expected /usage/v1/usage/query to document a 401 response"
        );
        assert!(
            responses.get("403").is_some(),
            "expected /usage/v1/usage/query to document a 403 response"
        );
    }

    /// #570: `/usage/v1/spend/query` now refuses a request carrying an `Authorization` header --
    /// pins the 403 response that behavior is documented under.
    #[test]
    fn usage_openapi_should_publish_spend_endpoint_forbidden_response() {
        let doc = usage_openapi();
        let responses = &doc["paths"]["/usage/v1/spend/query"]["post"]["responses"];

        assert!(
            responses.get("403").is_some(),
            "expected /usage/v1/spend/query to document a 403 response"
        );
    }

    /// #648: the same console-facing seam as the latency/truncation guards above, for the three
    /// usage dimensions. `converse-frontends` hand-maintains `openapi/usage.backend.yaml` and
    /// generates its typed client from it, so these enum values ARE the contract -- a rename here
    /// that is not mirrored there turns "cost by channel" into a 400 nobody notices until a
    /// dashboard is blank. Asserting the published document (not just the Rust enum) is what
    /// makes that drift fail on this side first.
    #[test]
    fn usage_openapi_should_publish_the_usage_dimension_contract() {
        let doc = usage_openapi();

        let group_by: Vec<&str> = doc["components"]["schemas"]["UsageGroupBy"]["enum"]
            .as_array()
            .expect("UsageGroupBy should publish an enum")
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        assert_eq!(
            group_by,
            vec![
                "account_id",
                "project_id",
                "api_key_id",
                "user_id",
                "user_name",
                "model",
                "metric_name",
                "signal_type",
                "azp",
                "operation",
                "billing_plan",
            ],
            "UsageGroupBy's published values are the console's client contract"
        );

        let filters = &doc["components"]["schemas"]["UsageQueryFilters"]["properties"];
        for field in ["azp", "operation", "billing_plan", "operation_in"] {
            assert!(
                filters.get(field).is_some(),
                "expected UsageQueryFilters.{field} in the published schema"
            );
        }
        assert_eq!(
            filters["operation_in"]["items"]["type"], "string",
            "operation_in must publish as an array of strings"
        );

        let point = &doc["components"]["schemas"]["UsageSeriesPoint"]["properties"];
        for field in ["azp", "operation", "billing_plan"] {
            assert!(
                point.get(field).is_some(),
                "expected UsageSeriesPoint.{field} in the published schema"
            );
        }
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
