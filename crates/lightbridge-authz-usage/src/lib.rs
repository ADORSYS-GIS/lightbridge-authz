use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait};
use lightbridge_authz_core::{
    Error, Result,
    build_info::log_build_info,
    config::{Database, Oauth2},
    db::{DbPool, DbPoolTrait, is_database_ready},
    server::{dev_cors_enabled, serve_tls},
};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod aggregate_refresh;
pub mod aggregate_refresh_config;
pub mod aggregate_refresh_lock;
pub mod config;
pub mod handlers;
pub mod instrumentation;
pub mod models;
pub mod normalizer;
pub mod replay;
pub mod replay_types;
pub mod repo;
pub mod retention;
pub mod retention_config;
pub mod retention_loop;
pub mod rollup_sql;
pub mod routers;
pub mod scope_authority;
pub mod spend;
pub mod state;
pub mod verify;

pub use config::{
    AggregateRefreshConfig, RetentionConfig, ScopeAuthorityConfig, UsageConfig, UsageServer,
    load_from_path,
};
use repo::StoreRepo;
use scope_authority::{RemoteScopeAuthority, ScopeAuthority};

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

pub use crate::state::{UsageRepoTrait, UsageState};

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
    let mut app = health_routes(readiness_pool, SERVICE_USAGE_INGEST)
        .merge(
            SwaggerUi::new("/usage/v1/usage/docs")
                .url("/usage/v1/usage/openapi.json", UsageDoc::openapi()),
        )
        .merge(routers::ingest_router());

    // #585: the authenticated surface is mounted only when `ingest_auth` is configured. This is a
    // MOUNT-CONDITIONAL gate, which this repo has been bitten by before -- #473 (`468084a`) left
    // discovery advertising `device_code` while `/device/verify` 404'd, because a route was
    // conditionally mounted and nothing said so (ADR-0023). Three things keep that from
    // recurring here, and all three are deliberate:
    //
    //   1. Nothing advertises /auth/v1/otel/*: it is absent from the OpenAPI document and from
    //      discovery, so there is no document to contradict the router.
    //   2. The decision is DERIVED from `state.ingest_auth`, not passed alongside it, so the mount
    //      and the state the handlers read cannot disagree.
    //   3. Absent means absent. There is no "mounted but permissive" branch -- the alternative
    //      failure mode is a route that exists and admits, which is strictly worse.
    //
    // Why conditional at all, and where it is heading: #585 frames authenticated ingest as a
    // PRErequisite for any non-gateway source going live, and ADR-0028 D8 makes the credential
    // the source of truth for `source`. That argues for eventually making this surface mandatory
    // the way `redis.url` is for authz-api/authz-idp/authz-budget (presence enforced loudly at
    // startup, no silent degradation) rather than optional. It is optional today because the only
    // callers are the out-of-cluster leg-3 sources, and forcing every deployment to configure a
    // machine credential it has no client for would be a worse default than leaving the legacy
    // gateway path as the sole door.
    if state.ingest_auth.is_some() {
        app = app.merge(routers::auth_ingest_router());
    }

    let router = app.with_state(state);

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
// `expect`: the function already carried 7 config args (the clippy ceiling) before #587 added the
// `aggregate_refresh` config, and each arg is a distinct, cohesive config slice the caller already
// holds -- grouping them into a struct would be a churnier refactor than the 8th arg is worth.
#[expect(
    clippy::too_many_arguments,
    reason = "one config slice per background job; 8th arg is the #587 aggregate_refresh block"
)]
pub async fn start_usage_server(
    usage: &UsageServer,
    query: &UsageServer,
    database: &Database,
    oauth2: &Oauth2,
    scope_authority: &ScopeAuthorityConfig,
    ingest_auth: Option<&config::IngestAuthConfig>,
    retention: &RetentionConfig,
    aggregate_refresh: &AggregateRefreshConfig,
) -> Result<()> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(database).await?);

    // Assert deploy sequencing: the rollup schema (migration 20260903000004) must exist before we
    // serve traffic. Since SQLx handles queries dynamically, failing here prevents obscure runtime
    // errors later. The error is propagated (not collapsed to "table missing") so a real failure --
    // pool exhaustion, a connection blip, wrong credentials -- is reported as what it is, per this
    // store's fail-loud migration doctrine.
    sqlx::query("SELECT 1 FROM usage_events_daily LIMIT 1")
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| {
            Error::Database(format!(
                "usage_events_daily precondition check failed (ensure migration 20260903000004 \
                 has run before starting): {e}"
            ))
        })?;

    // The KPI aggregate schema (migration 20260918000001) is NOT a startup precondition: the query
    // endpoints route to the aggregates when they exist and fall back to the raw grain table when
    // absent (see `repo::day_fact_query` / `repo::seat_query`), so a server started before the
    // migration serves correct raw data rather than failing to boot. The aggregate-refresh loop
    // likewise logs and retries if the views are not yet present. This is the documented graceful
    // degradation, not a silent stale-aggregate risk.

    let repo: Arc<dyn UsageRepoTrait> =
        Arc::new(StoreRepo::new(pool.clone()).with_aggregate_staleness(
            // The aggregate routing falls back to raw when the aggregate set is stale (older than
            // this bound). Bound it to two refresh intervals so it tracks the configured cadence:
            // a merely-late refresh does not bounce the query paths back to raw, but a disabled or
            // broken refresh degrades to raw within two intervals instead of serving a stale
            // snapshot forever (the #587 review's P2).
            Duration::from_secs(aggregate_refresh.interval_seconds.saturating_mul(2).max(1)),
        ));
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
        ingest_auth: ingest_auth.cloned(),
        raw_days: retention.enabled.then_some(retention.raw_days),
    });

    // #549 AC2: the retention/rollup background job. It runs on its OWN small dedicated pool, NOT
    // a shallow clone of the shared request pool: the rollup holds a connection for the whole run
    // (a `DELETE ... RETURNING` feeding an `INSERT ... SELECT ... ON CONFLICT`), so sharing the
    // request pool would let a long rollup starve the mTLS query listener's requests for
    // connections. A failure is logged and retried, never fatal.
    tokio::spawn(retention::run_retention_loop(
        Arc::new(build_background_pool(database)?),
        retention.clone(),
    ));

    // #587: the KPI aggregate-refresh background job. Same shape as the retention loop -- its own
    // small dedicated pool (see `build_background_pool`), independent of both listeners, a failure
    // logged and retried, never fatal. Refreshing a materialized view is non-destructive, so this
    // defaults ON (see `AggregateRefreshConfig`).
    tokio::spawn(aggregate_refresh::run_aggregate_refresh_loop(
        Arc::new(build_background_pool(database)?),
        aggregate_refresh.clone(),
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

/// Builds a small, dedicated connection pool for a background job (retention, aggregate-refresh).
///
/// This is deliberately NOT a shallow clone of the shared request pool: a background job holds a
/// connection for the whole run (a rollup, or up to four `REFRESH MATERIALIZED VIEW CONCURRENTLY`
/// statements that can take minutes on the day/seat matviews at scale), so sharing the request
/// pool would let a long job starve the mTLS query listener's requests for connections. A pool of
/// 2 keeps the job from contending with request traffic while still being small. `connect_lazy`
/// defers the actual dial until first use -- the shared pool has already verified connectivity at
/// startup, so a lazy background pool adds no startup ordering dependency.
fn build_background_pool(database: &Database) -> Result<sqlx::PgPool> {
    PgPoolOptions::new()
        .max_connections(2)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect_lazy(&database.url)
        .map_err(|e| Error::Server(format!("failed to build background job pool: {e}")))
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
        crate::handlers::seat::query_seat_snapshots,
        crate::handlers::day_fact::query_day_facts,
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
            crate::models::seat::SeatSnapshotQueryRequest,
            crate::models::seat::SeatSnapshotQueryResponse,
            crate::models::seat::SeatSnapshotQueryFilters,
            crate::models::seat::SeatSnapshotSeriesPoint,
            crate::models::seat::SeatGroupBy,
            crate::models::day_fact::DayFactQueryRequest,
            crate::models::day_fact::DayFactQueryResponse,
            crate::models::day_fact::DayFactQueryFilters,
            crate::models::day_fact::DayFactSeriesPoint,
            crate::models::day_fact::DayFactGroupBy,
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
