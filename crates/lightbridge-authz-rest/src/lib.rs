use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_api::routers::api_router;
use lightbridge_authz_core::{
    Account, Project, async_trait,
    config::{ApiServer, BasicAuth, Billing, Oauth2, OpaServer},
    db::{DbPoolTrait, is_database_ready},
    error::{Error, Result},
    server::{dev_cors_enabled, serve_tls},
};
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routers;
pub mod signing;
pub mod token_exchange;

use handlers::AuthzStoreImpl;
use middleware::bearer_auth;
use routers::opa_router;

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenService;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

/// Shared state for the OPA server.
pub struct OpaState {
    pub repo: Arc<dyn OpaRepoTrait>,
    pub basic_auth: BasicAuth,
}

#[async_trait]
pub trait OpaRepoTrait: Send + Sync {
    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey>;
    async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>>;
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>>;
    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>>;
    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>>;
    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>>;
    async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext>;
}

#[async_trait]
impl OpaRepoTrait for StoreRepo {
    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey> {
        StoreRepo::record_api_key_usage(self, key_id, ip).await
    }

    async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>> {
        StoreRepo::find_api_key_validation_by_hash(self, key_hash).await
    }

    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project(self, subject, project_id).await
    }

    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account(self, subject, account_id).await
    }

    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project_by_id(self, project_id).await
    }

    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account_by_id(self, account_id).await
    }

    async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext> {
        StoreRepo::resolve_context(self, subject, project_id).await
    }
}

/// Assembles the API server router (public probes, OIDC discovery/JWKS when signing is
/// enabled, and the bearer-protected CRUD API). Separated from `start_api_server` so the
/// composition can be tested without binding a TLS socket. `dev_cors` (driven by
/// `AUTHZ_DEV_CORS` in `start_api_server`) layers a wide-open CORS policy over the whole
/// router — preflights included — so browser SPAs on other origins can call the API in
/// local dev; never enable it in production.
pub fn build_api_router(
    oauth2: &Oauth2,
    app_state: Arc<lightbridge_authz_api::AppState>,
    readiness_pool: Arc<dyn DbPoolTrait>,
    signing_repo: Arc<StoreRepo>,
    token_exchange: Option<token_exchange::TokenExchangeState>,
    dev_cors: bool,
) -> Router {
    let mut public = Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(health_handler))
        .route("/healthz/startup", get(startup_handler))
        .route(
            "/healthz/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        )
        .merge(SwaggerUi::new("/api/v1/docs").url(
            "/api/v1/openapi.json",
            lightbridge_authz_api::openapi::ApiDoc::openapi(),
        ));

    let token_exchange_enabled = token_exchange.is_some();
    if oauth2.is_self_signed()
        && let Some(signing) = oauth2.signing.as_ref()
    {
        public = public.merge(signing::well_known_router(
            &signing.issuer,
            signing_repo,
            token_exchange_enabled,
        ));
    }

    if let Some(te_state) = token_exchange {
        public = public.merge(token_exchange::token_exchange_router(te_state));
    }

    let protected = Router::new()
        .nest("/api/v1", api_router())
        .with_state(app_state.clone())
        .route_layer(axum::middleware::from_fn(middleware::authorize))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            bearer_auth,
        ));

    let router = public.merge(protected).with_state(app_state);
    if dev_cors {
        router.layer(CorsLayer::permissive())
    } else {
        router
    }
}

/// Builds the native token-exchange state. Enabled only when `token_exchange.enabled` is set, and
/// it REQUIRES `oauth2.type: self` (the exchanged access token is a self-signed JWT). Returns
/// `Ok(None)` when the feature is off; errors on invalid config so startup fails fast.
fn build_token_exchange_state(
    oauth2: &Oauth2,
    repo: Arc<StoreRepo>,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
) -> Result<Option<token_exchange::TokenExchangeState>> {
    let Some(cfg) = oauth2.token_exchange.as_ref().filter(|t| t.enabled) else {
        return Ok(None);
    };
    if !oauth2.is_self_signed() {
        return Err(Error::Server(
            "oauth2.token_exchange is enabled but requires oauth2.type: self".to_string(),
        ));
    }
    let signing = oauth2.signing.as_ref().ok_or_else(|| {
        Error::Server("oauth2.token_exchange requires oauth2.signing (type: self)".to_string())
    })?;
    if cfg.access_ttl_seconds <= 0 || cfg.refresh_ttl_seconds <= 0 {
        return Err(Error::Server(
            "token_exchange access_ttl_seconds and refresh_ttl_seconds must be positive"
                .to_string(),
        ));
    }
    let signer = signing::ApiKeyJwtSigner::from_config(signing, repo.clone())?;
    Ok(Some(token_exchange::TokenExchangeState {
        repo,
        signer,
        bearer,
        cfg: cfg.clone(),
    }))
}

pub async fn start_api_server(
    api: &ApiServer,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
    billing: &Billing,
) -> Result<()> {
    let readiness_pool = pool.clone();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    if oauth2.is_self_signed() {
        let signing = oauth2.signing.as_ref().ok_or_else(|| {
            Error::Server("oauth2.type is 'self' but oauth2.signing is missing".to_string())
        })?;
        signing::bootstrap_signing_key(&signing_repo, signing).await?;
    }
    let store = Arc::new(AuthzStoreImpl::with_pool_and_oauth2(pool, oauth2, billing)?);
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

    let token_exchange_state =
        build_token_exchange_state(oauth2, signing_repo.clone(), bearer_service.clone())?;
    let token_exchange_enabled = token_exchange_state.is_some();

    let app_state = Arc::new(lightbridge_authz_api::AppState {
        store,
        bearer: bearer_service,
    });

    let dev_cors = dev_cors_enabled();
    let app = build_api_router(
        oauth2,
        app_state,
        readiness_pool,
        signing_repo,
        token_exchange_state,
        dev_cors,
    );

    if dev_cors {
        tracing::warn!("AUTHZ_DEV_CORS is set — API server allows any CORS origin (dev only)");
    }
    let signing_enabled = oauth2.is_self_signed();
    let issuance_enabled = oauth2.is_external();
    tracing::info!(
        server = "authz-api",
        address = %api.address,
        port = api.port,
        oauth2_type = ?oauth2.oauth2_type,
        signing_enabled,
        issuance_enabled,
        token_exchange_enabled,
        "starting api server"
    );

    serve_tls("API", &api.address, api.port, &api.tls, app).await
}

/// Assembles the OPA server router (public probes + Basic-auth introspection/resolve routes).
/// Separated from `start_opa_server` for testability.
pub fn build_opa_router(state: Arc<OpaState>, readiness_pool: Arc<dyn DbPoolTrait>) -> Router {
    let public = Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(health_handler))
        .route("/healthz/startup", get(startup_handler))
        .route(
            "/healthz/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        )
        .merge(SwaggerUi::new("/v1/opa/docs").url("/v1/opa/openapi.json", OpaDoc::openapi()));

    let protected = opa_router(state.clone()).with_state(state.clone());

    public.merge(protected).with_state(state)
}

pub async fn start_opa_server(opa: &OpaServer, pool: Arc<dyn DbPoolTrait>) -> Result<()> {
    let readiness_pool = pool.clone();
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
    });

    let app = build_opa_router(state, readiness_pool);

    tracing::info!(
        server = "authz-opa",
        address = %opa.address,
        port = opa.port,
        "starting opa server"
    );

    serve_tls("OPA", &opa.address, opa.port, &opa.tls, app).await
}

async fn root_handler() -> (StatusCode, Json<RootResponse>) {
    let response = RootResponse {
        status: "ok".to_string(),
        message: "Welcome to Lightbridge Authz API".to_string(),
    };
    (StatusCode::OK, Json(response))
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
        crate::handlers::introspect::introspect_api_key,
        crate::handlers::idp::resolve_context
    ),
    components(
        schemas(
            crate::models::IntrospectRequest,
            crate::models::IntrospectResponse,
            lightbridge_authz_core::ApiKey,
            lightbridge_authz_core::Project,
            lightbridge_authz_core::Account,
            lightbridge_authz_core::ResolveContextRequest,
            lightbridge_authz_core::ResolvedContext
        )
    ),
    tags(
        (name = "authorino", description = "Authorino integration"),
        (name = "idp", description = "Identity request resolution")
    )
)]
struct OpaDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;

    fn opa_openapi() -> Value {
        serde_json::to_value(OpaDoc::openapi()).expect("openapi should serialize")
    }

    #[test]
    fn introspect_endpoint_should_exist_in_opa_openapi() {
        let doc = opa_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/v1/authorino/validate/introspect"),
            "expected the OPA server to expose the RFC 7662 introspection endpoint"
        );
        assert!(
            !paths.contains_key("/v1/authorino/validate"),
            "the legacy authorino validate endpoint should no longer be exposed"
        );
        assert!(
            !paths.contains_key("/v1/opa/validate"),
            "the legacy opa validate endpoint should no longer be exposed"
        );
    }

    #[test]
    fn resolve_context_endpoint_should_exist_in_opa_openapi() {
        let doc = opa_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/idp/v1/resolve-context"),
            "expected the OPA server to expose the identity resolve-context endpoint"
        );
    }

    #[test]
    fn introspect_response_should_expose_active_flag() {
        let doc = opa_openapi();
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas should be an object");
        let resp = schemas
            .get("IntrospectResponse")
            .expect("missing IntrospectResponse schema");

        assert!(
            resp["properties"].get("active").is_some(),
            "IntrospectResponse should expose the RFC 7662 `active` flag"
        );
    }

    #[tokio::test]
    async fn health_and_startup_endpoints_report_ok() {
        assert_eq!(health_handler().await, StatusCode::OK);
        assert_eq!(startup_handler().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn root_handler_reports_welcome() {
        let (status, body) = root_handler().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
        assert!(!body.message.is_empty());
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_when_database_is_down() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool: Arc<dyn DbPoolTrait> =
            Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool));

        assert_eq!(
            readiness_handler(pool).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
