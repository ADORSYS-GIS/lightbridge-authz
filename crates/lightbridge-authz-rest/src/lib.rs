use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_api::routers::api_router;
use lightbridge_authz_core::{
    Account, Project, async_trait,
    config::{ApiServer, BasicAuth, Oauth2, OpaServer, Tls},
    db::DbPoolTrait,
    error::{Error, Result},
};
use std::sync::Once;

pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routers;

use handlers::AuthzStoreImpl;
use middleware::bearer_auth;
use routers::opa_router;

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenService;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
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
    async fn find_api_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKey>>;
    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey>;
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>>;
    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>>;
    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>>;
    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>>;
}

#[async_trait]
impl OpaRepoTrait for StoreRepo {
    async fn find_api_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKey>> {
        StoreRepo::find_api_key_by_hash(self, key_hash).await
    }

    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey> {
        StoreRepo::record_api_key_usage(self, key_id, ip).await
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
}

pub async fn start_api_server(
    api: &ApiServer,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
) -> Result<()> {
    let store = Arc::new(AuthzStoreImpl::with_pool(pool));
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

    let app_state = Arc::new(lightbridge_authz_api::AppState {
        store,
        bearer: bearer_service,
    });

    let public = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .merge(SwaggerUi::new("/api/v1/docs").url(
            "/api/v1/openapi.json",
            lightbridge_authz_api::openapi::ApiDoc::openapi(),
        ));

    let protected = Router::new()
        .nest("/api/v1", api_router())
        .with_state(app_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            bearer_auth,
        ));

    let app = public.merge(protected).with_state(app_state.clone());

    serve_tls("API", &api.address, api.port, &api.tls, app).await
}

pub async fn start_opa_server(opa: &OpaServer, pool: Arc<dyn DbPoolTrait>) -> Result<()> {
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
    });

    let public = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .merge(SwaggerUi::new("/v1/opa/docs").url("/v1/opa/openapi.json", OpaDoc::openapi()));

    let protected = opa_router(state.clone()).with_state(state.clone());

    let app = public.merge(protected).with_state(state.clone());

    serve_tls("OPA", &opa.address, opa.port, &opa.tls, app).await
}

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn serve_tls(name: &str, address: &str, port: u16, tls: &Tls, app: Router) -> Result<()> {
    ensure_rustls_provider();
    let addr: SocketAddr = format!("{}:{}", address, port).parse()?;
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
            .await
            .map_err(|e| Error::Server(format!("Failed to load TLS config for {name}: {e}")))?;
    tracing::info!("Starting {name} server with TLS on {}", addr);
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Server(format!("Failed to start {name} server: {e}")))?;
    Ok(())
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

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::opa::validate_api_key,
        crate::handlers::authorino::validate_authorino_api_key
    ),
    components(
        schemas(
            crate::models::OpaCheckRequest,
            crate::models::OpaCheckResponse,
            crate::models::authorino::AuthorinoCheckRequest,
            crate::models::authorino::AuthorinoCheckResponse,
            crate::models::authorino::AuthorinoMetadata,
            crate::models::OpaErrorResponse,
            lightbridge_authz_core::ApiKey,
            lightbridge_authz_core::Project,
            lightbridge_authz_core::Account
        )
    ),
    tags(
        (name = "opa", description = "OPA validation"),
        (name = "authorino", description = "Authorino integration")
    )
)]
struct OpaDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn opa_openapi() -> Value {
        serde_json::to_value(OpaDoc::openapi()).expect("openapi should serialize")
    }

    #[test]
    fn authorino_endpoint_should_exist_in_opa_openapi() {
        let doc = opa_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/v1/authorino/validate"),
            "expected OPA API to expose an Authorino-specific endpoint"
        );
    }

    #[test]
    fn authorino_request_should_support_dynamic_metadata() {
        let doc = opa_openapi();
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas should be an object");
        let req = schemas
            .get("AuthorinoCheckRequest")
            .expect("missing AuthorinoCheckRequest schema");
        let metadata = &req["properties"]["metadata"];

        assert_eq!(
            metadata["type"].as_str(),
            Some("object"),
            "metadata should be a JSON object for dynamic metadata"
        );
        assert!(
            metadata.get("additionalProperties").is_some(),
            "metadata should support arbitrary keys via additionalProperties"
        );
    }

    #[test]
    fn authorino_success_response_should_include_dynamic_metadata() {
        let doc = opa_openapi();
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas should be an object");

        // Check AuthorinoCheckResponse has dynamic_metadata
        let resp = schemas
            .get("AuthorinoCheckResponse")
            .expect("missing AuthorinoCheckResponse schema");
        let metadata_ref = &resp["properties"]["dynamic_metadata"];

        assert!(
            metadata_ref.get("$ref").is_some() || metadata_ref["type"].as_str() == Some("object"),
            "dynamic_metadata should be a reference or an object"
        );

        // Check AuthorinoMetadata schema
        let metadata_schema = schemas
            .get("AuthorinoMetadata")
            .expect("missing AuthorinoMetadata schema");

        assert_eq!(
            metadata_schema["type"].as_str(),
            Some("object"),
            "AuthorinoMetadata should be a JSON object"
        );

        assert!(
            metadata_schema.get("properties").is_some(),
            "AuthorinoMetadata should have explicit properties"
        );

        assert!(
            metadata_schema.get("additionalProperties").is_some(),
            "AuthorinoMetadata should support arbitrary keys via flattened extra field"
        );
    }
}
