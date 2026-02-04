use axum::{Json, Router, http::StatusCode, routing::get, response::IntoResponse};
use lightbridge_authz_api::routers::api_router;
use lightbridge_authz_core::{
    config::{ApiServer, BasicAuth, Oauth2, OpaServer, Tls},
    db::DbPoolTrait,
    error::{Error, Result},
    hash_api_key,
    ApiKeyStatus,
};
use std::sync::Once;

pub mod handlers;
mod middleware;
use handlers::AuthzStoreImpl;
use middleware::{basic_auth, bearer_auth};

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenService;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

/// Shared state for the OPA server.
pub struct OpaState {
    pub repo: Arc<StoreRepo>,
    pub basic_auth: BasicAuth,
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
        .route("/health", get(health_handler));

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

pub async fn start_opa_server(
    opa: &OpaServer,
    pool: Arc<dyn DbPoolTrait>,
) -> Result<()> {
    let repo = Arc::new(StoreRepo::new(pool));
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
    });

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/v1/opa/validate", axum::routing::post(validate_api_key))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(state, basic_auth));

    serve_tls("OPA", &opa.address, opa.port, &opa.tls, app).await
}

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn serve_tls(
    name: &str,
    address: &str,
    port: u16,
    tls: &Tls,
    app: Router,
) -> Result<()> {
    ensure_rustls_provider();
    let addr: SocketAddr = format!("{}:{}", address, port).parse()?;
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &tls.cert_path,
        &tls.key_path,
    )
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

#[derive(Debug, Deserialize)]
struct OpaCheckRequest {
    api_key: String,
    ip: Option<String>,
    region: Option<String>,
}

#[derive(Debug, Serialize)]
struct OpaCheckResponse {
    api_key: lightbridge_authz_core::ApiKey,
    project: lightbridge_authz_core::Project,
    account: lightbridge_authz_core::Account,
}

#[derive(Debug, Serialize)]
struct OpaErrorResponse {
    error: String,
}

async fn validate_api_key(
    axum::extract::State(state): axum::extract::State<Arc<OpaState>>,
    Json(input): Json<OpaCheckRequest>,
) -> Result<axum::response::Response> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(OpaErrorResponse {
                error: "unauthorized".to_string(),
            }),
        )
            .into_response()
    };

    let key_hash = hash_api_key(&input.api_key);
    let Some(api_key) = state.repo.find_api_key_by_hash(&key_hash).await? else {
        return Ok(unauthorized());
    };

    let now = chrono::Utc::now();
    if api_key.status != ApiKeyStatus::Active {
        return Ok(unauthorized());
    }
    if let Some(expires_at) = api_key.expires_at {
        if expires_at <= now {
            return Ok(unauthorized());
        }
    }

    let api_key = state
        .repo
        .record_api_key_usage(&api_key.id, input.ip, input.region)
        .await?;

    let project = state
        .repo
        .get_project(&api_key.project_id)
        .await?
        .ok_or_else(|| Error::NotFound)?;

    let account = state
        .repo
        .get_account(&project.account_id)
        .await?
        .ok_or_else(|| Error::NotFound)?;

    Ok((
        StatusCode::OK,
        Json(OpaCheckResponse {
            api_key,
            project,
            account,
        }),
    )
        .into_response())
}
