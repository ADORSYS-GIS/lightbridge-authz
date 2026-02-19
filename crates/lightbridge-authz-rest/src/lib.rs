use axum::{Json, Router, http::StatusCode, routing::get, response::IntoResponse};
use lightbridge_authz_api::routers::api_router;
use lightbridge_authz_core::{
    async_trait,
    config::{ApiServer, BasicAuth, Oauth2, OpaServer, Tls},
    db::DbPoolTrait,
    error::{Error, Result},
    hash_api_key,
    Account,
    ApiKeyStatus,
    Project,
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
    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<lightbridge_authz_core::ApiKey>>;
    async fn record_api_key_usage(&self, key_id: &str, ip: Option<String>) -> Result<lightbridge_authz_core::ApiKey>;
    async fn get_project(&self, project_id: &str) -> Result<Option<Project>>;
    async fn get_account(&self, account_id: &str) -> Result<Option<Account>>;
}

#[async_trait]
impl OpaRepoTrait for StoreRepo {
    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<lightbridge_authz_core::ApiKey>> {
        StoreRepo::find_api_key_by_hash(self, key_hash).await
    }

    async fn record_api_key_usage(&self, key_id: &str, ip: Option<String>) -> Result<lightbridge_authz_core::ApiKey> {
        StoreRepo::record_api_key_usage(self, key_id, ip).await
    }

    async fn get_project(&self, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project(self, project_id).await
    }

    async fn get_account(&self, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account(self, account_id).await
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
        .merge(
            SwaggerUi::new("/api/v1/docs")
                .url("/api/v1/openapi.json", lightbridge_authz_api::openapi::ApiDoc::openapi()),
        );

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
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
    });

    let public = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .merge(
            SwaggerUi::new("/v1/opa/docs")
                .url("/v1/opa/openapi.json", OpaDoc::openapi()),
        );

    let protected = Router::new()
        .route("/v1/opa/validate", axum::routing::post(validate_api_key))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            basic_auth,
        ));

    let app = public.merge(protected).with_state(state.clone());

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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct OpaCheckRequest {
    api_key: String,
    ip: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct OpaCheckResponse {
    api_key: lightbridge_authz_core::ApiKey,
    project: lightbridge_authz_core::Project,
    account: lightbridge_authz_core::Account,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct OpaErrorResponse {
    error: String,
}

#[derive(OpenApi)]
#[openapi(
    paths(validate_api_key),
    components(
        schemas(
            OpaCheckRequest,
            OpaCheckResponse,
            OpaErrorResponse,
            lightbridge_authz_core::ApiKey,
            lightbridge_authz_core::Project,
            lightbridge_authz_core::Account
        )
    ),
    tags(
        (name = "opa", description = "OPA validation")
    )
)]
struct OpaDoc;

#[utoipa::path(
    post,
    path = "/v1/opa/validate",
    request_body = OpaCheckRequest,
    responses(
        (status = 200, body = OpaCheckResponse),
        (status = 401, body = OpaErrorResponse)
    ),
    tag = "opa"
)]
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
        .record_api_key_usage(&api_key.id, input.ip)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chrono::{Duration, Utc};
    use lightbridge_authz_core::{ApiKey, ApiKeyStatus};
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use utoipa::OpenApi;

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
        let resp = schemas
            .get("AuthorinoCheckResponse")
            .expect("missing AuthorinoCheckResponse schema");
        let metadata = &resp["properties"]["dynamic_metadata"];

        assert_eq!(
            metadata["type"].as_str(),
            Some("object"),
            "dynamic_metadata should be a JSON object"
        );
        assert!(
            metadata.get("additionalProperties").is_some(),
            "dynamic_metadata should support arbitrary keys for Authorino output"
        );
    }

    #[derive(Debug)]
    struct MockOpaRepo {
        api_key: Option<ApiKey>,
        project: Option<Project>,
        account: Option<Account>,
        usage_calls: Arc<Mutex<Vec<(String, Option<String>)>>>,
    }

    #[async_trait]
    impl OpaRepoTrait for MockOpaRepo {
        async fn find_api_key_by_hash(&self, _key_hash: &str) -> Result<Option<ApiKey>> {
            Ok(self.api_key.clone())
        }

        async fn record_api_key_usage(&self, key_id: &str, ip: Option<String>) -> Result<ApiKey> {
            self.usage_calls
                .lock()
                .expect("lock should work")
                .push((key_id.to_string(), ip));
            Ok(self.api_key.clone().expect("api key should exist in mock"))
        }

        async fn get_project(&self, _project_id: &str) -> Result<Option<Project>> {
            Ok(self.project.clone())
        }

        async fn get_account(&self, _account_id: &str) -> Result<Option<Account>> {
            Ok(self.account.clone())
        }
    }

    fn mk_api_key(status: ApiKeyStatus, expires_at: Option<chrono::DateTime<Utc>>) -> ApiKey {
        ApiKey {
            id: "key_1".to_string(),
            project_id: "proj_1".to_string(),
            name: "demo".to_string(),
            key_prefix: "lbk_demo".to_string(),
            key_hash: "hash".to_string(),
            created_at: Utc::now(),
            expires_at,
            status,
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        }
    }

    fn mk_project() -> Project {
        Project {
            id: "proj_1".to_string(),
            account_id: "acct_1".to_string(),
            name: "demo-project".to_string(),
            allowed_models: vec![],
            default_limits: serde_json::json!({}),
            billing_plan: "free".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn mk_account() -> Account {
        Account {
            id: "acct_1".to_string(),
            billing_identity: "acme".to_string(),
            owners_admins: vec!["owner@example.com".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn mk_state(repo: MockOpaRepo) -> Arc<OpaState> {
        Arc::new(OpaState {
            repo: Arc::new(repo),
            basic_auth: BasicAuth {
                username: "authorino".to_string(),
                password: "change-me".to_string(),
            },
        })
    }

    #[tokio::test]
    async fn validate_api_key_returns_unauthorized_when_missing() {
        let state = mk_state(MockOpaRepo {
            api_key: None,
            project: Some(mk_project()),
            account: Some(mk_account()),
            usage_calls: Arc::new(Mutex::new(vec![])),
        });

        let response = validate_api_key(
            axum::extract::State(state),
            Json(OpaCheckRequest {
                api_key: "lbk_secret_missing".to_string(),
                ip: Some("203.0.113.10".to_string()),
            }),
        )
        .await
        .expect("handler should return response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_api_key_returns_unauthorized_when_revoked() {
        let repo = MockOpaRepo {
            api_key: Some(mk_api_key(ApiKeyStatus::Revoked, None)),
            project: Some(mk_project()),
            account: Some(mk_account()),
            usage_calls: Arc::new(Mutex::new(vec![])),
        };
        let state = mk_state(repo);

        let response = validate_api_key(
            axum::extract::State(state),
            Json(OpaCheckRequest {
                api_key: "lbk_secret_revoked".to_string(),
                ip: None,
            }),
        )
        .await
        .expect("handler should return response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_api_key_returns_unauthorized_when_expired() {
        let expired_at = Utc::now() - Duration::seconds(1);
        let state = mk_state(MockOpaRepo {
            api_key: Some(mk_api_key(ApiKeyStatus::Active, Some(expired_at))),
            project: Some(mk_project()),
            account: Some(mk_account()),
            usage_calls: Arc::new(Mutex::new(vec![])),
        });

        let response = validate_api_key(
            axum::extract::State(state),
            Json(OpaCheckRequest {
                api_key: "lbk_secret_expired".to_string(),
                ip: None,
            }),
        )
        .await
        .expect("handler should return response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_api_key_returns_ok_and_records_usage_when_valid() {
        let usage_calls = Arc::new(Mutex::new(vec![]));
        let repo = MockOpaRepo {
            api_key: Some(mk_api_key(
                ApiKeyStatus::Active,
                Some(Utc::now() + Duration::minutes(10)),
            )),
            project: Some(mk_project()),
            account: Some(mk_account()),
            usage_calls: usage_calls.clone(),
        };
        let state = mk_state(repo);

        let response = validate_api_key(
            axum::extract::State(state.clone()),
            Json(OpaCheckRequest {
                api_key: "lbk_secret_valid".to_string(),
                ip: Some("203.0.113.10".to_string()),
            }),
        )
        .await
        .expect("handler should return response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let payload: Value = serde_json::from_slice(&body).expect("body should be valid json");
        assert_eq!(payload["api_key"]["id"], "key_1");
        assert_eq!(payload["project"]["id"], "proj_1");
        assert_eq!(payload["account"]["id"], "acct_1");

        let calls = usage_calls.lock().expect("lock should work").clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "key_1");
        assert_eq!(calls[0].1.as_deref(), Some("203.0.113.10"));
    }
}
