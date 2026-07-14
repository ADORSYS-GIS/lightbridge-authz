use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use lightbridge_authz_api::AppState;
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, Permission, PermissionSet, Project, ResolvedContext,
    async_trait, config::BasicAuth, error::Result,
};
use lightbridge_authz_rest::OpaState;
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::middleware::bearer_auth;
use lightbridge_authz_rest::routers::opa_router;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Debug)]
struct MockOpaRepo;

#[async_trait]
impl lightbridge_authz_rest::OpaRepoTrait for MockOpaRepo {
    async fn find_api_key_by_hash(&self, _key_hash: &str) -> Result<Option<ApiKey>> {
        Ok(Some(ApiKey {
            id: "key_1".to_string(),
            project_id: "proj_1".to_string(),
            name: "demo".to_string(),
            key_prefix: "lbk_demo".to_string(),
            key_hash: "hash".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            status: ApiKeyStatus::Active,
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        }))
    }

    async fn record_api_key_usage(&self, _key_id: &str, _ip: Option<String>) -> Result<ApiKey> {
        self.find_api_key_by_hash("")
            .await
            .map(|k| k.expect("key exists"))
    }

    async fn get_project(&self, _subject: &str, _project_id: &str) -> Result<Option<Project>> {
        Ok(Some(mk_project()))
    }

    async fn get_account(&self, _subject: &str, _account_id: &str) -> Result<Option<Account>> {
        Ok(Some(mk_account()))
    }

    async fn get_project_by_id(&self, _project_id: &str) -> Result<Option<Project>> {
        Ok(Some(mk_project()))
    }

    async fn get_account_by_id(&self, _account_id: &str) -> Result<Option<Account>> {
        Ok(Some(mk_account()))
    }

    async fn resolve_context(&self, _subject: &str, _project_id: &str) -> Result<ResolvedContext> {
        Ok(ResolvedContext {
            account_id: "acct_1".to_string(),
            project_id: "proj_1".to_string(),
        })
    }
}

fn mk_project() -> Project {
    Project {
        id: "proj_1".to_string(),
        account_id: "acct_1".to_string(),
        name: "demo-project".to_string(),
        allowed_models: None,
        default_limits: None,
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

fn app() -> axum::Router {
    let state = Arc::new(OpaState {
        repo: Arc::new(MockOpaRepo),
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
    });
    opa_router(state.clone()).with_state(state)
}

fn basic(creds: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(creds)
    )
}

async fn send(req: Request<Body>) -> (StatusCode, Value) {
    let response = app().oneshot(req).await.expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body readable");
    let payload = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, payload)
}

fn introspect_req(auth: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/authorino/validate/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder
        .body(Body::from(
            "token=lbk_secret_x&token_type_hint=access_token",
        ))
        .unwrap()
}

#[tokio::test]
async fn basic_auth_rejects_missing_header() {
    let (status, _) = send(introspect_req(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_auth_rejects_non_basic_scheme() {
    let (status, _) = send(introspect_req(Some("Bearer sometoken"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_auth_rejects_malformed_base64() {
    let (status, _) = send(introspect_req(Some("Basic not@@base64"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_auth_rejects_wrong_credentials() {
    let (status, _) = send(introspect_req(Some(&basic("authorino:wrong")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_auth_accepts_valid_credentials_and_routes_to_introspect() {
    let (status, payload) = send(introspect_req(Some(&basic("authorino:change-me")))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert_eq!(payload["account_id"], "acct_1");
}

#[tokio::test]
async fn resolve_context_returns_tenant_context_for_authorized_caller() {
    let req = Request::builder()
        .method("POST")
        .uri("/idp/v1/resolve-context")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, basic("authorino:change-me"))
        .body(Body::from(r#"{"subject":"user-1","project_id":"proj_1"}"#))
        .unwrap();
    let (status, payload) = send(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["account_id"], "acct_1");
    assert_eq!(payload["project_id"], "proj_1");
}

enum BearerOutcome {
    Active,
    Inactive,
    Error,
}

struct MockBearer {
    outcome: BearerOutcome,
}

#[async_trait]
impl BearerTokenServiceTrait for MockBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        match self.outcome {
            BearerOutcome::Error => Err(anyhow::anyhow!("invalid token")),
            BearerOutcome::Inactive => Ok(mk_token_info(false)),
            BearerOutcome::Active => Ok(mk_token_info(true)),
        }
    }
}

fn mk_token_info(active: bool) -> TokenInfo {
    TokenInfo {
        active,
        sub: "user-1".to_string(),
        exp: 0,
        aud: vec![],
        roles: vec![],
        permissions: Default::default(),
        access_token: String::new(),
    }
}

fn protected_app(outcome: BearerOutcome) -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let store: Arc<dyn AuthzStore> = Arc::new(AuthzStoreImpl::with_pool(pool));
    let app_state = Arc::new(AppState {
        store,
        bearer: Arc::new(MockBearer { outcome }),
    });
    axum::Router::new()
        .route("/protected", axum::routing::get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            bearer_auth,
        ))
        .with_state(app_state)
}

async fn bearer_status(outcome: BearerOutcome, auth: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().method("GET").uri("/protected");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let req = builder.body(Body::empty()).unwrap();
    protected_app(outcome)
        .oneshot(req)
        .await
        .expect("router should respond")
        .status()
}

#[tokio::test]
async fn bearer_auth_rejects_missing_token() {
    assert_eq!(
        bearer_status(BearerOutcome::Active, None).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_auth_rejects_invalid_token() {
    assert_eq!(
        bearer_status(BearerOutcome::Error, Some("Bearer bad")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_auth_rejects_inactive_token() {
    assert_eq!(
        bearer_status(BearerOutcome::Inactive, Some("Bearer inactive")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_auth_accepts_active_token() {
    assert_eq!(
        bearer_status(BearerOutcome::Active, Some("Bearer good")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn bearer_auth_accepts_lowercase_scheme() {
    assert_eq!(
        bearer_status(BearerOutcome::Active, Some("bearer good")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn bearer_auth_accepts_mixed_case_scheme() {
    assert_eq!(
        bearer_status(BearerOutcome::Active, Some("BEARER good")).await,
        StatusCode::OK
    );
}

fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    Arc::new(DbPool::from_pool(pool))
}

fn oauth2_without_signing() -> lightbridge_authz_core::config::Oauth2 {
    lightbridge_authz_core::config::Oauth2 {
        oauth2_type: lightbridge_authz_core::config::Oauth2Type::External,
        jwks_url: "http://jwks".to_string(),
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience: None,
        signing: None,
        token_exchange: None,
        rbac: Default::default(),
    }
}

#[tokio::test]
async fn build_api_router_serves_probes_and_protects_the_api() {
    let store: Arc<dyn AuthzStore> = Arc::new(AuthzStoreImpl::with_pool(lazy_pool()));
    let app_state = Arc::new(AppState {
        store,
        bearer: Arc::new(MockBearer {
            outcome: BearerOutcome::Active,
        }),
    });
    let signing_repo = Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(lazy_pool()));
    let router = lightbridge_authz_rest::build_api_router(
        &oauth2_without_signing(),
        app_state,
        lazy_pool(),
        signing_repo,
        None,
    );

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let unauth = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/accounts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
}

#[derive(Debug)]
struct PermBearer {
    permissions: PermissionSet,
}

#[async_trait]
impl BearerTokenServiceTrait for PermBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        Ok(TokenInfo {
            active: true,
            sub: "user-1".to_string(),
            exp: 0,
            aud: vec![],
            roles: vec![],
            permissions: self.permissions.clone(),
            access_token: String::new(),
        })
    }
}

async fn create_account_status(permissions: PermissionSet) -> StatusCode {
    let store: Arc<dyn AuthzStore> = Arc::new(AuthzStoreImpl::with_pool(lazy_pool()));
    let app_state = Arc::new(AppState {
        store,
        bearer: Arc::new(PermBearer { permissions }),
    });
    let signing_repo = Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(lazy_pool()));
    let router = lightbridge_authz_rest::build_api_router(
        &oauth2_without_signing(),
        app_state,
        lazy_pool(),
        signing_repo,
        None,
    );

    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/accounts")
                .header(header::AUTHORIZATION, "Bearer any")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"billing_identity":"acct-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn api_denies_when_caller_lacks_required_permission() {
    assert_eq!(
        create_account_status(PermissionSet::new()).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn api_passes_rbac_gate_when_caller_has_required_permission() {
    let status = create_account_status(PermissionSet::from_iter([Permission::AccountCreate])).await;
    assert_ne!(status, StatusCode::FORBIDDEN);
    assert_ne!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn build_opa_router_serves_probes_and_introspection() {
    let state = Arc::new(OpaState {
        repo: Arc::new(MockOpaRepo),
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
    });
    let router = lightbridge_authz_rest::build_opa_router(state, lazy_pool());

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let introspect = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorino/validate/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic("authorino:change-me"))
                .body(Body::from("token=lbk_secret_x"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(introspect.status(), StatusCode::OK);
}
