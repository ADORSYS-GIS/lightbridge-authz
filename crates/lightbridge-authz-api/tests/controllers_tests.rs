use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use lightbridge_authz_api::AppState;
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_api::routers::api_router;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, ApiKeyStatus, CreateAccount, CreateApiKey, CreateProject,
    Project, ResourceStatus, RotateApiKey, UpdateAccount, UpdateApiKey, UpdateProject, async_trait,
    error::Error,
};
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Debug)]
enum MockResponse {
    Account(Result<Account, Error>),
    Accounts(Result<Vec<Account>, Error>),
    Project(Result<Project, Error>),
    Projects(Result<Vec<Project>, Error>),
    ApiKey(Result<ApiKey, Error>),
    ApiKeys(Result<Vec<ApiKey>, Error>),
    ApiKeySecret(Result<ApiKeySecret, Error>),
    Unit(Result<(), Error>),
}

#[derive(Debug)]
struct MockStore {
    response: Mutex<Option<MockResponse>>,
    captured_pagination: Mutex<Option<(u32, u32)>>,
}

impl MockStore {
    fn new(response: MockResponse) -> Self {
        Self {
            response: Mutex::new(Some(response)),
            captured_pagination: Mutex::new(None),
        }
    }

    fn record_pagination(&self, offset: u32, limit: u32) {
        *self.captured_pagination.lock().unwrap() = Some((offset, limit));
    }

    fn captured_pagination(&self) -> Option<(u32, u32)> {
        *self.captured_pagination.lock().unwrap()
    }

    fn take(&self) -> MockResponse {
        self.response
            .lock()
            .unwrap()
            .take()
            .expect("mock store called more times than a response was configured")
    }

    fn take_account(&self) -> Result<Account, Error> {
        match self.take() {
            MockResponse::Account(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_accounts(&self) -> Result<Vec<Account>, Error> {
        match self.take() {
            MockResponse::Accounts(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_project(&self) -> Result<Project, Error> {
        match self.take() {
            MockResponse::Project(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_projects(&self) -> Result<Vec<Project>, Error> {
        match self.take() {
            MockResponse::Projects(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_api_key(&self) -> Result<ApiKey, Error> {
        match self.take() {
            MockResponse::ApiKey(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_api_keys(&self) -> Result<Vec<ApiKey>, Error> {
        match self.take() {
            MockResponse::ApiKeys(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_api_key_secret(&self) -> Result<ApiKeySecret, Error> {
        match self.take() {
            MockResponse::ApiKeySecret(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }

    fn take_unit(&self) -> Result<(), Error> {
        match self.take() {
            MockResponse::Unit(r) => r,
            other => panic!("unexpected mock response: {other:?}"),
        }
    }
}

#[async_trait]
impl AuthzStore for MockStore {
    async fn create_account(
        &self,
        _subject: &str,
        _input: CreateAccount,
    ) -> Result<Account, Error> {
        self.take_account()
    }

    async fn list_accounts(
        &self,
        _subject: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Account>, Error> {
        self.record_pagination(offset, limit);
        self.take_accounts()
    }

    async fn get_account(&self, _subject: &str, _account_id: &str) -> Result<Account, Error> {
        self.take_account()
    }

    async fn update_account(
        &self,
        _subject: &str,
        _account_id: &str,
        _input: UpdateAccount,
    ) -> Result<Account, Error> {
        self.take_account()
    }

    async fn delete_account(&self, _subject: &str, _account_id: &str) -> Result<(), Error> {
        self.take_unit()
    }

    async fn set_account_status(
        &self,
        _subject: &str,
        _account_id: &str,
        _status: ResourceStatus,
    ) -> Result<Account, Error> {
        self.take_account()
    }

    async fn add_account_member(
        &self,
        _subject: &str,
        _account_id: &str,
        _new_member: &str,
    ) -> Result<Account, Error> {
        self.take_account()
    }

    async fn remove_account_member(
        &self,
        _subject: &str,
        _account_id: &str,
        _member: &str,
    ) -> Result<Account, Error> {
        self.take_account()
    }

    async fn create_project(
        &self,
        _subject: &str,
        _account_id: &str,
        _input: CreateProject,
    ) -> Result<Project, Error> {
        self.take_project()
    }

    async fn list_projects(
        &self,
        _subject: &str,
        _account_id: &str,
        _offset: u32,
        _limit: u32,
    ) -> Result<Vec<Project>, Error> {
        self.take_projects()
    }

    async fn get_project(&self, _subject: &str, _project_id: &str) -> Result<Project, Error> {
        self.take_project()
    }

    async fn update_project(
        &self,
        _subject: &str,
        _project_id: &str,
        _input: UpdateProject,
    ) -> Result<Project, Error> {
        self.take_project()
    }

    async fn delete_project(&self, _subject: &str, _project_id: &str) -> Result<(), Error> {
        self.take_unit()
    }

    async fn set_project_status(
        &self,
        _subject: &str,
        _project_id: &str,
        _status: ResourceStatus,
    ) -> Result<Project, Error> {
        self.take_project()
    }

    async fn create_api_key(
        &self,
        _subject: &str,
        _bearer_token: Option<&str>,
        _project_id: &str,
        _input: CreateApiKey,
    ) -> Result<ApiKeySecret, Error> {
        self.take_api_key_secret()
    }

    async fn list_api_keys(
        &self,
        _subject: &str,
        _project_id: &str,
        _offset: u32,
        _limit: u32,
    ) -> Result<Vec<ApiKey>, Error> {
        self.take_api_keys()
    }

    async fn get_api_key(&self, _subject: &str, _key_id: &str) -> Result<ApiKey, Error> {
        self.take_api_key()
    }

    async fn update_api_key(
        &self,
        _subject: &str,
        _key_id: &str,
        _input: UpdateApiKey,
    ) -> Result<ApiKey, Error> {
        self.take_api_key()
    }

    async fn delete_api_key(&self, _subject: &str, _key_id: &str) -> Result<(), Error> {
        self.take_unit()
    }

    async fn revoke_api_key(&self, _subject: &str, _key_id: &str) -> Result<ApiKey, Error> {
        self.take_api_key()
    }

    async fn rotate_api_key(
        &self,
        _subject: &str,
        _bearer_token: Option<&str>,
        _key_id: &str,
        _input: RotateApiKey,
    ) -> Result<ApiKeySecret, Error> {
        self.take_api_key_secret()
    }
}

#[derive(Debug)]
struct NoopBearer;

#[async_trait]
impl BearerTokenServiceTrait for NoopBearer {
    async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
        unreachable!("controllers tests bypass the bearer middleware entirely")
    }
}

fn mk_account(id: &str) -> Account {
    Account {
        id: id.to_string(),
        billing_identity: "acme".to_string(),
        owners_admins: vec!["owner@example.com".to_string()],
        status: ResourceStatus::Active,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mk_project(id: &str, account_id: &str) -> Project {
    Project {
        id: id.to_string(),
        account_id: account_id.to_string(),
        name: "demo-project".to_string(),
        allowed_models: None,
        default_limits: None,
        billing_plan: "free".to_string(),
        status: ResourceStatus::Active,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mk_api_key(id: &str, project_id: &str) -> ApiKey {
    ApiKey {
        id: id.to_string(),
        project_id: project_id.to_string(),
        name: "demo-key".to_string(),
        key_prefix: "lbk_demo".to_string(),
        key_hash: "hash".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        status: ApiKeyStatus::Active,
        last_used_at: None,
        last_ip: None,
        revoked_at: None,
        billing_plan: "free".to_string(),
    }
}

fn mk_api_key_secret(id: &str, project_id: &str) -> ApiKeySecret {
    ApiKeySecret {
        api_key: mk_api_key(id, project_id),
        secret: "lbk_secret_value".to_string(),
        oauth2_url: None,
    }
}

fn app(response: MockResponse) -> (Router, Arc<MockStore>) {
    let store = Arc::new(MockStore::new(response));
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(NoopBearer);
    let state = Arc::new(AppState {
        store: store.clone() as Arc<dyn AuthzStore>,
        bearer,
    });
    (Router::new().merge(api_router()).with_state(state), store)
}

fn token_info() -> TokenInfo {
    TokenInfo {
        active: true,
        sub: "user-1".to_string(),
        exp: 0,
        aud: vec![],
        roles: vec![],
        permissions: Default::default(),
        access_token: "access-token".to_string(),
    }
}

fn req(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    let axum_body = if let Some(json_body) = &body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(json_body.to_string())
    } else {
        Body::empty()
    };
    let mut request = builder.body(axum_body).unwrap();
    request.extensions_mut().insert(token_info());
    request
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router
        .oneshot(request)
        .await
        .expect("router should respond");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body readable");
    let payload = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, payload)
}

#[test]
fn app_state_debug_redacts_store_and_bearer_internals() {
    let store: Arc<dyn AuthzStore> = Arc::new(MockStore::new(MockResponse::Unit(Ok(()))));
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(NoopBearer);
    let state = AppState { store, bearer };

    let debug_output = format!("{state:?}");

    assert!(debug_output.contains("AppState"));
    assert!(debug_output.contains("<AuthzStore>"));
    assert!(debug_output.contains("<BearerTokenService>"));
}

#[tokio::test]
async fn create_account_returns_201_with_created_account() {
    let (router, _mock) = app(MockResponse::Account(Ok(mk_account("acct_1"))));
    let (status, payload) = send(
        router,
        req(
            "POST",
            "/accounts",
            Some(json!({"billing_identity": "acme"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(payload["id"], "acct_1");
}

#[tokio::test]
async fn create_account_maps_conflict_error_to_409() {
    let (router, _mock) = app(MockResponse::Account(Err(Error::Conflict(
        "billing_identity already exists".to_string(),
    ))));
    let (status, _) = send(
        router,
        req(
            "POST",
            "/accounts",
            Some(json!({"billing_identity": "acme"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn list_accounts_uses_default_pagination_when_omitted() {
    let (router, mock) = app(MockResponse::Accounts(Ok(vec![mk_account("acct_1")])));
    let (status, payload) = send(router, req("GET", "/accounts", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload.as_array().unwrap().len(), 1);
    assert_eq!(mock.captured_pagination(), Some((0, 50)));
}

#[tokio::test]
async fn list_accounts_clamps_limit_above_maximum_to_100() {
    let (router, mock) = app(MockResponse::Accounts(Ok(vec![])));
    let (status, _) = send(router, req("GET", "/accounts?offset=5&limit=5000", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mock.captured_pagination(), Some((5, 100)));
}

#[tokio::test]
async fn list_accounts_clamps_limit_below_one_to_1() {
    let (router, mock) = app(MockResponse::Accounts(Ok(vec![])));
    let (status, _) = send(router, req("GET", "/accounts?limit=0", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mock.captured_pagination(), Some((0, 1)));
}

#[tokio::test]
async fn get_account_returns_200_with_account() {
    let (router, _mock) = app(MockResponse::Account(Ok(mk_account("acct_1"))));
    let (status, payload) = send(router, req("GET", "/accounts/acct_1", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "acct_1");
}

#[tokio::test]
async fn get_account_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::Account(Err(Error::NotFound)));
    let (status, _) = send(router, req("GET", "/accounts/missing", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_account_returns_200_with_updated_account() {
    let (router, _mock) = app(MockResponse::Account(Ok(mk_account("acct_1"))));
    let (status, payload) = send(
        router,
        req(
            "PATCH",
            "/accounts/acct_1",
            Some(json!({"billing_identity": "new-billing"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "acct_1");
}

#[tokio::test]
async fn update_account_maps_bad_request_error_to_400() {
    let (router, _mock) = app(MockResponse::Account(Err(Error::BadRequest(
        "billing_identity cannot be empty".to_string(),
    ))));
    let (status, _) = send(
        router,
        req(
            "PATCH",
            "/accounts/acct_1",
            Some(json!({"billing_identity": ""})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_account_returns_204() {
    let (router, _mock) = app(MockResponse::Unit(Ok(())));
    let (status, _) = send(router, req("DELETE", "/accounts/acct_1", None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_account_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::Unit(Err(Error::NotFound)));
    let (status, _) = send(router, req("DELETE", "/accounts/missing", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn disable_account_returns_200_with_suspended_account() {
    let mut account = mk_account("acct_1");
    account.status = ResourceStatus::Suspended;
    let (router, _mock) = app(MockResponse::Account(Ok(account)));
    let (status, payload) = send(router, req("POST", "/accounts/acct_1/disable", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "suspended");
}

#[tokio::test]
async fn enable_account_returns_200_with_active_account() {
    let (router, _mock) = app(MockResponse::Account(Ok(mk_account("acct_1"))));
    let (status, payload) = send(router, req("POST", "/accounts/acct_1/enable", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "active");
}

#[tokio::test]
async fn add_account_member_returns_200_with_updated_account() {
    let (router, _mock) = app(MockResponse::Account(Ok(mk_account("acct_1"))));
    let (status, payload) = send(
        router,
        req(
            "POST",
            "/accounts/acct_1/members",
            Some(json!({"subject": "invitee"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "acct_1");
}

#[tokio::test]
async fn add_account_member_maps_conflict_error_to_409() {
    let (router, _mock) = app(MockResponse::Account(Err(Error::Conflict(
        "already a member".to_string(),
    ))));
    let (status, _) = send(
        router,
        req(
            "POST",
            "/accounts/acct_1/members",
            Some(json!({"subject": "invitee"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn remove_account_member_returns_200_with_updated_account() {
    let (router, _mock) = app(MockResponse::Account(Ok(mk_account("acct_1"))));
    let (status, payload) = send(
        router,
        req("DELETE", "/accounts/acct_1/members/invitee", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "acct_1");
}

#[tokio::test]
async fn remove_account_member_maps_bad_request_error_to_400() {
    let (router, _mock) = app(MockResponse::Account(Err(Error::BadRequest(
        "cannot remove the last member".to_string(),
    ))));
    let (status, _) = send(
        router,
        req("DELETE", "/accounts/acct_1/members/invitee", None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_project_returns_201_with_created_project() {
    let (router, _mock) = app(MockResponse::Project(Ok(mk_project("proj_1", "acct_1"))));
    let (status, payload) = send(
        router,
        req(
            "POST",
            "/accounts/acct_1/projects",
            Some(json!({"name": "demo-project", "billing_plan": "free"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(payload["id"], "proj_1");
}

#[tokio::test]
async fn create_project_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::Project(Err(Error::NotFound)));
    let (status, _) = send(
        router,
        req(
            "POST",
            "/accounts/missing/projects",
            Some(json!({"name": "demo-project", "billing_plan": "free"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_projects_returns_200_with_projects() {
    let (router, _mock) = app(MockResponse::Projects(Ok(vec![mk_project(
        "proj_1", "acct_1",
    )])));
    let (status, payload) = send(router, req("GET", "/accounts/acct_1/projects", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn get_project_returns_200_with_project() {
    let (router, _mock) = app(MockResponse::Project(Ok(mk_project("proj_1", "acct_1"))));
    let (status, payload) = send(router, req("GET", "/projects/proj_1", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "proj_1");
}

#[tokio::test]
async fn get_project_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::Project(Err(Error::NotFound)));
    let (status, _) = send(router, req("GET", "/projects/missing", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_project_returns_200_with_updated_project() {
    let (router, _mock) = app(MockResponse::Project(Ok(mk_project("proj_1", "acct_1"))));
    let (status, payload) = send(
        router,
        req(
            "PATCH",
            "/projects/proj_1",
            Some(json!({"name": "renamed-project"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "proj_1");
}

#[tokio::test]
async fn update_project_maps_bad_request_error_to_400() {
    let (router, _mock) = app(MockResponse::Project(Err(Error::BadRequest(
        "billing_plan is invalid".to_string(),
    ))));
    let (status, _) = send(
        router,
        req(
            "PATCH",
            "/projects/proj_1",
            Some(json!({"billing_plan": "not-a-plan"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_project_returns_204() {
    let (router, _mock) = app(MockResponse::Unit(Ok(())));
    let (status, _) = send(router, req("DELETE", "/projects/proj_1", None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_project_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::Unit(Err(Error::NotFound)));
    let (status, _) = send(router, req("DELETE", "/projects/missing", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn disable_project_returns_200_with_suspended_project() {
    let mut project = mk_project("proj_1", "acct_1");
    project.status = ResourceStatus::Suspended;
    let (router, _mock) = app(MockResponse::Project(Ok(project)));
    let (status, payload) = send(router, req("POST", "/projects/proj_1/disable", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "suspended");
}

#[tokio::test]
async fn enable_project_returns_200_with_active_project() {
    let (router, _mock) = app(MockResponse::Project(Ok(mk_project("proj_1", "acct_1"))));
    let (status, payload) = send(router, req("POST", "/projects/proj_1/enable", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "active");
}

#[tokio::test]
async fn create_api_key_returns_201_with_secret() {
    let (router, _mock) = app(MockResponse::ApiKeySecret(Ok(mk_api_key_secret(
        "key_1", "proj_1",
    ))));
    let (status, payload) = send(
        router,
        req(
            "POST",
            "/projects/proj_1/api-keys",
            Some(json!({"name": "demo-key", "billing_plan": "free"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(payload["api_key"]["id"], "key_1");
    assert_eq!(payload["secret"], "lbk_secret_value");
}

#[tokio::test]
async fn create_api_key_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::ApiKeySecret(Err(Error::NotFound)));
    let (status, _) = send(
        router,
        req(
            "POST",
            "/projects/missing/api-keys",
            Some(json!({"name": "demo-key", "billing_plan": "free"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_api_keys_returns_200_with_keys() {
    let (router, _mock) = app(MockResponse::ApiKeys(Ok(vec![mk_api_key(
        "key_1", "proj_1",
    )])));
    let (status, payload) = send(router, req("GET", "/projects/proj_1/api-keys", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn get_api_key_returns_200_with_key() {
    let (router, _mock) = app(MockResponse::ApiKey(Ok(mk_api_key("key_1", "proj_1"))));
    let (status, payload) = send(router, req("GET", "/api-keys/key_1", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "key_1");
}

#[tokio::test]
async fn get_api_key_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::ApiKey(Err(Error::NotFound)));
    let (status, _) = send(router, req("GET", "/api-keys/missing", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_api_key_returns_200_with_updated_key() {
    let (router, _mock) = app(MockResponse::ApiKey(Ok(mk_api_key("key_1", "proj_1"))));
    let (status, payload) = send(
        router,
        req(
            "PATCH",
            "/api-keys/key_1",
            Some(json!({"name": "renamed-key"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["id"], "key_1");
}

#[tokio::test]
async fn update_api_key_maps_bad_request_error_to_400() {
    let (router, _mock) = app(MockResponse::ApiKey(Err(Error::BadRequest(
        "name cannot be empty".to_string(),
    ))));
    let (status, _) = send(
        router,
        req("PATCH", "/api-keys/key_1", Some(json!({"name": ""}))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_api_key_returns_204() {
    let (router, _mock) = app(MockResponse::Unit(Ok(())));
    let (status, _) = send(router, req("DELETE", "/api-keys/key_1", None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_api_key_maps_not_found_error_to_404() {
    let (router, _mock) = app(MockResponse::Unit(Err(Error::NotFound)));
    let (status, _) = send(router, req("DELETE", "/api-keys/missing", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_api_key_returns_200_with_revoked_key() {
    let mut api_key = mk_api_key("key_1", "proj_1");
    api_key.status = ApiKeyStatus::Revoked;
    let (router, _mock) = app(MockResponse::ApiKey(Ok(api_key)));
    let (status, payload) = send(router, req("POST", "/api-keys/key_1/revoke", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "revoked");
}

#[tokio::test]
async fn rotate_api_key_returns_201_with_new_secret() {
    let (router, _mock) = app(MockResponse::ApiKeySecret(Ok(mk_api_key_secret(
        "key_2", "proj_1",
    ))));
    let (status, payload) = send(
        router,
        req(
            "POST",
            "/api-keys/key_1/rotate",
            Some(json!({"grace_period_seconds": 60})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(payload["api_key"]["id"], "key_2");
}

#[tokio::test]
async fn rotate_api_key_maps_conflict_error_to_409() {
    let (router, _mock) = app(MockResponse::ApiKeySecret(Err(Error::Conflict(
        "rotation already in progress".to_string(),
    ))));
    let (status, _) = send(
        router,
        req("POST", "/api-keys/key_1/rotate", Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
