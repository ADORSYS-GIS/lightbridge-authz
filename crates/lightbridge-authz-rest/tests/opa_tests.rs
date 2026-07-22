use axum::Form;
use axum::body::to_bytes;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, ApiKeyValidation, Project, ResourceStatus, async_trait,
    config::{BasicAuth, Billing, BillingLimits, BillingPlan},
    error::Result,
};
use lightbridge_authz_rest::OpaState;
use lightbridge_authz_rest::handlers::introspect::introspect_api_key;
use lightbridge_authz_rest::models::IntrospectRequest;
use serde_json::Value;
use std::sync::{Arc, Mutex};

type UsageCalls = Arc<Mutex<Vec<(String, Option<String>)>>>;

#[derive(Debug)]
struct MockOpaRepo {
    api_key: Option<ApiKey>,
    project: Option<Project>,
    account: Option<Account>,
    usage_calls: UsageCalls,
}

#[async_trait]
impl lightbridge_authz_rest::OpaRepoTrait for MockOpaRepo {
    async fn record_api_key_usage(&self, key_id: &str, ip: Option<String>) -> Result<ApiKey> {
        self.usage_calls
            .lock()
            .expect("lock should work")
            .push((key_id.to_string(), ip));
        Ok(self.api_key.clone().expect("api key should exist in mock"))
    }

    async fn find_api_key_validation_by_hash(
        &self,
        _key_hash: &str,
    ) -> Result<Option<ApiKeyValidation>> {
        let Some(api_key) = self.api_key.clone() else {
            return Ok(None);
        };
        let now = Utc::now();
        let project_suspended = self
            .project
            .as_ref()
            .map(|p| p.status != ResourceStatus::Active)
            .unwrap_or(false);
        let account_suspended = self
            .account
            .as_ref()
            .map(|a| a.status != ResourceStatus::Active)
            .unwrap_or(false);
        let effective_status = if api_key.status != ApiKeyStatus::Active {
            "key_revoked"
        } else if api_key.expires_at.map(|e| e <= now).unwrap_or(false) {
            "key_expired"
        } else if project_suspended {
            "project_suspended"
        } else if account_suspended {
            "account_suspended"
        } else {
            "active"
        };
        Ok(Some(ApiKeyValidation {
            api_key_id: api_key.id.clone(),
            key_hash: api_key.key_hash.clone(),
            project_id: api_key.project_id.clone(),
            account_id: self
                .account
                .as_ref()
                .map(|a| a.id.clone())
                .unwrap_or_default(),
            api_key_status: api_key.status.to_string(),
            project_status: self
                .project
                .as_ref()
                .map(|p| p.status.to_string())
                .unwrap_or_else(|| "active".to_string()),
            account_status: self
                .account
                .as_ref()
                .map(|a| a.status.to_string())
                .unwrap_or_else(|| "active".to_string()),
            expires_at: api_key.expires_at,
            effective_status: effective_status.to_string(),
        }))
    }

    async fn get_project(&self, _subject: &str, _project_id: &str) -> Result<Option<Project>> {
        Ok(self.project.clone())
    }

    async fn get_account(&self, _subject: &str, _account_id: &str) -> Result<Option<Account>> {
        Ok(self.account.clone())
    }

    async fn get_project_by_id(&self, _project_id: &str) -> Result<Option<Project>> {
        Ok(self.project.clone())
    }

    async fn get_account_by_id(&self, _account_id: &str) -> Result<Option<Account>> {
        Ok(self.account.clone())
    }

    async fn resolve_context(
        &self,
        _subject: &str,
        _project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext> {
        Err(lightbridge_authz_core::error::Error::NotFound)
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
        billing_plan: "free".to_string(),
        updated_at: Utc::now(),
    }
}

fn mk_project() -> Project {
    Project {
        id: "proj_1".to_string(),
        account_id: "acct_1".to_string(),
        name: "demo-project".to_string(),
        allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
        default_limits: None,
        billing_plan: "free".to_string(),
        status: ResourceStatus::Active,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mk_account() -> Account {
    Account {
        id: "acct_1".to_string(),
        billing_identity: "acme".to_string(),
        owners_admins: vec!["owner@example.com".to_string()],
        status: ResourceStatus::Active,
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
        billing: Arc::new(Billing {
            plans: vec![BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: Some(BillingLimits {
                    requests_per_second: Some(5),
                    requests_per_day: Some(1000),
                    requests_per_month: None,
                    concurrent_requests: Some(2),
                }),
            }],
        }),
    })
}

async fn introspect(state: Arc<OpaState>, token: &str) -> (StatusCode, Value) {
    let response = introspect_api_key(
        axum::extract::State(state),
        Form(IntrospectRequest {
            token: token.to_string(),
            token_type_hint: Some("access_token".to_string()),
        }),
    )
    .await
    .expect("handler should return response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    let payload: Value = serde_json::from_slice(&body).expect("body should be valid json");
    (status, payload)
}

#[tokio::test]
async fn introspect_returns_active_with_context_and_records_usage() {
    let expires_at = Utc::now() + Duration::minutes(10);
    let usage_calls = Arc::new(Mutex::new(vec![]));
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, Some(expires_at))),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: usage_calls.clone(),
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert_eq!(payload["account_id"], "acct_1");
    assert_eq!(payload["project_id"], "proj_1");
    assert_eq!(payload["api_key_id"], "key_1");
    assert_eq!(payload["api_key_status"], "active");
    assert_eq!(payload["billing_plan"], "free");
    assert_eq!(payload["billing_plan_name"], "Free");
    assert_eq!(payload["billing_plan_limits"]["requests_per_second"], 5);
    assert_eq!(payload["billing_plan_limits"]["concurrent_requests"], 2);
    assert!(
        payload["billing_plan_limits"]
            .get("requests_per_month")
            .is_none(),
        "unset limit fields must be omitted"
    );
    assert_eq!(
        payload["allowed_models"],
        serde_json::json!(["gpt-4.1-mini"])
    );
    assert_eq!(payload["exp"], expires_at.timestamp());

    let calls = usage_calls.lock().expect("lock should work").clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "key_1");
}

#[tokio::test]
async fn introspect_omits_name_and_limits_for_plan_absent_from_catalogue() {
    let mut api_key = mk_api_key(ApiKeyStatus::Active, None);
    api_key.billing_plan = "removed-plan".to_string();
    let state = mk_state(MockOpaRepo {
        api_key: Some(api_key),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert_eq!(
        payload["billing_plan"], "removed-plan",
        "the stored plan id is always returned"
    );
    assert!(
        payload.get("billing_plan_name").is_none(),
        "an id not in the catalogue resolves to no name"
    );
    assert!(
        payload.get("billing_plan_limits").is_none(),
        "an id not in the catalogue resolves to no limits"
    );
}

#[tokio::test]
async fn introspect_returns_inactive_when_revoked() {
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Revoked, None)),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_revoked").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
    assert!(payload.get("account_id").is_none());
    assert!(payload.get("api_key_id").is_none());
}

#[tokio::test]
async fn introspect_returns_inactive_when_missing() {
    let state = mk_state(MockOpaRepo {
        api_key: None,
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_missing").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_expired() {
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(
            ApiKeyStatus::Active,
            Some(Utc::now() - Duration::seconds(1)),
        )),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_expired").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_returns_inactive_when_account_suspended() {
    let mut account = mk_account();
    account.status = ResourceStatus::Suspended;
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(mk_project()),
        account: Some(account),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_suspended_account").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
    assert!(payload.get("account_id").is_none());
}

#[tokio::test]
async fn introspect_returns_inactive_when_project_suspended() {
    let mut project = mk_project();
    project.status = ResourceStatus::Suspended;
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_suspended_project").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], false);
}

#[tokio::test]
async fn introspect_omits_allowed_models_when_null() {
    let mut project = mk_project();
    project.allowed_models = None;
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert!(
        payload.get("allowed_models").is_none(),
        "allowed_models should be omitted when the project allows all models"
    );
    assert!(
        payload.get("exp").is_none(),
        "exp should be omitted when the key has no expiry"
    );
}

#[tokio::test]
async fn introspect_returns_empty_allowed_models_when_empty() {
    let mut project = mk_project();
    project.allowed_models = Some(vec![]);
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let (status, payload) = introspect(state, "lbk_secret_valid").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["active"], true);
    assert!(payload["allowed_models"].is_array());
    assert_eq!(payload["allowed_models"].as_array().unwrap().len(), 0);
}
