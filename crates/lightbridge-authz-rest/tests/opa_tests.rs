use axum::Json;
use axum::body::to_bytes;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use lightbridge_authz_core::{Account, ApiKey, ApiKeyStatus, Project, async_trait, config::BasicAuth, error::Result};
use lightbridge_authz_rest::OpaState;
use lightbridge_authz_rest::handlers::authorino::validate_authorino_api_key;
use lightbridge_authz_rest::handlers::opa::validate_api_key;
use lightbridge_authz_rest::models::OpaCheckRequest;
use lightbridge_authz_rest::models::authorino::AuthorinoCheckRequest;
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct MockOpaRepo {
    api_key: Option<ApiKey>,
    project: Option<Project>,
    account: Option<Account>,
    usage_calls: Arc<Mutex<Vec<(String, Option<String>)>>>,
}

#[async_trait]
impl lightbridge_authz_rest::OpaRepoTrait for MockOpaRepo {
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
        allowed_models: Some(vec![]),
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

#[tokio::test]
async fn validate_authorino_api_key_preserves_and_enriches_metadata() {
    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(
            ApiKeyStatus::Active,
            Some(Utc::now() + Duration::minutes(10)),
        )),
        project: Some(mk_project()),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let response = validate_authorino_api_key(
        axum::extract::State(state),
        Json(AuthorinoCheckRequest {
            api_key: "lbk_secret_valid".to_string(),
            ip: Some("203.0.113.10".to_string()),
            metadata: std::collections::HashMap::from([(
                "tenant".to_string(),
                serde_json::json!("acme"),
            )]),
        }),
    )
    .await
    .expect("handler should return response");

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    let payload: Value = serde_json::from_slice(&body).expect("body should be valid json");

    assert_eq!(payload["dynamic_metadata"]["tenant"], "acme");
    assert_eq!(payload["dynamic_metadata"]["account_id"], "acct_1");
    assert_eq!(payload["dynamic_metadata"]["project_id"], "proj_1");
    assert_eq!(payload["dynamic_metadata"]["api_key_id"], "key_1");
    assert_eq!(payload["dynamic_metadata"]["api_key_status"], "active");
}

#[tokio::test]
async fn validate_authorino_api_key_with_null_allowed_models() {
    let mut project = mk_project();
    project.allowed_models = None; // NULL in DB
    project.default_limits = None;

    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let response = validate_authorino_api_key(
        axum::extract::State(state),
        Json(AuthorinoCheckRequest {
            api_key: "lbk_secret_valid".to_string(),
            ip: None,
            metadata: std::collections::HashMap::new(),
        }),
    )
    .await
    .expect("handler should return response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    
    // Verify allowed_models is null in JSON
    assert!(payload["project"]["allowed_models"].is_null());
}

#[tokio::test]
async fn validate_authorino_api_key_with_empty_allowed_models() {
    let mut project = mk_project();
    project.allowed_models = Some(vec![]); // [] in DB
    project.default_limits = None;

    let state = mk_state(MockOpaRepo {
        api_key: Some(mk_api_key(ApiKeyStatus::Active, None)),
        project: Some(project),
        account: Some(mk_account()),
        usage_calls: Arc::new(Mutex::new(vec![])),
    });

    let response = validate_authorino_api_key(
        axum::extract::State(state),
        Json(AuthorinoCheckRequest {
            api_key: "lbk_secret_valid".to_string(),
            ip: None,
            metadata: std::collections::HashMap::new(),
        }),
    )
    .await
    .expect("handler should return response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    
    // Verify allowed_models is [] in JSON
    assert!(payload["project"]["allowed_models"].is_array());
    assert_eq!(payload["project"]["allowed_models"].as_array().unwrap().len(), 0);
}
