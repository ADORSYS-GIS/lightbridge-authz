use goose::goose::GooseMethod;
use goose::metrics::{GooseRawRequest, GooseRequestMetric};
use goose::prelude::*;
use lightbridge_authz_api::contract::{APIKeyHandler, APIKeyReader};
use lightbridge_authz_core::api_key::{Acl, CreateApiKey};
use lightbridge_authz_rest::handlers::APIKeyHandlerImpl;
use std::sync::Arc;

mod mock_repository {
    use lightbridge_authz_api_key::db::ApiKeyRepository;
    use lightbridge_authz_core::{
        api_key::{ApiKey, ApiKeyStatus, CreateApiKey, PatchApiKey},
        async_trait,
        cuid::cuid2,
        error::Result,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, Default)]
    pub struct MockApiKeyRepository {
        api_keys: Arc<Mutex<HashMap<String, ApiKey>>>,
    }

    impl MockApiKeyRepository {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl ApiKeyRepository for MockApiKeyRepository {
        async fn create(
            &self,
            user_id: &str,
            input: CreateApiKey,
            key_hash: String,
        ) -> Result<ApiKey> {
            let mut api_keys = self.api_keys.lock().unwrap();
            let api_key = ApiKey {
                id: cuid2(),
                user_id: user_id.to_string(),
                key_hash,
                created_at: None,
                expires_at: input.expires_at,
                metadata: input.metadata,
                status: ApiKeyStatus::Active,
                acl: input.acl.unwrap_or_default(),
            };
            api_keys.insert(api_key.id.clone(), api_key.clone());
            Ok(api_key)
        }

        async fn update(
            &self,
            user_id: &str,
            api_key_id: &str,
            input: PatchApiKey,
        ) -> Result<ApiKey> {
            let mut api_keys = self.api_keys.lock().unwrap();
            if let Some(api_key) = api_keys.get_mut(api_key_id) {
                if api_key.user_id != user_id {
                    return Err(lightbridge_authz_core::error::Error::Any(anyhow::anyhow!(
                        "Forbidden"
                    )));
                }
                if let Some(status) = input.status {
                    api_key.status = status;
                }
                api_key.expires_at = input.expires_at.or(api_key.expires_at);
                api_key.metadata = input.metadata.or(api_key.metadata.clone());
                api_key.acl = input.acl.unwrap_or_default();
                Ok(api_key.clone())
            } else {
                Err(lightbridge_authz_core::error::Error::NotFound)
            }
        }

        async fn delete(&self, user_id: &str, api_key_id: &str) -> Result<()> {
            let mut api_keys = self.api_keys.lock().unwrap();
            if let Some(api_key) = api_keys.get(api_key_id) {
                if api_key.user_id != user_id {
                    return Err(lightbridge_authz_core::error::Error::Any(anyhow::anyhow!(
                        "Forbidden"
                    )));
                }
                api_keys.remove(api_key_id);
                Ok(())
            } else {
                Err(lightbridge_authz_core::error::Error::NotFound)
            }
        }

        async fn find_by_id(&self, user_id: &str, api_key_id: &str) -> Result<Option<ApiKey>> {
            let api_keys = self.api_keys.lock().unwrap();
            Ok(api_keys
                .get(api_key_id)
                .cloned()
                .filter(|key| key.user_id == user_id))
        }

        async fn find_all(&self, user_id: &str, _limit: i64, _offset: i64) -> Result<Vec<ApiKey>> {
            let api_keys = self.api_keys.lock().unwrap();
            Ok(api_keys
                .values()
                .filter(|key| key.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn find_by_token(&self, token: &str) -> Result<Option<ApiKey>> {
            let api_keys = self.api_keys.lock().unwrap();
            Ok(api_keys
                .values()
                .find(|key| key.key_hash == token) // Assuming token is the key_hash
                .cloned())
        }

        async fn find_api_key_for_authz(&self, token: &str) -> Result<Option<ApiKey>> {
            let api_keys = self.api_keys.lock().unwrap();
            Ok(api_keys
                .values()
                .find(|key| key.key_hash == token && key.status == ApiKeyStatus::Active)
                .cloned())
        }

        async fn list(&self, _limit: i64, _offset: i64) -> Result<Vec<ApiKey>> {
            let api_keys = self.api_keys.lock().unwrap();
            Ok(api_keys.values().cloned().collect())
        }
    }
}

use mock_repository::MockApiKeyRepository;

async fn loadtest_create_api_key(user: &mut GooseUser) -> TransactionResult {
    let handler = APIKeyHandlerImpl {
        repo: Arc::new(MockApiKeyRepository::new()),
    };

    let user_id = format!("user_{}", user.weighted_users_index);
    let create_input = CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(Acl::default()),
    };

    let _ = handler
        .create_api_key(user_id.clone(), create_input)
        .await
        .map_err(|e| {
            let dummy_raw_request = GooseRawRequest {
                method: GooseMethod::Get,
                url: "/".to_string(),
                headers: Default::default(),
                body: "".to_string(),
            };
            let dummy_request_metric = GooseRequestMetric {
                elapsed: 0,
                scenario_index: 0,
                scenario_name: "loadtest".to_string(),
                transaction_index: "".to_string(),
                transaction_name: "".to_string(),
                raw: dummy_raw_request,
                name: "error_request".to_string(),
                final_url: "/".to_string(),
                redirected: false,
                response_time: 0,
                status_code: 500,
                success: false,
                update: false,
                user: user.weighted_users_index,
                error: e.to_string(),
                coordinated_omission_elapsed: 0,
                user_cadence: 0,
            };
            TransactionError::RequestFailed {
                raw_request: dummy_request_metric,
            }
        })?;

    Ok(())
}

async fn loadtest_get_api_key(user: &mut GooseUser) -> TransactionResult {
    let handler = APIKeyHandlerImpl {
        repo: Arc::new(MockApiKeyRepository::new()),
    };

    let user_id = format!("user_{}", user.weighted_users_index);
    let create_input = CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(Acl::default()),
    };
    let created_key = handler
        .create_api_key(user_id.clone(), create_input)
        .await
        .map_err(|e| {
            let dummy_raw_request = GooseRawRequest {
                method: GooseMethod::Get,
                url: "/".to_string(),
                headers: Default::default(),
                body: "".to_string(),
            };
            let dummy_request_metric = GooseRequestMetric {
                elapsed: 0,
                scenario_index: 0,
                scenario_name: "loadtest".to_string(),
                transaction_index: "".to_string(),
                transaction_name: "".to_string(),
                raw: dummy_raw_request,
                name: "error_request".to_string(),
                final_url: "/".to_string(),
                redirected: false,
                response_time: 0,
                status_code: 500,
                success: false,
                update: false,
                user: user.weighted_users_index,
                error: e.to_string(),
                coordinated_omission_elapsed: 0,
                user_cadence: 0,
            };
            TransactionError::RequestFailed {
                raw_request: dummy_request_metric,
            }
        })?;

    let _ = handler
        .get_api_key(user_id.clone(), created_key.id.clone())
        .await
        .map_err(|e| {
            let dummy_raw_request = GooseRawRequest {
                method: GooseMethod::Get,
                url: "/".to_string(),
                headers: Default::default(),
                body: "".to_string(),
            };
            let dummy_request_metric = GooseRequestMetric {
                elapsed: 0,
                scenario_index: 0,
                scenario_name: "loadtest".to_string(),
                transaction_index: "".to_string(),
                transaction_name: "".to_string(),
                raw: dummy_raw_request,
                name: "error_request".to_string(),
                final_url: "/".to_string(),
                redirected: false,
                response_time: 0,
                status_code: 500,
                success: false,
                update: false,
                user: user.weighted_users_index,
                error: e.to_string(),
                coordinated_omission_elapsed: 0,
                user_cadence: 0,
            };
            TransactionError::RequestFailed {
                raw_request: dummy_request_metric,
            }
        })?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("API Key Operations")
                .register_transaction(transaction!(loadtest_create_api_key))
                .register_transaction(transaction!(loadtest_get_api_key)),
        )
        .execute()
        .await?;

    Ok(())
}
