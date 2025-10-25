use lightbridge_authz_api::contract::{APIKeyCrud, APIKeyHandler, APIKeyReader};
use lightbridge_authz_api_key::db::ApiKeyRepository;
use lightbridge_authz_core::api_key::{Acl, ApiKeyStatus, CreateApiKey, PatchApiKey};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_rest::handlers::APIKeyHandlerImpl;
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{Duration, Utc};
use serde_json::json;

// Inlined mock_repository module for integration tests
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

#[tokio::test]
async fn test_create_api_key_success() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let expires_at = Utc::now() + Duration::days(30);
    let metadata = json!({"purpose": "test"});
    let create_input = CreateApiKey {
        expires_at: Some(expires_at),
        metadata: Some(metadata.clone()),
        acl: Some(Acl::default()),
    };

    let api_key = handler
        .create_api_key(user_id.clone(), create_input)
        .await
        .unwrap();

    assert_eq!(api_key.user_id, user_id);
    assert_eq!(api_key.status, ApiKeyStatus::Active);
    assert_eq!(api_key.expires_at, Some(expires_at));
    assert_eq!(api_key.metadata, Some(metadata.clone()));

    let fetched_key = mock_repo
        .find_by_id(&user_id, &api_key.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_key.id, api_key.id);
    assert_eq!(fetched_key.expires_at, Some(expires_at));
    assert_eq!(fetched_key.metadata, Some(metadata));
}

#[tokio::test]
async fn test_get_api_key_success() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let create_input = CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(Acl::default()),
    };
    let created_key = handler
        .create_api_key(user_id.clone(), create_input)
        .await
        .unwrap();

    let fetched_key = handler
        .get_api_key(user_id.clone(), created_key.id.clone())
        .await
        .unwrap();

    assert_eq!(fetched_key.id, created_key.id);
    assert_eq!(fetched_key.user_id, user_id);
}

#[tokio::test]
async fn test_get_api_key_not_found() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let api_key_id = "non_existent_id".to_string();

    let result = handler.get_api_key(user_id, api_key_id).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::NotFound));
}

#[tokio::test]
async fn test_patch_api_key_success() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let create_input = CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(Acl::default()),
    };
    let created_key = handler
        .create_api_key(user_id.clone(), create_input)
        .await
        .unwrap();

    let mut new_metadata = HashMap::new();
    new_metadata.insert("purpose".to_string(), serde_json::json!("test"));

    let patch_input = PatchApiKey {
        expires_at: None,
        metadata: Some(serde_json::to_value(&new_metadata).unwrap()),
        status: Some(ApiKeyStatus::Revoked),
        acl: None,
    };

    let updated_key = handler
        .patch_api_key(user_id.clone(), created_key.id.clone(), patch_input)
        .await
        .unwrap();

    assert_eq!(updated_key.id, created_key.id);
    assert_eq!(updated_key.user_id, user_id);
    assert_eq!(updated_key.metadata.unwrap()["purpose"], "test");
    assert_eq!(updated_key.status, ApiKeyStatus::Revoked);
}

#[tokio::test]
async fn test_patch_api_key_not_found() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let api_key_id = "non_existent_id".to_string();
    let patch_input = PatchApiKey {
        expires_at: None,
        metadata: None,
        status: None,
        acl: None,
    };

    let result = handler
        .patch_api_key(user_id, api_key_id, patch_input)
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::NotFound));
}

#[tokio::test]
async fn test_delete_api_key_success() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let create_input = CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(Acl::default()),
    };
    let created_key = handler
        .create_api_key(user_id.clone(), create_input)
        .await
        .unwrap();

    let result = handler
        .delete_api_key(user_id.clone(), created_key.id.clone())
        .await;

    assert!(result.is_ok());

    let fetched_key = mock_repo
        .find_by_id(&user_id, &created_key.id)
        .await
        .unwrap();
    assert!(fetched_key.is_none());
}

#[tokio::test]
async fn test_delete_api_key_not_found() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id = "user123".to_string();
    let api_key_id = "non_existent_id".to_string();

    let result = handler.delete_api_key(user_id, api_key_id).await;

    assert!(result.is_ok()); // Delete is idempotent, so it should return Ok(()) even if not found
}

#[tokio::test]
async fn test_list_api_keys_success() {
    let mock_repo = Arc::new(MockApiKeyRepository::new());
    let handler = APIKeyHandlerImpl {
        repo: mock_repo.clone(),
    };

    let user_id_1 = "user1".to_string();
    let user_id_2 = "user2".to_string();

    let create_input = CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(Acl::default()),
    };

    handler
        .create_api_key(user_id_1.clone(), create_input.clone())
        .await
        .unwrap();
    handler
        .create_api_key(user_id_1.clone(), create_input.clone())
        .await
        .unwrap();
    handler
        .create_api_key(user_id_2.clone(), create_input.clone())
        .await
        .unwrap();

    let user1_keys = handler.list_api_keys(user_id_1.clone()).await.unwrap();
    assert_eq!(user1_keys.len(), 2);

    let user2_keys = handler.list_api_keys(user_id_2.clone()).await.unwrap();
    assert_eq!(user2_keys.len(), 1);

    let all_keys = mock_repo.list(100, 0).await.unwrap();
    assert_eq!(all_keys.len(), 3);
}
