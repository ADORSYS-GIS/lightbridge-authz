use chrono::Utc;
use lightbridge_authz_api_key::db::ApiKeyRepository;
use lightbridge_authz_core::{
    api_key::{ApiKey, ApiKeyStatus, CreateApiKey},
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
    async fn create(&self, user_id: &str, input: CreateApiKey, key_hash: String) -> Result<ApiKey> {
        let mut api_keys = self.api_keys.lock().unwrap();
        let api_key = ApiKey {
            id: cuid2(),
            user_id: user_id.to_string(),
            key_hash,
            created_at: Utc::now(),
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
        input: lightbridge_authz_core::api_key::PatchApiKey,
    ) -> Result<ApiKey> {
        let mut api_keys = self.api_keys.lock().unwrap();
        api_keys
            .get_mut(api_key_id)
            .filter(|api_key| api_key.user_id == user_id)
            .map(|api_key| {
                if let Some(status) = input.status {
                    api_key.status = status;
                }
                api_key.expires_at = input.expires_at.or(api_key.expires_at);
                api_key.metadata = input.metadata.or(api_key.metadata.clone());
                api_key.acl = input.acl.unwrap_or_default();
                Ok(api_key.clone())
            })
            .unwrap_or(Err(lightbridge_authz_core::error::Error::Any(
                anyhow::anyhow!("Forbidden"),
            )))
            .map_err(|_| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn delete(&self, user_id: &str, api_key_id: &str) -> Result<()> {
        let mut api_keys = self.api_keys.lock().unwrap();
        match api_keys.get(api_key_id) {
            Some(api_key) if api_key.user_id == user_id => {
                api_keys.remove(api_key_id);
                Ok(())
            }
            Some(_) => Err(lightbridge_authz_core::error::Error::Any(anyhow::anyhow!(
                "Forbidden"
            ))),
            None => Err(lightbridge_authz_core::error::Error::NotFound),
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
