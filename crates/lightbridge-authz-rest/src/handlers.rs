use lightbridge_authz_api::contract::{APIKeyCrud, APIKeyHandler, APIKeyReader};
use lightbridge_authz_api_key::db::{ApiKeyRepo, ApiKeyRepository};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::cuid::{cuid2, cuid2_slug};
use lightbridge_authz_core::{
    api_key::{Acl, ApiKey, CreateApiKey, PatchApiKey},
    db::DbPoolTrait,
    error::Result,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct APIKeyHandlerImpl {
    pub repo: Arc<dyn ApiKeyRepository>,
}

impl std::fmt::Debug for APIKeyHandlerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("APIKeyHandlerImpl").finish()
    }
}

impl APIKeyHandlerImpl {
    pub fn with_pool(pool: Arc<dyn DbPoolTrait>) -> Self {
        let repo = ApiKeyRepo::new(pool);
        Self {
            repo: Arc::new(repo),
        }
    }
}

#[async_trait]
impl APIKeyHandler for APIKeyHandlerImpl {
    async fn create_api_key(&self, user_id: String, input: CreateApiKey) -> Result<ApiKey> {
        // Use the api-key service which generates the key and persists it.
        let acl: Acl = input.acl.unwrap_or_default();

        let create_api_key = CreateApiKey {
            expires_at: None,
            metadata: None,
            acl: Some(acl),
        };
        let key_plain = format!("sk-{}-{}", cuid2_slug(), cuid2());
        self.repo.create(&user_id, create_api_key, key_plain).await
    }

    async fn patch_api_key(
        &self,
        user_id: String,
        api_key_id: String,
        input: PatchApiKey,
    ) -> Result<ApiKey> {
        // User authorization/ownership can be enforced at a higher layer or here when needed.
        let acl = input.acl.unwrap_or_default();
        let patch_api_key = PatchApiKey {
            expires_at: input.expires_at,
            metadata: input.metadata,
            status: input.status,
            acl: Some(acl),
        };
        self.repo.update(&user_id, &api_key_id, patch_api_key).await
    }

    async fn delete_api_key(&self, user_id: String, api_key_id: String) -> Result<()> {
        let _ = self.repo.delete(&user_id, &api_key_id).await;
        Ok(())
    }
}

#[async_trait]
impl APIKeyReader for APIKeyHandlerImpl {
    async fn get_api_key(&self, user_id: String, api_key_id: String) -> Result<ApiKey> {
        let opt = self.repo.find_by_id(&user_id, &api_key_id).await?;
        opt.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }
}

#[async_trait]
impl APIKeyCrud for APIKeyHandlerImpl {
    async fn list_api_keys(&self, user_id: String) -> Result<Vec<ApiKey>> {
        self.repo.find_all(&user_id, 100, 0).await
    }
}
