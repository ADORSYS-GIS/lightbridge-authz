use async_trait::async_trait;
use lightbridge_authz_api::contract::{APIKeyCrud, APIKeyHandler};
use lightbridge_authz_core::{
    api_key::{ApiKey, CreateApiKey, PatchApiKey},
    db::DbPool,
    error::Result,
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct APIKeyHandlerImpl {
    pool: Arc<DbPool>,
}

impl APIKeyHandlerImpl {
    pub fn with_pool(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl APIKeyHandler for APIKeyHandlerImpl {
    async fn create_api_key(&self, input: CreateApiKey) -> Result<ApiKey> {
        let repo = lightbridge_authz_core::db::ApiKeyRepo;
        // TODO: generate a real key
        repo.create(&self.pool, input, "some_key".to_string()).await
    }

    async fn get_api_key(&self, api_key_id: String) -> Result<ApiKey> {
        let repo = lightbridge_authz_core::db::ApiKeyRepo;
        let uuid = Uuid::parse_str(&api_key_id)
            .map_err(|_| lightbridge_authz_core::error::Error::NotFound)?;
        repo.get_by_id(&self.pool, uuid)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn patch_api_key(&self, api_key_id: String, input: PatchApiKey) -> Result<ApiKey> {
        let repo = lightbridge_authz_core::db::ApiKeyRepo;
        let uuid = Uuid::parse_str(&api_key_id)
            .map_err(|_| lightbridge_authz_core::error::Error::NotFound)?;
        repo.patch(&self.pool, uuid, input).await
    }

    async fn delete_api_key(&self, api_key_id: String) -> Result<()> {
        let repo = lightbridge_authz_core::db::ApiKeyRepo;
        let uuid = Uuid::parse_str(&api_key_id)
            .map_err(|_| lightbridge_authz_core::error::Error::NotFound)?;
        repo.revoke(&self.pool, uuid).await?;
        Ok(())
    }
}

#[async_trait]
impl APIKeyCrud for APIKeyHandlerImpl {
    async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        let repo = lightbridge_authz_core::db::ApiKeyRepo;
        repo.list(&self.pool, 100, 0).await
    }
}
