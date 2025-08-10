use async_trait::async_trait;
use lightbridge_authz_api::contract::{APIKeyCrud, APIKeyHandler};
use lightbridge_authz_core::{
    api_key::{Acl, ApiKey, CreateApiKey, PatchApiKey},
    db::DbPool,
    error::Result,
};
use std::sync::Arc;

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
    async fn create_api_key(&self, user_id: String, input: CreateApiKey) -> Result<ApiKey> {
        // Use the api-key service which generates the key and persists it.
        let acl: Acl = input.acl.unwrap_or_default();
        lightbridge_authz_api_key::create_api_key(&self.pool, &user_id, acl).await
    }

    async fn get_api_key(&self, api_key_id: String) -> Result<ApiKey> {
        let opt = lightbridge_authz_api_key::get_api_key(&self.pool, &api_key_id).await?;
        opt.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn patch_api_key(&self, api_key_id: String, input: PatchApiKey) -> Result<ApiKey> {
        let acl = input.acl.unwrap_or_default();
        lightbridge_authz_api_key::update_api_key(&self.pool, &api_key_id, acl).await
    }

    async fn delete_api_key(&self, api_key_id: String) -> Result<()> {
        lightbridge_authz_api_key::delete_api_key(&self.pool, &api_key_id).await
    }
}

#[async_trait]
impl APIKeyCrud for APIKeyHandlerImpl {
    async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        lightbridge_authz_api_key::list_api_keys(&self.pool).await
    }
}
