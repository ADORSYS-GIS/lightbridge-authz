use async_trait::async_trait;
use lightbridge_authz_api::contract::{APIKeyCrud, APIKeyHandler, APIKeyReader};
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

    async fn patch_api_key(
        &self,
        _user_id: String,
        api_key_id: String,
        input: PatchApiKey,
    ) -> Result<ApiKey> {
        // User authorization/ownership can be enforced at a higher layer or here when needed.
        let acl = input.acl.unwrap_or_default();
        lightbridge_authz_api_key::update_api_key(&self.pool, &api_key_id, acl).await
    }

    async fn delete_api_key(&self, _user_id: String, api_key_id: String) -> Result<()> {
        // If required, verify that `user_id` owns `api_key_id` before deletion.
        lightbridge_authz_api_key::delete_api_key(&self.pool, &api_key_id).await
    }
}

#[async_trait]
impl APIKeyReader for APIKeyHandlerImpl {
    async fn get_api_key(&self, api_key_id: String) -> Result<ApiKey> {
        let opt = lightbridge_authz_api_key::get_api_key(&self.pool, &api_key_id).await?;
        opt.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }
}

#[async_trait]
impl APIKeyCrud for APIKeyHandlerImpl {
    async fn list_api_keys(&self, user_id: String) -> Result<Vec<ApiKey>> {
        lightbridge_authz_api_key::list_api_keys(&self.pool, &user_id).await
    }
}
