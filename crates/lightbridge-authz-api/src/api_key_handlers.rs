use async_trait::async_trait;
use lightbridge_authz_core::CreateApiKey;
use lightbridge_authz_core::api_key::{Acl, ApiKey};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Result;
use std::sync::Arc;

/// Defines the API key handling logic using the lightbridge-authz-api-key crate.
/// This trait serves as a contract for managing API keys,
/// ensuring a consistent interface across different implementations.
#[async_trait]
pub trait APIKeyHandlerViaCrate:
    APIKeyCrudViaCrate + Send + Sync + 'static + std::fmt::Debug
{
    /// Creates a new API key for a specific user.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `user_id` - The owner of the API key.
    /// * `input` - The data required to create a new API key.
    ///
    /// # Returns
    ///
    /// A `Result` containing the newly created `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn create_api_key(
        &self,
        pool: Arc<DbPool>,
        user_id: String,
        input: CreateApiKey,
    ) -> Result<ApiKey>;

    /// Retrieves an API key by its key string for a specific user.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `user_id` - The owner of the API key.
    /// * `key` - The key string of the API key to retrieve.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `ApiKey` if found,
    /// or an `Error` if the API key does not exist or an issue occurs.
    async fn get_api_key(&self, pool: Arc<DbPool>, user_id: String, key: String) -> Result<ApiKey>;

    /// Updates an existing API key for a specific user.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `user_id` - The owner of the API key.
    /// * `key` - The key string of the API key to update.
    /// * `acl` - The ACL to update the API key with.
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn update_api_key(
        &self,
        pool: Arc<DbPool>,
        user_id: String,
        key: String,
        acl: Acl,
    ) -> Result<ApiKey>;

    /// Deletes (revokes) an API key by its key string for a specific user.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `user_id` - The owner of the API key.
    /// * `key` - The key string of the API key to delete.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the deletion operation.
    async fn delete_api_key(&self, pool: Arc<DbPool>, user_id: String, key: String) -> Result<()>;
}

/// Defines CRUD operations for API keys using the lightbridge-authz-api-key crate.
/// This trait provides a more granular contract for specific API key management actions.
#[async_trait]
pub trait APIKeyCrudViaCrate: Send + Sync + 'static + std::fmt::Debug {
    /// Lists API keys for a specific user.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `user_id` - The owner whose API keys should be listed.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn list_api_keys(&self, pool: Arc<DbPool>, user_id: String) -> Result<Vec<ApiKey>>;
}

/// Implementation of APIKeyHandlerViaCrate that uses the lightbridge-authz-api-key crate.
#[derive(Debug, Clone)]
pub struct APIKeyHandlerViaCrateImpl;

#[async_trait]
impl APIKeyHandlerViaCrate for APIKeyHandlerViaCrateImpl {
    async fn create_api_key(
        &self,
        pool: Arc<DbPool>,
        user_id: String,
        input: CreateApiKey,
    ) -> Result<ApiKey> {
        // Extract ACL from input or use default
        let acl = input.acl.unwrap_or_default();

        // Forward to the api-key crate which expects (pool, user_id, acl)
        lightbridge_authz_api_key::create_api_key(&pool, &user_id, acl).await
    }

    async fn get_api_key(&self, pool: Arc<DbPool>, user_id: String, key: String) -> Result<ApiKey> {
        let opt = lightbridge_authz_api_key::get_api_key(&pool, &user_id, &key).await?;
        opt.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_api_key(
        &self,
        pool: Arc<DbPool>,
        user_id: String,
        key: String,
        acl: Acl,
    ) -> Result<ApiKey> {
        lightbridge_authz_api_key::update_api_key(&pool, &user_id, &key, acl).await
    }

    async fn delete_api_key(&self, pool: Arc<DbPool>, user_id: String, key: String) -> Result<()> {
        lightbridge_authz_api_key::delete_api_key(&pool, &user_id, &key).await
    }
}

#[async_trait]
impl APIKeyCrudViaCrate for APIKeyHandlerViaCrateImpl {
    async fn list_api_keys(&self, pool: Arc<DbPool>, user_id: String) -> Result<Vec<ApiKey>> {
        // Delegate to the api-key crate which filters by user
        lightbridge_authz_api_key::list_api_keys(&pool, &user_id).await
    }
}
