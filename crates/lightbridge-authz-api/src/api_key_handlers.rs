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
    /// Creates a new API key.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `input` - The data required to create a new API key.
    ///
    /// # Returns
    ///
    /// A `Result` containing the newly created `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn create_api_key(&self, pool: Arc<DbPool>, input: CreateApiKey) -> Result<ApiKey>;

    /// Retrieves an API key by its key string.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `key` - The key string of the API key to retrieve.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `ApiKey` if found,
    /// or an `Error` if the API key does not exist or an issue occurs.
    async fn get_api_key(&self, pool: Arc<DbPool>, key: String) -> Result<ApiKey>;

    /// Updates an existing API key.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `key` - The key string of the API key to update.
    /// * `acl` - The ACL to update the API key with.
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn update_api_key(&self, pool: Arc<DbPool>, key: String, acl: Acl) -> Result<ApiKey>;

    /// Deletes an API key by its key string.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database pool to use for the operation.
    /// * `key` - The key string of the API key to delete.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the deletion operation.
    async fn delete_api_key(&self, pool: Arc<DbPool>, key: String) -> Result<()>;
}

/// Defines CRUD operations for API keys using the lightbridge-authz-api-key crate.
/// This trait provides a more granular contract for specific API key management actions.
#[async_trait]
pub trait APIKeyCrudViaCrate: Send + Sync + 'static + std::fmt::Debug {
    // Currently no list operation in the api-key crate, so we'll leave this empty for now
}

/// Implementation of APIKeyHandlerViaCrate that uses the lightbridge-authz-api-key crate.
#[derive(Debug, Clone)]
pub struct APIKeyHandlerViaCrateImpl;

#[async_trait]
impl APIKeyHandlerViaCrate for APIKeyHandlerViaCrateImpl {
    async fn create_api_key(&self, pool: Arc<DbPool>, input: CreateApiKey) -> Result<ApiKey> {
        // Extract ACL from input or use default
        let acl = input.acl.unwrap_or_default();

        // TODO: Extract user_id from request context
        let user_id = "default_user";

        lightbridge_authz_api_key::create_api_key(&pool, user_id, acl).await
    }

    async fn get_api_key(&self, pool: Arc<DbPool>, key: String) -> Result<ApiKey> {
        lightbridge_authz_api_key::get_api_key(&pool, &key)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_api_key(&self, pool: Arc<DbPool>, key: String, acl: Acl) -> Result<ApiKey> {
        lightbridge_authz_api_key::update_api_key(&pool, &key, acl).await
    }

    async fn delete_api_key(&self, pool: Arc<DbPool>, key: String) -> Result<()> {
        lightbridge_authz_api_key::delete_api_key(&pool, &key).await
    }
}

#[async_trait]
impl APIKeyCrudViaCrate for APIKeyHandlerViaCrateImpl {
    // No CRUD operations needed for now
}
