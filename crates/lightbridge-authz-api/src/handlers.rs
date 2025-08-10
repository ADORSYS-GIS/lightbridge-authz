use async_trait::async_trait;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::{ApiKey, CreateApiKey, PatchApiKey};

/// Defines the core API key handling logic.
/// This trait serves as a contract for managing API keys,
/// ensuring a consistent interface across different implementations.
#[async_trait]
pub trait APIKeyHandler: APIKeyCrud + Send + Sync + 'static + std::fmt::Debug {
    /// Creates a new API key.
    ///
    /// # Arguments
    ///
    /// * `input` - The data required to create a new API key.
    ///
    /// # Returns
    ///
    /// A `Result` containing the newly created `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn create_api_key(&self, user_id: String, input: CreateApiKey) -> Result<ApiKey>;

    /// Retrieves an API key by its ID.
    ///
    /// # Arguments
    ///
    /// * `api_key_id` - The unique identifier of the API key to retrieve.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `ApiKey` if found,
    /// or an `Error` if the API key does not exist or an issue occurs.
    async fn get_api_key(&self, api_key_id: String) -> Result<ApiKey>;

    /// Updates an existing API key.
    ///
    /// # Arguments
    ///
    /// * `api_key_id` - The ID of the API key to update.
    /// * `input` - The data to patch the API key with.
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn patch_api_key(&self, api_key_id: String, input: PatchApiKey) -> Result<ApiKey>;

    /// Deletes an API key by its ID.
    ///
    /// # Arguments
    ///
    /// * `api_key_id` - The unique identifier of the API key to delete.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the deletion operation.
    async fn delete_api_key(&self, api_key_id: String) -> Result<()>;
}

/// Defines CRUD operations for API keys.
/// This trait provides a more granular contract for specific API key management actions.
#[async_trait]
pub trait APIKeyCrud: Send + Sync + 'static + std::fmt::Debug {
    /// Lists all API keys.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn list_api_keys(&self) -> Result<Vec<ApiKey>>;
}
