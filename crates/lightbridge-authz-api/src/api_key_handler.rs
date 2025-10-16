use lightbridge_authz_core::{ApiKey, CreateApiKey, PatchApiKey, async_trait, error::Error};

use crate::{api_key_crud::APIKeyCrud, api_key_reader::APIKeyReader};

#[async_trait]
pub trait APIKeyHandler:
    APIKeyCrud + APIKeyReader + Send + Sync + 'static + std::fmt::Debug
{
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
    async fn create_api_key(&self, user_id: String, input: CreateApiKey) -> Result<ApiKey, Error>;

    /// Updates an existing API key belonging to a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The owner of the API key.
    /// * `api_key_id` - The ID of the API key to update.
    /// * `input` - The data to patch the API key with.
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn patch_api_key(
        &self,
        user_id: String,
        api_key_id: String,
        input: PatchApiKey,
    ) -> Result<ApiKey, Error>;

    /// Deletes an API key by its ID for a specific user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The owner of the API key.
    /// * `api_key_id` - The unique identifier of the API key to delete.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the deletion operation.
    async fn delete_api_key(&self, user_id: String, api_key_id: String) -> Result<(), Error>;
}
