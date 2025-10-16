use lightbridge_authz_core::{ApiKey, async_trait, error::Error};

#[async_trait]
pub trait APIKeyReader: Send + Sync + 'static + std::fmt::Debug {
    /// Retrieves an API key by its ID for a specific user (read-only).
    ///
    /// This method requires a user context so that API key lookups can be
    /// scoped/authorized by owner. It is intended for use by services that
    /// need to validate or fetch keys within the context of the owning user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The owner of the API key.
    /// * `api_key_id` - The unique identifier of the API key to retrieve.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `ApiKey` if found,
    /// or an `Error` if the API key does not exist or an issue occurs.
    async fn get_api_key(&self, user_id: String, api_key_id: String) -> Result<ApiKey, Error>;
}
