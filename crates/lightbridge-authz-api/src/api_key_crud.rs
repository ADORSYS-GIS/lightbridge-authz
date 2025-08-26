use lightbridge_authz_core::{ApiKey, async_trait, error::Error};

#[async_trait]
pub trait APIKeyCrud: Send + Sync + 'static + std::fmt::Debug {
    /// Lists all API keys for a given user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The owner whose API keys should be listed.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `ApiKey` on success,
    /// or an `Error` if the operation fails.
    async fn list_api_keys(&self, user_id: String) -> Result<Vec<ApiKey>, Error>;
}
