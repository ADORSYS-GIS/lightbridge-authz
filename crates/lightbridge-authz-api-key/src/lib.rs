use lightbridge_authz_core::api_key::{Acl, ApiKey};
use lightbridge_authz_core::db::{ApiKeyRepo, DbPool};
use lightbridge_authz_core::error::Result;
use uuid::Uuid;

/// Create a new API key with the specified user ID and ACL.
///
/// # Arguments
///
/// * `pool` - The database pool to use for the operation
/// * `user_id` - The user ID to associate with the API key
/// * `acl` - The ACL to associate with the API key
///
/// # Returns
///
/// The newly created API key
pub async fn create_api_key(pool: &DbPool, _user_id: &str, acl: Acl) -> Result<ApiKey> {
    let api_key_repo = ApiKeyRepo;
    // TODO: Implement user ID handling
    let create_api_key = lightbridge_authz_core::api_key::CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(acl),
    };

    // Generate a random API key
    let key_plain = format!("sk-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

    api_key_repo.create(pool, create_api_key, key_plain).await
}

/// Get an API key by its key string.
///
/// # Arguments
///
/// * `pool` - The database pool to use for the operation
/// * `key` - The key string of the API key to retrieve
///
/// # Returns
///
/// The API key if found, or None if not found
pub async fn get_api_key(pool: &DbPool, key: &str) -> Result<Option<ApiKey>> {
    let api_key_repo = ApiKeyRepo;
    // TODO: Implement key lookup by key string
    // For now, we'll assume the key is a UUID
    let key_id = match Uuid::parse_str(key) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    api_key_repo.get_by_id(pool, key_id).await
}

/// Update an API key with the specified key string and ACL.
///
/// # Arguments
///
/// * `pool` - The database pool to use for the operation
/// * `key` - The key string of the API key to update
/// * `acl` - The new ACL to associate with the API key
///
/// # Returns
///
/// The updated API key
pub async fn update_api_key(pool: &DbPool, key: &str, acl: Acl) -> Result<ApiKey> {
    let api_key_repo = ApiKeyRepo;
    // TODO: Implement key lookup and update by key string
    // For now, we'll assume the key is a UUID
    let key_id = Uuid::parse_str(key).map_err(|_| {
        lightbridge_authz_core::error::Error::Any(anyhow::anyhow!("Invalid key format"))
    })?;

    let patch_api_key = lightbridge_authz_core::api_key::PatchApiKey {
        expires_at: None,
        metadata: None,
        status: None,
        acl: Some(acl),
    };

    api_key_repo.patch(pool, key_id, patch_api_key).await
}

/// Delete an API key by its key string.
///
/// # Arguments
///
/// * `pool` - The database pool to use for the operation
/// * `key` - The key string of the API key to delete
///
/// # Returns
///
/// A result indicating success or failure
pub async fn delete_api_key(pool: &DbPool, key: &str) -> Result<()> {
    let api_key_repo = ApiKeyRepo;
    // TODO: Implement key lookup and deletion by key string
    // For now, we'll assume the key is a UUID
    let key_id = Uuid::parse_str(key).map_err(|_| {
        lightbridge_authz_core::error::Error::Any(anyhow::anyhow!("Invalid key format"))
    })?;

    // For now, we'll just revoke the key instead of deleting it
    let _ = api_key_repo.revoke(pool, key_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // TODO: Add tests
    }
}
