pub mod db;
mod entities;
mod mappers;
mod repo;

use lightbridge_authz_core::api_key::{Acl, ApiKey, PatchApiKey};
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Result;

pub async fn create_api_key(pool: &DbPool, _user_id: &str, acl: Acl) -> Result<ApiKey> {
    let repo = db::ApiKeyRepo;
    let create_api_key = lightbridge_authz_core::api_key::CreateApiKey {
        expires_at: None,
        metadata: None,
        acl: Some(acl),
    };
    let key_plain = format!("sk-{}", cuid::cuid2());
    repo.create(pool, create_api_key, key_plain).await
}

pub async fn get_api_key(pool: &DbPool, key_id: &str) -> Result<Option<ApiKey>> {
    let repo = db::ApiKeyRepo;
    repo.get_by_id(pool, key_id).await
}

pub async fn update_api_key(pool: &DbPool, key_id: &str, acl: Acl) -> Result<ApiKey> {
    let repo = db::ApiKeyRepo;
    let patch_api_key = PatchApiKey {
        expires_at: None,
        metadata: None,
        status: None,
        acl: Some(acl),
    };
    repo.patch(pool, key_id, patch_api_key).await
}

pub async fn delete_api_key(pool: &DbPool, key_id: &str) -> Result<()> {
    let repo = db::ApiKeyRepo;
    let _ = repo.revoke(pool, key_id).await;
    Ok(())
}
