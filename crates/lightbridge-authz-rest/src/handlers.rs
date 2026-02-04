use std::sync::Arc;

use base64::Engine;
use chrono::{Duration, Utc};
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::{
    hash_api_key, Account, ApiKey, ApiKeySecret, ApiKeyStatus, CreateAccount, CreateApiKey,
    CreateProject, Project, RotateApiKey, UpdateAccount, UpdateApiKey, UpdateProject,
};
use lightbridge_authz_core::{db::DbPoolTrait, error::Result};
use rand::RngCore;

#[derive(Clone)]
pub struct AuthzStoreImpl {
    repo: Arc<StoreRepo>,
}

impl std::fmt::Debug for AuthzStoreImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthzStoreImpl").finish()
    }
}

impl AuthzStoreImpl {
    pub fn with_pool(pool: Arc<dyn DbPoolTrait>) -> Self {
        let repo = StoreRepo::new(pool);
        Self {
            repo: Arc::new(repo),
        }
    }

    fn generate_secret() -> String {
        let mut bytes = [0u8; 32];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut bytes);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        format!("lbk_{}", encoded)
    }

    fn key_prefix(secret: &str) -> String {
        secret.chars().take(8).collect()
    }
}

#[async_trait]
impl AuthzStore for AuthzStoreImpl {
    async fn create_account(&self, input: CreateAccount) -> Result<Account> {
        self.repo.create_account(input, cuid2()).await
    }

    async fn list_accounts(&self) -> Result<Vec<Account>> {
        self.repo.list_accounts().await
    }

    async fn get_account(&self, account_id: &str) -> Result<Account> {
        self.repo
            .get_account(account_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_account(&self, account_id: &str, input: UpdateAccount) -> Result<Account> {
        self.repo.update_account(account_id, input).await
    }

    async fn delete_account(&self, account_id: &str) -> Result<()> {
        self.repo.delete_account(account_id).await
    }

    async fn create_project(&self, account_id: &str, input: CreateProject) -> Result<Project> {
        self.repo.create_project(account_id, input, cuid2()).await
    }

    async fn list_projects(&self, account_id: &str) -> Result<Vec<Project>> {
        self.repo.list_projects(account_id).await
    }

    async fn get_project(&self, project_id: &str) -> Result<Project> {
        self.repo
            .get_project(project_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_project(&self, project_id: &str, input: UpdateProject) -> Result<Project> {
        self.repo.update_project(project_id, input).await
    }

    async fn delete_project(&self, project_id: &str) -> Result<()> {
        self.repo.delete_project(project_id).await
    }

    async fn create_api_key(&self, project_id: &str, input: CreateApiKey) -> Result<ApiKeySecret> {
        let secret = Self::generate_secret();
        let key_hash = hash_api_key(&secret);
        let key_prefix = Self::key_prefix(&secret);
        let now = Utc::now();
        let row = lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow {
            id: cuid2(),
            project_id: project_id.to_string(),
            name: input.name,
            key_prefix,
            key_hash,
            created_at: now,
            expires_at: input.expires_at,
            status: ApiKeyStatus::Active.to_string(),
            last_used_at: None,
            last_ip: None,
            last_region: None,
            revoked_at: None,
        };
        let api_key = self.repo.create_api_key(row).await?;
        Ok(ApiKeySecret { api_key, secret })
    }

    async fn list_api_keys(&self, project_id: &str) -> Result<Vec<ApiKey>> {
        self.repo.list_api_keys(project_id).await
    }

    async fn get_api_key(&self, key_id: &str) -> Result<ApiKey> {
        self.repo
            .get_api_key(key_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_api_key(&self, key_id: &str, input: UpdateApiKey) -> Result<ApiKey> {
        self.repo.update_api_key(key_id, input).await
    }

    async fn delete_api_key(&self, key_id: &str) -> Result<()> {
        self.repo.delete_api_key(key_id).await
    }

    async fn revoke_api_key(&self, key_id: &str) -> Result<ApiKey> {
        self.repo
            .set_api_key_status(key_id, ApiKeyStatus::Revoked, Some(Utc::now()), None)
            .await
    }

    async fn rotate_api_key(&self, key_id: &str, input: RotateApiKey) -> Result<ApiKeySecret> {
        let existing = self
            .repo
            .get_api_key(key_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;

        let now = Utc::now();
        if let Some(grace) = input.grace_period_seconds.filter(|v| *v > 0) {
            let grace_exp = now + Duration::seconds(grace);
            let expires_at = match existing.expires_at {
                Some(existing_exp) if existing_exp < grace_exp => Some(existing_exp),
                _ => Some(grace_exp),
            };
            let _ = self
                .repo
                .set_api_key_status(key_id, ApiKeyStatus::Active, None, expires_at)
                .await?;
        } else {
            let _ = self
                .repo
                .set_api_key_status(key_id, ApiKeyStatus::Revoked, Some(now), None)
                .await?;
        }

        let secret = Self::generate_secret();
        let key_hash = hash_api_key(&secret);
        let key_prefix = Self::key_prefix(&secret);
        let row = lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow {
            id: cuid2(),
            project_id: existing.project_id,
            name: input.name.unwrap_or(existing.name),
            key_prefix,
            key_hash,
            created_at: now,
            expires_at: input.expires_at,
            status: ApiKeyStatus::Active.to_string(),
            last_used_at: None,
            last_ip: None,
            last_region: None,
            revoked_at: None,
        };
        let api_key = self.repo.create_api_key(row).await?;
        Ok(ApiKeySecret { api_key, secret })
    }
}
