pub mod authorino;
pub mod opa;

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use getrandom::fill;
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, ApiKeyStatus, CreateAccount, CreateApiKey, CreateProject,
    Project, RotateApiKey, UpdateAccount, UpdateApiKey, UpdateProject, hash_api_key,
};
use lightbridge_authz_core::{db::DbPoolTrait, error::Result};

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

    fn generate_secret() -> Result<String> {
        let mut bytes = [0u8; 32];
        fill(&mut bytes)
            .map_err(|e| lightbridge_authz_core::error::Error::Database(e.to_string()))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        Ok(format!("lbk_secret_{}", encoded))
    }

    fn key_prefix(secret: &str) -> String {
        const SECRET_PREFIX: &str = "lbk_secret_";
        if let Some(after_prefix) = secret.strip_prefix(SECRET_PREFIX) {
            after_prefix.chars().take(8).collect()
        } else {
            secret.chars().take(8).collect()
        }
    }
}

fn resolve_rotated_expires_at(
    input: Option<DateTime<Utc>>,
    existing: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    input.or(existing)
}

#[async_trait]
impl AuthzStore for AuthzStoreImpl {
    async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account> {
        self.repo.create_account(subject, input, cuid2()).await
    }

    async fn list_accounts(&self, subject: &str) -> Result<Vec<Account>> {
        self.repo.list_accounts(subject).await
    }

    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo
            .get_account(subject, account_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_account(
        &self,
        subject: &str,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account> {
        self.repo.update_account(subject, account_id, input).await
    }

    async fn delete_account(&self, subject: &str, account_id: &str) -> Result<()> {
        self.repo.delete_account(subject, account_id).await
    }

    async fn create_project(
        &self,
        subject: &str,
        account_id: &str,
        input: CreateProject,
    ) -> Result<Project> {
        self.repo
            .create_project(subject, account_id, input, cuid2())
            .await
    }

    async fn list_projects(&self, subject: &str, account_id: &str) -> Result<Vec<Project>> {
        self.repo.list_projects(subject, account_id).await
    }

    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo
            .get_project(subject, project_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_project(
        &self,
        subject: &str,
        project_id: &str,
        input: UpdateProject,
    ) -> Result<Project> {
        self.repo.update_project(subject, project_id, input).await
    }

    async fn delete_project(&self, subject: &str, project_id: &str) -> Result<()> {
        self.repo.delete_project(subject, project_id).await
    }

    async fn create_api_key(
        &self,
        subject: &str,
        project_id: &str,
        input: CreateApiKey,
    ) -> Result<ApiKeySecret> {
        let secret = Self::generate_secret()?;
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
            revoked_at: None,
        };
        let api_key = self.repo.create_api_key(subject, row).await?;
        Ok(ApiKeySecret { api_key, secret })
    }

    async fn list_api_keys(&self, subject: &str, project_id: &str) -> Result<Vec<ApiKey>> {
        self.repo.list_api_keys(subject, project_id).await
    }

    async fn get_api_key(&self, subject: &str, key_id: &str) -> Result<ApiKey> {
        self.repo
            .get_api_key(subject, key_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn update_api_key(
        &self,
        subject: &str,
        key_id: &str,
        input: UpdateApiKey,
    ) -> Result<ApiKey> {
        self.repo.update_api_key(subject, key_id, input).await
    }

    async fn delete_api_key(&self, subject: &str, key_id: &str) -> Result<()> {
        self.repo.delete_api_key(subject, key_id).await
    }

    async fn revoke_api_key(&self, subject: &str, key_id: &str) -> Result<ApiKey> {
        self.repo
            .set_api_key_status(
                subject,
                key_id,
                ApiKeyStatus::Revoked,
                Some(Utc::now()),
                None,
            )
            .await
    }

    async fn rotate_api_key(
        &self,
        subject: &str,
        key_id: &str,
        input: RotateApiKey,
    ) -> Result<ApiKeySecret> {
        let existing = self
            .repo
            .get_api_key(subject, key_id)
            .await?
            .ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;

        let now = Utc::now();
        let (status, revoked_at, old_expires_at) =
            if let Some(grace) = input.grace_period_seconds.filter(|v| *v > 0) {
                let grace_exp = now + Duration::seconds(grace);
                let expires_at = match existing.expires_at {
                    Some(existing_exp) if existing_exp < grace_exp => Some(existing_exp),
                    _ => Some(grace_exp),
                };
                (ApiKeyStatus::Active, None, expires_at)
            } else {
                (ApiKeyStatus::Revoked, Some(now), None)
            };

        let secret = Self::generate_secret()?;
        let key_hash = hash_api_key(&secret);
        let key_prefix = Self::key_prefix(&secret);
        let expires_at = resolve_rotated_expires_at(input.expires_at, existing.expires_at);
        let row = lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow {
            id: cuid2(),
            project_id: existing.project_id,
            name: input.name.unwrap_or(existing.name),
            key_prefix,
            key_hash,
            created_at: now,
            expires_at,
            status: ApiKeyStatus::Active.to_string(),
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        };
        let api_key = self
            .repo
            .rotate_api_key_transaction(subject, key_id, status, revoked_at, old_expires_at, row)
            .await?;
        Ok(ApiKeySecret { api_key, secret })
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_rotated_expires_at;
    use chrono::{Duration, Utc};

    #[test]
    fn rotate_defaults_to_existing_expiry_when_missing() {
        let existing_expiry = Utc::now() + Duration::minutes(5);
        assert_eq!(
            resolve_rotated_expires_at(None, Some(existing_expiry)),
            Some(existing_expiry)
        );
    }

    #[test]
    fn rotate_prefers_input_expiry_when_provided() {
        let base_time = Utc::now();
        let existing_expiry = base_time + Duration::minutes(5);
        let input_expiry = base_time + Duration::minutes(10);

        assert_eq!(
            resolve_rotated_expires_at(Some(input_expiry), Some(existing_expiry)),
            Some(input_expiry)
        );
    }

    #[test]
    fn rotate_returns_none_when_no_expiry() {
        assert_eq!(resolve_rotated_expires_at(None, None), None);
    }
}
