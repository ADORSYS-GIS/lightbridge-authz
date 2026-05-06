pub mod authorino;
pub mod opa;

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use getrandom::fill;
use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{Oauth2, Oauth2Issuance};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, ApiKeyStatus, CreateAccount, CreateApiKey, CreateProject,
    Project, RotateApiKey, UpdateAccount, UpdateApiKey, UpdateProject, hash_api_key,
};
use lightbridge_authz_core::{
    db::DbPoolTrait,
    error::{Error, Result},
};
use reqwest::Client;
use serde::Deserialize;

#[derive(Clone)]
pub struct AuthzStoreImpl {
    repo: Arc<StoreRepo>,
    token_issuer: Option<OAuth2TokenIssuer>,
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
            token_issuer: None,
        }
    }

    pub fn with_pool_and_oauth2(pool: Arc<dyn DbPoolTrait>, oauth2: &Oauth2) -> Self {
        let repo = StoreRepo::new(pool);
        Self {
            repo: Arc::new(repo),
            token_issuer: OAuth2TokenIssuer::from_config(oauth2),
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

    async fn issue_secret(&self, bearer_token: Option<&str>) -> Result<IssuedSecret> {
        if let Some(token_issuer) = &self.token_issuer {
            token_issuer.issue(bearer_token).await
        } else {
            Ok(IssuedSecret {
                secret: Self::generate_secret()?,
                expires_at: None,
                oauth2_url: None,
            })
        }
    }
}

#[derive(Debug, Clone)]
struct IssuedSecret {
    secret: String,
    expires_at: Option<DateTime<Utc>>,
    oauth2_url: Option<String>,
}

#[derive(Debug, Clone)]
struct OAuth2TokenIssuer {
    client: Client,
    oauth2_url: String,
    issuance: Oauth2Issuance,
}

#[derive(Debug, Deserialize)]
struct OAuth2TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
}

impl OAuth2TokenIssuer {
    fn from_config(oauth2: &Oauth2) -> Option<Self> {
        let issuance = oauth2.issuance.clone()?;
        if !issuance.enabled {
            return None;
        }
        let oauth2_url = oauth2
            .oauth2_url
            .clone()
            .or_else(|| oauth2.token_endpoint.clone())?;
        Some(Self {
            client: Client::new(),
            oauth2_url,
            issuance,
        })
    }

    fn grant_type(&self) -> &str {
        self.issuance
            .grant_type
            .as_deref()
            .unwrap_or("urn:ietf:params:oauth:grant-type:token-exchange")
    }

    async fn issue(&self, bearer_token: Option<&str>) -> Result<IssuedSecret> {
        let grant_type = self.grant_type();
        if self.issuance.client_id.trim().is_empty() {
            return Err(Error::Server(
                "oauth2 issuance client_id is required".to_string(),
            ));
        }
        let subject_token = bearer_token
            .filter(|token| !token.trim().is_empty())
            .ok_or_else(|| Error::Server("oauth2 issuance bearer token is required".to_string()))?;
        let mut form = vec![
            ("grant_type".to_string(), grant_type.to_string()),
            ("client_id".to_string(), self.issuance.client_id.clone()),
            ("subject_token".to_string(), subject_token.to_string()),
            (
                "subject_token_type".to_string(),
                self.issuance
                    .subject_token_type
                    .clone()
                    .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:access_token".to_string()),
            ),
        ];

        if let Some(client_secret) = &self.issuance.client_secret {
            form.push(("client_secret".to_string(), client_secret.clone()));
        }
        if let Some(requested_token_type) = &self.issuance.requested_token_type {
            form.push((
                "requested_token_type".to_string(),
                requested_token_type.clone(),
            ));
        }
        if let Some(audience) = &self.issuance.audience {
            form.push(("audience".to_string(), audience.clone()));
        }
        if let Some(scope) = &self.issuance.scope {
            form.push(("scope".to_string(), scope.clone()));
        }

        let response = self
            .client
            .post(&self.oauth2_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| Error::Server(format!("oauth2 token issuance request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Server(format!(
                "oauth2 token issuance failed with status {status}: {body}"
            )));
        }
        let token = response
            .json::<OAuth2TokenResponse>()
            .await
            .map_err(|e| Error::Server(format!("oauth2 token response parse failed: {e}")))?;
        let expires_at = token
            .expires_in
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Utc::now() + Duration::seconds(seconds));
        Ok(IssuedSecret {
            secret: token.access_token,
            expires_at,
            oauth2_url: Some(self.oauth2_url.clone()),
        })
    }
}

fn resolve_rotated_expires_at(
    input: Option<DateTime<Utc>>,
    existing: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    input.or(existing)
}

fn resolve_issued_expires_at(
    requested: Option<DateTime<Utc>>,
    issued: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (requested, issued) {
        (Some(requested), Some(issued)) => Some(requested.min(issued)),
        (Some(requested), None) => Some(requested),
        (None, Some(issued)) => Some(issued),
        (None, None) => None,
    }
}

#[async_trait]
impl AuthzStore for AuthzStoreImpl {
    async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account> {
        self.repo.create_account(subject, input, cuid2()).await
    }

    async fn list_accounts(&self, subject: &str, offset: u32, limit: u32) -> Result<Vec<Account>> {
        self.repo.list_accounts(subject, offset, limit).await
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

    async fn list_projects(
        &self,
        subject: &str,
        account_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Project>> {
        self.repo
            .list_projects(subject, account_id, offset, limit)
            .await
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
        bearer_token: Option<&str>,
        project_id: &str,
        input: CreateApiKey,
    ) -> Result<ApiKeySecret> {
        let issued = self.issue_secret(bearer_token).await?;
        let key_hash = hash_api_key(&issued.secret);
        let key_prefix = Self::key_prefix(&issued.secret);
        let now = Utc::now();
        let expires_at = resolve_issued_expires_at(input.expires_at, issued.expires_at);
        let row = lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow {
            id: cuid2(),
            project_id: project_id.to_string(),
            name: input.name,
            key_prefix,
            key_hash,
            created_at: now,
            expires_at,
            status: ApiKeyStatus::Active.to_string(),
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        };
        let api_key = self.repo.create_api_key(subject, row).await?;
        Ok(ApiKeySecret {
            api_key,
            secret: issued.secret,
            oauth2_url: issued.oauth2_url,
        })
    }

    async fn list_api_keys(
        &self,
        subject: &str,
        project_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>> {
        self.repo
            .list_api_keys(subject, project_id, offset, limit)
            .await
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
        bearer_token: Option<&str>,
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

        let issued = self.issue_secret(bearer_token).await?;
        let key_hash = hash_api_key(&issued.secret);
        let key_prefix = Self::key_prefix(&issued.secret);
        let requested_expires_at =
            resolve_rotated_expires_at(input.expires_at, existing.expires_at);
        let expires_at = resolve_issued_expires_at(requested_expires_at, issued.expires_at);
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
        Ok(ApiKeySecret {
            api_key,
            secret: issued.secret,
            oauth2_url: issued.oauth2_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{OAuth2TokenIssuer, resolve_issued_expires_at, resolve_rotated_expires_at};
    use chrono::{Duration, Utc};
    use httpmock::{Method::POST, MockServer};
    use lightbridge_authz_core::config::{Oauth2, Oauth2Issuance};
    use serde_json::json;

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

    #[test]
    fn issued_expiry_prefers_earliest_timestamp() {
        let base_time = Utc::now();
        let requested = base_time + Duration::minutes(10);
        let issued = base_time + Duration::minutes(5);

        assert_eq!(
            resolve_issued_expires_at(Some(requested), Some(issued)),
            Some(issued)
        );
    }

    #[tokio::test]
    async fn oauth2_issuer_posts_token_exchange_and_returns_access_token() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/token")
                .body_contains(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
                )
                .body_contains("client_id=test-client")
                .body_contains("client_secret=test-client-secret")
                .body_contains("subject_token=incoming-access-token")
                .body_contains(
                    "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                )
                .body_contains(
                    "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                )
                .body_contains("audience=test-client");
            then.status(200).json_body(json!({
                "access_token": "issued-access-token",
                "expires_in": 60,
                "token_type": "Bearer"
            }));
        });
        let oauth2_url = server.url("/token");
        let issuer = OAuth2TokenIssuer::from_config(&Oauth2 {
            jwks_url: server.url("/jwks"),
            oauth2_url: Some(oauth2_url.clone()),
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            issuance: Some(Oauth2Issuance {
                enabled: true,
                grant_type: Some("urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
                client_id: "test-client".to_string(),
                client_secret: Some("test-client-secret".to_string()),
                subject_token_type: Some(
                    "urn:ietf:params:oauth:token-type:access_token".to_string(),
                ),
                requested_token_type: Some(
                    "urn:ietf:params:oauth:token-type:access_token".to_string(),
                ),
                audience: Some("test-client".to_string()),
                scope: None,
            }),
        })
        .expect("issuer should be configured");

        let issued = issuer.issue(Some("incoming-access-token")).await.unwrap();

        assert_eq!(issued.secret, "issued-access-token");
        assert_eq!(issued.oauth2_url, Some(oauth2_url));
        assert!(issued.expires_at.is_some());
        assert_eq!(mock.hits(), 1);
    }
}
