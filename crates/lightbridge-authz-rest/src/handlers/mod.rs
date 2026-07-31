pub mod idp;
pub mod introspect;
pub mod opa;

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use getrandom::fill;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::{Billing, Oauth2, Oauth2Issuance};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, ApiKeyStatus, CreateAccount, CreateApiKey, Project,
    ProjectMember, ResourceStatus, RotateApiKey, hash_api_key,
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
    jwt_signer: Option<Arc<crate::signing::ApiKeyJwtSigner>>,
    billing: Arc<Billing>,
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
            jwt_signer: None,
            billing: Arc::new(Billing::default()),
        }
    }

    /// Override the configured billing plans. Primarily for tests that drive `create_api_key`
    /// without going through the full config-loading path.
    pub fn with_billing(mut self, billing: Billing) -> Self {
        self.billing = Arc::new(billing);
        self
    }

    pub fn with_pool_and_oauth2(
        pool: Arc<dyn DbPoolTrait>,
        oauth2: &Oauth2,
        billing: &Billing,
    ) -> Result<Self> {
        use lightbridge_authz_core::config::Oauth2Type;
        let repo = Arc::new(StoreRepo::new(pool));
        let (jwt_signer, token_issuer) = match oauth2.oauth2_type {
            Oauth2Type::SelfSigned => {
                let signing = oauth2.signing.as_ref().ok_or_else(|| {
                    Error::Server("oauth2.type is 'self' but oauth2.signing is missing".to_string())
                })?;
                let signer = crate::signing::ApiKeyJwtSigner::from_config(signing, repo.clone())?;
                (Some(Arc::new(signer)), None)
            }
            Oauth2Type::External => (None, Some(OAuth2TokenIssuer::from_config(oauth2)?)),
        };
        Ok(Self {
            repo,
            token_issuer,
            jwt_signer,
            billing: Arc::new(billing.clone()),
        })
    }

    async fn issue_api_key_secret(
        &self,
        subject: &str,
        bearer_token: Option<&str>,
        project_id: &str,
        api_key_id: &str,
        requested_expires_at: Option<DateTime<Utc>>,
    ) -> Result<IssuedSecret> {
        if let Some(signer) = &self.jwt_signer {
            let project = self
                .repo
                .get_project(subject, project_id)
                .await?
                .ok_or(Error::NotFound)?;
            let (email, email_verified) = decode_bearer_profile(bearer_token);
            let owner = crate::signing::KeyOwner {
                subject: subject.to_string(),
                email,
                email_verified,
            };
            let signed = signer
                .sign(
                    &owner,
                    api_key_id,
                    project_id,
                    &project.account_id,
                    project.allowed_models.clone(),
                    Utc::now(),
                    requested_expires_at,
                )
                .await?;
            Ok(IssuedSecret {
                secret: signed.token,
                expires_at: Some(signed.expires_at),
                oauth2_url: None,
            })
        } else {
            self.issue_secret(bearer_token, Some(project_id)).await
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

    async fn issue_secret(
        &self,
        bearer_token: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<IssuedSecret> {
        if let Some(token_issuer) = &self.token_issuer {
            token_issuer.issue(bearer_token, project_id).await
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
    /// Builds the upstream token-exchange proxy from config (only reached under
    /// `oauth2.type: external`). Errors if the `issuance` block or the upstream token URL is
    /// missing, so a misconfigured external mode fails fast at startup.
    fn from_config(oauth2: &Oauth2) -> Result<Self> {
        let issuance = oauth2.issuance.clone().ok_or_else(|| {
            Error::Server("oauth2.type is 'external' but oauth2.issuance is missing".to_string())
        })?;
        let oauth2_url = oauth2
            .oauth2_url
            .clone()
            .or_else(|| oauth2.token_endpoint.clone())
            .ok_or_else(|| {
                Error::Server(
                    "oauth2.type is 'external' but neither oauth2.oauth2_url nor oauth2.token_endpoint is set"
                        .to_string(),
                )
            })?;
        Ok(Self {
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

    async fn issue(
        &self,
        bearer_token: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<IssuedSecret> {
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
        if let Some(project_id) = project_id.filter(|value| !value.trim().is_empty()) {
            form.push(("project_id".to_string(), project_id.to_string()));
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

fn decode_bearer_profile(bearer_token: Option<&str>) -> (Option<String>, Option<bool>) {
    let Some(payload) = bearer_token.and_then(|token| token.split('.').nth(1)) else {
        return (None, None);
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (None, None);
    };
    let email = value
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let email_verified = value
        .get("email_verified")
        .and_then(serde_json::Value::as_bool);
    (email, email_verified)
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

/// The four write operations the RPC procedures delegate to (ADR-0003 item 4). Everything else the
/// old `AuthzStore` trait exposed (account/project/api-key list/read/create/update/delete) now runs
/// through the generated cratestack CRUD client, so only these survive — as inherent methods, no
/// trait. They reuse the hand-written sqlx in `StoreRepo` (tenant-scoped by account ownership or a
/// `project_members` row, ADR-0006); none use cratestack's `run_in_tx`, per the deadlock finding in
/// ADR-0003 ("Known cratestack-pg 0.4.9 bugs", item 1).
impl AuthzStoreImpl {
    /// Create the caller's account. Backs the `createAccount` procedure. Since ADR-0006 the account
    /// id **is** the caller's JWT subject — one account per person — so no id is generated and none
    /// may be supplied: the generic `model.Account.create` verb stays denied precisely because a
    /// caller-chosen id would let one subject create an account keyed to another. Calling this twice
    /// for the same subject is a `Conflict`, not a second account.
    pub async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account> {
        let account = self.repo.create_account(subject, input).await?;
        tracing::info!(
            operation = "create_account",
            subject = %subject,
            account_id = %account.id,
            "account created"
        );
        Ok(account)
    }

    /// Create an API key: validate the requested `billing_plan` against the operator-configured
    /// catalogue (before any DB write), issue a fresh secret (generation/hashing unchanged from
    /// before the migration), and insert the row via hand-written sqlx. Backs the `createApiKey`
    /// procedure. Since ADR-0006 this path is **lead-gated** in SQL: the caller must own the
    /// project's account or hold `role = 'lead'` on it, because a key is live spending power with
    /// no per-request human in the loop.
    pub async fn create_api_key(
        &self,
        subject: &str,
        bearer_token: Option<&str>,
        project_id: &str,
        input: CreateApiKey,
    ) -> Result<ApiKeySecret> {
        if !self.billing.is_allowed(&input.billing_plan) {
            return Err(Error::BadRequest(format!(
                "unknown billing_plan '{}': must be one of the configured plans [{}]",
                input.billing_plan,
                self.billing.plan_ids().join(", ")
            )));
        }
        let id = cuid2();
        let issued = self
            .issue_api_key_secret(subject, bearer_token, project_id, &id, input.expires_at)
            .await?;
        let key_hash = hash_api_key(&issued.secret);
        let key_prefix = Self::key_prefix(&issued.secret);
        let now = Utc::now();
        let expires_at = resolve_issued_expires_at(input.expires_at, issued.expires_at);
        let row = lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow {
            id,
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
            billing_plan: input.billing_plan,
        };
        let api_key = self.repo.create_api_key(subject, row).await?;
        tracing::info!(
            operation = "create_api_key",
            subject = %subject,
            project_id = %project_id,
            api_key_id = %api_key.id,
            expires_at = ?api_key.expires_at,
            "api key created and secret issued"
        );
        Ok(ApiKeySecret {
            api_key,
            secret: issued.secret,
            oauth2_url: issued.oauth2_url,
        })
    }

    /// Suspend an account (`status = 'suspended'`). Backs `disableAccount`. Thin wrapper over
    /// `StoreRepo::set_account_status` (membership enforced in SQL).
    pub async fn disable_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo
            .set_account_status(subject, account_id, ResourceStatus::Suspended)
            .await
    }

    /// Reactivate a suspended account (`status = 'active'`). Backs `enableAccount`.
    pub async fn enable_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo
            .set_account_status(subject, account_id, ResourceStatus::Active)
            .await
    }

    /// Suspend a project (`status = 'suspended'`). Backs `disableProject`. Thin wrapper over
    /// `StoreRepo::set_project_status` (membership enforced in SQL).
    pub async fn disable_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo
            .set_project_status(subject, project_id, ResourceStatus::Suspended)
            .await
    }

    /// Reactivate a suspended project (`status = 'active'`). Backs `enableProject`.
    pub async fn enable_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo
            .set_project_status(subject, project_id, ResourceStatus::Active)
            .await
    }

    /// Promote `project_id` to be its account's new default project. Backs `setDefaultProject`.
    /// Thin wrapper over `StoreRepo::set_default_project` (ownership + atomic unset/set enforced
    /// in SQL).
    pub async fn set_default_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo.set_default_project(subject, project_id).await
    }

    /// Revoke an API key (business-state transition to `revoked`). Backs `revokeApiKey`.
    pub async fn revoke_api_key(&self, subject: &str, key_id: &str) -> Result<ApiKey> {
        let api_key = self
            .repo
            .set_api_key_status(
                subject,
                key_id,
                ApiKeyStatus::Revoked,
                Some(Utc::now()),
                None,
            )
            .await?;
        tracing::info!(
            operation = "revoke_api_key",
            subject = %subject,
            project_id = %api_key.project_id,
            api_key_id = %api_key.id,
            "api key revoked"
        );
        Ok(api_key)
    }

    /// Add an account to a project's roster (idempotent). Backs `addProjectMember`. Lead-gated in
    /// SQL: the acting `subject` must own the project's account or hold `role = 'lead'` on it.
    pub async fn add_project_member(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        role: Option<&str>,
    ) -> Result<Project> {
        self.repo
            .add_project_member(subject, project_id, target_account_id, role)
            .await
    }

    /// Remove an account from a project's roster. Backs `removeProjectMember`. Lead-gated in SQL.
    /// Unlike the account-membership model it replaces, there is no last-member invariant to
    /// enforce: the project's owning account is a standing authority over the roster, so a project
    /// can never be left without one.
    pub async fn remove_project_member(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
    ) -> Result<Project> {
        self.repo
            .remove_project_member(subject, project_id, target_account_id)
            .await
    }

    /// Change a roster member's role (`lead`/`member`). Backs `setProjectMemberRole`. Lead-gated in
    /// SQL.
    pub async fn set_project_member_role(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        role: &str,
    ) -> Result<Project> {
        self.repo
            .set_project_member_role(subject, project_id, target_account_id, role)
            .await
    }

    /// Set a roster member's per-project spending ceiling. Backs `setProjectMemberQuotaTier`.
    /// Lead-gated in SQL, and the tier is validated against the configured catalogue at write time.
    pub async fn set_project_member_quota_tier(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        quota_tier: Option<&str>,
    ) -> Result<Project> {
        self.repo
            .set_project_member_quota_tier(subject, project_id, target_account_id, quota_tier)
            .await
    }

    /// List a project's roster. Backs `listProjectRoster`, the roster's only read path (the four
    /// mutations above all return `Project`). Authorization is deliberately wider than theirs --
    /// any member of the project may read it, not only leads -- and is enforced in SQL.
    pub async fn list_project_roster(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<Vec<ProjectMember>> {
        self.repo.list_project_roster(subject, project_id).await
    }

    /// Permanently delete an account, cascading to its projects and api-keys. Backs
    /// `deleteAccountPermanently`. Since ADR-0006 the authorization is simply "the caller is this
    /// account" — there is no role concept left to gate on.
    pub async fn delete_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo.delete_account(subject, account_id).await
    }

    /// Rotate an API key: issue a fresh secret (generation/hashing unchanged from before the
    /// migration) and, in one hand-written transaction (`StoreRepo::rotate_api_key_transaction`,
    /// NOT `run_in_tx`), revoke the old key and insert its successor. Backs `rotateApiKey`.
    pub async fn rotate_api_key(
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

        let new_id = cuid2();
        let requested_expires_at =
            resolve_rotated_expires_at(input.expires_at, existing.expires_at);
        let issued = self
            .issue_api_key_secret(
                subject,
                bearer_token,
                existing.project_id.as_str(),
                &new_id,
                requested_expires_at,
            )
            .await?;
        let key_hash = hash_api_key(&issued.secret);
        let key_prefix = Self::key_prefix(&issued.secret);
        let expires_at = resolve_issued_expires_at(requested_expires_at, issued.expires_at);
        let row = lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow {
            id: new_id,
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
            billing_plan: existing.billing_plan,
        };
        let api_key = self
            .repo
            .rotate_api_key_transaction(subject, key_id, status, revoked_at, old_expires_at, row)
            .await?;
        tracing::info!(
            operation = "rotate_api_key",
            subject = %subject,
            project_id = %api_key.project_id,
            previous_api_key_id = %key_id,
            api_key_id = %api_key.id,
            expires_at = ?api_key.expires_at,
            "api key rotated and new secret issued"
        );
        Ok(ApiKeySecret {
            api_key,
            secret: issued.secret,
            oauth2_url: issued.oauth2_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthzStoreImpl, OAuth2TokenIssuer, resolve_issued_expires_at, resolve_rotated_expires_at,
    };
    use chrono::{Duration, Utc};
    use httpmock::{Method::POST, MockServer};
    use lightbridge_authz_core::config::{Billing, Oauth2, Oauth2Issuance, Oauth2Type};
    use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    fn base_oauth2(oauth2_type: Oauth2Type) -> Oauth2 {
        Oauth2 {
            oauth2_type,
            jwks_url: "http://x".to_string(),
            oauth2_url: None,
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            audience: None,
            signing: None,
            token_exchange: None,
            rbac: Default::default(),
            issuance: None,
        }
    }

    fn lazy_pool() -> Arc<dyn DbPoolTrait> {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/x")
            .unwrap();
        Arc::new(DbPool::from_pool(pool))
    }

    #[tokio::test]
    async fn self_type_without_signing_block_errors() {
        let err = AuthzStoreImpl::with_pool_and_oauth2(
            lazy_pool(),
            &base_oauth2(Oauth2Type::SelfSigned),
            &Billing::default(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("oauth2.signing is missing"));
    }

    #[tokio::test]
    async fn external_type_without_issuance_block_errors() {
        let err = AuthzStoreImpl::with_pool_and_oauth2(
            lazy_pool(),
            &base_oauth2(Oauth2Type::External),
            &Billing::default(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("oauth2.issuance is missing"));
    }

    // ADR-0003 follow-up: billing-plan validation on create is re-established. Creation now goes
    // through the `createApiKey` procedure -> `AuthzStoreImpl::create_api_key`, which validates the
    // requested plan against the configured catalogue before any DB write (the generic
    // `model.ApiKey.create` verb is fail-closed at the schema and denied at the RBAC layer).
    #[tokio::test]
    async fn create_api_key_rejects_billing_plan_not_in_configured_set() {
        use lightbridge_authz_core::CreateApiKey;
        use lightbridge_authz_core::config::BillingPlan;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_billing(Billing {
            plans: vec![BillingPlan {
                id: "pro".to_string(),
                name: "Pro".to_string(),
                limits: None,
            }],
        });

        for plan in ["free", ""] {
            let err = store
                .create_api_key(
                    "subject",
                    None,
                    "proj",
                    CreateApiKey {
                        name: "k".to_string(),
                        expires_at: None,
                        billing_plan: plan.to_string(),
                    },
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, lightbridge_authz_core::error::Error::BadRequest(ref m) if m.contains("unknown billing_plan")),
                "plan {plan:?} should be rejected before any DB access, got: {err}"
            );
        }
    }

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
                .body_includes(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
                )
                .body_includes("client_id=test-client")
                .body_includes("client_secret=test-client-secret")
                .body_includes("subject_token=incoming-access-token")
                .body_includes(
                    "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                )
                .body_includes(
                    "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
                )
                .body_includes("project_id=proj-test");
            then.status(200).json_body(json!({
                "access_token": "issued-access-token",
                "expires_in": 60,
                "token_type": "Bearer"
            }));
        });
        let oauth2_url = server.url("/token");
        let issuer = OAuth2TokenIssuer::from_config(&Oauth2 {
            oauth2_type: lightbridge_authz_core::config::Oauth2Type::External,
            jwks_url: server.url("/jwks"),
            oauth2_url: Some(oauth2_url.clone()),
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            audience: None,
            signing: None,
            token_exchange: None,
            rbac: Default::default(),
            issuance: Some(Oauth2Issuance {
                grant_type: Some("urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
                client_id: "test-client".to_string(),
                client_secret: Some("test-client-secret".to_string()),
                subject_token_type: Some(
                    "urn:ietf:params:oauth:token-type:access_token".to_string(),
                ),
                requested_token_type: Some(
                    "urn:ietf:params:oauth:token-type:access_token".to_string(),
                ),
                audience: None,
                scope: None,
            }),
        })
        .expect("issuer should be configured");

        let issued = issuer
            .issue(Some("incoming-access-token"), Some("proj-test"))
            .await
            .unwrap();

        assert_eq!(issued.secret, "issued-access-token");
        assert_eq!(issued.oauth2_url, Some(oauth2_url));
        assert!(issued.expires_at.is_some());
        assert_eq!(mock.calls(), 1);
    }

    fn test_issuer(oauth2_url: String, client_id: &str) -> OAuth2TokenIssuer {
        OAuth2TokenIssuer::from_config(&Oauth2 {
            oauth2_type: lightbridge_authz_core::config::Oauth2Type::External,
            jwks_url: "http://jwks".to_string(),
            oauth2_url: Some(oauth2_url),
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            audience: None,
            signing: None,
            token_exchange: None,
            rbac: Default::default(),
            issuance: Some(Oauth2Issuance {
                grant_type: None,
                client_id: client_id.to_string(),
                client_secret: None,
                subject_token_type: None,
                requested_token_type: None,
                audience: None,
                scope: None,
            }),
        })
        .expect("issuer should be configured")
    }

    #[test]
    fn issuer_config_without_issuance_block_errors() {
        let cfg = Oauth2 {
            oauth2_type: lightbridge_authz_core::config::Oauth2Type::External,
            jwks_url: "http://jwks".to_string(),
            oauth2_url: Some("http://token".to_string()),
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            audience: None,
            signing: None,
            token_exchange: None,
            rbac: Default::default(),
            issuance: None,
        };
        let err = OAuth2TokenIssuer::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("oauth2.issuance is missing"));
    }

    #[tokio::test]
    async fn issue_requires_non_empty_client_id() {
        let issuer = test_issuer("http://unused".to_string(), "   ");
        let err = issuer.issue(Some("token"), None).await.unwrap_err();
        assert!(format!("{err}").contains("client_id is required"));
    }

    #[tokio::test]
    async fn issue_requires_bearer_token() {
        let issuer = test_issuer("http://unused".to_string(), "client");
        let err = issuer.issue(None, None).await.unwrap_err();
        assert!(format!("{err}").contains("bearer token is required"));
    }

    #[tokio::test]
    async fn issue_errors_on_non_success_status() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(400).body("bad request");
        });
        let issuer = test_issuer(server.url("/token"), "client");
        let err = issuer.issue(Some("token"), None).await.unwrap_err();
        assert!(format!("{err}").contains("issuance failed with status"));
    }

    #[tokio::test]
    async fn issue_errors_on_unparsable_response() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200).body("not json");
        });
        let issuer = test_issuer(server.url("/token"), "client");
        let err = issuer.issue(Some("token"), None).await.unwrap_err();
        assert!(format!("{err}").contains("response parse failed"));
    }
}
