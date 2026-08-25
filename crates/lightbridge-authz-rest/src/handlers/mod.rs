pub mod exchange_token;
pub mod idp;
pub mod introspect;
pub mod opa;

use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use getrandom::fill;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::{
    ApiKeyExpiry, Billing, ModelCatalog, Oauth2, Oauth2Issuance, QuotaTiers,
};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::{
    Account, AccountId, ApiKey, ApiKeySecret, ApiKeyStatus, CreateAccount, CreateApiKey,
    ModelPolicy, Project, ProjectMember, ResourceStatus, RotateApiKey, hash_api_key,
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
    /// Operator-configured governance quota-tier catalogue (#177). Validated the same way as
    /// `billing` above -- `QuotaTiers::is_allowed` rejects a value absent from a non-empty
    /// catalogue, and accepts everything (including `None`) when the catalogue is empty/absent
    /// (see that type's own doc comment for why that default is deliberate, unlike `Billing`'s).
    quota_tiers: Arc<QuotaTiers>,
    /// Operator-configured AI-model catalogue backing `listModelCatalog` -- a read-only display
    /// aid, not a value validated anywhere (see that type's own doc comment). Threaded through the
    /// same way as `billing`/`quota_tiers` above.
    models: Arc<ModelCatalog>,
    /// Operator-configured ceiling `create_api_key`/`rotate_api_key` validate `expires_at`
    /// against (lightbridge-authz#395). Threaded through the same way as `billing`/`quota_tiers`/
    /// `models` above, but unlike those, absent config still resolves to a real value (90 days),
    /// never to "no ceiling" -- see `ApiKeyExpiry`'s own doc comment.
    api_key_expiry: Arc<ApiKeyExpiry>,
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
            quota_tiers: Arc::new(QuotaTiers::default()),
            models: Arc::new(ModelCatalog::default()),
            api_key_expiry: Arc::new(ApiKeyExpiry::default()),
        }
    }

    /// Override the configured billing plans. Primarily for tests that drive `create_api_key`
    /// without going through the full config-loading path.
    pub fn with_billing(mut self, billing: Billing) -> Self {
        self.billing = Arc::new(billing);
        self
    }

    /// Override the configured quota-tier catalogue. Primarily for tests that drive
    /// `create_account`/`set_project_member_quota_tier` without going through the full
    /// config-loading path -- mirrors `with_billing` above.
    pub fn with_quota_tiers(mut self, quota_tiers: QuotaTiers) -> Self {
        self.quota_tiers = Arc::new(quota_tiers);
        self
    }

    /// Override the configured model catalogue. Primarily for tests that drive `list_model_catalog`
    /// without going through the full config-loading path -- mirrors `with_billing` above.
    pub fn with_model_catalog(mut self, models: ModelCatalog) -> Self {
        self.models = Arc::new(models);
        self
    }

    /// Override the configured api-key expiry ceiling. Primarily for tests that drive
    /// `create_api_key`/`rotate_api_key` without going through the full config-loading path --
    /// mirrors `with_billing` above.
    pub fn with_api_key_expiry(mut self, api_key_expiry: ApiKeyExpiry) -> Self {
        self.api_key_expiry = Arc::new(api_key_expiry);
        self
    }

    pub fn with_pool_and_oauth2(
        pool: Arc<dyn DbPoolTrait>,
        oauth2: &Oauth2,
        billing: &Billing,
        quota_tiers: &QuotaTiers,
        models: &ModelCatalog,
        api_key_expiry: &ApiKeyExpiry,
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
            quota_tiers: Arc::new(quota_tiers.clone()),
            models: Arc::new(models.clone()),
            api_key_expiry: Arc::new(api_key_expiry.clone()),
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
            let account_id = AccountId::assert_already_resolved(subject);
            let project = self
                .repo
                .get_project(&account_id, project_id)
                .await?
                .ok_or(Error::NotFound)?;
            let (email, email_verified) = decode_bearer_profile(bearer_token);
            let owner = crate::signing::KeyOwner {
                subject: subject.to_string(),
                account_id: account_id.into(),
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

/// The single gate every `api_keys.expires_at` write funnels through (lightbridge-authz#395: "all
/// api-keys created from our system MUST have an expiry date... max 90 days"). Called by
/// `create_api_key` and `rotate_api_key` before any DB write or external issuance call, so a
/// rejection never touches the database. Fail-closed on every axis, never a silent default or
/// clamp:
///   - missing `expires_at` -> rejected (no more nullable "never expires" keys)
///   - `expires_at` at or before `now` -> rejected (a dead-on-arrival key is as good as none)
///   - `expires_at` beyond `now + max_lifetime.max_lifetime_days` -> rejected
///
/// This is deliberately independent of `signing::capped_expiry`, which *clamps* (never rejects)
/// the JWT `exp` claim to `oauth2.signing.ttl_seconds` under `oauth2.type: self` only -- a
/// cryptographic-freshness concern for the bearer token itself. This function is the
/// mode-independent governance gate on the DB row's `expires_at`, and runs for every issuance mode
/// (self-signed, external token-exchange, and the plain opaque-secret fallback alike).
fn validate_expires_at(
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    max_lifetime: &ApiKeyExpiry,
) -> Result<DateTime<Utc>> {
    let expires_at = expires_at.ok_or_else(|| {
        Error::BadRequest(
            "expiresAt is required: api keys may not be created or rotated without an expiry"
                .to_string(),
        )
    })?;
    if expires_at <= now {
        return Err(Error::BadRequest(
            "expiresAt must be in the future".to_string(),
        ));
    }
    let max_allowed = now + Duration::days(i64::from(max_lifetime.max_lifetime_days));
    if expires_at > max_allowed {
        return Err(Error::BadRequest(format!(
            "expiresAt exceeds the configured maximum api key lifetime of {} day(s)",
            max_lifetime.max_lifetime_days
        )));
    }
    Ok(expires_at)
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
    ///
    /// `input.default_quota` is validated against the operator-configured quota-tier catalogue
    /// (#177) before any DB write, same pattern and error shape as `create_api_key`'s
    /// `billing_plan` check below: `None` always passes, and an empty/absent catalogue accepts
    /// any value (see `QuotaTiers::is_allowed`).
    pub async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account> {
        if !self.quota_tiers.is_allowed(input.default_quota.as_deref()) {
            let tier = input.default_quota.as_deref().unwrap_or_default();
            return Err(Error::BadRequest(format!(
                "unknown defaultQuota '{tier}': must be one of the configured tiers [{}]",
                self.quota_tiers.tier_ids().join(", ")
            )));
        }
        let account = self.repo.create_account(subject, input).await?;
        tracing::info!(
            operation = "create_account",
            subject = %subject,
            account_id = %account.id,
            "account created"
        );
        Ok(account)
    }

    /// Updates `Account.defaultQuota` post-creation. Backs `updateAccountDefaultQuota` (#379,
    /// completing #177/#375): `Account.defaultQuota` is now `@readonly` on the generic
    /// `model.Account.update` verb (which has no hook for a runtime-configured catalogue check),
    /// so this procedure is the only write path left. Same catalogue check, same pattern/error
    /// shape, as `create_account`'s `default_quota` check above -- see that method's doc comment
    /// for the full contract (`None` always passes, an empty/absent catalogue accepts any value).
    pub async fn update_account_default_quota(
        &self,
        subject: &str,
        account_id: &str,
        default_quota: Option<&str>,
    ) -> Result<Account> {
        if !self.quota_tiers.is_allowed(default_quota) {
            return Err(Error::BadRequest(format!(
                "unknown defaultQuota '{}': must be one of the configured tiers [{}]",
                default_quota.unwrap_or_default(),
                self.quota_tiers.tier_ids().join(", ")
            )));
        }
        let account = self
            .repo
            .update_account_default_quota(
                &AccountId::assert_already_resolved(subject),
                account_id,
                default_quota,
            )
            .await?;
        tracing::info!(
            operation = "update_account_default_quota",
            subject = %subject,
            account_id = %account.id,
            "account defaultQuota updated"
        );
        Ok(account)
    }

    /// Create an API key: validate the requested `billing_plan` against the operator-configured
    /// catalogue and `expires_at` against the operator-configured `ApiKeyExpiry` ceiling (both
    /// before any DB write), issue a fresh secret (generation/hashing unchanged from before the
    /// migration), and insert the row via hand-written sqlx. Backs the `createApiKey` procedure.
    /// Since ADR-0006 this path is **lead-gated** in SQL: the caller must own the project's
    /// account or hold `role = 'lead'` on it, because a key is live spending power with no
    /// per-request human in the loop.
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
        let now = Utc::now();
        let requested_expires_at =
            validate_expires_at(input.expires_at, now, &self.api_key_expiry)?;
        let id = cuid2();
        let issued = self
            .issue_api_key_secret(
                subject,
                bearer_token,
                project_id,
                &id,
                Some(requested_expires_at),
            )
            .await?;
        let key_hash = hash_api_key(&issued.secret);
        let key_prefix = Self::key_prefix(&issued.secret);
        let expires_at = resolve_issued_expires_at(Some(requested_expires_at), issued.expires_at);
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
        let api_key = self
            .repo
            .create_api_key(&AccountId::assert_already_resolved(subject), row)
            .await?;
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

    /// The operator-configured billing-plan catalogue `create_api_key` above validates
    /// `billing_plan` against. Backs `listBillingPlans` -- a plain accessor, no DB round-trip,
    /// since the catalogue is config (`Billing`), not a table.
    pub fn billing_plans(&self) -> &Billing {
        &self.billing
    }

    /// The operator-configured AI-model catalogue backing `listModelCatalog` -- a plain accessor,
    /// no DB round-trip, since the catalogue is config (`ModelCatalog`), not a table. Mirrors
    /// `billing_plans` above.
    pub fn model_catalog(&self) -> &ModelCatalog {
        &self.models
    }

    /// Suspend an account (`status = 'suspended'`). Backs `disableAccount`. Thin wrapper over
    /// `StoreRepo::set_account_status` (membership enforced in SQL).
    pub async fn disable_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo
            .set_account_status(
                &AccountId::assert_already_resolved(subject),
                account_id,
                ResourceStatus::Suspended,
            )
            .await
    }

    /// Reactivate a suspended account (`status = 'active'`). Backs `enableAccount`.
    pub async fn enable_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo
            .set_account_status(
                &AccountId::assert_already_resolved(subject),
                account_id,
                ResourceStatus::Active,
            )
            .await
    }

    /// Suspend a project (`status = 'suspended'`). Backs `disableProject`. Thin wrapper over
    /// `StoreRepo::set_project_status` (membership enforced in SQL).
    pub async fn disable_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo
            .set_project_status(
                &AccountId::assert_already_resolved(subject),
                project_id,
                ResourceStatus::Suspended,
            )
            .await
    }

    /// Reactivate a suspended project (`status = 'active'`). Backs `enableProject`.
    pub async fn enable_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo
            .set_project_status(
                &AccountId::assert_already_resolved(subject),
                project_id,
                ResourceStatus::Active,
            )
            .await
    }

    /// Revokes every active session (of either `kind`, ADR-0021 Decision 3) for `subject`,
    /// cascading to every `exchange_refresh_tokens` row chained under one of them (ADR-0020
    /// Decision 9), and returns how many SESSIONS were revoked. Backs both `revokeOwnSessions`
    /// (`subject` is the caller's own, from `auth().id`) and `revokeSubjectSessions` (`subject`
    /// is an operator-supplied target) -- the operation is identical either way; only which
    /// `subject` reaches this method differs, and that choice is made entirely by the two
    /// procedures' own RBAC gates (`session:revoke-own` vs `session:revoke`, `docs/rbac.md`), not
    /// by anything in this method.
    pub async fn revoke_sessions(&self, subject: &str) -> Result<u64> {
        self.repo
            .revoke_sessions_and_cascade(&AccountId::assert_already_resolved(subject))
            .await
    }

    /// Promote `project_id` to be its account's new default project. Backs `setDefaultProject`.
    /// Thin wrapper over `StoreRepo::set_default_project` (ownership + atomic unset/set enforced
    /// in SQL).
    pub async fn set_default_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        self.repo
            .set_default_project(&AccountId::assert_already_resolved(subject), project_id)
            .await
    }

    /// Sets `Project.projectQuota` post-creation. Backs `setProjectQuota` (#379, completing
    /// #177/#375): `Project.projectQuota` is now `@readonly` on both generic
    /// `model.Project.create`/`.update` verbs (neither has a hook for a runtime-configured
    /// catalogue check), so this procedure is the only write path left. `project_quota` is
    /// validated against the operator-configured catalogue here, before the ownership-gated SQL
    /// write (`StoreRepo::set_project_quota`) -- same pattern/error shape as `create_account`'s
    /// `default_quota` check and `set_project_member_quota_tier`'s `quota_tier` check above.
    pub async fn set_project_quota(
        &self,
        subject: &str,
        project_id: &str,
        project_quota: Option<&str>,
    ) -> Result<Project> {
        if !self.quota_tiers.is_allowed(project_quota) {
            return Err(Error::BadRequest(format!(
                "unknown projectQuota '{}': must be one of the configured tiers [{}]",
                project_quota.unwrap_or_default(),
                self.quota_tiers.tier_ids().join(", ")
            )));
        }
        self.repo
            .set_project_quota(
                &AccountId::assert_already_resolved(subject),
                project_id,
                project_quota,
            )
            .await
    }

    /// Sets `Project.allowedModels` post-creation/update. Backs `setProjectAllowedModels` (#415,
    /// ADR-0018 Decision 5): `Project.allowedModels` is now `@readonly` on both generic
    /// `model.Project.create`/`.update` verbs (same "no runtime-catalogue-check hook" gap #379
    /// closed for `projectQuota`), so this procedure is the only write path left. Every entry in
    /// `allowed_models` is validated against the operator-configured AI-model catalogue here,
    /// before the ownership-gated SQL write (`StoreRepo::set_project_allowed_models`) -- same
    /// pattern/error shape as `set_project_quota`'s `project_quota` check above, except the
    /// catalogue check here names every invalid entry (`ModelCatalog::invalid_ids`) rather than
    /// accept/reject a single scalar. `None` always passes (unchanged "all models allowed"
    /// meaning); an empty/absent catalogue accepts anything (see `ModelCatalog::invalid_ids`'s own
    /// doc comment).
    pub async fn set_project_allowed_models(
        &self,
        subject: &str,
        project_id: &str,
        allowed_models: Option<Vec<String>>,
    ) -> Result<Project> {
        let invalid = self.models.invalid_ids(allowed_models.as_deref());
        if !invalid.is_empty() {
            return Err(Error::BadRequest(format!(
                "unknown allowedModels entr{} [{}]: must each be one of the configured models [{}]",
                if invalid.len() == 1 { "y" } else { "ies" },
                invalid.join(", "),
                self.models.model_ids().join(", ")
            )));
        }
        self.repo
            .set_project_allowed_models(
                &AccountId::assert_already_resolved(subject),
                project_id,
                allowed_models,
            )
            .await
    }

    /// Sets `Project.modelPolicy` (ADR-0018 Decision 5 follow-up). Backs `setProjectModelPolicy`:
    /// `Project.modelPolicy` is `@readonly` on both generic `model.Project.create`/`.update` verbs
    /// (it needed a precondition -- `allowedModels` catalogue validation, #415 -- before a write
    /// path could safely exist at all; see that field's own schema doc comment), so this procedure
    /// is the only write path.
    ///
    /// `model_policy` is validated to be one of the three canonical wire values here
    /// (`ModelPolicy::parse_strict`), fail-closed: an unrecognized value is refused outright with
    /// `BadRequest`, never silently coerced to a default -- the opposite of `ModelPolicy::from`'s
    /// read-path coercion to `DenyAll`, which exists only because a DB read has no caller left to
    /// return an error to (see that type's own doc comment). The other business rule this
    /// procedure enforces -- refusing a transition to `allowlist` while `allowedModels` is empty,
    /// because that would silently deny every model rather than the caller's evident intent -- is
    /// NOT checked here: it needs the row's current `allowed_models` read under lock, so it lives
    /// in `StoreRepo::set_project_model_policy`'s single transaction instead (see that method's
    /// own doc comment for the full reasoning, including why this is a refusal rather than a
    /// warning or a silent allow).
    ///
    /// `allowedModels` itself is never touched by this procedure -- switching to `allow_all` (or
    /// back to `allowlist`) preserves whatever list was already there, so toggling `allow_all` off
    /// and back on restores the previous selection instead of forcing the caller to re-enter it.
    /// The list is simply inert while `model_policy` is not `allowlist` (ADR-0018 Decision 2).
    pub async fn set_project_model_policy(
        &self,
        subject: &str,
        project_id: &str,
        model_policy: &str,
    ) -> Result<Project> {
        let parsed = ModelPolicy::parse_strict(model_policy).ok_or_else(|| {
            Error::BadRequest(format!(
                "unknown modelPolicy '{model_policy}': must be one of allow_all, allowlist, deny_all"
            ))
        })?;
        self.repo
            .set_project_model_policy(
                &AccountId::assert_already_resolved(subject),
                project_id,
                &parsed.to_string(),
            )
            .await
    }

    /// Revoke an API key (business-state transition to `revoked`). Backs `revokeApiKey`.
    pub async fn revoke_api_key(&self, subject: &str, key_id: &str) -> Result<ApiKey> {
        let api_key = self
            .repo
            .set_api_key_status(
                &AccountId::assert_already_resolved(subject),
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
            .add_project_member(
                &AccountId::assert_already_resolved(subject),
                project_id,
                target_account_id,
                role,
            )
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
            .remove_project_member(
                &AccountId::assert_already_resolved(subject),
                project_id,
                target_account_id,
            )
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
            .set_project_member_role(
                &AccountId::assert_already_resolved(subject),
                project_id,
                target_account_id,
                role,
            )
            .await
    }

    /// Set a roster member's per-project spending ceiling. Backs `setProjectMemberQuotaTier`.
    /// Lead-gated in SQL (`StoreRepo::authorize_project_lead`), and `quota_tier` is validated
    /// against the operator-configured catalogue here, before the lead-gated SQL write (#177):
    /// this is "where the request is first accepted" that repository's own doc comment on
    /// `set_project_member_quota_tier` refers to. Same pattern/error shape as `create_account`'s
    /// `default_quota` check and `create_api_key`'s `billing_plan` check.
    pub async fn set_project_member_quota_tier(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        quota_tier: Option<&str>,
    ) -> Result<Project> {
        if !self.quota_tiers.is_allowed(quota_tier) {
            return Err(Error::BadRequest(format!(
                "unknown quotaTier '{}': must be one of the configured tiers [{}]",
                quota_tier.unwrap_or_default(),
                self.quota_tiers.tier_ids().join(", ")
            )));
        }
        self.repo
            .set_project_member_quota_tier(
                &AccountId::assert_already_resolved(subject),
                project_id,
                target_account_id,
                quota_tier,
            )
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
        self.repo
            .list_project_roster(&AccountId::assert_already_resolved(subject), project_id)
            .await
    }

    /// Permanently delete an account, cascading to its projects and api-keys. Backs
    /// `deleteAccountPermanently`. Since ADR-0006 the authorization is simply "the caller is this
    /// account" — there is no role concept left to gate on.
    pub async fn delete_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        self.repo
            .delete_account(&AccountId::assert_already_resolved(subject), account_id)
            .await
    }

    /// Rotate an API key: issue a fresh secret (generation/hashing unchanged from before the
    /// migration) and, in one hand-written transaction (`StoreRepo::rotate_api_key_transaction`,
    /// NOT `run_in_tx`), revoke the old key and insert its successor. Backs `rotateApiKey`. The
    /// successor's `expires_at` -- normally the preserved existing value, since
    /// `RotateApiKeyInput` carries no `expiresAt` of its own -- is re-validated against the
    /// operator-configured `ApiKeyExpiry` ceiling the same way `create_api_key` validates it
    /// (lightbridge-authz#395): a pre-existing key whose expiry now exceeds a newly-lowered
    /// ceiling fails to rotate rather than silently carrying the stale value forward.
    pub async fn rotate_api_key(
        &self,
        subject: &str,
        bearer_token: Option<&str>,
        key_id: &str,
        input: RotateApiKey,
    ) -> Result<ApiKeySecret> {
        let account_id = AccountId::assert_already_resolved(subject);
        let existing = self
            .repo
            .get_api_key(&account_id, key_id)
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
        let requested_expires_at =
            validate_expires_at(requested_expires_at, now, &self.api_key_expiry)?;
        let issued = self
            .issue_api_key_secret(
                subject,
                bearer_token,
                existing.project_id.as_str(),
                &new_id,
                Some(requested_expires_at),
            )
            .await?;
        let key_hash = hash_api_key(&issued.secret);
        let key_prefix = Self::key_prefix(&issued.secret);
        let expires_at = resolve_issued_expires_at(Some(requested_expires_at), issued.expires_at);
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
            .rotate_api_key_transaction(
                &account_id,
                key_id,
                status,
                revoked_at,
                old_expires_at,
                row,
            )
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
    use lightbridge_authz_core::config::{
        ApiKeyExpiry, Billing, ModelCatalog, Oauth2, Oauth2Issuance, Oauth2Type, QuotaTiers,
    };
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
            relying_party: None,
            rbac: Default::default(),
            clients: Vec::new(),
            issuance: None,
            federation: Some(lightbridge_authz_core::config::Federation {
                issuer: "https://keycloak.example.test/realms/dev".to_string(),
            }),
        }
    }

    fn lazy_pool() -> Arc<dyn DbPoolTrait> {
        let pool = PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
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
            &QuotaTiers::default(),
            &ModelCatalog::default(),
            &ApiKeyExpiry::default(),
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
            &QuotaTiers::default(),
            &ModelCatalog::default(),
            &ApiKeyExpiry::default(),
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

    // #177: `defaultQuota` validation on `createAccount`, same shape as the billing-plan check
    // above -- `AuthzStoreImpl::create_account` rejects a value absent from a non-empty configured
    // catalogue before the DB write. Uses `lazy_pool()` (a dead connection) exactly like the
    // billing test above: if the check did not run first, this would hang/time out on the DB call
    // instead of returning `BadRequest` immediately, so a passing test proves the check is wired
    // in, not merely that `QuotaTiers::is_allowed` itself works (that's covered directly in
    // `lightbridge_authz_core::config::mod::tests`).
    #[tokio::test]
    async fn create_account_rejects_default_quota_not_in_configured_set() {
        use lightbridge_authz_core::CreateAccount;
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        for tier in ["medim", ""] {
            let err = store
                .create_account(
                    "subject",
                    CreateAccount {
                        default_quota: Some(tier.to_string()),
                    },
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, lightbridge_authz_core::error::Error::BadRequest(ref m) if m.contains("unknown defaultQuota")),
                "tier {tier:?} should be rejected before any DB access, got: {err}"
            );
        }
    }

    /// Mirrors the reject test above but proves `None` (the field left unset) is never rejected,
    /// even against a non-empty catalogue -- requirement #2 of #177 ("NULL/absent stays valid").
    /// Reaches the dead `lazy_pool()` connection and fails with a *connection* error (not
    /// `BadRequest`), which is exactly the point: the quota-tier check let it through and the
    /// failure came from further down the call chain instead.
    #[tokio::test]
    async fn create_account_allows_missing_default_quota_against_a_configured_catalogue() {
        use lightbridge_authz_core::CreateAccount;
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        let err = store
            .create_account(
                "subject",
                CreateAccount {
                    default_quota: None,
                },
            )
            .await
            .unwrap_err();
        assert!(
            !matches!(err, lightbridge_authz_core::error::Error::BadRequest(_)),
            "a missing default_quota must not be rejected by the catalogue check, got: {err}"
        );
    }

    // #177: `quotaTier` validation on `setProjectMemberQuotaTier`, same shape/reasoning as the two
    // `create_account` tests above.
    #[tokio::test]
    async fn set_project_member_quota_tier_rejects_tier_not_in_configured_set() {
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        for tier in ["medim", ""] {
            let err = store
                .set_project_member_quota_tier("subject", "proj", "target", Some(tier))
                .await
                .unwrap_err();
            assert!(
                matches!(err, lightbridge_authz_core::error::Error::BadRequest(ref m) if m.contains("unknown quotaTier")),
                "tier {tier:?} should be rejected before any DB access (including the lead-gate \
                 check), got: {err}"
            );
        }
    }

    /// Mirrors `create_account_allows_missing_default_quota_against_a_configured_catalogue`:
    /// `None` must pass the catalogue check and reach the (dead) DB connection, never `BadRequest`.
    #[tokio::test]
    async fn set_project_member_quota_tier_allows_none_against_a_configured_catalogue() {
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        let err = store
            .set_project_member_quota_tier("subject", "proj", "target", None)
            .await
            .unwrap_err();
        assert!(
            !matches!(err, lightbridge_authz_core::error::Error::BadRequest(_)),
            "None must not be rejected by the catalogue check, got: {err}"
        );
    }

    // #379 (completing #177/#375): `defaultQuota` validation on `updateAccountDefaultQuota`, same
    // shape/reasoning as the two `create_account` tests above -- the only difference is this write
    // path used to be the generic, entirely-unvalidated `model.Account.update` verb before #379
    // marked `Account.defaultQuota` `@readonly` and moved the write behind this procedure.
    #[tokio::test]
    async fn update_account_default_quota_rejects_default_quota_not_in_configured_set() {
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        for tier in ["medim", ""] {
            let err = store
                .update_account_default_quota("subject", "subject", Some(tier))
                .await
                .unwrap_err();
            assert!(
                matches!(err, lightbridge_authz_core::error::Error::BadRequest(ref m) if m.contains("unknown defaultQuota")),
                "tier {tier:?} should be rejected before any DB access, got: {err}"
            );
        }
    }

    /// Mirrors `create_account_allows_missing_default_quota_against_a_configured_catalogue`:
    /// `None` must pass the catalogue check and reach the (dead) DB connection, never `BadRequest`.
    #[tokio::test]
    async fn update_account_default_quota_allows_missing_default_quota_against_a_configured_catalogue()
     {
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        let err = store
            .update_account_default_quota("subject", "subject", None)
            .await
            .unwrap_err();
        assert!(
            !matches!(err, lightbridge_authz_core::error::Error::BadRequest(_)),
            "a missing default_quota must not be rejected by the catalogue check, got: {err}"
        );
    }

    // #379 (completing #177/#375): `projectQuota` validation on `setProjectQuota`, same
    // shape/reasoning as above -- this write path used to be the generic, entirely-unvalidated
    // `model.Project.create`/`model.Project.update` verbs before #379 marked `Project.projectQuota`
    // `@readonly` and moved the write behind this procedure.
    #[tokio::test]
    async fn set_project_quota_rejects_project_quota_not_in_configured_set() {
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        for tier in ["medim", ""] {
            let err = store
                .set_project_quota("subject", "proj", Some(tier))
                .await
                .unwrap_err();
            assert!(
                matches!(err, lightbridge_authz_core::error::Error::BadRequest(ref m) if m.contains("unknown projectQuota")),
                "tier {tier:?} should be rejected before any DB access, got: {err}"
            );
        }
    }

    /// Mirrors `set_project_member_quota_tier_allows_none_against_a_configured_catalogue`: `None`
    /// must pass the catalogue check and reach the (dead) DB connection, never `BadRequest`.
    #[tokio::test]
    async fn set_project_quota_allows_none_against_a_configured_catalogue() {
        use lightbridge_authz_core::config::QuotaTier;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_quota_tiers(QuotaTiers {
            tiers: vec![QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            }],
        });

        let err = store
            .set_project_quota("subject", "proj", None)
            .await
            .unwrap_err();
        assert!(
            !matches!(err, lightbridge_authz_core::error::Error::BadRequest(_)),
            "None must not be rejected by the catalogue check, got: {err}"
        );
    }

    // #415 (ADR-0018 Decision 5): `allowedModels` validation on `setProjectAllowedModels`, same
    // shape/reasoning as `setProjectQuota` above -- this write path used to be the generic,
    // entirely-unvalidated `model.Project.create`/`model.Project.update` verbs before #415 marked
    // `Project.allowedModels` `@readonly` and moved the write behind this procedure.
    #[tokio::test]
    async fn set_project_allowed_models_rejects_models_not_in_configured_set() {
        use lightbridge_authz_core::config::ModelCatalogEntry;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_model_catalog(ModelCatalog {
            models: vec![ModelCatalogEntry {
                id: "gpt-4.1-mini".to_string(),
                name: "GPT-4.1 Mini".to_string(),
            }],
        });

        let err = store
            .set_project_allowed_models(
                "subject",
                "proj",
                Some(vec!["gpt-4.1-mini".to_string(), "gtp-4.1-typo".to_string()]),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, lightbridge_authz_core::error::Error::BadRequest(ref m) if m.contains("unknown allowedModels") && m.contains("gtp-4.1-typo")),
            "an entry absent from the catalogue should be rejected by name before any DB access, got: {err}"
        );
    }

    /// Mirrors `set_project_quota_allows_none_against_a_configured_catalogue`: `None` must pass the
    /// catalogue check and reach the (dead) DB connection, never `BadRequest`.
    #[tokio::test]
    async fn set_project_allowed_models_allows_none_against_a_configured_catalogue() {
        use lightbridge_authz_core::config::ModelCatalogEntry;

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_model_catalog(ModelCatalog {
            models: vec![ModelCatalogEntry {
                id: "gpt-4.1-mini".to_string(),
                name: "GPT-4.1 Mini".to_string(),
            }],
        });

        let err = store
            .set_project_allowed_models("subject", "proj", None)
            .await
            .unwrap_err();
        assert!(
            !matches!(err, lightbridge_authz_core::error::Error::BadRequest(_)),
            "None must not be rejected by the catalogue check, got: {err}"
        );
    }

    /// #415: proves the "empty/absent catalogue accepts anything" default is real, not merely
    /// documented -- an entry that matches nothing configured must still pass when `models` is
    /// never set (`AuthzStoreImpl::with_pool` defaults to `ModelCatalog::default()`).
    #[tokio::test]
    async fn set_project_allowed_models_accepts_anything_when_catalogue_is_empty() {
        let store = AuthzStoreImpl::with_pool(lazy_pool());

        let err = store
            .set_project_allowed_models("subject", "proj", Some(vec!["anything-goes".to_string()]))
            .await
            .unwrap_err();
        assert!(
            !matches!(err, lightbridge_authz_core::error::Error::BadRequest(_)),
            "an empty/absent catalogue must accept any value, got: {err}"
        );
    }

    // Backs `listBillingPlans`: proves `billing_plans()` hands back the exact catalogue the store
    // was constructed with (same plans, in order, `limits` intact including a plan with no limits
    // at all) rather than e.g. a default-constructed `Billing` or a stale clone from before
    // `with_billing` -- this would fail if `billing_plans()` returned `&Billing::default()` or
    // otherwise didn't thread through the field `with_billing` sets.
    #[tokio::test]
    async fn billing_plans_returns_the_configured_catalogue_verbatim() {
        use lightbridge_authz_core::config::{BillingLimits, BillingPlan};

        let configured = Billing {
            plans: vec![
                BillingPlan {
                    id: "free".to_string(),
                    name: "Free".to_string(),
                    limits: Some(BillingLimits {
                        requests_per_second: Some(5),
                        requests_per_day: Some(5000),
                        requests_per_month: None,
                        concurrent_requests: Some(5),
                    }),
                },
                BillingPlan {
                    id: "enterprise".to_string(),
                    name: "Enterprise".to_string(),
                    limits: None,
                },
            ],
        };

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_billing(configured.clone());

        assert_eq!(store.billing_plans().plans, configured.plans);
    }

    // Backs `listModelCatalog`: proves `model_catalog()` hands back the exact catalogue the store
    // was constructed with (same entries, in order) rather than e.g. a default-constructed
    // `ModelCatalog` or a stale clone from before `with_model_catalog` -- this would fail if
    // `model_catalog()` returned `&ModelCatalog::default()` or otherwise didn't thread through the
    // field `with_model_catalog` sets. Mirrors `billing_plans_returns_the_configured_catalogue_verbatim`
    // above.
    #[tokio::test]
    async fn model_catalog_returns_the_configured_catalogue_verbatim() {
        use lightbridge_authz_core::config::ModelCatalogEntry;

        let configured = ModelCatalog {
            models: vec![
                ModelCatalogEntry {
                    id: "dev-model-a".to_string(),
                    name: "Dev Model A".to_string(),
                },
                ModelCatalogEntry {
                    id: "dev-model-b".to_string(),
                    name: "Dev Model B".to_string(),
                },
            ],
        };

        let store = AuthzStoreImpl::with_pool(lazy_pool()).with_model_catalog(configured.clone());

        assert_eq!(store.model_catalog().models, configured.models);
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
            relying_party: None,
            rbac: Default::default(),
            clients: Vec::new(),
            federation: None,
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
            relying_party: None,
            rbac: Default::default(),
            clients: Vec::new(),
            federation: None,
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
            relying_party: None,
            rbac: Default::default(),
            clients: Vec::new(),
            federation: None,
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
