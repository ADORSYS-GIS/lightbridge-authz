//! LoC rationale: `OpaState`, `OpaRepoTrait` (12 methods), `SessionStatusRow`, and `StoreRepo`'s `OpaRepoTrait` impl form one cohesive repository trait & implementation unit for authz-opa server state.

use std::sync::Arc;

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::{
    Account, AccountId, Project, async_trait,
    config::{BasicAuth, Billing},
    error::{Error, Result},
};

use crate::{auth_provider, introspect_budget};

/// Shared state for the OPA server.
pub struct OpaState {
    pub repo: Arc<dyn OpaRepoTrait>,
    pub basic_auth: BasicAuth,
    /// Configured billing-plan catalogue, used to resolve a key's plan id into its display name
    /// and limits at introspection time.
    pub billing: Arc<Billing>,
    /// `oauth2.signing.audience` -- the FIXED `azp` value a self-signed API-key JWT always
    /// carries (`ApiKeyJwtSigner::sign`). `handlers::exchange_token::verify_self_issued_token`
    /// uses this to refuse any self-issued token shaped like an API-key JWT before ever treating
    /// it as an exchange session, independent of whether an `api_keys` row still exists for it --
    /// see that function's doc comment. `None` when `oauth2.type` is `external` (no self-signing
    /// at all) or when `oauth2.signing.audience` is left unconfigured under `type: self`.
    pub api_key_audience: Option<String>,
    /// ADR-0025 Stage 2: translates `handlers::idp::resolve_context`'s presented
    /// `(issuer, subject)` into the acting account id -- the real translation seam for that
    /// endpoint, distinct from [`OpaRepoTrait`]'s own `subject: &str` methods (whose callers
    /// already hold an ADR-0025-resolved value -- see the `OpaRepoTrait for StoreRepo` impl's own
    /// doc comment).
    pub resolver: Arc<dyn auth_provider::SubjectResolver>,
    /// `oauth2.federation.issuer` -- the default `handlers::idp::resolve_context` uses when the
    /// request body omits `issuer` (the legacy `lightbridge-keycloak-spi` adapter's shape).
    pub federation_issuer: String,
    /// ADR-0034 §15: the budget half of the introspection response. `authz-opa` reads
    /// `budget_remaining_snapshots` by primary key so the gateway needs ONE metadata call per
    /// request instead of two — see [`crate::introspect_budget`] for what is and is not reported.
    pub budget: introspect_budget::BudgetIntrospection,
}

#[async_trait]
pub trait OpaRepoTrait: Send + Sync {
    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey>;
    async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>>;
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>>;
    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>>;
    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>>;
    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>>;
    async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext>;
    /// Backs `POST /idp/v1/authorize-usage-scope` (#570): does `subject` (already ADR-0025-
    /// resolved to an account id, exactly like every other `subject: &str` method on this trait)
    /// own `scope_id` under `scope` (`"account"` or `"project"`)? `Ok(())` when authorized,
    /// `Err(Error::NotFound)` for every refusal (unowned, unknown scope_id, or an unrecognized
    /// `scope`) -- see `StoreRepo::authorize_usage_scope`'s doc comment for the full predicate and
    /// why refusal is uniform.
    async fn authorize_usage_scope(&self, subject: &str, scope: &str, scope_id: &str)
    -> Result<()>;
    /// `subject`'s per-member `quota_tier` on `project_id` (ADR-0017), or `None` for "no
    /// per-member ceiling" -- see `StoreRepo::project_member_quota_tier`'s doc comment for the
    /// full `Ok(None)` vs `Err` distinction. Used by introspection to resolve the `quota_tier`
    /// field for a native RFC 8693 exchange session the same way `owner_quota_tier` already does
    /// for the API-key plane.
    /// ADR-0034 §15: this account's precomputed remaining balance, or `None` when there is no row.
    ///
    /// Defaulted to `Ok(None)` — "this repository serves no budget snapshots" — so the mock repos
    /// in this crate's and `lightbridge-mcp`'s tests stay honest without restating it. `StoreRepo`
    /// overrides it with the real primary-key read, and `StoreRepo` is the only implementation any
    /// server runs.
    async fn budget_remaining_snapshot(
        &self,
        _budget_account_id: &str,
    ) -> Result<Option<lightbridge_authz_budget::BudgetSnapshot>> {
        Ok(None)
    }

    /// Records that the request path just asked about this account, so `authz-budget`'s refresher
    /// keeps its reading warm. Called write-behind, never awaited on the hot path.
    async fn touch_budget_remaining_snapshot(&self, _budget_account_id: &str) -> Result<()> {
        Ok(())
    }

    async fn project_member_quota_tier(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>>;
    /// `subject`'s roster `role` on `project_id`, or `None` if they hold no `project_members` row.
    /// Used by introspection to resolve the `role` field for a native RFC 8693 exchange session,
    /// the human/OIDC-plane mirror of `owner_role` on the API-key plane.
    async fn project_member_role(&self, project_id: &str, subject: &str) -> Result<Option<String>>;
    /// Every signing key (active + retired-but-not-yet-expired) this service has minted, as raw
    /// JWK JSON -- the same rows `signing::well_known_router`'s `/.well-known/jwks.json` handler
    /// serves. Introspection uses this to verify a presented token was signed by one of THIS
    /// service's own keys (a *different* trust root than `oauth2.jwks_url`, the external IdP)
    /// before trusting any tenant claim on it -- see
    /// `handlers::exchange_token::verify_self_issued_token`.
    async fn list_verification_jwks(&self) -> Result<Vec<serde_json::Value>>;
    /// ADR-0020 Decision 4 / #437: the current `status`/`expires_at` of the `sessions` row named
    /// by a token-exchange access token's `sid` claim -- `Ok(None)` when no such row exists (a
    /// pre-ADR-0020 token, or an unrecognized `sid`), `Err` when the lookup itself fails (DB
    /// unreachable). See `handlers::exchange_token::resolve_exchange_token_context`'s own doc
    /// comment for why the `Err` case must never be read as "session is fine" -- it is the one
    /// fail-closed branch this whole ADR exists to add.
    async fn find_session_status(&self, session_id: &str) -> Result<Option<SessionStatusRow>>;
}

/// The two session-row fields introspection needs to decide `active`/`revoked`/`expired`
/// (ADR-0020 Decision 6) -- deliberately narrower than the full `sessions` row (no `account_id`/
/// `project_id`/`client_id`/`kind`/etc, none of which `resolve_exchange_token_context` needs).
#[derive(Debug, Clone)]
pub struct SessionStatusRow {
    /// `"active"` / `"revoked"` -- plain `String`, parsed fail-closed on the read side (an
    /// unrecognized value is never treated as `"active"`), matching this schema's established
    /// convention for closed-set string columns (`Project.modelPolicy`, `AugmentationRequest.status`).
    pub status: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
impl OpaRepoTrait for StoreRepo {
    /// One primary-key probe of `budget_remaining_snapshots`, on the connection pool this repo
    /// already holds — ADR-0034 §15's whole reason for existing (see `crate::introspect_budget`).
    async fn budget_remaining_snapshot(
        &self,
        budget_account_id: &str,
    ) -> Result<Option<lightbridge_authz_budget::BudgetSnapshot>> {
        use lightbridge_authz_budget::BudgetSnapshotReader;
        lightbridge_authz_budget::SnapshotStore::new(self.pool.clone())
            .read(budget_account_id)
            .await
            .map_err(|err| Error::Server(err.to_string()))
    }

    async fn touch_budget_remaining_snapshot(&self, budget_account_id: &str) -> Result<()> {
        use lightbridge_authz_budget::BudgetSnapshotReader;
        lightbridge_authz_budget::SnapshotStore::new(self.pool.clone())
            .touch(budget_account_id)
            .await
            .map_err(|err| Error::Server(err.to_string()))
    }

    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey> {
        StoreRepo::record_api_key_usage(self, key_id, ip).await
    }

    async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>> {
        StoreRepo::find_api_key_validation_by_hash(self, key_hash).await
    }

    // ADR-0025: `OpaRepoTrait`'s own `subject: &str` contract is UNCHANGED here on purpose --
    // every caller of this trait (OPA/Authorino introspection, `handlers::opa`/
    // `handlers::exchange_token`) already holds a value read straight off an `accounts.id`-anchored
    // column (`owner_account_id`, a resolved exchange session's `account_id`, ...), never a raw
    // bearer claim that has not passed through `StoreRepo::resolve_account_for_federated_subject`.
    // Wrapping via `AccountId::assert_already_resolved` here is exactly the "already-legitimate account id,
    // just not yet typed" case that constructor's own doc comment describes -- this trait is
    // deliberately outside the ingress list ADR-0025 Stage 2 translates (auth_provider.rs,
    // bearer, mcp.rs, handlers/idp.rs, relying_party.rs, oauth2_op/store.rs).
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project(
            self,
            &AccountId::assert_already_resolved(subject),
            project_id,
        )
        .await
    }

    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account(
            self,
            &AccountId::assert_already_resolved(subject),
            account_id,
        )
        .await
    }

    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project_by_id(self, project_id).await
    }

    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account_by_id(self, account_id).await
    }

    async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext> {
        StoreRepo::resolve_context(
            self,
            &AccountId::assert_already_resolved(subject),
            project_id,
        )
        .await
    }

    async fn authorize_usage_scope(
        &self,
        subject: &str,
        scope: &str,
        scope_id: &str,
    ) -> Result<()> {
        StoreRepo::authorize_usage_scope(
            self,
            &AccountId::assert_already_resolved(subject),
            scope,
            scope_id,
        )
        .await
    }

    async fn project_member_quota_tier(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>> {
        StoreRepo::project_member_quota_tier(
            self,
            project_id,
            &AccountId::assert_already_resolved(subject),
        )
        .await
    }

    async fn project_member_role(&self, project_id: &str, subject: &str) -> Result<Option<String>> {
        StoreRepo::project_member_role(
            self,
            project_id,
            &AccountId::assert_already_resolved(subject),
        )
        .await
    }

    async fn list_verification_jwks(&self) -> Result<Vec<serde_json::Value>> {
        StoreRepo::list_verification_jwks(self).await
    }

    async fn find_session_status(&self, session_id: &str) -> Result<Option<SessionStatusRow>> {
        StoreRepo::find_session_status(self, session_id)
            .await
            .map(|opt| {
                opt.map(|row| SessionStatusRow {
                    status: row.status,
                    expires_at: row.expires_at,
                })
            })
    }
}
