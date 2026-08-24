//! `TokenExchangeOpStore`: the `OpStore` implementation ADR-0011 phase 2 wires into
//! `authkestra_op::handlers::token::handle_token`, plus `RequestScopedOpStore`, the thin
//! per-request wrapper that closes over the one field `handle_token`'s dispatch has no room to
//! carry -- see that type's doc comment for why.
//!
//! **How much RFC 8693 logic this file hand-writes, and why:** on `authkestra-op`/
//! `authkestra-engine` 0.5.0, `OpStore::handle_token_exchange` and `OpStore::handle_refresh_token`
//! are real, overridable, defaulted trait methods -- so this store reaches `handle_token` (the
//! entry point) and overrides both here rather than forking anything. Both overrides below are
//! full reimplementations of the RFC 8693 exchange/refresh logic (subject-token validation,
//! audience binding, scope intersection, token minting), not thin wrappers -- everything from
//! "validate the subject_token" onward is hand-written here.
//!
//! **Re-evaluated on the 0.5.0 bump, not just carried forward:** upstream PR #217 made
//! `handlers::token::default_handle_token_exchange` `pub` specifically so external `OpStore`
//! overrides could delegate to it and post-process the result instead of reimplementing RFC 8693
//! from scratch. Delegating here was evaluated and rejected for two independent, sufficient
//! reasons, either alone enough to keep the full reimplementation:
//!
//! 1. `default_handle_token_exchange` validates the presented `subject_token` via
//!    `tokens.validate_token` -- i.e. against *this service's own* `TokenManager` signing key.
//!    Our `subject_token` is a Keycloak access token signed by a completely different key (a
//!    different issuer's JWKS), so delegating would make every real exchange request fail
//!    validation with `invalid_grant`. This override validates it via
//!    `BearerTokenServiceTrait::validate_bearer_token` (the existing JWKS-backed Keycloak
//!    validator) instead, exactly as the phase-1 hand-rolled dispatch already did.
//! 2. Even setting (1) aside, `default_handle_token_exchange`'s returned `TokenResponse` does not
//!    expose the `Identity`/claims it resolved internally -- only the final `scope` and the
//!    already-signed `access_token`. Stamping `account_id`/`project_id`/`api_key_id`/
//!    `allowed_models`/`at_hash`/`azp` requires those onto the token *at mint time*
//!    (`issue_user_token_with_extra`/`issue_id_token_with_extra`); a signed JWT cannot be
//!    "post-processed" to add claims afterward. Doing this correctly means independently
//!    resolving `resolve_context`/`get_project_by_id`/decoding the subject token -- i.e. most of
//!    what this override already does -- so delegating would not remove that work, only add a
//!    second, unusable token-minting call on top of it.
//!
//! `default_handle_refresh_token` remains `pub(crate)` to `authkestra-op` in 0.5.0 (PR #217 only
//! touched the token-exchange default) -- unreachable from this crate regardless, so the
//! `handle_refresh_token` override below has no delegation option to evaluate at all.

use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_engine::token::TokenManager;
use authkestra_op::client::{ClientRegistration, ClientStore, GrantType, TokenEndpointAuthMethod};
use authkestra_op::client_assertion::ClientAssertionStore;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::config::OpConfig;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStore};
use authkestra_op::error::OpError;
use authkestra_op::handlers::token::{TokenErrorResponse, TokenRequest, TokenResponse};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_op::store::OpStore;
use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_api_key::entities::exchange_refresh_token_row::NewExchangeRefreshToken;
use lightbridge_authz_api_key::entities::session_row::NewSession;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_budget::repo::BudgetRepo;
use lightbridge_authz_budget::{BudgetTier, Period, PolicyEngine};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::Oauth2TokenExchange;
use lightbridge_authz_core::crypto::hash_api_key;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::dto::{ModelPolicy, ResourceStatus};
use lightbridge_authz_core::error::Error;
use serde_json::Value;

use crate::signing::{KeyOwner, access_token_extra, id_token_extra, identity_for};

use super::authorization_code_store::DbAuthorizationCodeStore;
use super::client_assertion_store::RedisClientAssertionStore;
use super::client_store::ConfigClientStore;
use super::device_store::{DbDeviceCodeStore, create_pending_device_authorization};
use super::refresh_store::DbRefreshTokenStore;
use super::{
    ACCESS_TOKEN_TYPE, OFFLINE_ACCESS_SCOPE, OPENID_SCOPE, decode_auth_time_and_nonce,
    decode_email, generate_refresh_secret, grant_scopes, oauth_err, scope_to_string,
};

/// The `budget_tier` claim's wire label for an arbitrary amount, in micros. ADR-0008's ladder
/// used `"b-<dollars>"` (`"b-15"`, `"b-30"`, ...) for its seven compile-time rungs; ADR-0015
/// moved the amounts that can appear here (notably the fail-closed floor, which now defaults to
/// $6 -- below `B15`) out of that compile-time enum and onto a policy document a revision can
/// change without a deploy. Per ADR-0015's own "Neutral / follow-ups": "the wire labels the old
/// enum used ... may still be a reasonable *display* convention for whatever amounts a policy
/// happens to configure, but they are no longer a source of truth for which amounts are valid."
/// This function is that convention, generalized to any amount: prefer the exact legacy label
/// when `amount_micros` happens to match a known rung (byte-for-byte unchanged claim shape for
/// every account on today's $15/$30/.../$1000 ladder), otherwise synthesize `"b-<dollars>"`
/// directly from the amount so a policy-configured floor (or any other new amount) gets an
/// honest label instead of being misrepresented as the nearest legacy rung.
///
/// Assumes whole-dollar amounts (integer micros divisible by `1_000_000`), matching every
/// `allowed_amounts_micros`/`starting_amount_micros`/`fail_closed_floor_micros` value this
/// codebase ships today (`rule_data::default_rule_set_json`, the ADR-0015 migration). A
/// non-whole-dollar amount still produces a label (truncating division), just not one that
/// round-trips back through [`BudgetTier::from_amount_micros`] -- no different in kind from the
/// legacy enum, which likewise had no representation for a non-whole-dollar amount.
fn budget_tier_wire_label(amount_micros: i64) -> String {
    match BudgetTier::from_amount_micros(amount_micros) {
        Some(tier) => tier.label().to_string(),
        None => format!("b-{}", amount_micros / 1_000_000),
    }
}

struct InitialRefreshToken<'a> {
    owner: &'a KeyOwner,
    account_id: &'a str,
    project_id: &'a str,
    client_id: &'a str,
    scope: Option<&'a str>,
    auth_time: Option<i64>,
    session_id: &'a str,
}

/// Everything the native token-exchange endpoint needs, minus the one per-request field
/// (`project_id`) `handle_token`'s dispatch has no room to carry -- see `RequestScopedOpStore`.
/// One instance is built once at server startup and shared (`Arc`) across every request.
pub struct TokenExchangeOpStore {
    clients: ConfigClientStore,
    codes: DbAuthorizationCodeStore,
    refresh: DbRefreshTokenStore,
    /// Real, CAS-consuming storage over `device_authorizations`. The native RFC 8628 endpoint
    /// creates and redeems its rows directly so token issuance can preserve this service's
    /// tenant-context and fail-closed claims contract.
    devices: DbDeviceCodeStore,
    assertions: RedisClientAssertionStore,
    repo: Arc<StoreRepo>,
    /// The `project_members` handle [`Self::resolve_quota_tier`] (ADR-0017) reads from.
    /// Production (`start_idp_server`) always constructs this as a clone of the same `repo`
    /// pointed at the same Postgres pool -- there is no operational separation, only a
    /// deliberately independent injection seam, mirroring exactly why `budget_repo` below is its
    /// own field rather than a method on `repo` (ADR-0014 Decision 2): it lets a test hold `repo`
    /// reachable (so `resolve_context` succeeds) while pointing `quota_repo` at an unreachable
    /// pool, proving [`Self::resolve_quota_tier`]'s own fail-closed branch fires on its own
    /// dependency failing, not merely as a side effect of `resolve_context` failing first --
    /// `crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`'s
    /// `quota_tier_lookup_failure_refuses_the_exchange_even_though_context_resolution_succeeds`
    /// and its refresh-grant mirror are exactly that proof.
    quota_repo: Arc<StoreRepo>,
    budget_repo: Arc<BudgetRepo>,
    /// ADR-0015 Decision 6's fail-closed floor, read live (see [`Self::resolve_budget_tier`]) --
    /// the SAME hot-swappable engine `authz-api`/`authz-budget` already hold via
    /// `policy_store.engine()`, not a private copy. `authz-idp` (this store's only production
    /// constructor, `start_idp_server`) loads its own `PolicyStore` off the shared Postgres
    /// `budget_policy_sets`/`budget_policy_revisions` tables for exactly this reason.
    policy_engine: Arc<dyn PolicyEngine>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    cfg: Oauth2TokenExchange,
}

impl TokenExchangeOpStore {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: ConfigClientStore,
        assertions: RedisClientAssertionStore,
        repo: Arc<StoreRepo>,
        quota_repo: Arc<StoreRepo>,
        budget_repo: Arc<BudgetRepo>,
        policy_engine: Arc<dyn PolicyEngine>,
        bearer: Arc<dyn BearerTokenServiceTrait>,
        cfg: Oauth2TokenExchange,
    ) -> Self {
        Self {
            clients,
            codes: DbAuthorizationCodeStore::new(repo.clone()),
            refresh: DbRefreshTokenStore::new(repo.clone()),
            devices: DbDeviceCodeStore::new(repo.clone()),
            assertions,
            repo,
            quota_repo,
            budget_repo,
            policy_engine,
            bearer,
            cfg,
        }
    }

    /// Whether the discovery document should advertise `private_key_jwt`
    /// (`signing::discovery_document`).
    pub fn has_confidential_client(&self) -> bool {
        self.clients.has_confidential_client()
    }

    pub async fn authorization_code_matches_binding(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<bool, OpError> {
        self.codes
            .matches_binding(code, client_id, redirect_uri)
            .await
    }

    pub(crate) async fn find_client_registration(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, OpError> {
        self.clients.find_client(client_id).await
    }

    /// Revokes a single refresh token by its plaintext value, scoped to the presented
    /// `client_id` (RFC 7009 -- a client may only revoke tokens issued to it). Backs
    /// `POST /oauth2/revoke` (`token_exchange::revoke_endpoint`).
    pub async fn revoke_refresh_token_for_client(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<(), OpError> {
        let hash = lightbridge_authz_core::crypto::hash_api_key(token);
        self.repo
            .revoke_exchange_refresh_token_for_client(&hash, client_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to revoke refresh token for client");
                OpError::Storage
            })
    }

    /// Spends a `private_key_jwt` client assertion's `jti` (ADR-0011, Decision 6). Exposed
    /// directly on `TokenExchangeOpStore` -- not only reachable through the `OpStore` trait on
    /// `RequestScopedOpStore` -- because `POST /oauth2/revoke` has no per-request `project_id` to
    /// wrap in a `RequestScopedOpStore` and still needs to authenticate a confidential client the
    /// same way the token endpoint does.
    pub async fn record_client_assertion_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError> {
        self.assertions.record_jti(jti, expires_at).await
    }

    pub async fn create_device_authorization(
        &self,
        client_id: &str,
        scope: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<DeviceCodeSession, TokenErrorResponse> {
        let client = self
            .clients
            .find_client(client_id)
            .await
            .map_err(|_| oauth_err("server_error", "client registry lookup failed"))?
            .ok_or_else(|| oauth_err("invalid_client", "client authentication failed"))?;
        if !client.allows_grant_type(&GrantType::DeviceCode) {
            return Err(oauth_err(
                "unauthorized_client",
                "client is not authorized for the device grant",
            ));
        }
        if client.token_endpoint_auth_method != Some(TokenEndpointAuthMethod::NoAuth) {
            return Err(oauth_err(
                "unauthorized_client",
                "device authorization requires a public client",
            ));
        }
        let requested = scope.unwrap_or_default();
        let granted = grant_scopes(
            &Some(requested.to_string()),
            &self.cfg.allowed_scopes,
            &client.scopes,
        );
        let requested_scopes: Vec<_> = requested.split_whitespace().collect();
        if !requested_scopes.is_empty() && requested_scopes.len() != granted.len() {
            return Err(oauth_err(
                "invalid_scope",
                "requested scope is not permitted",
            ));
        }
        if granted.iter().any(|scope| scope == OFFLINE_ACCESS_SCOPE)
            && !client.allows_grant_type(&GrantType::RefreshToken)
        {
            return Err(oauth_err(
                "unauthorized_client",
                "client is not authorized for refresh tokens",
            ));
        }
        create_pending_device_authorization(
            self.repo.as_ref(),
            client_id,
            project_id.filter(|id| !id.trim().is_empty()),
            &scope_to_string(&granted).unwrap_or_default(),
            Duration::seconds(self.cfg.device_code_ttl_seconds),
            self.cfg.device_poll_interval_seconds,
        )
        .await
        .map_err(|_| oauth_err("server_error", "device authorization persistence failed"))
    }

    /// Polls and, after approval, consumes an RFC 8628 device code before minting. This makes a
    /// decision one-shot even if subsequent tenant resolution or signing fails: retrying a bearer
    /// device code after partial issuance is less safe than requiring a fresh login.
    pub async fn poll_device_grant(
        &self,
        client_id: &str,
        device_code: &str,
        tokens: &TokenManager,
    ) -> Result<TokenResponse, TokenErrorResponse> {
        let now = Utc::now();
        let client = self
            .clients
            .find_client(client_id)
            .await
            .map_err(|_| oauth_err("server_error", "client registry lookup failed"))?
            .ok_or_else(|| oauth_err("invalid_client", "client authentication failed"))?;
        if !client.allows_grant_type(&GrantType::DeviceCode)
            || client.token_endpoint_auth_method != Some(TokenEndpointAuthMethod::NoAuth)
        {
            return Err(oauth_err(
                "unauthorized_client",
                "client is not authorized for the device grant",
            ));
        }
        let row = self
            .repo
            .find_device_authorization_by_device_code(device_code)
            .await
            .map_err(|_| oauth_err("server_error", "device authorization lookup failed"))?
            .ok_or_else(|| oauth_err("invalid_grant", "device code is invalid"))?;
        if row.client_id != client_id {
            return Err(oauth_err(
                "invalid_grant",
                "device code was issued to another client",
            ));
        }
        if now >= row.expires_at {
            return Err(oauth_err("expired_token", "device code has expired"));
        }
        match row.status.as_str() {
            "pending" => {
                self.repo
                    .touch_device_authorization_poll(device_code, now)
                    .await
                    .map_err(|_| {
                        oauth_err("server_error", "device authorization polling failed")
                    })?;
                if let Some(last_polled_at) = row.last_polled_at
                    && now < last_polled_at + Duration::seconds(i64::from(row.interval_secs))
                {
                    return Err(oauth_err(
                        "slow_down",
                        "device client is polling too quickly",
                    ));
                }
                Err(oauth_err(
                    "authorization_pending",
                    "device authorization is still pending",
                ))
            }
            "denied" | "approved" => {
                let consumed = self
                    .repo
                    .consume_device_authorization(device_code, now)
                    .await
                    .map_err(|_| oauth_err("server_error", "device authorization consume failed"))?
                    .ok_or_else(|| {
                        oauth_err("invalid_grant", "device code is invalid or consumed")
                    })?;
                if consumed.status == "denied" {
                    return Err(oauth_err(
                        "access_denied",
                        "device authorization was denied",
                    ));
                }
                self.issue_device_tokens(
                    consumed,
                    client_id,
                    client.allows_grant_type(&GrantType::RefreshToken),
                    tokens,
                    now,
                )
                .await
            }
            _ => Err(oauth_err(
                "invalid_grant",
                "device code is invalid or consumed",
            )),
        }
    }

    async fn issue_device_tokens(
        &self,
        row: lightbridge_authz_api_key::entities::device_authorization_row::DeviceAuthorizationRow,
        client_id: &str,
        client_allows_refresh: bool,
        tokens: &TokenManager,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, TokenErrorResponse> {
        let subject = row.subject.clone().ok_or_else(|| {
            oauth_err(
                "server_error",
                "approved device authorization has no subject",
            )
        })?;
        let project_id = match row.project_id.as_deref() {
            Some(project_id) => project_id.to_string(),
            None => self
                .repo
                .find_default_project_id(&subject)
                .await
                .map_err(|_| oauth_err("server_error", "context resolution failed"))?
                .ok_or_else(|| oauth_err("access_denied", "subject has no default project"))?,
        };
        let context = match self.repo.resolve_context(&subject, &project_id).await {
            Ok(context) => context,
            Err(Error::NotFound) => {
                return Err(oauth_err(
                    "access_denied",
                    "subject is not a member of the requested project",
                ));
            }
            Err(_) => return Err(oauth_err("server_error", "context resolution failed")),
        };
        let project = match self.repo.get_project_by_id(&context.project_id).await {
            Ok(Some(project)) if project.status == ResourceStatus::Active => project,
            Ok(_) => return Err(oauth_err("access_denied", "project is inactive")),
            Err(_) => return Err(oauth_err("server_error", "project lookup failed")),
        };
        match self.repo.get_account_by_id(&context.account_id).await {
            Ok(Some(account)) if account.status == ResourceStatus::Active => {}
            Ok(_) => return Err(oauth_err("access_denied", "account is inactive")),
            Err(_) => return Err(oauth_err("server_error", "account lookup failed")),
        }
        let scope = row.scope.clone();
        let offline = scope.as_deref().is_some_and(|scopes| {
            scopes
                .split_whitespace()
                .any(|scope| scope == OFFLINE_ACCESS_SCOPE)
        });
        if offline && !client_allows_refresh {
            return Err(oauth_err(
                "unauthorized_client",
                "client is not authorized for refresh tokens",
            ));
        }
        let session_expires_at = if offline {
            now + Duration::seconds(self.cfg.refresh_absolute_ttl_seconds.max(0))
        } else {
            now + Duration::seconds(self.cfg.access_ttl_seconds)
        };
        let session = self
            .repo
            .create_session(NewSession {
                id: cuid2(),
                account_id: context.account_id.clone(),
                project_id: context.project_id.clone(),
                client_id: Some(client_id.to_string()),
                kind: "token".to_string(),
                expires_at: session_expires_at,
                subject: None,
            })
            .await
            .map_err(|_| oauth_err("server_error", "session persistence failed"))?;
        let owner = KeyOwner {
            subject: subject.clone(),
            email: None,
            email_verified: None,
        };
        let expires_in = self.cfg.access_ttl_seconds as u64;
        let budget_tier = self.resolve_budget_tier(&context.account_id, now).await;
        let quota_tier = self
            .resolve_quota_tier(&context.project_id, &subject)
            .await?;
        let mut extra = access_token_extra(
            &owner,
            &session.id,
            &session.id,
            &context.project_id,
            &context.account_id,
            project.allowed_models,
            Some(client_id),
        );
        extra.insert("budget_tier".to_string(), Value::String(budget_tier));
        if let Some(quota_tier) = quota_tier {
            extra.insert("quota_tier".to_string(), Value::String(quota_tier));
        }
        extra.insert(
            "model_policy".to_string(),
            Value::String(project.model_policy.to_string()),
        );
        let access_token = tokens
            .issue_user_token_with_extra(
                identity_for(&owner),
                expires_in,
                scope.clone(),
                Some(client_id.to_string()),
                extra,
            )
            .map_err(|_| oauth_err("server_error", "access token signing failed"))?;
        let id_token = scope
            .as_deref()
            .is_some_and(|scopes| scopes.split_whitespace().any(|scope| scope == OPENID_SCOPE))
            .then(|| {
                tokens
                    .issue_id_token_with_extra(
                        identity_for(&owner),
                        client_id,
                        None,
                        expires_in,
                        id_token_extra(&owner, &access_token, None, client_id),
                    )
                    .map_err(|_| oauth_err("server_error", "id token signing failed"))
            })
            .transpose()?;
        let refresh_token = if offline {
            Some(
                self.create_initial_refresh_token(
                    InitialRefreshToken {
                        owner: &owner,
                        account_id: &context.account_id,
                        project_id: &context.project_id,
                        client_id,
                        scope: scope.as_deref(),
                        auth_time: None,
                        session_id: &session.id,
                    },
                    now,
                )
                .await?,
            )
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            id_token,
            refresh_token,
            scope,
            issued_token_type: None,
        })
    }

    async fn create_initial_refresh_token(
        &self,
        input: InitialRefreshToken<'_>,
        now: DateTime<Utc>,
    ) -> Result<String, TokenErrorResponse> {
        let plaintext = generate_refresh_secret();
        let chain_id = cuid2();
        let chain_expires_at =
            now + Duration::seconds(self.cfg.refresh_absolute_ttl_seconds.max(0));
        let identity = refresh_identity(
            input.owner,
            input.account_id,
            input.project_id,
            input.auth_time,
            &chain_id,
            chain_expires_at,
            input.session_id,
        );
        let refresh = RefreshToken {
            token: plaintext.clone(),
            client_id: input.client_id.to_string(),
            identity,
            scope: input.scope.unwrap_or_default().to_string(),
            expires_at: now + Duration::seconds(self.cfg.refresh_ttl_seconds),
        };
        self.refresh
            .store_token(refresh)
            .await
            .map_err(|_| oauth_err("server_error", "refresh token persistence failed"))?;
        Ok(plaintext)
    }

    /// Resolves the `budget_tier` claim to stamp on a minted access token (ADR-0014,
    /// superseding ADR-0008's Keycloak-attribute delivery mechanism -- the tier ladder and
    /// reset-not-topup semantics from ADR-0008 are unchanged, only *how the tier reaches the
    /// gateway* changed). Called from both [`Self::handle_token_exchange`] and
    /// [`Self::handle_refresh_token`], since ADR-0011 already re-mints both symmetrically through
    /// the same signing calls.
    ///
    /// **Fail-closed, unconditionally, at the policy-configured floor -- not a hard-coded
    /// rung (ADR-0015 Decision 6).** [`BudgetRepo::current_tier`] handles the ADR-0008 "no grant
    /// yet this period" / "grant amount doesn't match a known rung" cases internally by
    /// defaulting to [`BudgetTier::B15`] -- that is the *starting-amount* case (a brand-new
    /// account), a distinct concept from the fail-closed floor this method is about, and it is
    /// deliberately left alone here: see `BudgetRepo::current_tier`'s own doc comment for why
    /// that default stays a flagged, pre-existing simplification rather than being wired to
    /// [`PolicyEngine::starting_amount_micros`] in this change.
    ///
    /// What `BudgetRepo::current_tier` does NOT swallow is a genuine storage failure
    /// (`Err(BudgetError::StorageFailed)`, e.g. the budget ledger's database being unreachable):
    /// that propagates as an `Err`, because a caller that wants to tell "new account" apart from
    /// "ledger down" (an operator alert, say) still can. THIS caller does not want that
    /// distinction -- a budget-ledger outage is orthogonal to whether a login/refresh should
    /// succeed, and per the budget-tier-rekey-cutover runbook, "an account with no claim lands on
    /// no matching rule, which is the difference between base budget and unlimited". So any `Err`
    /// here -- for any reason -- is caught, logged, and downgraded to
    /// [`PolicyEngine::fail_closed_floor_micros`] (read live off the same hot-swappable engine
    /// `authz-api`/`authz-budget` use, never a private snapshot), and the token mint proceeds.
    /// The claim is never omitted and the exchange/refresh grant never fails because of this
    /// lookup.
    ///
    /// Returns the wire label to stamp directly (not a [`BudgetTier`]): the floor amount a policy
    /// revision configures has no guarantee of matching any compile-time rung (the shipped
    /// default is $6, below `B15`'s $15), so [`budget_tier_wire_label`] is used for both the
    /// success and fallback paths to produce a consistent `"b-<dollars>"` label either way.
    async fn resolve_budget_tier(&self, budget_account_id: &str, now: DateTime<Utc>) -> String {
        let period = Period::current(now);
        match self
            .budget_repo
            .current_tier(budget_account_id, &period)
            .await
        {
            Ok(tier) => tier.label().to_string(),
            Err(err) => {
                let floor_micros = self.policy_engine.fail_closed_floor_micros();
                tracing::error!(
                    error = %err,
                    account_id = %budget_account_id,
                    fail_closed_floor_micros = floor_micros,
                    "budget tier resolution failed; falling back to the policy-configured \
                     fail-closed floor rather than omitting the claim or failing the token \
                     exchange"
                );
                budget_tier_wire_label(floor_micros)
            }
        }
    }

    /// Resolves the `quota_tier` claim to stamp on a minted access token (ADR-0017, superseding
    /// ADR-0011 Decision 7's "role/quota data stays out of both JWTs" specifically for
    /// `quota_tier` -- see that ADR for the full rationale and why the general principle otherwise
    /// still stands).
    ///
    /// **Deliberately NOT the same fail-closed shape as [`Self::resolve_budget_tier`].** That
    /// method downgrades any lookup failure to a policy-configured floor because `budget_tier` has
    /// one: a well-ordered ladder with a defined "most conservative" rung. `quota_tier` has no such
    /// ladder -- it is an operator-defined, unordered catalogue (`QuotaTiers`) with no floor to
    /// fall back to, and per `StoreRepo::project_member_quota_tier`'s own doc comment, `Ok(None)`
    /// is ALREADY the resolved-and-legitimate "no per-member ceiling" answer (mirroring the
    /// `api_key_validation` view's NULL semantics for the API-key plane). Reusing that same shape
    /// for "the lookup failed" would make a database outage indistinguishable on the wire from
    /// "this account genuinely has no per-member ceiling" -- silently trading an availability
    /// failure for a quota bypass, exactly the failure mode this repository's review guidance
    /// treats as the highest-yield question to ask of any code on this boundary.
    ///
    /// So this method refuses instead: any `Err` from the lookup is surfaced as `server_error` and
    /// the token exchange/refresh fails outright -- no token is minted, and therefore no
    /// `quota_tier` value (real, absent, or sentinel) ever reaches the wire for that request. This
    /// is not a new failure philosophy invented here -- it is the exact one `resolve_context`'s own
    /// `Err(_) => oauth_err("server_error", ...)` branches already apply to account/project
    /// resolution failures a few lines above every call site of this method; this only extends the
    /// same rule to the per-member tier lookup instead of quietly exempting it.
    async fn resolve_quota_tier(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>, TokenErrorResponse> {
        self.quota_repo
            .project_member_quota_tier(project_id, subject)
            .await
            .map_err(|err| {
                tracing::error!(
                    error = %err,
                    project_id = %project_id,
                    subject = %subject,
                    "quota tier resolution failed; refusing to mint rather than omitting the \
                     claim, which would be indistinguishable from a legitimate 'no per-member \
                     ceiling' account"
                );
                oauth_err("server_error", "quota tier resolution failed")
            })
    }

    /// Resolves `allowed_models` and `model_policy` (ADR-0018) from the SAME project row for the
    /// token-exchange grant -- one query for both, generalizing the ADR's "same call, same row, no
    /// new query" shape (stated there for introspection) to this call site too. Not used by
    /// [`Self::handle_refresh_token`], which already loads `project` earlier for its own
    /// re-validation and reads both fields directly off that value instead of calling this again.
    ///
    /// `allowed_models` keeps its pre-existing behavior, UNCHANGED by this method: any lookup
    /// failure (not found, or a genuine error) resolves to `None`, same as before this ADR existed
    /// -- not a decision this ticket revisits.
    ///
    /// `model_policy` is different, and deliberately NOT given that same fail-open shape: unlike
    /// `allowed_models`'s `None` (a legitimate "no restriction" answer), there is no reading of "the
    /// lookup failed" that safely maps to a permissive `model_policy`. So any lookup failure here
    /// fails CLOSED to [`ModelPolicy::DenyAll`] (logged as an error) -- the claim is still always
    /// minted, never omitted, and the exchange itself is never refused because of this lookup,
    /// mirroring [`Self::resolve_budget_tier`]'s "downgrade to the safest value, don't fail the
    /// mint" shape rather than [`Self::resolve_quota_tier`]'s "refuse the exchange" shape, because
    /// -- like `budget_tier` and unlike `quota_tier` -- `model_policy` always has a well-defined
    /// most-conservative value to fall back to.
    async fn resolve_project_model_access(
        &self,
        project_id: &str,
    ) -> (Option<Vec<String>>, ModelPolicy) {
        match self.repo.get_project_by_id(project_id).await {
            Ok(Some(project)) => (project.allowed_models, project.model_policy),
            Ok(None) => {
                tracing::error!(
                    project_id = %project_id,
                    "project not found while resolving model_policy claim; failing closed to \
                     deny_all rather than defaulting to allow_all"
                );
                (None, ModelPolicy::DenyAll)
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    project_id = %project_id,
                    "project lookup failed while resolving model_policy claim; failing closed to \
                     deny_all rather than defaulting to allow_all"
                );
                (None, ModelPolicy::DenyAll)
            }
        }
    }

    /// The RFC 8693 token-exchange grant (ADR-0011, Decisions 1, 5, 7). `project_id` is this
    /// crate's own extension to the request, threaded in by `RequestScopedOpStore` since it is
    /// not a field `authkestra_op::handlers::token::TokenRequest` has room for. Optional: a
    /// first-time caller has no way to know their project id, so an absent `project_id` falls back
    /// to `subject`'s auto-provisioned default project (`StoreRepo::find_default_project_id`) once
    /// the subject is known from the validated `subject_token`.
    async fn handle_token_exchange(
        &self,
        req: TokenRequest,
        client_id: String,
        client: ClientRegistration,
        tokens: &TokenManager,
        project_id: Option<&str>,
    ) -> Result<TokenResponse, TokenErrorResponse> {
        if !self.cfg.enabled {
            return Err(oauth_err(
                "unsupported_grant_type",
                "Token exchange is not enabled on this authorization server",
            ));
        }
        if !client.allows_grant_type(&GrantType::TokenExchange) {
            return Err(oauth_err(
                "unauthorized_client",
                "Client is not authorized to use token_exchange grant type",
            ));
        }
        if req.actor_token.is_some() || req.actor_token_type.is_some() {
            return Err(oauth_err("invalid_request", "actor_token is not supported"));
        }
        if req.subject_token_type.as_deref() != Some(ACCESS_TOKEN_TYPE) {
            return Err(oauth_err(
                "invalid_request",
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token",
            ));
        }
        let requested_token_type = req
            .requested_token_type
            .as_deref()
            .unwrap_or(ACCESS_TOKEN_TYPE);
        if requested_token_type != ACCESS_TOKEN_TYPE {
            return Err(oauth_err(
                "invalid_request",
                "Unsupported requested_token_type. Only access_token is supported.",
            ));
        }
        let Some(subject_token) = req
            .subject_token
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        else {
            return Err(oauth_err("invalid_request", "subject_token is required"));
        };
        let requested_project_id = project_id.map(str::trim).filter(|s| !s.is_empty());

        let token_info = match self.bearer.validate_bearer_token(subject_token).await {
            Ok(info) if info.active => info,
            Ok(_) | Err(_) => {
                return Err(oauth_err("invalid_request", "subject_token is invalid"));
            }
        };
        let subject = token_info.sub.clone();

        // Audience binding (mirrors authkestra-op's own default_handle_token_exchange, adapted to
        // TokenInfo.aud rather than authkestra_engine::token::Claims.aud -- see this module's
        // header comment for why validation itself goes through a different path): the
        // requesting client must be a member of the subject token's own `aud` claim.
        if !token_info.aud.iter().any(|a| a == &client_id) {
            return Err(oauth_err(
                "invalid_grant",
                "Client is not authorized to exchange this token",
            ));
        }

        // No `project_id` on the request: resolve to the subject's own auto-provisioned default
        // project instead of rejecting -- see this method's doc comment. A subject with zero
        // projects yet (a real, reachable state: account creation and the bootstrap "ensure
        // default project" flow are separate calls) has no default to fall back to; that resolves
        // identically to `resolve_context`'s own `NotFound` below, not as a distinct error class,
        // so this endpoint never leaks "you have no projects" any more than it leaks "that project
        // doesn't exist".
        let effective_project_id = match requested_project_id {
            Some(project_id) => project_id.to_string(),
            None => match self.repo.find_default_project_id(&subject).await {
                Ok(Some(project_id)) => project_id,
                Ok(None) => {
                    return Err(oauth_err(
                        "access_denied",
                        "subject is not a member of the requested project",
                    ));
                }
                Err(_) => {
                    return Err(oauth_err("server_error", "context resolution failed"));
                }
            },
        };

        let context = match self
            .repo
            .resolve_context(&subject, &effective_project_id)
            .await
        {
            Ok(context) => context,
            Err(Error::NotFound) => {
                return Err(oauth_err(
                    "access_denied",
                    "subject is not a member of the requested project",
                ));
            }
            Err(_) => {
                return Err(oauth_err("server_error", "context resolution failed"));
            }
        };

        let (allowed_models, model_policy) =
            self.resolve_project_model_access(&context.project_id).await;

        let granted_scopes = grant_scopes(&req.scope, &self.cfg.allowed_scopes, &client.scopes);
        let offline = granted_scopes.iter().any(|s| s == OFFLINE_ACCESS_SCOPE);
        let openid = granted_scopes.iter().any(|s| s == OPENID_SCOPE);

        let (email, email_verified) = decode_email(subject_token);
        let (auth_time, nonce) = decode_auth_time_and_nonce(subject_token);
        let owner = KeyOwner {
            subject: subject.clone(),
            email,
            email_verified,
        };

        let now = Utc::now();
        let expires_in_secs = self.cfg.access_ttl_seconds.max(0) as u64;
        let scope_str = scope_to_string(&granted_scopes);

        // ADR-0020 Decision 1: a session row is created exactly once, at the initial
        // handle_token_exchange grant -- unconditionally, whether or not offline_access was
        // requested, since even an access-token-only grant needs a revocable identity.
        // `expires_at` mirrors the refresh chain's own absolute cap (`chain_expires_at`, set
        // below) when this grant has one, so the two agree; for an access-token-only grant there
        // is no chain, so the session's own cap is just the access token's own TTL.
        let session_expires_at = if offline {
            now + Duration::seconds(self.cfg.refresh_absolute_ttl_seconds.max(0))
        } else {
            now + Duration::seconds(expires_in_secs as i64)
        };
        let session = match self
            .repo
            .create_session(NewSession {
                id: cuid2(),
                account_id: context.account_id.clone(),
                project_id: context.project_id.clone(),
                client_id: Some(client_id.clone()),
                kind: "token".to_string(),
                expires_at: session_expires_at,
                subject: None,
            })
            .await
        {
            Ok(session) => session,
            Err(_) => return Err(oauth_err("server_error", "session persistence failed")),
        };
        let session_id = session.id;

        let budget_tier = self.resolve_budget_tier(&context.account_id, now).await;
        let quota_tier = self
            .resolve_quota_tier(&context.project_id, &subject)
            .await?;
        // ADR-0020 Decision 2 (#437's scoped-down interpretation, see `access_token_extra`'s doc
        // comment): `sid` and `api_key_id` carry the SAME real, persisted session id.
        let mut access_extra = access_token_extra(
            &owner,
            &session_id,
            &session_id,
            &context.project_id,
            &context.account_id,
            allowed_models,
            Some(&client_id),
        );
        access_extra.insert("budget_tier".to_string(), Value::String(budget_tier));
        if let Some(quota_tier) = quota_tier {
            access_extra.insert("quota_tier".to_string(), Value::String(quota_tier));
        }
        access_extra.insert(
            "model_policy".to_string(),
            Value::String(model_policy.to_string()),
        );
        let access_token = tokens
            .issue_user_token_with_extra(
                identity_for(&owner),
                expires_in_secs,
                scope_str.clone(),
                Some(client_id.clone()),
                access_extra,
            )
            .map_err(|_| oauth_err("server_error", "access token signing failed"))?;

        let id_token = if openid {
            let extra = id_token_extra(&owner, &access_token, auth_time, &client_id);
            match tokens.issue_id_token_with_extra(
                identity_for(&owner),
                &client_id,
                nonce,
                expires_in_secs,
                extra,
            ) {
                Ok(t) => Some(t),
                Err(_) => return Err(oauth_err("server_error", "id token signing failed")),
            }
        } else {
            None
        };

        let refresh_token = if offline {
            Some(
                self.create_initial_refresh_token(
                    InitialRefreshToken {
                        owner: &owner,
                        account_id: &context.account_id,
                        project_id: &context.project_id,
                        client_id: &client_id,
                        scope: scope_str.as_deref(),
                        auth_time,
                        session_id: &session_id,
                    },
                    now,
                )
                .await?,
            )
        } else {
            None
        };

        tracing::info!(
            subject = %subject,
            account_id = %context.account_id,
            project_id = %context.project_id,
            client_id = %client_id,
            offline,
            openid,
            "token-exchange issued access token"
        );

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: expires_in_secs,
            id_token,
            refresh_token,
            scope: scope_str,
            // RFC 8693 §2.2.1: REQUIRED on a token-exchange grant response, mirroring
            // `default_handle_token_exchange`'s own value for this field.
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
        })
    }

    /// The `refresh_token` grant (ADR-0011, Decision 1): re-mints access + id_token symmetrically
    /// with the exchange grant above, through the same signing calls, which is what fixes the
    /// phase-1-era `mint_from_refresh` email-dropping bug by construction (there is only one
    /// minting path now).
    ///
    /// Hardened against three gaps a security review found (all three needed the same new
    /// `chain_id`/`chain_expires_at` schema, hence one change):
    ///
    /// 1. **Re-validation.** The pre-hardening version's only DB read here was an unfiltered
    ///    `get_project_by_id` -- a subject removed from the project's roster, or whose account/
    ///    project was suspended, could keep refreshing forever, and a project that could not be
    ///    resolved fell through to `allowed_models = None`, which this codebase reads as "no
    ///    restriction" (fail-open on a deleted project). This now re-runs the same
    ///    `resolve_context` ownership/membership check the exchange grant uses, plus the same
    ///    project/account `status == active` cascade `api_key_validation` enforces for API keys,
    ///    and refuses (`invalid_grant`) on any resolution failure rather than falling through.
    ///    Scope limit: this does NOT re-validate against Keycloak -- no Keycloak credential is
    ///    held at refresh time, so a subject *disabled in Keycloak* (as opposed to removed from
    ///    this service's own roster) is bounded only by the absolute cap below and an operator's
    ///    revoke action, not by this check.
    /// 2. **Absolute cap.** Each rotation used to reset `expires_at` to `now() +
    ///    refresh_ttl_seconds` with nothing bounding how many times that could repeat, so a
    ///    session that kept refreshing before every expiry never actually ended. `chain_expires_at`
    ///    (`Oauth2TokenExchange::refresh_absolute_ttl_seconds`, set once when the chain is born
    ///    and inherited unchanged by every rotation) is now checked here and refused past its
    ///    deadline.
    /// 3. **Reuse cascade.** The single-use CAS (`WHERE status = 'active'`) already rejected a
    ///    replay of a superseded token, but did nothing to the live token that superseded it --
    ///    RFC 6819 §5.2.2.3 calls this out by name: a reused refresh token is the strongest signal
    ///    this codebase has that a token was stolen, and the whole family must die, not just the
    ///    replayed member. `find_exchange_refresh_token_by_hash` distinguishes "already rotated"
    ///    (cascade) from "unknown/expired/revoked" (plain `invalid_grant`, no cascade) after the
    ///    CAS fails, and `revoke_exchange_refresh_token_chain` performs the cascade.
    ///
    /// Still matches `default_handle_refresh_token`'s own client-binding shape: a refresh token
    /// presented by a different client than the one it was issued to is burned (single-use,
    /// already consumed) rather than silently honored -- see `exchange_refresh_tokens_add_client_id`
    /// migration.
    async fn handle_refresh_token(
        &self,
        req: TokenRequest,
        client_id: String,
        client: ClientRegistration,
        tokens: &TokenManager,
    ) -> Result<TokenResponse, TokenErrorResponse> {
        if !client.allows_grant_type(&GrantType::RefreshToken) {
            return Err(oauth_err(
                "unauthorized_client",
                "Client is not authorized to use refresh_token grant type",
            ));
        }
        let Some(presented) = req
            .refresh_token
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        else {
            return Err(oauth_err("invalid_request", "refresh_token is required"));
        };

        let now = Utc::now();
        let presented_hash = hash_api_key(presented);
        let invalid_grant = || {
            oauth_err(
                "invalid_grant",
                "refresh_token is invalid, expired, or already used",
            )
        };

        let old_row = match self
            .repo
            .consume_exchange_refresh_token(&presented_hash, now)
            .await
        {
            Ok(Some(row)) => row,
            Ok(None) => {
                self.revoke_chain_on_reuse(&presented_hash).await;
                return Err(invalid_grant());
            }
            Err(_) => {
                return Err(oauth_err("server_error", "refresh token rotation failed"));
            }
        };

        if old_row.client_id != client_id {
            tracing::warn!(
                client_id = %client_id,
                "refresh token was issued to a different client; burned, not honored"
            );
            return Err(invalid_grant());
        }

        if now >= old_row.chain_expires_at {
            tracing::warn!(
                subject = %old_row.subject,
                chain_id = %old_row.chain_id,
                "refresh token chain past its absolute cap; refusing to rotate"
            );
            return Err(invalid_grant());
        }

        // Re-validation (gap 1 above): the same ownership/membership check the exchange grant
        // uses, plus the account/project suspension cascade `resolve_context` alone does not
        // cover. Any failure here refuses the refresh -- no permissive fallback.
        let context = match self
            .repo
            .resolve_context(&old_row.subject, &old_row.project_id)
            .await
        {
            Ok(context) => context,
            Err(Error::NotFound) => return Err(invalid_grant()),
            Err(_) => {
                return Err(oauth_err("server_error", "context resolution failed"));
            }
        };
        let project = match self.repo.get_project_by_id(&context.project_id).await {
            Ok(Some(project)) if project.status == ResourceStatus::Active => project,
            Ok(_) => return Err(invalid_grant()),
            Err(_) => {
                return Err(oauth_err("server_error", "context resolution failed"));
            }
        };
        match self.repo.get_account_by_id(&context.account_id).await {
            Ok(Some(account)) if account.status == ResourceStatus::Active => {}
            Ok(_) => return Err(invalid_grant()),
            Err(_) => {
                return Err(oauth_err("server_error", "context resolution failed"));
            }
        }

        let owner = KeyOwner {
            subject: old_row.subject.clone(),
            email: old_row.email.clone(),
            email_verified: old_row.email_verified,
        };
        let allowed_models = project.allowed_models;
        let model_policy = project.model_policy;
        let openid = old_row
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .any(|s| s == OPENID_SCOPE);

        // ADR-0020 Decision 1 (the bug this ticket fixes): reuse the session already bound to the
        // refresh token being redeemed, instead of minting a new one on every refresh -- a fresh
        // `cuid2()` here would silently discard session continuity on every single rotation,
        // exactly the correction ADR-0020 calls out (`chain_id` one column over already gets this
        // right). No new `sessions` row is inserted for a refresh.
        let session_id = old_row.session_id.clone();
        let expires_in_secs = self.cfg.access_ttl_seconds.max(0) as u64;
        let scope_str = old_row.scope.clone();

        let budget_tier = self.resolve_budget_tier(&context.account_id, now).await;
        let quota_tier = self
            .resolve_quota_tier(&context.project_id, &old_row.subject)
            .await?;
        // ADR-0020 Decision 2 (#437's scoped-down interpretation, see `access_token_extra`'s doc
        // comment): `sid` and `api_key_id` carry the SAME real, persisted (reused) session id.
        let mut access_extra = access_token_extra(
            &owner,
            &session_id,
            &session_id,
            &context.project_id,
            &context.account_id,
            allowed_models,
            Some(&client_id),
        );
        access_extra.insert("budget_tier".to_string(), Value::String(budget_tier));
        if let Some(quota_tier) = quota_tier {
            access_extra.insert("quota_tier".to_string(), Value::String(quota_tier));
        }
        access_extra.insert(
            "model_policy".to_string(),
            Value::String(model_policy.to_string()),
        );
        let access_token = tokens
            .issue_user_token_with_extra(
                identity_for(&owner),
                expires_in_secs,
                scope_str.clone(),
                Some(client_id.clone()),
                access_extra,
            )
            .map_err(|_| oauth_err("server_error", "access token signing failed"))?;

        let id_token = if openid {
            let extra = id_token_extra(&owner, &access_token, old_row.auth_time, &client_id);
            match tokens.issue_id_token_with_extra(
                identity_for(&owner),
                &client_id,
                None,
                expires_in_secs,
                extra,
            ) {
                Ok(t) => Some(t),
                Err(_) => return Err(oauth_err("server_error", "id token signing failed")),
            }
        } else {
            None
        };

        let new_plaintext = generate_refresh_secret();
        let new_row = NewExchangeRefreshToken {
            id: cuid2(),
            subject: old_row.subject.clone(),
            account_id: context.account_id.clone(),
            project_id: context.project_id.clone(),
            client_id: client_id.clone(),
            token_hash: hash_api_key(&new_plaintext),
            scope: old_row.scope.clone(),
            email: old_row.email.clone(),
            email_verified: old_row.email_verified,
            auth_time: old_row.auth_time,
            // Inherited unchanged from the token just consumed -- this is what makes it one
            // chain, not a new one born on every rotation.
            chain_id: old_row.chain_id.clone(),
            chain_expires_at: old_row.chain_expires_at,
            // Inherited unchanged too (ADR-0020 Decision 1) -- same "born once, inherited across
            // rotation" shape as chain_id immediately above.
            session_id: session_id.clone(),
            created_at: now,
            expires_at: now + Duration::seconds(self.cfg.refresh_ttl_seconds),
        };
        if self
            .repo
            .create_exchange_refresh_token(new_row)
            .await
            .is_err()
        {
            return Err(oauth_err(
                "server_error",
                "refresh token persistence failed",
            ));
        }

        tracing::info!(
            client_id = %client_id,
            account_id = %context.account_id,
            project_id = %context.project_id,
            chain_id = %old_row.chain_id,
            openid,
            "token-exchange refreshed access token"
        );

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: expires_in_secs,
            id_token,
            refresh_token: Some(new_plaintext),
            scope: scope_str,
            // Not a token-exchange response -- `default_handle_refresh_token` likewise leaves
            // this `None` on the plain `refresh_token` grant; RFC 8693 §2.2.1 only requires it on
            // a token-exchange response.
            issued_token_type: None,
        })
    }

    /// RFC 6819 §5.2.2.3 reuse-detection cascade: called after a CAS consume
    /// (`consume_exchange_refresh_token`) has already returned `None` for `presented_hash`, to
    /// decide whether that `None` means "replay of an already-rotated token" (revoke the whole
    /// chain) or something else (unknown/expired/already-revoked -- no cascade, see
    /// `find_exchange_refresh_token_by_hash`'s own doc comment for why only `status == "rotated"`
    /// triggers this). Never logs the token or its hash -- only `subject`/`chain_id`, matching
    /// this repo's existing rule against logging secret-shaped material.
    async fn revoke_chain_on_reuse(&self, presented_hash: &str) {
        let Ok(Some(row)) = self
            .repo
            .find_exchange_refresh_token_by_hash(presented_hash)
            .await
        else {
            return;
        };
        if row.status != "rotated" {
            return;
        }
        tracing::warn!(
            subject = %row.subject,
            chain_id = %row.chain_id,
            "refresh token reuse detected (an already-rotated token was replayed); revoking its chain"
        );
        if let Err(e) = self
            .repo
            .revoke_exchange_refresh_token_chain(&row.chain_id)
            .await
        {
            tracing::error!(
                error = %e,
                chain_id = %row.chain_id,
                "failed to revoke refresh token chain after reuse detection"
            );
        }
    }
}

/// Builds the `Identity` a refresh-token row round-trips through `RefreshTokenStore` (see
/// `refresh_store`'s doc comment for why `account_id`/`project_id`/`email_verified`/`auth_time`/
/// `chain_id`/`chain_expires_at` live in `attributes`). Only used for the initial
/// offline-scope mint in `handle_token_exchange` -- `handle_refresh_token` mints rotations
/// directly against `StoreRepo`, reading/writing the typed `ExchangeRefreshTokenRow` columns
/// instead of round-tripping through this string-keyed map.
fn refresh_identity(
    owner: &KeyOwner,
    account_id: &str,
    project_id: &str,
    auth_time: Option<i64>,
    chain_id: &str,
    chain_expires_at: DateTime<Utc>,
    session_id: &str,
) -> Identity {
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("account_id".to_string(), account_id.to_string());
    attributes.insert("project_id".to_string(), project_id.to_string());
    if let Some(verified) = owner.email_verified {
        attributes.insert("email_verified".to_string(), verified.to_string());
    }
    if let Some(auth_time) = auth_time {
        attributes.insert("auth_time".to_string(), auth_time.to_string());
    }
    attributes.insert("chain_id".to_string(), chain_id.to_string());
    attributes.insert(
        "chain_expires_at".to_string(),
        chain_expires_at.to_rfc3339(),
    );
    attributes.insert("session_id".to_string(), session_id.to_string());
    Identity {
        provider_id: "keycloak".to_string(),
        external_id: owner.subject.clone(),
        email: owner.email.clone(),
        username: None,
        attributes,
    }
}

#[async_trait]
impl ClientStore for TokenExchangeOpStore {
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
        self.clients.find_client(client_id).await
    }
}

#[async_trait]
impl AuthorizationCodeStore for TokenExchangeOpStore {
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
        self.codes.store_code(code).await
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        self.codes.consume_code(code).await
    }
}

#[async_trait]
impl RefreshTokenStore for TokenExchangeOpStore {
    async fn store_token(&self, token: RefreshToken) -> Result<(), OpError> {
        self.refresh.store_token(token).await
    }

    async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        self.refresh.get_token(token).await
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OpError> {
        self.refresh.revoke_token(token).await
    }

    async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        self.refresh.consume_token(token).await
    }
}

#[async_trait]
impl DeviceCodeStore for TokenExchangeOpStore {
    async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        self.devices.store_device_code(session).await
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.devices.get_device_code(device_code).await
    }

    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.devices.get_by_user_code(user_code).await
    }

    async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        self.devices.update_device_code(session).await
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
        self.devices.delete_device_code(device_code).await
    }

    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.devices.consume_device_code(device_code).await
    }
}

/// Per-request `OpStore` wrapper. `authkestra_op::handlers::token::handle_token` takes
/// `op_store: &dyn OpStore` and dispatches the exchange/refresh grants through
/// `OpStore::handle_token_exchange`/`handle_refresh_token`, whose signatures are fixed by the
/// upstream trait -- there is no parameter on them for `project_id`, a field this service's
/// exchange grant needs (which project's context to seal into the token) but that is not part of
/// RFC 8693 and has no home on `authkestra_op::handlers::token::TokenRequest`. Rather than smuggle
/// it through an existing field (every candidate already means something else -- `audience` is
/// RFC 8693's own resource-indicator parameter) or reach for thread-local/global state, this
/// wrapper is built fresh per HTTP request, closes over `project_id` parsed straight off that
/// request's form body, and forwards everything else to the shared `Arc<TokenExchangeOpStore>`.
pub struct RequestScopedOpStore<'a> {
    pub inner: &'a TokenExchangeOpStore,
    pub project_id: Option<String>,
}

#[async_trait]
impl ClientStore for RequestScopedOpStore<'_> {
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
        self.inner.find_client(client_id).await
    }
}

#[async_trait]
impl AuthorizationCodeStore for RequestScopedOpStore<'_> {
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
        self.inner.store_code(code).await
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        self.inner.consume_code(code).await
    }
}

#[async_trait]
impl RefreshTokenStore for RequestScopedOpStore<'_> {
    async fn store_token(&self, token: RefreshToken) -> Result<(), OpError> {
        self.inner.store_token(token).await
    }

    async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        self.inner.get_token(token).await
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OpError> {
        self.inner.revoke_token(token).await
    }

    async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        self.inner.consume_token(token).await
    }
}

#[async_trait]
impl DeviceCodeStore for RequestScopedOpStore<'_> {
    async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        self.inner.store_device_code(session).await
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.inner.get_device_code(device_code).await
    }

    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.inner.get_by_user_code(user_code).await
    }

    async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        self.inner.update_device_code(session).await
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
        self.inner.delete_device_code(device_code).await
    }

    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.inner.consume_device_code(device_code).await
    }
}

#[async_trait]
impl OpStore for RequestScopedOpStore<'_> {
    async fn record_client_assertion_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError> {
        self.inner.assertions.record_jti(jti, expires_at).await
    }

    async fn handle_token_exchange(
        &self,
        req: TokenRequest,
        client_id: String,
        client: ClientRegistration,
        _config: &OpConfig,
        tokens: &TokenManager,
    ) -> Result<TokenResponse, TokenErrorResponse> {
        self.inner
            .handle_token_exchange(req, client_id, client, tokens, self.project_id.as_deref())
            .await
    }

    async fn handle_refresh_token(
        &self,
        req: TokenRequest,
        client_id: String,
        client: ClientRegistration,
        _config: &OpConfig,
        tokens: &TokenManager,
    ) -> Result<TokenResponse, TokenErrorResponse> {
        self.inner
            .handle_refresh_token(req, client_id, client, tokens)
            .await
    }
}

#[cfg(test)]
mod budget_tier_wire_label_tests {
    use super::budget_tier_wire_label;
    use lightbridge_authz_budget::tier::BudgetTier;

    /// The ADR-0015-shipped fail-closed floor ($6, `6_000_000` micros) -- the whole reason
    /// `budget_tier_wire_label` exists: `BudgetTier` has no variant below `B15`'s $15, so a
    /// caller that stamped `BudgetTier::B15.label()` here regardless of the configured floor
    /// would misrepresent a $6 outage fallback as the $15 rung, silently granting more than the
    /// policy actually authorizes on the one path (a budget-ledger outage) meant to be the most
    /// conservative. This is the exact fail-open shape ADR-0015 Decision 6 exists to prevent.
    #[test]
    fn the_adr_0015_fail_closed_floor_gets_its_own_honest_label_not_the_nearest_legacy_rung() {
        assert_eq!(budget_tier_wire_label(6_000_000), "b-6");
        assert_ne!(
            budget_tier_wire_label(6_000_000),
            BudgetTier::B15.label(),
            "a $6 floor must never be represented as the $15 rung"
        );
    }

    /// Every legacy `BudgetTier` rung round-trips through its exact, pre-ADR-0015 label --
    /// stamping the claim for an account that resolved through the real ledger (not the
    /// fail-closed fallback) must not change shape for any account already on a known rung.
    #[test]
    fn every_legacy_rung_keeps_its_exact_pre_adr_0015_label() {
        for tier in BudgetTier::ALL {
            assert_eq!(budget_tier_wire_label(tier.amount().get()), tier.label());
        }
    }

    /// An amount that matches neither a legacy rung nor a whole number of dollars still produces
    /// a label (truncating division) rather than panicking -- no different in kind from the
    /// legacy enum, which likewise had no representation for a non-whole-dollar amount. Documents
    /// the behavior rather than asserting it is ideal.
    #[test]
    fn a_non_whole_dollar_amount_truncates_rather_than_panics() {
        assert_eq!(budget_tier_wire_label(6_500_000), "b-6");
    }
}
