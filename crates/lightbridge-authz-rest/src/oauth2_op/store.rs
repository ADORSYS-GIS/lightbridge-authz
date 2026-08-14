//! `TokenExchangeOpStore`: the `OpStore` implementation ADR-0011 phase 2 wires into
//! `authkestra_op::handlers::token::handle_token`, plus `RequestScopedOpStore`, the thin
//! per-request wrapper that closes over the one field `handle_token`'s dispatch has no room to
//! carry -- see that type's doc comment for why.
//!
//! **How much RFC 8693 logic this file hand-writes, and why:** at the pinned rev
//! (`authkestra-op`/`authkestra-engine` git rev `a19cdd2`), `OpStore::handle_token_exchange` and
//! `OpStore::handle_refresh_token` are real, overridable, defaulted trait methods -- so this store
//! reaches `handle_token` (the entry point) and overrides both here rather than forking anything.
//! But the *default bodies* those methods fall back to
//! (`handlers::token::default_handle_token_exchange`/`default_handle_refresh_token`) are
//! `pub(crate)` to `authkestra-op` -- unreachable from this crate -- and neither one ever calls
//! `issue_user_token_with_extra`/`issue_id_token_with_extra`, so neither could stamp
//! `account_id`/`project_id`/`api_key_id`/`allowed_models` even if this crate could call them.
//! Both overrides below are therefore full reimplementations of the RFC 8693 exchange/refresh
//! logic (subject-token validation, audience binding, scope intersection, token minting), not
//! thin wrappers -- everything from "validate the subject_token" onward is hand-written here. The
//! one further, deliberate divergence from upstream's own default: `default_handle_token_exchange`
//! validates the presented `subject_token` via `tokens.validate_token` (i.e. against *this
//! service's own* signing key), which cannot be right for us -- our `subject_token` is a Keycloak
//! access token signed by a completely different key. This override validates it via
//! `BearerTokenServiceTrait::validate_bearer_token` (the existing JWKS-backed Keycloak validator)
//! instead, exactly as the phase-1 hand-rolled dispatch already did.

use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_engine::token::TokenManager;
use authkestra_op::client::{ClientRegistration, ClientStore, GrantType};
use authkestra_op::client_assertion::ClientAssertionStore;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::config::OpConfig;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStore};
use authkestra_op::error::OpError;
use authkestra_op::handlers::token::{TokenErrorResponse, TokenRequest, TokenResponse};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_op::store::OpStore;
use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::Oauth2TokenExchange;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::Error;

use crate::signing::{KeyOwner, access_token_extra, id_token_extra, identity_for};

use super::client_assertion_store::RedisClientAssertionStore;
use super::client_store::ConfigClientStore;
use super::noop_stores::{NoAuthorizationCodeStore, NoDeviceCodeStore};
use super::refresh_store::DbRefreshTokenStore;
use super::{
    ACCESS_TOKEN_TYPE, OFFLINE_ACCESS_SCOPE, OPENID_SCOPE, decode_auth_time_and_nonce,
    decode_email, generate_refresh_secret, grant_scopes, oauth_err, scope_to_string,
};

/// Everything the native token-exchange endpoint needs, minus the one per-request field
/// (`project_id`) `handle_token`'s dispatch has no room to carry -- see `RequestScopedOpStore`.
/// One instance is built once at server startup and shared (`Arc`) across every request.
pub struct TokenExchangeOpStore {
    clients: ConfigClientStore,
    codes: NoAuthorizationCodeStore,
    refresh: DbRefreshTokenStore,
    devices: NoDeviceCodeStore,
    assertions: RedisClientAssertionStore,
    repo: Arc<StoreRepo>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    cfg: Oauth2TokenExchange,
}

impl TokenExchangeOpStore {
    pub fn new(
        clients: ConfigClientStore,
        assertions: RedisClientAssertionStore,
        repo: Arc<StoreRepo>,
        bearer: Arc<dyn BearerTokenServiceTrait>,
        cfg: Oauth2TokenExchange,
    ) -> Self {
        Self {
            clients,
            codes: NoAuthorizationCodeStore,
            refresh: DbRefreshTokenStore::new(repo.clone()),
            devices: NoDeviceCodeStore,
            assertions,
            repo,
            bearer,
            cfg,
        }
    }

    /// Whether the discovery document should advertise `private_key_jwt`
    /// (`signing::discovery_document`).
    pub fn has_confidential_client(&self) -> bool {
        self.clients.has_confidential_client()
    }

    /// The RFC 8693 token-exchange grant (ADR-0011, Decisions 1, 5, 7). `project_id` is this
    /// crate's own extension to the request, threaded in by `RequestScopedOpStore` since it is
    /// not a field `authkestra_op::handlers::token::TokenRequest` has room for.
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
        if let Some(token_type) = req.subject_token_type.as_deref() {
            let token_type = token_type.trim();
            if !token_type.is_empty() && token_type != ACCESS_TOKEN_TYPE {
                return Err(oauth_err(
                    "invalid_request",
                    "subject_token_type must be urn:ietf:params:oauth:token-type:access_token",
                ));
            }
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
        let Some(project_id) = project_id.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(oauth_err("invalid_request", "project_id is required"));
        };

        let token_info = match self.bearer.validate_bearer_token(subject_token).await {
            Ok(info) if info.active => info,
            Ok(_) => {
                return Err(oauth_err("invalid_token", "subject_token is not active"));
            }
            Err(_) => {
                return Err(oauth_err(
                    "invalid_token",
                    "subject_token validation failed",
                ));
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

        let context = match self.repo.resolve_context(&subject, project_id).await {
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

        let allowed_models = match self.repo.get_project_by_id(&context.project_id).await {
            Ok(Some(project)) => project.allowed_models,
            _ => None,
        };

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
        let session_id = cuid2();
        let expires_in_secs = self.cfg.access_ttl_seconds.max(0) as u64;
        let scope_str = scope_to_string(&granted_scopes);

        let access_extra = access_token_extra(
            &owner,
            &session_id,
            &context.project_id,
            &context.account_id,
            allowed_models,
            Some(&client_id),
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
            let plaintext = generate_refresh_secret();
            let identity =
                refresh_identity(&owner, &context.account_id, &context.project_id, auth_time);
            let rt = RefreshToken {
                token: plaintext.clone(),
                client_id: client_id.clone(),
                identity,
                scope: scope_str.clone().unwrap_or_default(),
                expires_at: now + Duration::seconds(self.cfg.refresh_ttl_seconds),
            };
            match self.refresh.store_token(rt).await {
                Ok(()) => Some(plaintext),
                Err(_) => {
                    return Err(oauth_err(
                        "server_error",
                        "refresh token persistence failed",
                    ));
                }
            }
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
        })
    }

    /// The `refresh_token` grant (ADR-0011, Decision 1): re-mints access + id_token symmetrically
    /// with the exchange grant above, through the same signing calls, which is what fixes the
    /// phase-1-era `mint_from_refresh` email-dropping bug by construction (there is only one
    /// minting path now). Consumes-then-validates client ownership, matching
    /// `default_handle_refresh_token`'s own shape: a refresh token presented by a different
    /// client than the one it was issued to is burned (single-use, already consumed) rather than
    /// silently honored -- see `exchange_refresh_tokens_add_client_id` migration.
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

        let old_rt = match self.refresh.consume_token(presented).await {
            Ok(Some(rt)) => rt,
            Ok(None) => {
                return Err(oauth_err(
                    "invalid_grant",
                    "refresh_token is invalid, expired, or already used",
                ));
            }
            Err(_) => {
                return Err(oauth_err("server_error", "refresh token rotation failed"));
            }
        };

        if old_rt.client_id != client_id {
            tracing::warn!(
                client_id = %client_id,
                "refresh token was issued to a different client; burned, not honored"
            );
            return Err(oauth_err(
                "invalid_grant",
                "refresh_token is invalid, expired, or already used",
            ));
        }

        let account_id = old_rt
            .identity
            .attributes
            .get("account_id")
            .cloned()
            .unwrap_or_default();
        let project_id = old_rt
            .identity
            .attributes
            .get("project_id")
            .cloned()
            .unwrap_or_default();
        let email_verified = old_rt
            .identity
            .attributes
            .get("email_verified")
            .and_then(|v| v.parse::<bool>().ok());
        let auth_time = old_rt
            .identity
            .attributes
            .get("auth_time")
            .and_then(|v| v.parse::<i64>().ok());
        let owner = KeyOwner {
            subject: old_rt.identity.external_id.clone(),
            email: old_rt.identity.email.clone(),
            email_verified,
        };

        let allowed_models = match self.repo.get_project_by_id(&project_id).await {
            Ok(Some(project)) => project.allowed_models,
            _ => None,
        };
        let openid = old_rt.scope.split_whitespace().any(|s| s == OPENID_SCOPE);

        let now = Utc::now();
        let session_id = cuid2();
        let expires_in_secs = self.cfg.access_ttl_seconds.max(0) as u64;
        let scope_str = if old_rt.scope.is_empty() {
            None
        } else {
            Some(old_rt.scope.clone())
        };

        let access_extra = access_token_extra(
            &owner,
            &session_id,
            &project_id,
            &account_id,
            allowed_models,
            Some(&client_id),
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
        let new_identity = refresh_identity(&owner, &account_id, &project_id, auth_time);
        let new_rt = RefreshToken {
            token: new_plaintext.clone(),
            client_id: client_id.clone(),
            identity: new_identity,
            scope: old_rt.scope.clone(),
            expires_at: now + Duration::seconds(self.cfg.refresh_ttl_seconds),
        };
        if self.refresh.store_token(new_rt).await.is_err() {
            return Err(oauth_err(
                "server_error",
                "refresh token persistence failed",
            ));
        }

        tracing::info!(
            client_id = %client_id,
            account_id = %account_id,
            project_id = %project_id,
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
        })
    }
}

/// Builds the `Identity` a refresh-token row round-trips through `RefreshTokenStore` (see
/// `refresh_store`'s doc comment for why `account_id`/`project_id`/`email_verified`/`auth_time`
/// live in `attributes`).
fn refresh_identity(
    owner: &KeyOwner,
    account_id: &str,
    project_id: &str,
    auth_time: Option<i64>,
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
