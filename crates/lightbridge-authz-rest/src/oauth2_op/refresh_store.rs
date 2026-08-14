//! `authkestra_op::refresh::RefreshTokenStore` backed by the existing `exchange_refresh_tokens`
//! table (PR #95's own table, now carrying a `client_id` column -- ADR-0011 phase 2 migration
//! `20260814000003_exchange_refresh_tokens_add_client_id.sql`).
//!
//! Two representational gaps between the trait and this repo's storage, both handled here so the
//! rest of the codebase never has to think about them:
//!
//! - **Plaintext vs hash.** `RefreshToken.token` is documented as "the actual token string" --
//!   plaintext. This repo stores only `token_hash` (SHA-256, same convention as API keys) and
//!   never persists the plaintext. `store_token` hashes what it is given; `get_token`/
//!   `consume_token` cannot recover the original plaintext (it was never stored), so the `token`
//!   field on what they return carries the row's hash instead -- callers of this store never read
//!   `.token` back off a fetched/consumed `RefreshToken` (see `oauth2_op::store`), only off one
//!   *they* just built to hand to `store_token`, so this is never observed as a real value by
//!   anything that matters.
//! - **No room for tenant context.** `RefreshToken`'s only carrier for anything beyond
//!   `client_id`/`scope`/`expires_at` is `Identity`, which has no `account_id`/`project_id`
//!   fields. `Identity::attributes: HashMap<String, String>` (documented upstream as "additional
//!   provider-specific attributes") is the sanctioned extension point, so `account_id`/
//!   `project_id` (and `email_verified`/`auth_time`, which are booleans/integers with nowhere
//!   else to live either) round-trip through it as strings: `store_token` reads them out of
//!   `identity.attributes` to populate the table's real, typed columns; `get_token`/
//!   `consume_token` write the row's columns back into `identity.attributes` on the way out. Both
//!   directions live in this file so the string<->column mapping has exactly one home.

use std::collections::HashMap;

use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::OpError;
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use chrono::Utc;
use lightbridge_authz_api_key::entities::exchange_refresh_token_row::{
    ExchangeRefreshTokenRow, NewExchangeRefreshToken,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::crypto::hash_api_key;
use lightbridge_authz_core::cuid::cuid2;

/// [`Identity::provider_id`] stamped on every refresh-token identity, mirroring
/// `signing::IDENTITY_PROVIDER_ID` -- every subject here is a snapshot of an upstream Keycloak
/// login, never an identity this service authenticated itself.
const IDENTITY_PROVIDER_ID: &str = "keycloak";
const ATTR_ACCOUNT_ID: &str = "account_id";
const ATTR_PROJECT_ID: &str = "project_id";
const ATTR_EMAIL_VERIFIED: &str = "email_verified";
const ATTR_AUTH_TIME: &str = "auth_time";

pub struct DbRefreshTokenStore {
    repo: Arc<StoreRepo>,
}

impl DbRefreshTokenStore {
    pub fn new(repo: Arc<StoreRepo>) -> Self {
        Self { repo }
    }
}

fn row_to_refresh_token(row: ExchangeRefreshTokenRow) -> RefreshToken {
    let mut attributes = HashMap::new();
    attributes.insert(ATTR_ACCOUNT_ID.to_string(), row.account_id);
    attributes.insert(ATTR_PROJECT_ID.to_string(), row.project_id);
    if let Some(verified) = row.email_verified {
        attributes.insert(ATTR_EMAIL_VERIFIED.to_string(), verified.to_string());
    }
    if let Some(auth_time) = row.auth_time {
        attributes.insert(ATTR_AUTH_TIME.to_string(), auth_time.to_string());
    }
    RefreshToken {
        // See this module's doc comment: the plaintext was never stored, so this is the hash --
        // never read back as a real secret by anything in this codebase.
        token: row.token_hash,
        client_id: row.client_id,
        identity: Identity {
            provider_id: IDENTITY_PROVIDER_ID.to_string(),
            external_id: row.subject,
            email: row.email,
            username: None,
            attributes,
        },
        scope: row.scope.unwrap_or_default(),
        expires_at: row.expires_at,
    }
}

#[async_trait]
impl RefreshTokenStore for DbRefreshTokenStore {
    async fn store_token(&self, token: RefreshToken) -> Result<(), OpError> {
        let account_id = token
            .identity
            .attributes
            .get(ATTR_ACCOUNT_ID)
            .cloned()
            .unwrap_or_default();
        let project_id = token
            .identity
            .attributes
            .get(ATTR_PROJECT_ID)
            .cloned()
            .unwrap_or_default();
        let email_verified = token
            .identity
            .attributes
            .get(ATTR_EMAIL_VERIFIED)
            .and_then(|v| v.parse::<bool>().ok());
        let auth_time = token
            .identity
            .attributes
            .get(ATTR_AUTH_TIME)
            .and_then(|v| v.parse::<i64>().ok());
        let new = NewExchangeRefreshToken {
            id: cuid2(),
            subject: token.identity.external_id,
            account_id,
            project_id,
            client_id: token.client_id,
            token_hash: hash_api_key(&token.token),
            scope: if token.scope.is_empty() {
                None
            } else {
                Some(token.scope)
            },
            email: token.identity.email,
            email_verified,
            auth_time,
            created_at: Utc::now(),
            expires_at: token.expires_at,
        };
        self.repo
            .create_exchange_refresh_token(new)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to persist refresh token");
                OpError::Storage
            })?;
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        let hash = hash_api_key(token);
        let row = self
            .repo
            .find_active_exchange_refresh_token(&hash, Utc::now())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to look up refresh token");
                OpError::Storage
            })?;
        Ok(row.map(row_to_refresh_token))
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OpError> {
        let hash = hash_api_key(token);
        self.repo
            .revoke_exchange_refresh_token(&hash)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to revoke refresh token");
                OpError::Storage
            })
    }

    async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        let hash = hash_api_key(token);
        let row = self
            .repo
            .consume_exchange_refresh_token(&hash, Utc::now())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to consume refresh token");
                OpError::Storage
            })?;
        Ok(row.map(row_to_refresh_token))
    }
}
