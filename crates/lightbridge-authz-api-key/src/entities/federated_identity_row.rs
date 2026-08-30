use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// ADR-0024's `federated_identities` table -- the row keyed by `(issuer, subject)` that carries
/// the sealed Keycloak token set (`token_envelope`, AES-256-GCM via
/// `lightbridge_authz_core::crypto`) plus its non-secret queryable metadata.
///
/// Deliberate plain `#[derive(Debug)]`: the only field that could look sensitive is
/// `token_envelope`, and it is always already-sealed ciphertext (`"v1." + base64url(...)`) by the
/// time a row reaches Rust -- `StoreRepo::upsert_federated_identity` only ever writes what
/// `KeycloakRelyingParty::persist_federated_identity` already sealed via
/// `lightbridge_authz_core::crypto::seal`. There is no plaintext refresh token or raw ID-token JWT
/// anywhere on this type; contrast [`UpsertFederatedIdentity`] below, whose hand-written `Debug`
/// still redacts the same field defensively (never printing ciphertext bytes is free insurance
/// against a future caller building this struct from something that isn't sealed yet).
///
/// `email`/`email_verified`/`preferred_username`/`name` (migration
/// `20260830000001_federated_identities_add_profile_claims.sql`) are plaintext, queryable
/// identity claims, exactly the class of data ADR-0024 Q2 already documents living OUTSIDE the
/// sealed envelope (`issuer`/`subject`/`scope`/the expiry columns below). They are not secrets --
/// possession of the access token this deployment mints already discloses them (see
/// `userinfo`'s own module doc comment for the same disclosure argument) -- and minting needs
/// them readable without a `token_encryption_key` in hand, which `oauth2_op::store`'s
/// `TokenExchangeOpStore` never holds.
#[derive(Debug, Clone, FromRow)]
pub struct FederatedIdentityRow {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    /// `NOT NULL` since the ADR-0024 Correction (2026-08-25) -- a federated identity always links
    /// to an `accounts` row; there is no longer a mint-a-user, accountless branch. The owning
    /// `users` row is DERIVED, never stored here: `federated_identities.account_id ->
    /// accounts.user_id -> users.id`. `federated_identities_account_uidx` in the owning migration
    /// still enforces that at most one federated identity may ever hold a given `account_id`.
    pub account_id: String,
    pub token_envelope: Option<String>,
    pub token_sealed_at: Option<DateTime<Utc>>,
    pub access_expires_at: Option<DateTime<Utc>>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    /// Snapshot of the upstream id-token's `email`/`email_verified`/`preferred_username`/`name`
    /// as of the subject's most recent login -- refreshed on every `upsert_federated_identity`
    /// call, including back to `NULL` if a claim upstream disappears (unlike `token_envelope`,
    /// which is left unchanged when a fresh token set was not sealed).
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub last_authenticated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Everything `StoreRepo::upsert_federated_identity` needs to seal-and-persist a login's token
/// set. `issuer`/`subject` are the federation key (never rewritten once a row exists);
/// `token_envelope` is the ALREADY-SEALED ciphertext (see [`FederatedIdentityRow`]'s doc comment)
/// -- this struct never carries a raw refresh token or ID-token JWT. `email`/`email_verified`/
/// `preferred_username`/`name` are plaintext (see [`FederatedIdentityRow`]'s doc comment for why)
/// and are written unconditionally on every call, including as `None` when the upstream id-token
/// no longer carries a claim it once did.
#[derive(Clone)]
pub struct UpsertFederatedIdentity {
    pub issuer: String,
    pub subject: String,
    pub token_envelope: Option<String>,
    pub token_sealed_at: Option<DateTime<Utc>>,
    pub access_expires_at: Option<DateTime<Utc>>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

impl std::fmt::Debug for UpsertFederatedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpsertFederatedIdentity")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field(
                "token_envelope",
                &self.token_envelope.as_ref().map(|_| "<redacted>"),
            )
            .field("token_sealed_at", &self.token_sealed_at)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("scope", &self.scope)
            .field("email", &self.email)
            .field("email_verified", &self.email_verified)
            .field("preferred_username", &self.preferred_username)
            .field("name", &self.name)
            .finish()
    }
}
