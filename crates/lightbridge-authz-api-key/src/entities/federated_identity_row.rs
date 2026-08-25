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
/// `lightbridge_authz_core::crypto::seal`. There is no plaintext refresh token or ID-token claim
/// anywhere on this type; contrast [`UpsertFederatedIdentity`] below, whose hand-written `Debug`
/// still redacts the same field defensively (never printing ciphertext bytes is free insurance
/// against a future caller building this struct from something that isn't sealed yet).
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
    pub last_authenticated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Everything `StoreRepo::upsert_federated_identity` needs to seal-and-persist a login's token
/// set. `issuer`/`subject` are the federation key (never rewritten once a row exists);
/// `token_envelope` is the ALREADY-SEALED ciphertext (see [`FederatedIdentityRow`]'s doc comment)
/// -- this struct never carries a raw refresh token or ID-token JWT.
#[derive(Clone)]
pub struct UpsertFederatedIdentity {
    pub issuer: String,
    pub subject: String,
    pub token_envelope: Option<String>,
    pub token_sealed_at: Option<DateTime<Utc>>,
    pub access_expires_at: Option<DateTime<Utc>>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
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
            .finish()
    }
}
