use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SigningKeyRow {
    pub kid: String,
    pub algorithm: String,
    pub private_key_pem: String,
    pub public_jwk: serde_json::Value,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// Listing-only projection over `signing_keys` -- deliberately carries NEITHER
/// `private_key_pem` NOR `public_jwk`, unlike [`SigningKeyRow`]. This is the type
/// `StoreRepo::list_signing_keys` (`crate::signing_keys_admin`) returns for the `idp jwk list`
/// operator command: the private key must never reach stdout/logs, so the query behind this type
/// does not even select that column -- there is no code path through which it could leak, rather
/// than relying on a formatter to omit it.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SigningKeyMeta {
    pub kid: String,
    /// `'access'` or `'refresh'` -- see [`NewSigningKey::purpose`].
    pub purpose: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewSigningKey {
    pub kid: String,
    pub algorithm: String,
    pub private_key_pem: String,
    pub public_jwk: serde_json::Value,
    /// `'access'` or `'refresh'` -- see `migrations/20260902000001_signing_keys_add_purpose.sql`.
    /// Scopes [`crate::repo::StoreRepo::ensure_active_signing_key`]'s single-active-key rotation
    /// to keys of the SAME purpose, so an access key and a refresh key can be active at once (the
    /// `(status, purpose) WHERE status = 'active'` unique index is what makes this legal).
    pub purpose: String,
    pub created_at: DateTime<Utc>,
}
