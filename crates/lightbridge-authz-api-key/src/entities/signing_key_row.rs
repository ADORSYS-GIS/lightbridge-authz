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
