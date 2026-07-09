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
    pub created_at: DateTime<Utc>,
}
