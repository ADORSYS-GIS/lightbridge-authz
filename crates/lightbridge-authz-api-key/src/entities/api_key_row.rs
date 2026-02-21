use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyChangeset {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}
