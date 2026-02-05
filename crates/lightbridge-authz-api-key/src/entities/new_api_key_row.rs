use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewApiKeyRow {
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
