use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountRow {
    pub id: String,
    pub billing_identity: String,
    pub owners_admins: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AccountChangeset {
    pub billing_identity: Option<String>,
    pub owners_admins: Option<serde_json::Value>,
    pub updated_at: DateTime<Utc>,
}
