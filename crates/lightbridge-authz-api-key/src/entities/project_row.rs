use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProjectRow {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub allowed_models: Option<serde_json::Value>,
    pub default_limits: serde_json::Value,
    pub billing_plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ProjectChangeset {
    pub name: Option<String>,
    pub allowed_models: Option<serde_json::Value>,
    pub default_limits: Option<serde_json::Value>,
    pub billing_plan: Option<String>,
    pub updated_at: DateTime<Utc>,
}
