use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProjectRow {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub allowed_models: Option<serde_json::Value>,
    pub default_limits: serde_json::Value,
    pub billing_plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
