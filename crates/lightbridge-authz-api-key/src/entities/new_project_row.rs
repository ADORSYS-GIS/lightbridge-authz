use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Row shape for inserting a fresh `projects` row. `billing_identity` (moved from `accounts`,
/// ADR-0006) and `project_quota` (new pooled, tier-catalog-validated ceiling) are supplied by the
/// caller at creation time -- unlike `is_default`, which is computed entirely by the
/// `set_project_is_default` `BEFORE INSERT` trigger and never appears here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProjectRow {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub allowed_models: Option<serde_json::Value>,
    pub default_limits: serde_json::Value,
    pub billing_plan: String,
    pub billing_identity: String,
    pub project_quota: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
