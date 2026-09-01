use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// A `projects` row after ADR-0006's `billing_identity`/`project_quota` addition
/// (`migrations/20260727000002_projects_billing_identity_and_quota.sql`): `billing_identity`
/// moved here from `accounts` (one project, one billing identity), and `project_quota` is the new
/// pooled, tier-catalog-validated ceiling shared by everyone on the project.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProjectRow {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub allowed_models: Option<serde_json::Value>,
    pub default_limits: serde_json::Value,
    pub billing_plan: String,
    pub billing_identity: String,
    pub project_quota: Option<String>,
    pub status: String,
    pub is_default: bool,
    pub model_policy: String,
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
