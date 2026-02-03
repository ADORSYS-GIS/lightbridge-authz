use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Identifiable, Queryable};
use serde::{Deserialize, Serialize};

use super::schema::projects;

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = projects)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProjectRow {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub allowed_models: serde_json::Value,
    pub default_limits: serde_json::Value,
    pub billing_plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = projects)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProjectChangeset {
    pub name: Option<String>,
    pub allowed_models: Option<serde_json::Value>,
    pub default_limits: Option<serde_json::Value>,
    pub billing_plan: Option<String>,
    pub updated_at: DateTime<Utc>,
}
