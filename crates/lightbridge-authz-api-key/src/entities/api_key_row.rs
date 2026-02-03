use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Identifiable, Queryable};
use serde::{Deserialize, Serialize};

use super::schema::api_keys;

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
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
    pub last_region: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ApiKeyChangeset {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub last_region: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}
