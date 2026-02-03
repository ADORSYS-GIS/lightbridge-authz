use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Identifiable, Queryable};
use serde::{Deserialize, Serialize};

use super::schema::accounts;

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccountRow {
    pub id: String,
    pub billing_identity: String,
    pub owners_admins: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccountChangeset {
    pub billing_identity: Option<String>,
    pub owners_admins: Option<serde_json::Value>,
    pub updated_at: DateTime<Utc>,
}
