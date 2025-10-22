use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Identifiable, Insertable, Queryable};
use serde::{Deserialize, Serialize};

use super::schema::api_keys;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Queryable,
    Identifiable,
    Insertable,
    AsChangeset,
    Serialize,
    Deserialize,
)]
#[diesel(table_name = api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ApiKeyRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub created_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}
