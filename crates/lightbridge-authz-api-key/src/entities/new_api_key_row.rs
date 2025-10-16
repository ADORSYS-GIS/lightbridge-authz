use chrono::{DateTime, Utc};
use diesel::Insertable;
use serde::{Deserialize, Serialize};

use super::schema::api_keys;

#[derive(Debug, Clone, PartialEq, Eq, Insertable, Serialize, Deserialize)]
#[diesel(table_name = api_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewApiKeyRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
}
