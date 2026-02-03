use chrono::{DateTime, Utc};
use diesel::Insertable;
use serde::{Deserialize, Serialize};

use super::schema::accounts;

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewAccountRow {
    pub id: String,
    pub billing_identity: String,
    pub owners_admins: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
