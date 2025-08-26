use diesel::Insertable;
use serde::{Deserialize, Serialize};

use super::schema::acls;

#[derive(Debug, Clone, PartialEq, Eq, Insertable, Serialize, Deserialize)]
#[diesel(table_name = acls)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewAclRow {
    pub id: String,
    pub api_key_id: String,
    pub permission: String,
}
