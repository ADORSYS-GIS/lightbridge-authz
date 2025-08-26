use diesel::{AsChangeset, Identifiable, Insertable, Queryable};
use serde::{Deserialize, Serialize};

use super::schema::acls;

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
#[diesel(table_name = acls)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AclRow {
    pub id: String,
    pub api_key_id: String,
    pub permission: String,
}
