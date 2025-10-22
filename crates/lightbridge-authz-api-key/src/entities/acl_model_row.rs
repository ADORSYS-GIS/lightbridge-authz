use diesel::{AsChangeset, Identifiable, Insertable, Queryable};
use serde::{Deserialize, Serialize};

use super::schema::acl_models;

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
#[diesel(table_name = acl_models)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AclModelRow {
    pub id: String,
    pub model: String,
}
