use diesel::Insertable;
use serde::{Deserialize, Serialize};

use super::schema::acl_models;

#[derive(Debug, Clone, PartialEq, Eq, Insertable, Serialize, Deserialize)]
#[diesel(table_name = acl_models)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewAclModelRow {
    pub id: String,
    pub name: String,
    pub model: String,
}
