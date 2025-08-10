use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde_json::Value;

pub mod schema {
    diesel::table! {
        use diesel::sql_types::*;
        api_keys (id) {
            id -> Text,
            key_hash -> Text,
            created_at -> Timestamptz,
            expires_at -> Nullable<Timestamptz>,
            metadata -> Nullable<Jsonb>,
            status -> Text,
            acl_id -> Text,
        }
    }

    diesel::table! {
        use diesel::sql_types::*;
        acls (id) {
            id -> Text,
            rate_limit_requests -> Integer,
            rate_limit_window -> Integer,
            created_at -> Timestamptz,
            updated_at -> Timestamptz,
        }
    }

    diesel::table! {
        use diesel::sql_types::*;
        acl_models (acl_id, model_name) {
            acl_id -> Text,
            model_name -> Text,
            token_limit -> BigInt,
        }
    }

    diesel::joinable!(api_keys -> acls (acl_id));
    diesel::joinable!(acl_models -> acls (acl_id));

    diesel::allow_tables_to_appear_in_same_query!(api_keys, acls, acl_models,);
}

use crate::entities::schema::{acl_models, acls, api_keys};

#[derive(Debug, Clone, Identifiable, Queryable)]
#[diesel(table_name = api_keys)]
pub struct ApiKeyRow {
    pub id: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: String,
    pub acl_id: String,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = api_keys)]
pub struct NewApiKeyRow {
    pub id: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Value>,
    pub status: String,
    pub acl_id: String,
}

#[derive(Debug, Clone, Identifiable, Queryable)]
#[diesel(table_name = acls)]
pub struct AclRow {
    pub id: String,
    pub rate_limit_requests: i32,
    pub rate_limit_window: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = acls)]
pub struct NewAclRow {
    pub id: String,
    pub rate_limit_requests: i32,
    pub rate_limit_window: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Identifiable, Queryable, Associations)]
#[diesel(belongs_to(AclRow, foreign_key = acl_id))]
#[diesel(primary_key(acl_id, model_name))]
#[diesel(table_name = acl_models)]
pub struct AclModelRow {
    pub acl_id: String,
    pub model_name: String,
    pub token_limit: i64,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = acl_models)]
pub struct NewAclModelRow {
    pub acl_id: String,
    pub model_name: String,
    pub token_limit: i64,
}
