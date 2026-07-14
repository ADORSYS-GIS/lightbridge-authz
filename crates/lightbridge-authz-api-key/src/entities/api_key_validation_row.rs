use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// One row of the `api_key_validation` view (see the migration): the effective validity of an API
/// key with the account -> project -> key status cascade resolved by the database.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKeyValidationRow {
    pub api_key_id: String,
    pub key_hash: String,
    pub project_id: String,
    pub account_id: String,
    pub api_key_status: String,
    pub project_status: String,
    pub account_status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub effective_status: String,
}
