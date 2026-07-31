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
    /// The member this key belongs to (ADR-0006 follow-up). Distinct from `account_id`, which is
    /// the project's OWNING account: a lead who is not the owner may create keys, and their
    /// per-member ceiling is the one that applies.
    pub owner_account_id: String,
    /// The owner's roster role/tier on this project, `None` when they hold no `project_members`
    /// row -- which is the normal case for the project's owning account, since ownership and
    /// roster membership are separate standings.
    pub owner_role: Option<String>,
    pub owner_quota_tier: Option<String>,
    pub api_key_status: String,
    pub project_status: String,
    pub account_status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub effective_status: String,
}
