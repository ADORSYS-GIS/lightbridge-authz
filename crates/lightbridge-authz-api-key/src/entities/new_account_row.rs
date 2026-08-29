use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Row shape for inserting a fresh `accounts` row. `id` is always the caller's JWT subject now
/// (ADR-0006), never server-generated or caller-supplied, so `create_account` populates it
/// directly from `subject` rather than accepting a separate `id` argument. `billing_identity` and
/// `is_default` are gone (moved to `Project`/removed outright, respectively); `default_quota`
/// replaces `billing_identity` as the account-level, tier-catalog-validated field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAccountRow {
    pub id: String,
    pub default_quota: Option<String>,
    /// Optional human-facing label; already normalised (blank -> `None`) by the time it gets here.
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
