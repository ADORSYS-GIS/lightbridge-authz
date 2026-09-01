use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// A plain `accounts` row. Per ADR-0006 there is no more account-level membership to aggregate
/// (`accounts.id` IS the JWT subject -- one account, one person), so this replaces the former
/// `AccountWithMembersRow` and its `array_agg(account_memberships.subject)` machinery entirely.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountRow {
    pub id: String,
    pub default_quota: Option<String>,
    pub status: String,
    /// `NULL` for every account created before `migrations/20260829000001_accounts_add_name.sql`,
    /// and for any account whose owner has not set one -- a real "unnamed" state, not a missing
    /// value to be papered over.
    pub name: Option<String>,
    /// The owning person (`accounts.user_id -> users.id`, ADR-0024), and since ADR-0026 the column
    /// that answers "whose account is this" now that one identity may own several. Always the
    /// owner's HOME-account id -- see the LOAD-BEARING INVARIANT block on `Account.userId` in
    /// `crates/lightbridge-authz-api/schema/authz.cstack`.
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
