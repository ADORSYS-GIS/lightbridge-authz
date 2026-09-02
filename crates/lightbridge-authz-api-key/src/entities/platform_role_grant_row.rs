//! Row types and listing bounds for `platform_role_grants` (ADR-0033).
//!
//! Split from `platform_roles.rs` (which holds the [`crate::db::StoreRepo`] queries themselves) to
//! keep both files inside the repository's 200-LoC ceiling — the same arrangement
//! `identity_label_row.rs` has with `identity_resolution.rs`. The *why* for the whole surface,
//! including why it is hand-written SQL under ADR-0038, lives in that module's doc comment.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// `listPlatformRoleGrants`'s page size when the caller supplies none.
pub const DEFAULT_PLATFORM_ROLE_GRANTS_PAGE_SIZE: i64 = 50;
/// `listPlatformRoleGrants`'s ceiling. CLAMPS rather than rejects: unlike an id batch, a caller
/// asking for "as many as you have" is making no correctness claim about a specific set of rows,
/// and `nextCursor` is right there to continue the walk.
pub const MAX_PLATFORM_ROLE_GRANTS_PAGE_SIZE: i64 = 200;

/// One row of `platform_role_grants`, verbatim.
///
/// `granted_by` is `None` for a CLI bootstrap grant (`lightbridge-authz rbac grant`) — the
/// only way the FIRST admin can exist, since there is no admin to grant it. That is a real,
/// permanent distinction on the wire, not a missing value: a console must render it as "CLI
/// bootstrap", never as "unknown".
///
/// `revoked_at` is `None` for an ACTIVE grant. Revocation is a soft delete on purpose — "X held
/// admin between these two timestamps, granted by Y, for reason Z" is the audit trail the whole
/// table exists to produce.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct PlatformRoleGrantRow {
    pub id: String,
    pub user_id: String,
    pub role: String,
    pub granted_by: Option<String>,
    pub granted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

impl PlatformRoleGrantRow {
    /// Whether this grant currently confers its role. Exists so no caller has to re-derive the
    /// `revoked_at IS NULL` convention (and get it backwards).
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// A new grant, as `grant_platform_role` inserts it. `id` is minted by the caller (CUID2,
/// ADR-0039); `granted_at` is the database's `now()`, never a caller-supplied timestamp, so an
/// audit row cannot be backdated by whoever writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlatformRoleGrant {
    pub id: String,
    pub user_id: String,
    pub role: String,
    /// The granting admin's `users.id`, or `None` for a CLI bootstrap.
    pub granted_by: Option<String>,
    pub reason: Option<String>,
}

/// Filters for `list_platform_role_grants`. Every field is optional and they AND together; the
/// unfiltered call is "every active grant, newest first".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformRoleGrantFilter {
    pub user_id: Option<String>,
    pub role: Option<String>,
    /// `false` (the default) lists ACTIVE grants only. `true` lists the full history including
    /// revoked rows — which is what an audit view wants, and what a "who can do what right now"
    /// view must not show.
    pub include_revoked: bool,
    /// Keyset cursor: return rows strictly OLDER than this `granted_at`. Taken from the previous
    /// page's last row, mirroring `listBudgetGrants`' own `createdAt` cursor convention.
    ///
    /// Known, accepted limitation, identical to that precedent: `granted_at` is not unique, so two
    /// grants written inside the same microsecond straddling a page boundary could have the second
    /// skipped. Grants are operator actions measured in dozens per deployment, not a ledger, so
    /// the composite `(granted_at, id)` cursor that would close this is not worth the wire
    /// complexity here — recorded rather than silently accepted.
    pub after: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}

impl PlatformRoleGrantFilter {
    /// The page size to actually query, clamped to
    /// `[1, MAX_PLATFORM_ROLE_GRANTS_PAGE_SIZE]` and defaulting to
    /// [`DEFAULT_PLATFORM_ROLE_GRANTS_PAGE_SIZE`].
    pub fn page_size(&self) -> i64 {
        match self.limit {
            Some(requested) => requested.clamp(1, MAX_PLATFORM_ROLE_GRANTS_PAGE_SIZE),
            None => DEFAULT_PLATFORM_ROLE_GRANTS_PAGE_SIZE,
        }
    }
}

/// One `(user_id, email)` pair matching a `rbac --user <email>` lookup. A `Vec` of these is what
/// makes the CLI's ambiguity refusal possible: the resolver returns EVERY match and the caller
/// decides, rather than the query picking one and hiding the collision.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct UserEmailMatchRow {
    pub user_id: String,
    pub email: String,
}
