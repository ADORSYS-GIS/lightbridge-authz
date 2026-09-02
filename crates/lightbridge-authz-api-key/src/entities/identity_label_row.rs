//! Row types, batch limits and query helpers for estate-wide identity resolution (#647).
//!
//! Split from `identity_resolution.rs` (which holds the [`crate::db::StoreRepo`] queries
//! themselves) to keep both files inside the repository's 200-LoC ceiling. The *why* for the
//! whole surface — including why it is hand-written SQL under ADR-0038 — lives in that module's
//! doc comment; this file is the data shapes and the two pure helpers its SQL needs.

use lightbridge_authz_core::error::{Error, Result};
use sqlx::FromRow;

/// Maximum ids accepted in one batch, per kind. A longer batch is REJECTED, never truncated: a
/// truncated result is indistinguishable from "those ids do not exist", which is precisely the
/// confusion an identity-resolution surface must not create.
pub const MAX_IDENTITY_BATCH: usize = 200;
/// `searchUsers`'s `limit` when the caller supplies none.
pub const DEFAULT_USER_SEARCH_LIMIT: i64 = 20;
/// `searchUsers`'s ceiling. Unlike the batch cap this CLAMPS rather than rejects — a caller asking
/// for "as many as you have" makes no correctness claim about a specific set of ids.
pub const MAX_USER_SEARCH_LIMIT: i64 = 50;
/// Shortest accepted `searchUsers` query. A one-character substring search is a table dump.
pub const MIN_USER_SEARCH_QUERY_CHARS: usize = 2;

/// One person's display identity. Every field but `user_id` is independently nullable.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct UserProfileRow {
    pub user_id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
}

/// An account's label plus the edge back to its owner, so a console can chain lenses without a
/// second round trip. `name` is nullable (`accounts.name` has no truthful backfill); `user_id` is
/// not (`accounts.user_id` is `NOT NULL`, trigger-provisioned).
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct AccountLabelRow {
    pub account_id: String,
    pub name: Option<String>,
    pub owner_user_id: String,
}

/// A project's label plus its account edge. Both columns are `NOT NULL` on `projects`.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct ProjectLabelRow {
    pub project_id: String,
    pub name: String,
    pub account_id: String,
}

/// Rejects an over-cap batch (see [`MAX_IDENTITY_BATCH`]).
pub(crate) fn check_batch(kind: &str, ids: &[String]) -> Result<()> {
    if ids.len() > MAX_IDENTITY_BATCH {
        return Err(Error::BadRequest(format!(
            "{kind}: {} ids requested, maximum is {MAX_IDENTITY_BATCH} per call",
            ids.len()
        )));
    }
    Ok(())
}

/// Escapes the LIKE metacharacters in caller-supplied search text so a query of `100%` searches
/// for the literal string rather than matching everything. `\` first, or it would double-escape
/// the escapes this adds.
pub(crate) fn escape_like(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
