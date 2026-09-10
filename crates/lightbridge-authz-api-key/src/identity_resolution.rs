//! Estate-wide identity resolution for the admin console (#647).
//!
//! Turns opaque `users.id` / `accounts.id` / `projects.id` values into human labels, with **no
//! ownership filter at all** — that is the point: these queries back `resolveUserProfiles`,
//! `resolveActorLabels` and `searchUsers`, which the RPC layer gates on the single dedicated
//! `user:read` permission (`Permission::UserRead`, admin-only by default).
//!
//! # Why hand-written SQL (ADR-0038)
//!
//! Two independent reasons, either alone disqualifying for the generated model client:
//!
//! 1. `federated_identities` is the ONLY source of display claims (`name`, `email`,
//!    `preferred_username`; `users` carries `id`/`status` and nothing else), and it is
//!    deliberately absent from `authz.cstack` entirely because it also carries the sealed Keycloak
//!    token envelope (ADR-0024 Q4, and `AGENTS.md`'s Persistence exception list names it). There
//!    is no generated read path to reach it through, by design.
//! 2. `Account`/`Project`'s `@@allow("read", ...)` clauses are ownership-scoped
//!    (`userId == auth().id`) and cratestack folds them into every query unconditionally with no
//!    bypass (see `listMyExpiringApiKeys`'s doc comment). An estate-wide admin label lookup is
//!    exactly the query that policy cannot express, and widening the shared clause would widen
//!    `model.Account.list`/`model.Project.list` for every other caller too.
//!
//! Lives in its own module rather than in `repo.rs` because that file sits on its committed
//! LoC-gate baseline (`.github/loc-baseline.json`) — same reason as `session_revocation.rs`.
//!
//! # Never fabricate an identity
//!
//! An id with no row is simply ABSENT from the result. The console owns every "Unknown" sentinel
//! it renders, so nothing here invents a placeholder. A `users` row that exists but has no
//! `federated_identities` row still comes back — with three `None`s.
//!
//! # The user → profile join
//!
//! `federated_identities.account_id` points at the account the identity ADOPTED, and
//! `accounts.user_id` is the owning person, so the path is
//! `users.id -> accounts.user_id -> accounts.id -> federated_identities.account_id`. One person
//! may own several accounts (ADR-0026), and `federated_identities_account_uidx` is per
//! `account_id`, not per `user_id` — so several identity rows per user are structurally possible.
//! `DISTINCT ON` + `updated_at DESC NULLS LAST` picks the most recently refreshed one and puts the
//! no-identity row last, so a real profile always beats a null one.

use lightbridge_authz_core::error::{Error, Result};
use tracing::instrument;

use crate::db::StoreRepo;
use crate::entities::identity_label_row::{
    AccountLabelRow, DEFAULT_USER_SEARCH_LIMIT, MAX_USER_SEARCH_LIMIT, MIN_USER_SEARCH_QUERY_CHARS,
    ProjectLabelRow, UserProfileRow, check_batch, escape_like,
};

impl StoreRepo {
    /// Display profiles for `user_ids`. Unknown ids are absent from the result; a known user with
    /// no federated identity comes back with `None` in all three claim fields.
    #[instrument(skip(self, user_ids), fields(count = user_ids.len()))]
    pub async fn resolve_user_profiles(&self, user_ids: &[String]) -> Result<Vec<UserProfileRow>> {
        check_batch("userIds", user_ids)?;
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, UserProfileRow>(
            r#"
            SELECT DISTINCT ON (u.id)
                   u.id                  AS user_id,
                   fi.name               AS display_name,
                   fi.email              AS email,
                   fi.preferred_username AS username
            FROM users u
            LEFT JOIN accounts a ON a.user_id = u.id
            LEFT JOIN federated_identities fi ON fi.account_id = a.id
            WHERE u.id = ANY($1)
            ORDER BY u.id, fi.updated_at DESC NULLS LAST
            "#,
        )
        .bind(user_ids)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Labels for `account_ids`. One query, no ownership filter, unknown ids absent.
    #[instrument(skip(self, account_ids), fields(count = account_ids.len()))]
    pub async fn resolve_account_labels(
        &self,
        account_ids: &[String],
    ) -> Result<Vec<AccountLabelRow>> {
        check_batch("accountIds", account_ids)?;
        if account_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, AccountLabelRow>(
            r#"
            SELECT id AS account_id, name, user_id AS owner_user_id
            FROM accounts
            WHERE id = ANY($1)
            ORDER BY id
            "#,
        )
        .bind(account_ids)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Labels for `project_ids`. One query, no ownership filter, unknown ids absent.
    #[instrument(skip(self, project_ids), fields(count = project_ids.len()))]
    pub async fn resolve_project_labels(
        &self,
        project_ids: &[String],
    ) -> Result<Vec<ProjectLabelRow>> {
        check_batch("projectIds", project_ids)?;
        if project_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, ProjectLabelRow>(
            r#"
            SELECT id AS project_id, name, account_id
            FROM projects
            WHERE id = ANY($1)
            ORDER BY id
            "#,
        )
        .bind(project_ids)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Case-insensitive prefix-or-substring search over the three display columns.
    ///
    /// `limit` is clamped to [`MAX_USER_SEARCH_LIMIT`]; a query shorter than
    /// [`MIN_USER_SEARCH_QUERY_CHARS`] is rejected. Order is fully deterministic and never depends
    /// on physical row order: prefix matches first, then by the best available label, then by
    /// `user_id`. The prefix arm of the `WHERE` is what
    /// `20260902000003_federated_identities_display_claim_indexes.sql`'s three
    /// `lower(<col>) text_pattern_ops` indexes serve; the substring arm cannot use a btree index
    /// (that would need `pg_trgm`, an extension this deployment does not install) and is a scan —
    /// acceptable because reaching it at all requires the admin-only `user:read` permission and
    /// the result is bounded either way.
    #[instrument(skip(self))]
    pub async fn search_user_profiles(
        &self,
        query: &str,
        limit: Option<i64>,
    ) -> Result<Vec<UserProfileRow>> {
        let trimmed = query.trim();
        if trimmed.chars().count() < MIN_USER_SEARCH_QUERY_CHARS {
            return Err(Error::BadRequest(format!(
                "query must be at least {MIN_USER_SEARCH_QUERY_CHARS} characters"
            )));
        }
        let limit = limit
            .unwrap_or(DEFAULT_USER_SEARCH_LIMIT)
            .clamp(1, MAX_USER_SEARCH_LIMIT);
        let needle = escape_like(&trimmed.to_lowercase());
        let prefix = format!("{needle}%");
        let substring = format!("%{needle}%");

        let rows = sqlx::query_as::<_, UserProfileRow>(
            r#"
            WITH matches AS (
                SELECT DISTINCT ON (a.user_id)
                       a.user_id             AS user_id,
                       fi.name               AS display_name,
                       fi.email              AS email,
                       fi.preferred_username AS username,
                       (lower(fi.name) LIKE $1 ESCAPE '\'
                        OR lower(fi.email) LIKE $1 ESCAPE '\'
                        OR lower(fi.preferred_username) LIKE $1 ESCAPE '\') IS TRUE AS is_prefix
                FROM federated_identities fi
                JOIN accounts a ON a.id = fi.account_id
                WHERE lower(fi.name) LIKE $2 ESCAPE '\'
                   OR lower(fi.email) LIKE $2 ESCAPE '\'
                   OR lower(fi.preferred_username) LIKE $2 ESCAPE '\'
                ORDER BY a.user_id, fi.updated_at DESC
            )
            SELECT user_id, display_name, email, username
            FROM matches
            ORDER BY is_prefix DESC,
                     lower(coalesce(display_name, email, username, user_id)) ASC,
                     user_id ASC
            LIMIT $3
            "#,
        )
        .bind(&prefix)
        .bind(&substring)
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}
