use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::identity::AccountId;

use crate::entities::session_row::{
    BrowserSessionContextRow, NewSession, SessionRow, SessionStatusRow,
};
use crate::repo::StoreRepo;

impl StoreRepo {
    /// Inserts a new `sessions` row (ADR-0020 Decision 1). Every call site this PR touches mints
    /// `kind = "token"` -- see [`NewSession`]'s own doc comment.
    pub async fn create_session(&self, input: NewSession) -> Result<SessionRow> {
        let row: SessionRow = sqlx::query_as(
            r#"
            INSERT INTO sessions
              (id, account_id, project_id, client_id, kind, status, expires_at, subject)
            VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
            RETURNING id, account_id, project_id, client_id, kind, status, created_at, updated_at, last_used_at, expires_at, user_agent, subject
            "#,
        )
        .bind(input.id)
        .bind(input.account_id)
        .bind(input.project_id)
        .bind(input.client_id)
        .bind(input.kind)
        .bind(input.expires_at)
        .bind(input.subject)
        .fetch_one(self.pool())
        .await?;
        Ok(row)
    }

    /// ADR-0020 Decision 4 / #437: the current `status`/`expires_at` of the `sessions` row named
    /// `session_id`, for introspection's fail-closed status check. `Ok(None)` (never an error) for
    /// an unrecognized `session_id` -- distinguishing "not found" from a real DB error is exactly
    /// what lets the caller (`resolve_exchange_token_context`) tell "session doesn't exist" (fail
    /// to `active: false`) apart from "couldn't check" (fail the whole call closed, propagate
    /// `Err`).
    pub async fn find_session_status(&self, session_id: &str) -> Result<Option<SessionStatusRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT status, expires_at
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_active_browser_session(
        &self,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserSessionContextRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT account_id, project_id, subject
            FROM sessions
            WHERE id = $1
              AND kind = 'browser'
              AND status = 'active'
              AND expires_at > $2
            "#,
        )
        .bind(session_id)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Revokes every currently-active session for `subject` -- of EITHER `kind` (ADR-0021
    /// Decision 3: the query is deliberately `kind`-blind, which is exactly what makes it cover
    /// both `kind = 'token'` and `kind = 'browser'` rows in one call) -- and cascades to revoke
    /// every `exchange_refresh_tokens` row chained under one of those sessions (ADR-0020 Decision
    /// 9), so a bulk "log out everywhere" cannot leave a live refresh token behind for a session
    /// it just killed. Backs both the self-service "log out everywhere" RPC procedure and the
    /// admin offboarding kill switch (`docs/rbac.md`'s `session:revoke-own`/`session:revoke`).
    /// Returns how many SESSIONS were revoked (not refresh-token rows), so the caller gets
    /// confirmation the kill switch did something; `0` (not an error) when the subject has no
    /// active sessions of either kind. Two statements in one transaction, not a single query --
    /// see the module doc comment on why this repo keeps this operation hand-written rather than
    /// cratestack-generated (ADR-0020 Decision 9).
    ///
    /// Matches on `sessions.subject` (the real authenticated actor), never `sessions.account_id`
    /// (#492): `account_id` always holds the PROJECT's OWNING account (`resolve_context`'s
    /// documented behavior), identical for every session ever minted against a given project
    /// regardless of which real person -- owner or roster member -- minted it. Keying this query
    /// on `account_id` mixed up "which project" with "which person": a roster member's own
    /// "log out everywhere" silently no-opped on their own session (it never matched), while the
    /// project owner's own "log out everywhere" collaterally revoked every OTHER member's session
    /// on a shared project too (it always matched). `subject` is populated for every session this
    /// repo creates -- `kind = 'browser'` rows since
    /// `migrations/20260824000003_sessions_add_subject.sql`, `kind = 'token'` rows since this
    /// fix's companion change to `oauth2_op::store::TokenExchangeOpStore`'s two `create_session`
    /// call sites -- so only sessions minted before this fix (`subject IS NULL`) go unmatched
    /// here; those are TTL-bounded and self-heal on their own expiry, the same trade-off the
    /// nullable-column migration already made for pre-migration browser rows.
    pub async fn revoke_sessions_and_cascade(&self, account_id: &AccountId) -> Result<u64> {
        let mut tx = self.pool().begin().await?;
        let revoked_sessions = sqlx::query(
            r#"
            UPDATE sessions
            SET status = 'revoked', updated_at = now()
            WHERE subject = $1
              AND status = 'active'
            "#,
        )
        .bind(account_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE status = 'active'
              AND session_id IN (SELECT id FROM sessions WHERE subject = $1)
            "#,
        )
        .bind(account_id.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(revoked_sessions.rows_affected())
    }
}
