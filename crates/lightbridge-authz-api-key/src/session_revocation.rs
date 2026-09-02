//! Scoped session revocation for OIDC RP-Initiated Logout.
//!
//! Lives in its own module rather than alongside [`StoreRepo`]'s other methods in `repo.rs`
//! purely because that file sits exactly on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown.

use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::identity::AccountId;

use crate::db::StoreRepo;
use crate::entities::session_row::SessionOwnerRow;

impl StoreRepo {
    /// Ends a browser SSO session without disturbing other clients' `offline_access` grants.
    ///
    /// Revokes, for `account_id`: every `kind = 'browser'` session, plus every session belonging
    /// to `client_id` (the RP that asked for the logout), plus the refresh chains hanging off
    /// exactly those sessions. A `None` `client_id` revokes the browser sessions only.
    ///
    /// # Why this is not [`StoreRepo::revoke_sessions_and_cascade`]
    ///
    /// That method matches on `subject` ALONE -- no `kind`, no `client_id` -- so it revokes every
    /// session the person holds and every refresh chain hanging off any of them. It is the right
    /// behaviour for `procedure.revokeOwnSessions` and `procedure.revokeSubjectSessions`, which
    /// mean "log out everywhere" and "offboard this person", and it remains their implementation.
    ///
    /// It was the WRONG behaviour for `/oauth2/end_session`, and shipping it there was a real
    /// production defect: every CLI grant persists a `kind = 'token'` session
    /// (`oauth2_op/store.rs`'s `create_session`), so one browser logout in the console silently
    /// revoked the refresh chain of every other client that person had ever authorised -- their
    /// `opencode-cli`, their `governance-auth-cli`. The symptom was a CLI that had worked for
    /// hours suddenly answering `400 invalid_grant` on refresh and demanding a fresh device-code
    /// login, at no fixed interval, because the trigger was a browser action in a different
    /// client rather than anything time-based (the refresh TTLs are 30 and 90 days). Nothing was
    /// logged, because the plain `invalid_grant` arm of `handle_refresh_token` is silent.
    ///
    /// `offline_access` is defined by OpenID Connect Core §11 as access that outlives the
    /// end-user's browser session; revoking it *because* that browser session ended inverts the
    /// meaning of the scope the client explicitly asked for. The RP that requested the logout is
    /// still included, so signing out of the console does still end the console's own tokens.
    pub async fn revoke_for_logout(
        &self,
        account_id: &AccountId,
        client_id: Option<&str>,
    ) -> Result<u64> {
        let mut tx = self.pool().begin().await?;
        // The `kind = 'browser' OR (... client_id = $2)` predicate is repeated verbatim by the
        // refresh-chain subquery below rather than the two being derived separately, so they can
        // never drift into revoking different sets of sessions.
        let revoked_sessions = sqlx::query(
            r#"
            UPDATE sessions
            SET status = 'revoked', updated_at = now()
            WHERE subject = $1
              AND status = 'active'
              AND (kind = 'browser' OR ($2::text IS NOT NULL AND client_id = $2))
            "#,
        )
        .bind(account_id.as_str())
        .bind(client_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE status = 'active'
              AND session_id IN (
                SELECT id FROM sessions
                WHERE subject = $1
                  AND (kind = 'browser' OR ($2::text IS NOT NULL AND client_id = $2))
              )
            "#,
        )
        .bind(account_id.as_str())
        .bind(client_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(revoked_sessions.rows_affected())
    }
}

impl StoreRepo {
    /// Who a session belongs to, and whether it is already revoked — the two facts
    /// `procedure.revokeSession` (#649) needs to decide whether the caller may act on it, read
    /// BEFORE anything is written.
    ///
    /// `Ok(None)` means no such session: the caller gets a clean not-found, distinct from the
    /// forbidden a real-but-someone-else's session produces. Keeping the two distinct is safe here
    /// precisely because a session id is an opaque CUID2 (ADR-0039) that nobody can enumerate — a
    /// `403` confirms existence only to someone who already had the id.
    pub async fn find_session_owner(&self, session_id: &str) -> Result<Option<SessionOwnerRow>> {
        let row = sqlx::query_as::<_, SessionOwnerRow>(
            r#"
            SELECT subject, status
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Revokes ONE session and the refresh chain hanging off it, in one transaction.
    ///
    /// The missing middle between [`StoreRepo::revoke_sessions_and_cascade`] ("every session this
    /// subject holds") and [`StoreRepo::revoke_for_logout`] ("the browser ones plus this client's")
    /// — same two statements, same order, same transaction, keyed on the session's own id instead
    /// of on `subject`. The refresh-chain `UPDATE` is not optional and not a follow-up: a revoked
    /// session whose chain is still `active` leaves a working refresh token for a session that is
    /// gone, which is exactly the hole ADR-0020 Decision 9's cascade requirement closes.
    ///
    /// Returns whether THIS call changed anything: `true` when an `active` row flipped to
    /// `revoked`, `false` when it was already revoked. Idempotent by construction — the `WHERE
    /// status = 'active'` guard makes a second call a no-op rather than a second state change —
    /// and the boolean is what `RevokeSessionResult.revoked` reports, mirroring
    /// `revokeSubjectSessions` answering `revokedCount: 0` for a subject with nothing left.
    ///
    /// Callers must have already authorized the action (see
    /// `lightbridge_authz_rest::session_directory::revoke_session`): this method applies no
    /// ownership filter, deliberately, because `session:revoke` holders act on sessions that are
    /// not theirs and the filter would have to be bypassed for them anyway.
    pub async fn revoke_session_by_id(&self, session_id: &str) -> Result<bool> {
        let mut tx = self.pool().begin().await?;
        let revoked = sqlx::query(
            r#"
            UPDATE sessions
            SET status = 'revoked', updated_at = now()
            WHERE id = $1
              AND status = 'active'
            "#,
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
        // Runs unconditionally, not only when the session row flipped: a chain left active under
        // an already-revoked session (possible for a row revoked before this cascade existed) is
        // exactly the state this is here to clean up, and re-revoking nothing costs one no-op
        // statement.
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE status = 'active'
              AND session_id = $1
            "#,
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(revoked.rows_affected() > 0)
    }
}
