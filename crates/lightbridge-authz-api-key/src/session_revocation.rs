//! Scoped session revocation for OIDC RP-Initiated Logout.
//!
//! Lives in its own module rather than alongside [`StoreRepo`]'s other methods in `repo.rs`
//! purely because that file sits exactly on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown.

use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::identity::AccountId;

use crate::db::StoreRepo;

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
