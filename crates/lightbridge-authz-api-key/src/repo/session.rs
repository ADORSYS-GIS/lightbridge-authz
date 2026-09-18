use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::identity::AccountId;

use crate::entities::session_row::{
    BrowserSessionContextRow, NewSession, SessionRow, SessionStatusRow,
};
use crate::repo::StoreRepo;

impl StoreRepo {
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
