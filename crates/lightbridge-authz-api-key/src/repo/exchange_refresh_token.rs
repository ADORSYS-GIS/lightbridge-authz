use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::Result;

use crate::entities::exchange_refresh_token_row::{
    ExchangeRefreshTokenRow, NewExchangeRefreshToken,
};
use crate::repo::StoreRepo;

impl StoreRepo {
    pub async fn create_exchange_refresh_token(
        &self,
        input: NewExchangeRefreshToken,
    ) -> Result<ExchangeRefreshTokenRow> {
        let row: ExchangeRefreshTokenRow = sqlx::query_as(
            r#"
            INSERT INTO exchange_refresh_tokens
              (id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, preferred_username, name, chain_id, chain_expires_at, session_id, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, preferred_username, name, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at, rotated_at, successor_id
            "#,
        )
        .bind(input.id)
        .bind(input.subject)
        .bind(input.account_id)
        .bind(input.project_id)
        .bind(input.client_id)
        .bind(input.token_hash)
        .bind(input.scope)
        .bind(input.email)
        .bind(input.email_verified)
        .bind(input.auth_time)
        .bind(input.preferred_username)
        .bind(input.name)
        .bind(input.chain_id)
        .bind(input.chain_expires_at)
        .bind(input.session_id)
        .bind(input.created_at)
        .bind(input.expires_at)
        .fetch_one(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_active_exchange_refresh_token(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ExchangeRefreshTokenRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, preferred_username, name, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at, rotated_at, successor_id
            FROM exchange_refresh_tokens
            WHERE token_hash = $1
              AND status = 'active'
              AND expires_at > $2
            "#,
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_exchange_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<ExchangeRefreshTokenRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, preferred_username, name, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at, rotated_at, successor_id
            FROM exchange_refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn revoke_exchange_refresh_token_chain(&self, chain_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE chain_id = $1
              AND status = 'active'
            "#,
        )
        .bind(chain_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn consume_exchange_refresh_token(
        &self,
        presented_hash: &str,
        now: DateTime<Utc>,
        successor_id: Option<&str>,
    ) -> Result<Option<ExchangeRefreshTokenRow>> {
        let row: Option<ExchangeRefreshTokenRow> = sqlx::query_as(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'rotated', last_used_at = $2, rotated_at = $2, successor_id = $3
            WHERE token_hash = $1
              AND status = 'active'
              AND expires_at > $2
            RETURNING id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, preferred_username, name, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at, rotated_at, successor_id
            "#,
        )
        .bind(presented_hash)
        .bind(now)
        .bind(successor_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn revoke_exchange_refresh_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE token_hash = $1
              AND status = 'active'
            "#,
        )
        .bind(token_hash)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn revoke_exchange_refresh_token_for_client(
        &self,
        token_hash: &str,
        client_id: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE token_hash = $1
              AND client_id = $2
              AND status = 'active'
            "#,
        )
        .bind(token_hash)
        .bind(client_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
