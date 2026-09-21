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

    /// Unconditional lookup by hash -- no `status`/`expires_at` filter. Used only to classify why
    /// a CAS consume (`consume_exchange_refresh_token`) just returned `None`: distinguishing "this
    /// hash names a token that was already rotated" (a replay of a superseded token -- RFC 6819
    /// §5.2.2.3 reuse detection, which must cascade-revoke the whole chain) from "no such token" /
    /// "expired" / "already revoked" (a plain `invalid_grant`, no cascade). Never used to decide
    /// whether to honor a refresh -- the CAS `UPDATE ... WHERE status = 'active'` remains the only
    /// source of truth for that.
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

    /// Cascade-revokes an entire refresh-token family (RFC 6819 §5.2.2.3): flips every
    /// still-`active` row sharing `chain_id` to `revoked`. Called when a token that was already
    /// rotated (superseded) is presented again -- the strongest signal this codebase has that a
    /// refresh token was stolen, since a legitimate client never re-presents a token it already
    /// exchanged for a successor. A no-op (not an error) when nothing in the chain is still
    /// active, matching `revoke_exchange_refresh_token`'s own idempotent-no-op convention.
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

    /// Atomically consumes a refresh token (single-use enforcement, backing
    /// `authkestra_op::refresh::RefreshTokenStore::consume_token`): flips the presented token from
    /// `active` to `rotated` and returns the row that was consumed, or `None` if it was not
    /// active/live (already used, revoked, expired) so the caller rejects those cases uniformly.
    /// A single `UPDATE ... WHERE status = 'active' ... RETURNING` is its own compare-and-swap --
    /// Postgres holds the row lock for the statement's duration, so two concurrent presentations
    /// of the same token can never both observe `status = 'active'` and both succeed. Unlike the
    /// combined rotate-and-insert this replaces, minting the successor is a separate call
    /// (`create_exchange_refresh_token`, driving `RefreshTokenStore::store_token`) -- the trait
    /// splits "atomically revoke" from "store a new one" into two methods, so this mirrors that
    /// shape rather than reintroducing the old single-transaction combo.
    ///
    /// Also stamps `rotated_at = $2` and `successor_id = $3` in the SAME statement (refresh-reuse
    /// grace window, migration `20260830000004_exchange_refresh_tokens_add_reuse_grace.sql`, added
    /// after the 2026-08-30 console-401s incident -- see that migration's doc comment). `successor
    /// _id` is the id of the row about to be minted by the caller's own follow-up
    /// `create_exchange_refresh_token` call; the caller generates it BEFORE calling this method
    /// specifically so it can be recorded here atomically, rather than only existing after a
    /// second, separate `INSERT` this method has no transaction spanning into. Pass `None` when
    /// the caller has no successor to record (e.g. the generic `RefreshTokenStore::consume_token`
    /// path, which only ever consumes -- it never mints a replacement row itself).
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

    /// Unconditionally revokes a refresh token by its hash (backing
    /// `authkestra_op::refresh::RefreshTokenStore::revoke_token`). A no-op (not an error) when the
    /// hash does not match an active row -- revoking something already gone is not a failure.
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

    /// Revokes a refresh token by its hash, scoped to `client_id` (backs `POST /oauth2/revoke`,
    /// RFC 7009). Same idempotent, no-op-if-no-match semantics as
    /// [`Self::revoke_exchange_refresh_token`], with one addition: a hash that matches a row
    /// belonging to a *different* client is also treated as "nothing to do", never as an error --
    /// RFC 7009 §2.2 requires the endpoint to return success uniformly for an unknown, already-
    /// revoked, *or* out-of-scope token, so a client can never use this endpoint to probe whether
    /// a given token string belongs to another client.
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
