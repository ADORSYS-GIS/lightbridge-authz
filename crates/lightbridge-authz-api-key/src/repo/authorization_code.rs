use chrono::{DateTime, Utc};
use lightbridge_authz_core::error::Result;

use crate::entities::authorization_code_row::{AuthorizationCodeRow, NewAuthorizationCode};
use crate::repo::StoreRepo;

impl StoreRepo {
    pub async fn create_authorization_code(&self, input: NewAuthorizationCode) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO authorization_codes
              (id, code_hash, client_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, identity, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(input.id)
        .bind(input.code_hash)
        .bind(input.client_id)
        .bind(input.redirect_uri)
        .bind(input.scope)
        .bind(input.code_challenge)
        .bind(input.code_challenge_method)
        .bind(input.nonce)
        .bind(input.identity)
        .bind(input.expires_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn consume_authorization_code(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthorizationCodeRow>> {
        let row = sqlx::query_as(
            r#"
            UPDATE authorization_codes
            SET consumed_at = $2
            WHERE code_hash = $1
              AND consumed_at IS NULL
              AND expires_at > $2
            RETURNING id, code_hash, client_id, redirect_uri, scope, code_challenge,
                      code_challenge_method, nonce, identity, created_at, expires_at, consumed_at
            "#,
        )
        .bind(code_hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Stores a sealed, single-use secret claim (GHSA-9pc6-965v-2c44, #538). ADR-0038
    /// persistence exception, same class as `authorization_codes`: see the migration's own
    /// comment and `consume_secret_claim` below for why redemption cannot be generated CRUD.
    pub async fn create_secret_claim(
        &self,
        id: &str,
        token_hash: &str,
        subject: &str,
        sealed_secret: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO secret_claims (id, token_hash, subject, sealed_secret, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(id)
        .bind(token_hash)
        .bind(subject)
        .bind(sealed_secret)
        .bind(expires_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Claims a secret exactly once, for `subject` only, returning the sealed envelope.
    ///
    /// `subject` is in the `WHERE` clause, not checked afterwards, and that placement is the
    /// whole point: a wrong-subject attempt matches no row, so `consumed_at` is never written and
    /// the legitimate owner's claim survives. Consuming first and comparing second would let
    /// anyone holding the token -- including the model it travelled through -- burn the owner's
    /// one chance to collect their key.
    ///
    /// Single-statement CAS, mirroring `consume_authorization_code`: concurrent redemptions by
    /// the same subject cannot both win, because only the first sees `consumed_at IS NULL`.
    pub async fn consume_secret_claim(
        &self,
        token_hash: &str,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let sealed = sqlx::query_scalar(
            r#"
            UPDATE secret_claims
            SET consumed_at = $3
            WHERE token_hash = $1
              AND subject = $2
              AND consumed_at IS NULL
              AND expires_at > $3
            RETURNING sealed_secret
            "#,
        )
        .bind(token_hash)
        .bind(subject)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(sealed)
    }

    pub async fn authorization_code_matches(
        &self,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let matches = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM authorization_codes
                WHERE code_hash = $1
                  AND client_id = $2
                  AND redirect_uri = $3
                  AND consumed_at IS NULL
                  AND expires_at > $4
            )
            "#,
        )
        .bind(code_hash)
        .bind(client_id)
        .bind(redirect_uri)
        .bind(now)
        .fetch_one(self.pool())
        .await?;
        Ok(matches)
    }
}
