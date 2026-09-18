use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use tracing::instrument;

use crate::entities::federated_identity_row::{FederatedIdentityRow, UpsertFederatedIdentity};
use crate::repo::StoreRepo;

/// Fine-grained outcome of [`StoreRepo::resolve_account_for_federated_subject_detailed`]
/// (ADR-0025 Correction, "the Stage 2..5 bootstrap window"). The two refusal variants exist ONLY
/// so `FederatedSubjectResolver::resolve` (`lightbridge-authz-rest::auth_provider`) can decide
/// whether the temporary grandfather-issuer bootstrap fallback applies -- every OTHER caller must
/// keep using [`StoreRepo::resolve_account_for_federated_subject`], whose `Result<String>`
/// collapses both variants to the identical `Error::Forbidden("no federated identity for this
/// subject")` so no ingress becomes an account-existence oracle. Do not match on this enum
/// anywhere else without re-reading that ADR section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedResolution {
    /// A `federated_identities` row already existed, or the grandfather-issuer subject was just
    /// adopted -- the resolved acting account id.
    Resolved(String),
    /// The presented issuer is not the grandfather issuer, and no `federated_identities` row
    /// exists either. Refuse unconditionally -- never eligible for the bootstrap fallback.
    RogueIssuer,
    /// The grandfather issuer presented a subject with no `federated_identities` row AND no
    /// matching `accounts` row. Eligible for the temporary bootstrap fallback.
    NoAccount,
}

impl StoreRepo {
    #[instrument(skip(self, subject, grandfather_issuer))]
    pub async fn resolve_account_for_federated_subject(
        &self,
        issuer: &str,
        subject: &str,
        grandfather_issuer: &str,
    ) -> Result<String> {
        match self
            .resolve_account_for_federated_subject_detailed(issuer, subject, grandfather_issuer)
            .await?
        {
            FederatedResolution::Resolved(account_id) => Ok(account_id),
            FederatedResolution::RogueIssuer | FederatedResolution::NoAccount => Err(
                Error::Forbidden("no federated identity for this subject".to_string()),
            ),
        }
    }

    #[instrument(skip(self, subject, grandfather_issuer))]
    pub async fn resolve_account_for_federated_subject_detailed(
        &self,
        issuer: &str,
        subject: &str,
        grandfather_issuer: &str,
    ) -> Result<FederatedResolution> {
        let mut tx = self.pool().begin().await?;

        let existing: Option<(String,)> = sqlx::query_as(
            r#"SELECT account_id FROM federated_identities WHERE issuer = $1 AND subject = $2"#,
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((account_id,)) = existing {
            tx.commit().await?;
            return Ok(FederatedResolution::Resolved(account_id));
        }

        if issuer != grandfather_issuer {
            return Ok(FederatedResolution::RogueIssuer);
        }

        let account: Option<(String,)> =
            sqlx::query_as("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(subject)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((account_id,)) = account else {
            return Ok(FederatedResolution::NoAccount);
        };

        let inserted: Option<(String,)> = sqlx::query_as(
            r#"
            INSERT INTO federated_identities (id, issuer, subject, account_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (issuer, subject) DO NOTHING
            RETURNING account_id
            "#,
        )
        .bind(cuid2())
        .bind(issuer)
        .bind(subject)
        .bind(&account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict(
                    "account already adopted by another federated identity".to_string(),
                );
            }
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23503")
            {
                return Error::Forbidden("no federated identity for this subject".to_string());
            }
            Error::from(e)
        })?;

        let account_id = match inserted {
            Some((account_id,)) => account_id,
            None => {
                let (account_id,): (String,) = sqlx::query_as(
                    r#"SELECT account_id FROM federated_identities WHERE issuer = $1 AND subject = $2"#,
                )
                .bind(issuer)
                .bind(subject)
                .fetch_one(&mut *tx)
                .await?;
                account_id
            }
        };

        tx.commit().await?;
        Ok(FederatedResolution::Resolved(account_id))
    }

    #[instrument(skip(self, input))]
    pub async fn upsert_federated_identity(
        &self,
        input: UpsertFederatedIdentity,
        grandfather_issuer: &str,
    ) -> Result<FederatedIdentityRow> {
        let mut tx = self.pool().begin().await?;

        let existing: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT id
            FROM federated_identities
            WHERE issuer = $1 AND subject = $2
            FOR UPDATE
            "#,
        )
        .bind(&input.issuer)
        .bind(&input.subject)
        .fetch_optional(&mut *tx)
        .await?;

        let row: FederatedIdentityRow = if let Some((id,)) = existing {
            sqlx::query_as(
                r#"
                UPDATE federated_identities
                SET token_envelope = $1,
                    token_sealed_at = $2,
                    access_expires_at = $3,
                    refresh_expires_at = $4,
                    scope = $5,
                    email = $6,
                    email_verified = $7,
                    preferred_username = $8,
                    name = $9,
                    last_authenticated_at = now(),
                    updated_at = now()
                WHERE id = $10
                RETURNING id, issuer, subject, account_id, token_envelope,
                          token_sealed_at, access_expires_at, refresh_expires_at, scope,
                          email, email_verified, preferred_username, name,
                          last_authenticated_at, created_at, updated_at
                "#,
            )
            .bind(&input.token_envelope)
            .bind(input.token_sealed_at)
            .bind(input.access_expires_at)
            .bind(input.refresh_expires_at)
            .bind(&input.scope)
            .bind(&input.email)
            .bind(input.email_verified)
            .bind(&input.preferred_username)
            .bind(&input.name)
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?
        } else {
            if input.issuer != grandfather_issuer {
                return Err(Error::Forbidden(
                    "no federated identity for this subject".to_string(),
                ));
            }
            let account: Option<(String,)> =
                sqlx::query_as("SELECT id FROM accounts WHERE id = $1")
                    .bind(&input.subject)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some((account_id,)) = account else {
                return Err(Error::Forbidden(
                    "federated subject has no lightbridge account".to_string(),
                ));
            };
            sqlx::query_as(
                r#"
                INSERT INTO federated_identities
                  (id, issuer, subject, account_id, token_envelope, token_sealed_at,
                   access_expires_at, refresh_expires_at, scope,
                   email, email_verified, preferred_username, name)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING id, issuer, subject, account_id, token_envelope,
                          token_sealed_at, access_expires_at, refresh_expires_at, scope,
                          email, email_verified, preferred_username, name,
                          last_authenticated_at, created_at, updated_at
                "#,
            )
            .bind(cuid2())
            .bind(&input.issuer)
            .bind(&input.subject)
            .bind(&account_id)
            .bind(&input.token_envelope)
            .bind(input.token_sealed_at)
            .bind(input.access_expires_at)
            .bind(input.refresh_expires_at)
            .bind(&input.scope)
            .bind(&input.email)
            .bind(input.email_verified)
            .bind(&input.preferred_username)
            .bind(&input.name)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(db_err) = &e
                    && db_err.code().as_deref() == Some("23505")
                {
                    return Error::Conflict(format!(
                        "federated identity already exists or account already adopted for \
                         subject '{}'",
                        input.subject
                    ));
                }
                if let sqlx::Error::Database(db_err) = &e
                    && db_err.code().as_deref() == Some("23503")
                {
                    return Error::Forbidden(
                        "federated subject has no lightbridge account".to_string(),
                    );
                }
                Error::from(e)
            })?
        };

        tx.commit().await?;
        Ok(row)
    }

    #[instrument(skip(self, subject))]
    pub async fn find_federated_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<FederatedIdentityRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, issuer, subject, account_id, token_envelope, token_sealed_at,
                   access_expires_at, refresh_expires_at, scope,
                   email, email_verified, preferred_username, name,
                   last_authenticated_at, created_at, updated_at
            FROM federated_identities
            WHERE issuer = $1 AND subject = $2
            "#,
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    #[instrument(skip(self))]
    pub async fn find_federated_identity_by_account_id(
        &self,
        account_id: &str,
    ) -> Result<Option<FederatedIdentityRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, issuer, subject, account_id, token_envelope, token_sealed_at,
                   access_expires_at, refresh_expires_at, scope,
                   email, email_verified, preferred_username, name,
                   last_authenticated_at, created_at, updated_at
            FROM federated_identities
            WHERE account_id = $1
            "#,
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }
}
