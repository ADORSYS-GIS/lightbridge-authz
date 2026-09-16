//! Self-service account provisioning at first federated login -- the mint-on-login branch
//! ADR-0024's 2026-08-25 correction removed, with nothing to replace it in production (#739).
//! Its own file because `repo.rs` sits on its LoC-gate baseline: touchable, not growable.
//!
//! ADR-0038: hand-written SQL because no table here is expressible through the generated client.
//! `federated_identities` is ABSENT from `authz.cstack` by design (ADR-0024 Q4,
//! credential-bearing); `accounts` deliberately has no `@@allow("create", ...)` and
//! `model.Account.create` is denied at the RBAC layer besides (ADR-0006, procedure-only, which is
//! why `create_account`/`provision_account` are hand-written too); `projects` HAS an
//! `@@allow("create", ...)`, but every conjunct is unsatisfiable at `/idp/callback`, where there is
//! no `auth()` context at all. Full argument: AGENTS.md's ADR-0038 exception list.

use chrono::Utc;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use tracing::instrument;

use crate::db::StoreRepo;
use crate::entities::federated_identity_row::{FederatedIdentityRow, UpsertFederatedIdentity};

/// Whether the account existed, or was minted (with its default project) in the same transaction.
/// `persist_federated_identity` books the #697 starting grant only when it was minted.
#[derive(Debug)]
pub struct FederatedIdentityOutcome {
    pub row: FederatedIdentityRow,
    pub provisioned: bool,
}

impl StoreRepo {
    /// The provisioning-capable sibling of [`Self::upsert_federated_identity`]: identical
    /// UPDATE-on-existing behaviour and identical ADR-0025 issuer pin (any issuer other than
    /// `grandfather_issuer` is still refused, never provisioned), but where that method refuses a
    /// `subject` with no `accounts` row, this one provisions the anchor account and its default
    /// project in the SAME transaction -- mirroring [`Self::provision_account`]'s two INSERTs --
    /// then runs the identical `federated_identities` INSERT either way. The original is untouched.
    ///
    /// `billing_identity` (globally UNIQUE) is the ID token's `email` only when `email_verified ==
    /// Some(true)`, else `subject` verbatim: trusting an unverified email would let one user squat
    /// another's billing identity, and `subject` is unique and non-squattable, so a user with no
    /// verified email (9 of the 42 affected in production) can still sign in.
    #[instrument(skip(self, input))]
    pub async fn upsert_federated_identity_and_provision(
        &self,
        input: UpsertFederatedIdentity,
        grandfather_issuer: &str,
    ) -> Result<FederatedIdentityOutcome> {
        let mut tx = self.pool().begin().await?;

        let existing: Option<(String,)> = sqlx::query_as(
            r#"SELECT id FROM federated_identities WHERE issuer = $1 AND subject = $2 FOR UPDATE"#,
        )
        .bind(&input.issuer)
        .bind(&input.subject)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some((id,)) = existing {
            let row: FederatedIdentityRow = sqlx::query_as(
                r#"
                UPDATE federated_identities
                SET token_envelope = $1, token_sealed_at = $2, access_expires_at = $3,
                    refresh_expires_at = $4, scope = $5, email = $6, email_verified = $7,
                    preferred_username = $8, name = $9, last_authenticated_at = now(),
                    updated_at = now()
                WHERE id = $10
                RETURNING id, issuer, subject, account_id, token_envelope, token_sealed_at,
                          access_expires_at, refresh_expires_at, scope, email, email_verified,
                          preferred_username, name, last_authenticated_at, created_at, updated_at
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
            .await?;
            tx.commit().await?;
            return Ok(FederatedIdentityOutcome {
                row,
                provisioned: false,
            });
        }

        // ADR-0025: only the grandfather issuer's subjects may adopt (or, since this method
        // exists, provision) a pre-existing `accounts.id == subject` row -- same refusal message
        // as `upsert_federated_identity`'s own pin, so this never becomes an account-existence
        // oracle for a rogue issuer either.
        if input.issuer != grandfather_issuer {
            return Err(Error::Forbidden(
                "no federated identity for this subject".to_string(),
            ));
        }

        let account: Option<(String,)> = sqlx::query_as("SELECT id FROM accounts WHERE id = $1")
            .bind(&input.subject)
            .fetch_optional(&mut *tx)
            .await?;
        let provisioned = account.is_none();
        if provisioned {
            let now = Utc::now();
            sqlx::query(
                "INSERT INTO accounts (id, name, created_at, updated_at) VALUES ($1, $2, $3, $3)",
            )
            .bind(&input.subject)
            .bind(&input.name)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| provisioning_conflict(e, "account already exists for this subject"))?;
            let billing_identity = match (&input.email, input.email_verified) {
                (Some(email), Some(true)) => email.clone(),
                _ => input.subject.clone(),
            };
            sqlx::query(
                r#"
                INSERT INTO projects
                  (id, account_id, name, billing_plan, billing_identity, created_at, updated_at)
                VALUES ($1, $2, 'Default Project', 'free', $3, $4, $4)
                "#,
            )
            .bind(cuid2())
            .bind(&input.subject)
            .bind(&billing_identity)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                let message =
                    format!("a project with billing identity '{billing_identity}' already exists");
                provisioning_conflict(e, &message)
            })?;
        }

        let row: FederatedIdentityRow = sqlx::query_as(
            r#"
            INSERT INTO federated_identities
              (id, issuer, subject, account_id, token_envelope, token_sealed_at,
               access_expires_at, refresh_expires_at, scope,
               email, email_verified, preferred_username, name)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id, issuer, subject, account_id, token_envelope, token_sealed_at,
                      access_expires_at, refresh_expires_at, scope, email, email_verified,
                      preferred_username, name, last_authenticated_at, created_at, updated_at
            "#,
        )
        .bind(cuid2())
        .bind(&input.issuer)
        .bind(&input.subject)
        .bind(&input.subject)
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
                    "federated identity already exists or account already adopted for subject '{}'",
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
        })?;

        tx.commit().await?;
        Ok(FederatedIdentityOutcome { row, provisioned })
    }
}

/// Shared `23505` mapping for the two provisioning INSERTs -- the narrow race of two concurrent
/// first logins for one never-seen subject. Same posture as `provision_account`'s identical race.
fn provisioning_conflict(e: sqlx::Error, message: &str) -> Error {
    if let sqlx::Error::Database(db_err) = &e
        && db_err.code().as_deref() == Some("23505")
    {
        return Error::Conflict(message.to_string());
    }
    Error::from(e)
}
