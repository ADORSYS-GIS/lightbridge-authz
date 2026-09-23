//! **Legitimately exceeds the 200-LoC gate**: this file is one domain slice of the verbatim
//! `repo.rs` -> `repo/` split (#521), with its load-bearing comments restored move-intact
//! under the #760 review. Deeper burn-down is tracked separately, not silently re-factored
//! here (see `docs/code-size-baseline.md`'s rule for honestly-oversized modules).
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
    /// ADR-0024, corrected 2026-08-25: seals-and-persists a login's Keycloak token set for
    /// `(input.issuer, input.subject)`, inside one transaction (pattern:
    /// `rotate_api_key_transaction` above). `SELECT ... FOR UPDATE` first, so a second call for the
    /// same `(issuer, subject)` racing concurrently serializes onto the UPDATE branch rather than
    /// double-inserting.
    ///
    /// On this identity's FIRST login ever (no existing row): adopt-or-REFUSE, decided entirely
    /// inside this same transaction, before any write. A subject matching a grandfathered
    /// `accounts` row (a pre-ADR-0024 account, ADR-0006's "id is the stored sub" property) is
    /// adopted. A subject with no `accounts` row at all has no relationship with this service --
    /// there is no mint-a-user branch any more -- so the login is REFUSED (`Error::Forbidden`)
    /// before any row is written; nothing is left behind. Bounded, not a new failure: an
    /// accountless subject already dead-ended downstream in both flows (browser SSO's
    /// `find_default_project_id`, device pairing's `issue_device_tokens`) -- this refuses earlier
    /// and leaves nothing behind. Never rewrites `issuer`/`subject`/`account_id` on an update --
    /// those are the federation key and its owner, fixed at creation.
    ///
    /// `federated_identities_issuer_subject_uidx`/`federated_identities_account_uidx` (the owning
    /// migration, `20260825000001_users_and_federated_identities.sql`, FK action corrected by
    /// `20260825000002_federated_identities_link_accounts_not_users.sql`) make a concurrent insert
    /// racing on either index surface as `Error::Conflict` here, mirroring `create_account`'s own
    /// 23505 idiom above -- in particular, a second issuer presenting a subject that already
    /// adopted an account is REFUSED, never silently merged onto that account. A `23503` (the
    /// adopted account was deleted between this method's own SELECT and its INSERT) maps to the
    /// same `Error::Forbidden` as the no-account case above -- both are "this subject has no
    /// lightbridge account right now."
    /// ADR-0025: `(issuer, subject)` -> the acting person's lightbridge account id. THE ONLY
    /// translation from a remote IdP subject to an id this service owns -- every repository
    /// method below this line takes an account id, never a remote sub.
    ///
    /// Step 1 is the steady-state path: an already-adopted `federated_identities` row (written
    /// either by [`Self::upsert_federated_identity`] at login time, or by this method's own
    /// self-healing insert below the first time a grandfathered subject is ever resolved)
    /// resolves directly, no write.
    ///
    /// Step 2, the grandfather branch, is TEMPORARY and issuer-pinned: it exists only until the
    /// ADR-0025 residue query (every remaining `accounts` row with no adopting
    /// `federated_identities` row) reaches steady state, at which point this branch is deleted.
    /// It is NOT a read-side `accounts.id == subject` fallback -- that shape would re-open
    /// ADR-0024's cross-issuer merge on every plane that never calls
    /// [`Self::upsert_federated_identity`]: a subject presented by `grandfather_issuer` (the
    /// deployment's one configured `oauth2.federation.issuer`) that matches a pre-ADR-0024
    /// `accounts.id == subject` row is adopted, self-healing a real `federated_identities` row
    /// into existence right here, under `FOR UPDATE` on the `accounts` row so two concurrent
    /// resolutions for the same subject serialize rather than double-adopt. A subject presented
    /// by any OTHER issuer, or with no matching `accounts` row at all, is refused
    /// (`Error::Forbidden`) with the SAME message in both cases -- never a distinct status that
    /// would let a caller distinguish "wrong issuer" from "no such account."
    ///
    /// `token_envelope` and its sibling columns are left `NULL` on the self-healed row (ADR-0024
    /// Q2: an absent envelope is read identically to "no stored token" -- the relying-party leg
    /// re-seals a real token set the next time this subject completes a browser-SSO login).
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
            // Deliberately the SAME variant and message for both refusal cases -- see
            // `FederatedResolution`'s own doc comment for why, and
            // `resolve_account_for_federated_subject_detailed` for the one caller allowed to tell
            // them apart.
            FederatedResolution::RogueIssuer | FederatedResolution::NoAccount => Err(
                Error::Forbidden("no federated identity for this subject".to_string()),
            ),
        }
    }

    /// Fine-grained twin of [`Self::resolve_account_for_federated_subject`], which stays the
    /// externally-uniform `Result<String>` every ingress except one already relies on. This
    /// method exists ONLY for
    /// `lightbridge_authz_rest::auth_provider::FederatedSubjectResolver::resolve` (ADR-0025
    /// Correction, "the Stage 2..5 bootstrap window"): that caller needs to tell "wrong issuer"
    /// apart from "no account yet" to decide whether the temporary grandfather-issuer bootstrap
    /// fallback applies, WITHOUT the distinction ever leaking past that one internal seam --
    /// `resolve_account_for_federated_subject` above still collapses both cases to the identical
    /// `Error::Forbidden` message no caller can distinguish, so this repo remains exactly as much
    /// of an account-existence non-oracle as it always was. Do not add a second caller without
    /// re-reading that ADR section first.
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
                // Not the (issuer, subject) target of the ON CONFLICT clause above (that race is
                // handled by the re-SELECT below) -- this is the OTHER unique index,
                // `federated_identities_account_uidx`: a different (issuer, subject) pair has
                // already adopted this same account_id. Refused, never silently merged.
                return Error::Conflict(
                    "account already adopted by another federated identity".to_string(),
                );
            }
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23503")
            {
                // The account was deleted between this transaction's own FOR UPDATE lookup above
                // and this INSERT -- the same "no lightbridge account" outcome as the early
                // refusal above, just discovered a few microseconds later.
                return Error::Forbidden("no federated identity for this subject".to_string());
            }
            Error::from(e)
        })?;

        let account_id = match inserted {
            Some((account_id,)) => account_id,
            None => {
                // Lost the race to a concurrent resolution for the SAME (issuer, subject): the
                // other transaction's row already committed between this transaction's own
                // step-1 SELECT and this INSERT. Re-read it rather than erroring -- this is
                // exactly the self-healing idempotency this method promises under concurrency,
                // not a conflict.
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

    /// `grandfather_issuer` mirrors `resolve_account_for_federated_subject`'s own parameter of the
    /// same name (ADR-0025): only a subject presented by the ONE configured grandfather issuer may
    /// adopt a pre-existing `accounts.id == subject` row. Without this pin, ANY issuer whose token
    /// happens to carry a `sub` matching an existing account id could adopt it -- first-mover-wins
    /// across any future second issuer, contradicting the resolver's own issuer-pinned rule. The
    /// existing-row UPDATE branch below stays un-pinned: the row itself already proves which issuer
    /// legitimately owns this `(issuer, subject)` pair, so there is nothing left to check.
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
            // ADR-0025: a subject presented by any issuer OTHER than the configured grandfather
            // issuer may never adopt a pre-existing account, no matter how well the subject
            // matches -- same message as `resolve_account_for_federated_subject`'s own issuer-pin
            // refusal (deliberately indistinguishable from "no account", so this never becomes an
            // account-existence oracle either).
            if input.issuer != grandfather_issuer {
                return Err(Error::Forbidden(
                    "no federated identity for this subject".to_string(),
                ));
            }
            // ADR-0024 Correction (2026-08-25): a Keycloak identity links to an ACCOUNT and to
            // nothing else. There is no mint-a-user branch: a subject with no accounts row has no
            // relationship with this service, so the login is refused HERE -- inside the same
            // transaction that would otherwise insert, so there is no window between the check and
            // the write -- and federated_identities.account_id NOT NULL is the structural backstop
            // behind this guard. Bounded, not a new failure: an accountless subject already
            // dead-ended downstream in both flows (browser SSO's find_default_project_id, device
            // pairing's issue_device_tokens); this refuses earlier and leaves nothing behind.
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
                    // The adopted account was deleted between this method's own SELECT above and
                    // this INSERT -- the same "no lightbridge account" outcome as the early-return
                    // refusal above, just discovered a few microseconds later.
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

    /// Read-side counterpart to [`Self::upsert_federated_identity`], and the reason it was
    /// written ahead of a caller: its consumer arrived as RP-initiated logout's back-channel leg
    /// (`KeycloakRelyingParty::end_upstream_session`), which needs the sealed token set to
    /// terminate the upstream Keycloak SSO session. Still not wired to any RPC surface -- nothing
    /// exposes a federated identity to a client.
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

    /// The by-`account_id` twin of [`Self::find_federated_identity`] (which looks up by the
    /// `(issuer, subject)` federation key instead). Exists because several human-plane token-
    /// minting paths -- `oauth2_op::store::TokenExchangeOpStore::mint_from_authorization_code`
    /// (the browser flow) and `issue_device_tokens` -- only ever have the ADR-0025-resolved
    /// ACCOUNT id in hand at mint time, never the raw upstream `(issuer, subject)` pair: the
    /// authorization code's stored identity carries `external_id = account_id`, not the Keycloak
    /// subject (see `authorize.rs::issue_code`'s own doc comment). `account_id` is a safe lookup
    /// key here because `federated_identities_account_uidx` (ADR-0024 Q1) already enforces at
    /// most one federated identity may ever hold a given `account_id`, so this can never return
    /// more than one candidate row to begin with.
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
