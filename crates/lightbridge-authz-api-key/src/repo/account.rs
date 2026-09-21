use chrono::Utc;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{Account, CreateAccount, ResourceStatus, UpdateAccount};
use tracing::instrument;

use crate::entities::account_row::AccountRow;
use crate::entities::new_account_row::NewAccountRow;
use crate::repo::StoreRepo;

impl StoreRepo {
    /// Creates an account owned by the caller. ADR-0026: an identity may hold SEVERAL, so this is
    /// no longer "the account IS the subject" and a second call is no longer a `Conflict`.
    ///
    /// Which id the new account gets is decided here, and the rule is not arbitrary:
    ///
    /// * **The identity's FIRST account keeps `id = subject`.** That account is the identity's
    ///   ANCHOR -- `federated_identities` adopts an account by matching `accounts.id == subject`
    ///   (`resolve_account_for_federated_subject_detailed`), and it is the only account
    ///   `auth().id` is ever set to. Minting a CUID2 here instead would break adoption for every
    ///   brand-new signup: the grandfather lookup would find nothing, the resolver would fall
    ///   through to ADR-0025's `NoAccount` bootstrap arm forever, and the person's own account
    ///   would be invisible to them. ADR-0025 Stage 5 anticipated this and required
    ///   `createAccount` to write the adopting `federated_identities` row itself; keeping
    ///   `id = subject` for the anchor achieves the same end without this method needing the
    ///   issuer, and without a second account ever being able to adopt the identity (which
    ///   `federated_identities_account_uidx` forbids, ADR-0026 D6).
    /// * **Every subsequent account gets a minted CUID2** (ADR-0039, via the one chokepoint) and
    ///   INHERITS the owner's existing `user_id`. It anchors no identity; it is a pure owned
    ///   tenant.
    ///
    /// The consequence both branches preserve, and which the `@@allow` clauses in
    /// `authz.cstack` depend on: **`accounts.user_id` is always the owner's home-account id**,
    /// i.e. always `auth().id`. See that file's "LOAD-BEARING INVARIANT" block on `Account.userId`.
    ///
    /// One transaction, because the owner lookup and the insert must not interleave with a
    /// concurrent first-account bootstrap for the same identity.
    #[instrument(skip(self))]
    pub async fn create_account(
        &self,
        acting_account_id: &AccountId,
        input: CreateAccount,
    ) -> Result<Account> {
        let now = Utc::now();
        let mut tx = self.pool().begin().await?;

        // The acting account is the caller's home account (or nothing at all, if this identity is
        // bootstrapping its very first one). `FOR UPDATE` serializes two concurrent creates by the
        // same person so they cannot both read "no owner yet" and both try to claim the anchor.
        let existing_owner: Option<(String,)> =
            sqlx::query_as("SELECT user_id FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(acting_account_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;

        let (new_id, owner_user_id) = match existing_owner {
            // Bootstrap: the anchor. `user_id` stays NULL so the `accounts_set_user` trigger
            // provisions it (and the `users` row) exactly as it always has.
            None => (acting_account_id.as_str().to_string(), None),
            // Second and subsequent: minted id, inherited owner.
            Some((user_id,)) => (cuid2(), Some(user_id)),
        };

        let new_account = NewAccountRow {
            id: new_id,
            default_quota: input.default_quota,
            name: input.name,
            created_at: now,
            updated_at: now,
        };

        sqlx::query(
            r#"
            INSERT INTO accounts (id, user_id, default_quota, name, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(new_account.id.clone())
        .bind(owner_user_id)
        .bind(new_account.default_quota.clone())
        .bind(new_account.name.clone())
        .bind(new_account.created_at)
        .bind(new_account.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                match db_err.code().as_deref() {
                    // Two concurrent bootstraps for the same identity raced for the anchor id.
                    // Still a `Conflict`, and still the ONLY way this method produces one -- an
                    // ordinary second account can no longer collide, since its id is minted.
                    Some("23505") => {
                        return Error::Conflict(
                            "account already exists for this subject".to_string(),
                        );
                    }
                    // `user_id` referenced a `users` row that vanished, i.e. the acting account was
                    // deleted between this transaction's own SELECT and this INSERT. Same meaning,
                    // and the same error, as `upsert_federated_identity`'s 23503 arm: "this subject
                    // has no lightbridge account right now."
                    Some("23503") => {
                        return Error::Forbidden("acting account no longer exists".to_string());
                    }
                    _ => {}
                }
            }
            Error::from(e)
        })?;

        let account: AccountRow = sqlx::query_as(
            r#"
            SELECT id, default_quota, status, name, user_id, created_at, updated_at
            FROM accounts
            WHERE id = $1
            "#,
        )
        .bind(&new_account.id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Self::to_account(account))
    }

    /// The admin-targets-an-arbitrary-subject account bootstrap (#720). Unlike [`Self::create_account`]
    /// above, `subject` is operator-supplied, not the caller's own identity -- this exists because
    /// a Keycloak-authenticated subject with no `accounts` row can never complete `authz-idp`'s
    /// `/idp/callback` (ADR-0024's 2026-08-25 correction removed the old mint-on-login branch), and
    /// ADR-0025's `NoAccount` self-service bootstrap fallback is unreachable in production (`authz-api`'s
    /// bearer middleware there validates against `authz-idp`'s own JWKS, not Keycloak's). Before this
    /// method existed, the only remedy was a manual SQL `INSERT` against production.
    ///
    /// Always mints the subject's ANCHOR account (`id = subject`, never a minted CUID2) -- this
    /// procedure only ever creates the FIRST account for a subject, so unlike `create_account`'s
    /// ADR-0026 "several accounts per identity" contract, a second call for the same subject is
    /// `Error::Conflict`, not a new row.
    ///
    /// Also creates the account's mandatory default `projects` row in the SAME transaction: an
    /// account with no `is_default` project still dead-ends the browser SSO callback one step later
    /// (`find_default_project_id`, `crates/lightbridge-authz-rest/src/relying_party.rs`), so
    /// provisioning the account alone would not actually unblock sign-in. `email` becomes that
    /// project's `billing_identity` (globally unique via `idx_projects_billing_identity`); a
    /// collision is `Error::Conflict`, and -- since both inserts share one transaction -- never a
    /// partial write (an orphaned account with no default project).
    ///
    /// `user_id` is left unbound on the `accounts` insert so `accounts_set_user`'s `BEFORE INSERT`
    /// trigger provisions the `users` row and sets `user_id := id`, exactly as `create_account`'s
    /// own bootstrap branch does. `projects.is_default` is likewise left for
    /// `projects_set_is_default`'s `BEFORE INSERT` trigger to compute -- `true` here, since this is
    /// the account's first (and, until a caller adds more via `model.Project.create`, only) project.
    pub async fn provision_account(
        &self,
        subject: &AccountId,
        email: &str,
        name: Option<&str>,
    ) -> Result<Account> {
        let now = Utc::now();
        let mut tx = self.pool().begin().await?;

        sqlx::query(
            r#"
            INSERT INTO accounts (id, name, created_at, updated_at)
            VALUES ($1, $2, $3, $3)
            "#,
        )
        .bind(subject.as_str())
        .bind(name)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict("account already exists for this subject".to_string());
            }
            Error::from(e)
        })?;

        sqlx::query(
            r#"
            INSERT INTO projects (id, account_id, name, billing_plan, billing_identity, created_at, updated_at)
            VALUES ($1, $2, 'Default Project', 'free', $3, $4, $4)
            "#,
        )
        .bind(cuid2())
        .bind(subject.as_str())
        .bind(email)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict(format!(
                    "a project with billing identity '{email}' already exists"
                ));
            }
            Error::from(e)
        })?;

        let account: AccountRow = sqlx::query_as(
            r#"
            SELECT id, default_quota, status, name, user_id, created_at, updated_at
            FROM accounts
            WHERE id = $1
            "#,
        )
        .bind(subject.as_str())
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Self::to_account(account))
    }

    /// Lists every account the caller OWNS (ADR-0026), not just the one that IS them.
    ///
    /// The owner is derived rather than passed: `accounts.user_id` is always the owner's
    /// home-account id, and `acting_account_id` is always that home account, so the correlated
    /// subquery is an indexed PK lookup that reads "everyone owned by the same person as me".
    /// Deriving it here rather than threading a `UserId` down from the ingress keeps the seam in
    /// one place and means an acting account that does not exist (a bootstrapping identity)
    /// yields `user_id = NULL`, which matches no row -- fail-closed, an empty list, never a
    /// wildcard.
    ///
    /// `ORDER BY created_at` (never by id -- ADR-0039: CUID2 has no ordering) is covered by
    /// `idx_accounts_user_id_created_at`.
    #[instrument(skip(self))]
    pub async fn list_accounts(
        &self,
        acting_account_id: &AccountId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Account>> {
        let rows: Vec<AccountRow> = sqlx::query_as(
            r#"
            SELECT id, default_quota, status, name, user_id, created_at, updated_at
            FROM accounts
            WHERE user_id = (SELECT user_id FROM accounts WHERE id = $1)
            ORDER BY created_at ASC
            LIMIT $2
            OFFSET $3
            "#,
        )
        .bind(acting_account_id.as_str())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_account).collect())
    }

    /// Reads one account the caller OWNS. Was `WHERE id = $1 AND id = $2` ("the target must BE
    /// me"); ADR-0026 makes it "the target must be owned by the same person as me", via the same
    /// derived-owner subquery as [`Self::list_accounts`]. A target the caller does not own is
    /// `None`, exactly as before -- not an error, and indistinguishable from a target that does
    /// not exist, so this never becomes an account-existence oracle.
    #[instrument(skip(self))]
    pub async fn get_account(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
    ) -> Result<Option<Account>> {
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT id, default_quota, status, name, user_id, created_at, updated_at
            FROM accounts
            WHERE id = $1
              AND user_id = (SELECT user_id FROM accounts WHERE id = $2)
            "#,
        )
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_account))
    }

    #[instrument(skip(self))]
    pub async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>> {
        let row = self.load_account_row_optional(account_id).await?;
        Ok(row.map(Self::to_account))
    }

    #[instrument(skip(self))]
    pub async fn update_account(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account> {
        let now = Utc::now();
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET default_quota = COALESCE($1, default_quota), updated_at = $2
            WHERE id = $3
              AND user_id = (SELECT user_id FROM accounts WHERE id = $4)
            RETURNING id, default_quota, status, name, user_id, created_at, updated_at
            "#,
        )
        .bind(input.default_quota)
        .bind(now)
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
    }

    /// Permanently delete `account_id` (cascades to projects, their api-keys, and their
    /// `project_members` rows via the existing `ON DELETE CASCADE` foreign keys). Per ADR-0006
    /// there is no more owner/role concept to gate this with -- one account is one person, so the
    /// authorization collapses to "the caller is this account" (`id = subject`), enforced directly
    /// in the `WHERE` clause rather than a separate role lookup. The removed default-account
    /// undeletable guard (`accounts.is_default`) no longer applies -- that column and the whole
    /// default-*account* feature were dropped outright (ADR-0006 decision 2); only
    /// `projects.is_default` (default-*project*) survives, and it is enforced on `Project`, not
    /// here.
    pub async fn delete_account(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
    ) -> Result<Account> {
        let mut tx = self.pool().begin().await?;

        // Ownership, plus one thing the WHERE clause alone must not decide silently. ADR-0026 lets
        // a person own several accounts, and exactly one of them is the HOME account -- the
        // identity's anchor, the row `federated_identities` adopted by matching
        // `accounts.id == subject`, and the only id `auth().id` is ever set to.
        //
        // Deleting the anchor while other accounts are still owned would ORPHAN them: the
        // `federated_identities` row cascades away with it, the next login resolves through
        // ADR-0025's bootstrap fallback to a subject with no `accounts` row, and
        // `user_id = (SELECT user_id FROM accounts WHERE id = $subject)` then yields NULL -- so the
        // surviving accounts match nothing and become permanently unreachable, with their projects
        // and keys still live. Refuse it explicitly; a `WHERE` clause that just failed to match
        // would surface as `NotFound` and read like the account did not exist.
        //
        // Deleting the home account when it is the ONLY one is untouched, pre-ADR-0026 behaviour.
        let target: Option<(bool, bool)> = sqlx::query_as(
            r#"
            SELECT
                (a.id = a.user_id) AS is_home,
                EXISTS (
                    SELECT 1 FROM accounts o
                    WHERE o.user_id = a.user_id AND o.id <> a.id
                ) AS has_siblings
            FROM accounts a
            WHERE a.id = $1
              AND a.user_id = (SELECT user_id FROM accounts WHERE id = $2)
            FOR UPDATE
            "#,
        )
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;

        match target {
            None => return Err(Error::NotFound),
            Some((true, true)) => {
                return Err(Error::BadRequest(
                    "cannot delete your primary account while you still own others; delete or \
                     transfer them first"
                        .to_string(),
                ));
            }
            Some(_) => {}
        }

        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            DELETE FROM accounts
            WHERE id = $1
            RETURNING id, default_quota, status, name, user_id, created_at, updated_at
            "#,
        )
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        tx.commit().await?;
        Ok(Self::to_account(row))
    }

    /// Suspend/resume an account. Per ADR-0006 there is no more owner/admin role to gate this with
    /// -- one account is one person, so authorization collapses to "the caller is this account"
    /// (`id = subject`), enforced directly in the `WHERE` clause. Replaces the deleted
    /// `member_role`-based owner-or-admin check.
    #[instrument(skip(self))]
    pub async fn set_account_status(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
        status: ResourceStatus,
    ) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET status = $1, updated_at = $2
            WHERE id = $3
              AND user_id = (SELECT user_id FROM accounts WHERE id = $4)
            RETURNING id, default_quota, status, name, user_id, created_at, updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(Utc::now())
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
    }

    /// Updates `Account.defaultQuota` (#379, completing #177/#375). Backs
    /// `updateAccountDefaultQuota` -- the sole write path left now that `Account.defaultQuota` is
    /// `@readonly` on the generic `model.Account.update` verb. Same authorization shape as
    /// `set_account_status`: since ADR-0006 there is no owner/role concept left, so "the caller is
    /// this account" (`id = account_id = subject`) is the entire check, enforced in the `WHERE`
    /// clause -- a mismatched `account_id`/`subject` pair or an unknown account is `NotFound`. The
    /// tier value itself is NOT validated against the operator-configured quota-tier catalogue
    /// here -- same layering as `create_account`/`set_project_member_quota_tier`: that check
    /// happens in `AuthzStoreImpl::update_account_default_quota`, before this method is ever
    /// called, so an empty/absent catalogue transparently accepts any value with no special casing
    /// needed here.
    #[instrument(skip(self))]
    pub async fn update_account_default_quota(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
        default_quota: Option<&str>,
    ) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET default_quota = $1, updated_at = $2
            WHERE id = $3
              AND user_id = (SELECT user_id FROM accounts WHERE id = $4)
            RETURNING id, default_quota, status, name, user_id, created_at, updated_at
            "#,
        )
        .bind(default_quota)
        .bind(Utc::now())
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
    }

    /// Sets `Account.name`. Backs `updateAccountName` -- the sole write path for that column, since
    /// `model.Account.update` does not exist (#398) and the field is `@readonly` in the schema.
    /// Authorization is identical to [`Self::update_account_default_quota`] directly above: since
    /// ADR-0006 there is no owner/role concept left, so "the caller is this account"
    /// (`id = account_id = subject`) is the entire check and it lives in the `WHERE` clause -- a
    /// mismatched `account_id`/`subject` pair and an unknown account are the same `NotFound`, so
    /// this cannot be used to probe which accounts exist.
    ///
    /// `name` is free text with no catalogue to validate against, but it MUST already be
    /// normalised (blank/whitespace-only collapsed to `None`) by
    /// `AuthzStoreImpl::update_account_name` before it reaches here -- same layering as the
    /// quota-tier checks -- so the DB `CHECK (name IS NULL OR btrim(name) <> '')` never fires from
    /// this path. Passing `None` clears the name back to unnamed; this is a set, not a PATCH.
    #[instrument(skip(self))]
    pub async fn update_account_name(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
        name: Option<&str>,
    ) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET name = $1, updated_at = $2
            WHERE id = $3
              AND user_id = (SELECT user_id FROM accounts WHERE id = $4)
            RETURNING id, default_quota, status, name, user_id, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(Utc::now())
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
    }
}
