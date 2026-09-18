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

        let existing_owner: Option<(String,)> =
            sqlx::query_as("SELECT user_id FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(acting_account_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;

        let (new_id, owner_user_id) = match existing_owner {
            None => (acting_account_id.as_str().to_string(), None),
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
                    Some("23505") => {
                        return Error::Conflict(
                            "account already exists for this subject".to_string(),
                        );
                    }
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

    /// The admin-targets-an-arbitrary-subject account bootstrap (#720).
    #[instrument(skip(self))]
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

    /// Lists every account the caller OWNS (ADR-0026).
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

    /// Reads one account the caller OWNS.
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

    /// Permanently delete `account_id`.
    #[instrument(skip(self))]
    pub async fn delete_account(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
    ) -> Result<Account> {
        let mut tx = self.pool().begin().await?;

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

    /// Suspend/resume an account.
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

    /// Updates `Account.defaultQuota` (#379).
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

    /// Sets `Account.name`.
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
