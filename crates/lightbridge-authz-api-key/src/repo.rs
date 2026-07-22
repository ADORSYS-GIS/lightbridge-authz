use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, ApiKeyValidation, CreateAccount, CreateProject, DefaultLimits,
    Project, ResolvedContext, ResourceStatus, UpdateAccount, UpdateApiKey, UpdateProject,
};
use serde_json::Value;
use sqlx::{Executor, PgPool, Postgres, Transaction};
use tracing::instrument;

use crate::entities::account_row::AccountWithMembersRow;
use crate::entities::api_key_row::{ApiKeyChangeset, ApiKeyRow};
use crate::entities::api_key_validation_row::ApiKeyValidationRow;
use crate::entities::exchange_refresh_token_row::{
    ExchangeRefreshTokenRow, NewExchangeRefreshToken,
};
use crate::entities::new_account_row::NewAccountRow;
use crate::entities::new_api_key_row::NewApiKeyRow;
use crate::entities::new_project_row::NewProjectRow;
use crate::entities::project_row::{ProjectChangeset, ProjectRow};
use crate::entities::signing_key_row::{NewSigningKey, SigningKeyRow};

#[derive(Debug, Clone)]
pub struct StoreRepo {
    pub pool: Arc<dyn DbPoolTrait>,
}

impl StoreRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    fn vec_to_json(values: &Option<Vec<String>>) -> Value {
        match values {
            Some(v) => serde_json::json!(v),
            None => Value::Null,
        }
    }

    fn json_to_vec(value: &Option<Value>) -> Option<Vec<String>> {
        value.as_ref().and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
            }
        })
    }

    fn limits_to_json(limits: &Option<DefaultLimits>) -> Value {
        match limits {
            Some(l) => serde_json::to_value(l).unwrap_or_else(|_| serde_json::json!({})),
            None => serde_json::json!({}),
        }
    }

    fn json_to_limits(value: &Value) -> Option<DefaultLimits> {
        if value.is_null() {
            None
        } else {
            serde_json::from_value(value.clone()).ok()
        }
    }

    fn to_account(row: AccountWithMembersRow) -> Account {
        Account {
            id: row.id,
            billing_identity: row.billing_identity,
            owners_admins: row.owners_admins,
            status: ResourceStatus::from(row.status),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    fn normalize_members(mut members: Vec<String>, subject: &str) -> Vec<String> {
        if !members.iter().any(|owner| owner == subject) {
            members.push(subject.to_string());
        }
        members.sort_unstable();
        members.dedup();
        members
    }

    async fn upsert_account_memberships<'e, E>(
        &self,
        account_id: &str,
        members: &[String],
        executor: E,
    ) -> Result<()>
    where
        E: Executor<'e, Database = Postgres>,
    {
        if members.is_empty() {
            return Ok(());
        }
        sqlx::query(
            r#"
            INSERT INTO account_memberships (account_id, subject)
            SELECT $1, member
            FROM unnest($2::text[]) AS member
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(account_id)
        .bind(members)
        .execute(executor)
        .await?;
        Ok(())
    }

    async fn delete_account_memberships_not_in<'e, E>(
        &self,
        account_id: &str,
        members: &[String],
        executor: E,
    ) -> Result<()>
    where
        E: Executor<'e, Database = Postgres>,
    {
        if members.is_empty() {
            return Ok(());
        }
        sqlx::query(
            r#"
            DELETE FROM account_memberships
            WHERE account_id = $1
              AND NOT (subject = ANY($2::text[]))
            "#,
        )
        .bind(account_id)
        .bind(members)
        .execute(executor)
        .await?;
        Ok(())
    }

    async fn load_account_with_members_row(
        &self,
        account_id: &str,
    ) -> Result<AccountWithMembersRow> {
        let row = self
            .load_account_with_members_row_optional(account_id)
            .await?;
        row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)
    }

    async fn load_account_with_members_row_optional(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountWithMembersRow>> {
        let row = sqlx::query_as::<_, AccountWithMembersRow>(
            r#"
            SELECT
              accounts.id,
              accounts.billing_identity,
              COALESCE(array_agg(account_memberships.subject ORDER BY account_memberships.subject), '{}'::text[]) AS owners_admins,
              accounts.status,
              accounts.created_at,
              accounts.updated_at
            FROM accounts
            LEFT JOIN account_memberships ON accounts.id = account_memberships.account_id
            WHERE accounts.id = $1
            GROUP BY accounts.id
            "#,
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    async fn load_account_with_members_row_for_subject(
        &self,
        account_id: &str,
        subject: &str,
    ) -> Result<Option<AccountWithMembersRow>> {
        let row = sqlx::query_as::<_, AccountWithMembersRow>(
            r#"
            SELECT
              accounts.id,
              accounts.billing_identity,
              COALESCE(array_agg(account_memberships.subject ORDER BY account_memberships.subject), '{}'::text[]) AS owners_admins,
              accounts.status,
              accounts.created_at,
              accounts.updated_at
            FROM accounts
            LEFT JOIN account_memberships ON accounts.id = account_memberships.account_id
            WHERE accounts.id = $1
              AND EXISTS (
                SELECT 1
                FROM account_memberships AS auth
                WHERE auth.account_id = accounts.id
                  AND auth.subject = $2
              )
            GROUP BY accounts.id
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    fn to_project(row: ProjectRow) -> Project {
        Project {
            id: row.id,
            account_id: row.account_id,
            name: row.name,
            allowed_models: Self::json_to_vec(&row.allowed_models),
            default_limits: Self::json_to_limits(&row.default_limits),
            billing_plan: row.billing_plan,
            status: ResourceStatus::from(row.status),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    fn to_api_key(row: ApiKeyRow) -> ApiKey {
        ApiKey {
            id: row.id,
            project_id: row.project_id,
            name: row.name,
            key_prefix: row.key_prefix,
            key_hash: row.key_hash,
            created_at: row.created_at,
            expires_at: row.expires_at,
            status: ApiKeyStatus::from(row.status),
            last_used_at: row.last_used_at,
            last_ip: row.last_ip,
            revoked_at: row.revoked_at,
            billing_plan: row.billing_plan,
            updated_at: row.updated_at,
        }
    }

    #[instrument(skip(self))]
    pub async fn create_account(
        &self,
        subject: &str,
        input: CreateAccount,
        id: String,
    ) -> Result<Account> {
        let now = Utc::now();
        let members = Self::normalize_members(Vec::new(), subject);
        let new_account = NewAccountRow {
            id: id.clone(),
            billing_identity: input.billing_identity,
            created_at: now,
            updated_at: now,
        };

        let mut tx: Transaction<'_, Postgres> = self.pool().begin().await?;
        sqlx::query(
            r#"
            INSERT INTO accounts (id, billing_identity, created_at, updated_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(new_account.id.clone())
        .bind(new_account.billing_identity.clone())
        .bind(new_account.created_at)
        .bind(new_account.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return lightbridge_authz_core::error::Error::Conflict(format!(
                    "Account with billing identity '{}' already exists",
                    new_account.billing_identity
                ));
            }
            e.into()
        })?;

        self.upsert_account_memberships(&new_account.id, &members, &mut *tx)
            .await?;
        tx.commit().await?;

        let account = self.load_account_with_members_row(&new_account.id).await?;
        Ok(Self::to_account(account))
    }

    #[instrument(skip(self))]
    pub async fn list_accounts(
        &self,
        subject: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Account>> {
        let rows: Vec<AccountWithMembersRow> = sqlx::query_as(
            r#"
            SELECT
              accounts.id,
              accounts.billing_identity,
              COALESCE(array_agg(account_memberships.subject ORDER BY account_memberships.subject), '{}'::text[]) AS owners_admins,
              accounts.status,
              accounts.created_at,
              accounts.updated_at
            FROM accounts
            LEFT JOIN account_memberships ON accounts.id = account_memberships.account_id
            WHERE EXISTS (
                SELECT 1
                FROM account_memberships AS auth
                WHERE auth.account_id = accounts.id
                  AND auth.subject = $1
            )
            GROUP BY accounts.id
            ORDER BY accounts.created_at ASC
            LIMIT $2
            OFFSET $3
            "#,
        )
        .bind(subject)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_account).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>> {
        let row = self
            .load_account_with_members_row_for_subject(account_id, subject)
            .await?;
        Ok(row.map(Self::to_account))
    }

    #[instrument(skip(self))]
    pub async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>> {
        let row = self
            .load_account_with_members_row_optional(account_id)
            .await?;
        Ok(row.map(Self::to_account))
    }

    #[instrument(skip(self))]
    pub async fn update_account(
        &self,
        subject: &str,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account> {
        let mut tx: Transaction<'_, Postgres> = self.pool().begin().await?;
        let now = Utc::now();
        let update_result = sqlx::query(
            r#"
            WITH authorized AS (
                SELECT account_id
                FROM account_memberships
                WHERE account_id = $1
                  AND subject = $2
            )
            UPDATE accounts
            SET
              billing_identity = COALESCE($3, billing_identity),
              updated_at = $4
            FROM authorized
            WHERE accounts.id = authorized.account_id
            RETURNING accounts.id
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .bind(input.billing_identity)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        if update_result.is_none() {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }

        if let Some(owners) = input.owners_admins {
            let members = Self::normalize_members(owners, subject);
            self.upsert_account_memberships(account_id, &members, &mut *tx)
                .await?;
            self.delete_account_memberships_not_in(account_id, &members, &mut *tx)
                .await?;
        }

        tx.commit().await?;

        let row = self.load_account_with_members_row(account_id).await?;
        Ok(Self::to_account(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_account(&self, subject: &str, account_id: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM accounts
            WHERE id = $1
              AND EXISTS (
                SELECT 1
                FROM account_memberships AS auth
                WHERE auth.account_id = accounts.id
                  AND auth.subject = $2
              )
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }
        Ok(())
    }

    /// Add `new_member` to `account_id`, authorised by `subject` already being a member. Idempotent
    /// (re-adding an existing member is a no-op). A non-member acting subject or unknown account is
    /// a uniform `NotFound`, mirroring the rest of the membership-scoped repo surface.
    #[instrument(skip(self))]
    pub async fn add_account_member(
        &self,
        subject: &str,
        account_id: &str,
        new_member: &str,
    ) -> Result<Account> {
        if new_member.trim().is_empty() {
            return Err(lightbridge_authz_core::error::Error::BadRequest(
                "member subject must not be empty".to_string(),
            ));
        }

        let authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM account_memberships
                WHERE account_id = $1 AND subject = $2
            )
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .fetch_one(self.pool())
        .await?;
        if !authorized {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }

        sqlx::query(
            r#"
            INSERT INTO account_memberships (account_id, subject)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(account_id)
        .bind(new_member)
        .execute(self.pool())
        .await?;

        let row = self.load_account_with_members_row(account_id).await?;
        Ok(Self::to_account(row))
    }

    /// Remove `member` from `account_id`, authorised by `subject` being a member. Refuses to remove
    /// the last remaining member (that would trigger `prune_account_without_memberships` and delete
    /// the account — use `delete_account` for that intent). Removing a non-member is a no-op.
    ///
    /// Runs in a transaction that takes `SELECT ... FOR UPDATE` on the account row, serialising
    /// concurrent membership mutations so the last-member guard is race-free: two concurrent removes
    /// cannot both pass the count check and drop the account to zero members.
    #[instrument(skip(self))]
    pub async fn remove_account_member(
        &self,
        subject: &str,
        account_id: &str,
        member: &str,
    ) -> Result<Account> {
        let mut tx: Transaction<'_, Postgres> = self.pool().begin().await?;

        let account_exists: Option<String> =
            sqlx::query_scalar(r#"SELECT id FROM accounts WHERE id = $1 FOR UPDATE"#)
                .bind(account_id)
                .fetch_optional(&mut *tx)
                .await?;
        if account_exists.is_none() {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }

        let authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM account_memberships
                WHERE account_id = $1 AND subject = $2
            )
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .fetch_one(&mut *tx)
        .await?;
        if !authorized {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }

        let member_count: i64 =
            sqlx::query_scalar(r#"SELECT count(*) FROM account_memberships WHERE account_id = $1"#)
                .bind(account_id)
                .fetch_one(&mut *tx)
                .await?;
        let removing_existing_member: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM account_memberships
                WHERE account_id = $1 AND subject = $2
            )
            "#,
        )
        .bind(account_id)
        .bind(member)
        .fetch_one(&mut *tx)
        .await?;
        if removing_existing_member && member_count <= 1 {
            return Err(lightbridge_authz_core::error::Error::Conflict(
                "cannot remove the last member of an account".to_string(),
            ));
        }

        sqlx::query(r#"DELETE FROM account_memberships WHERE account_id = $1 AND subject = $2"#)
            .bind(account_id)
            .bind(member)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        let row = self.load_account_with_members_row(account_id).await?;
        Ok(Self::to_account(row))
    }

    #[instrument(skip(self))]
    pub async fn create_project(
        &self,
        subject: &str,
        account_id: &str,
        input: CreateProject,
        id: String,
    ) -> Result<Project> {
        let now = Utc::now();
        let new_project = NewProjectRow {
            id,
            account_id: account_id.to_string(),
            name: input.name,
            allowed_models: Some(Self::vec_to_json(&input.allowed_models)),
            default_limits: Self::limits_to_json(&input.default_limits),
            billing_plan: input.billing_plan,
            created_at: now,
            updated_at: now,
        };
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            WITH account_auth AS (
                SELECT account_id
                FROM account_memberships
                WHERE account_id = $1
                  AND subject = $2
            )
            INSERT INTO projects (
              id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
            )
            SELECT $3, account_auth.account_id, $4, $5, $6, $7, $8, $9
            FROM account_auth
            RETURNING id, account_id, name, allowed_models, default_limits, billing_plan, status, created_at, updated_at
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .bind(new_project.id)
        .bind(new_project.name)
        .bind(new_project.allowed_models)
        .bind(new_project.default_limits)
        .bind(new_project.billing_plan)
        .bind(new_project.created_at)
        .bind(new_project.updated_at)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self, subject))]
    pub async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<ResolvedContext> {
        let row: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT projects.account_id, projects.id AS project_id
            FROM projects
            JOIN account_memberships ON account_memberships.account_id = projects.account_id
            WHERE projects.id = $1
              AND account_memberships.subject = $2
            "#,
        )
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let (account_id, project_id) =
            row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(ResolvedContext {
            account_id,
            project_id,
        })
    }

    pub async fn create_exchange_refresh_token(
        &self,
        input: NewExchangeRefreshToken,
    ) -> Result<ExchangeRefreshTokenRow> {
        let row: ExchangeRefreshTokenRow = sqlx::query_as(
            r#"
            INSERT INTO exchange_refresh_tokens
              (id, subject, account_id, project_id, token_hash, scope, status, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8)
            RETURNING id, subject, account_id, project_id, token_hash, scope, status, created_at, expires_at, last_used_at
            "#,
        )
        .bind(input.id)
        .bind(input.subject)
        .bind(input.account_id)
        .bind(input.project_id)
        .bind(input.token_hash)
        .bind(input.scope)
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
            SELECT id, subject, account_id, project_id, token_hash, scope, status, created_at, expires_at, last_used_at
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

    /// Atomically consumes a refresh token (single-use rotation): under a row lock, flips the
    /// presented token to `rotated` and inserts a successor that copies the session context
    /// (subject/account/project/scope), returning the successor. Returns `None` if the presented
    /// token is no longer active/live (already used, revoked, expired) so the caller can reject
    /// replay. Copying context inside the transaction keeps rotation race-safe without the caller
    /// needing a separate lookup.
    pub async fn rotate_exchange_refresh_token(
        &self,
        presented_hash: &str,
        new_id: &str,
        new_token_hash: &str,
        new_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Option<ExchangeRefreshTokenRow>> {
        let mut tx = self.pool().begin().await?;
        let existing: Option<ExchangeRefreshTokenRow> = sqlx::query_as(
            r#"
            SELECT id, subject, account_id, project_id, token_hash, scope, status, created_at, expires_at, last_used_at
            FROM exchange_refresh_tokens
            WHERE token_hash = $1
              AND status = 'active'
              AND expires_at > $2
            FOR UPDATE
            "#,
        )
        .bind(presented_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(existing) = existing else {
            tx.rollback().await?;
            return Ok(None);
        };

        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'rotated', last_used_at = $2
            WHERE id = $1
            "#,
        )
        .bind(&existing.id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        let inserted: ExchangeRefreshTokenRow = sqlx::query_as(
            r#"
            INSERT INTO exchange_refresh_tokens
              (id, subject, account_id, project_id, token_hash, scope, status, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8)
            RETURNING id, subject, account_id, project_id, token_hash, scope, status, created_at, expires_at, last_used_at
            "#,
        )
        .bind(new_id)
        .bind(&existing.subject)
        .bind(&existing.account_id)
        .bind(&existing.project_id)
        .bind(new_token_hash)
        .bind(&existing.scope)
        .bind(now)
        .bind(new_expires_at)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(inserted))
    }

    #[instrument(skip(self))]
    pub async fn list_projects(
        &self,
        subject: &str,
        account_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Project>> {
        let rows: Vec<ProjectRow> = sqlx::query_as(
            r#"
            SELECT
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.status,
              projects.created_at,
              projects.updated_at
            FROM projects
            WHERE projects.account_id = $1
              AND EXISTS (
                SELECT 1
                FROM account_memberships
                WHERE account_memberships.account_id = projects.account_id
                  AND account_memberships.subject = $2
              )
            ORDER BY projects.created_at ASC
            LIMIT $3
            OFFSET $4
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_project).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.status,
              projects.created_at,
              projects.updated_at
            FROM projects
            WHERE projects.id = $1
              AND EXISTS (
                SELECT 1
                FROM account_memberships
                WHERE account_memberships.account_id = projects.account_id
                  AND account_memberships.subject = $2
              )
            "#,
        )
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_project))
    }

    #[instrument(skip(self))]
    pub async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              id,
              account_id,
              name,
              allowed_models,
              default_limits,
              billing_plan,
              status,
              created_at,
              updated_at
            FROM projects
            WHERE id = $1
            "#,
        )
        .bind(project_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_project))
    }

    #[instrument(skip(self))]
    pub async fn update_project(
        &self,
        subject: &str,
        project_id: &str,
        input: UpdateProject,
    ) -> Result<Project> {
        let (allowed_models_supplied, allowed_models_value) = match input.allowed_models {
            Some(Some(models)) => (true, Some(serde_json::json!(models))),
            Some(None) => (true, None),
            None => (false, None),
        };
        let changes = ProjectChangeset {
            name: input.name,
            allowed_models: allowed_models_value.clone(),
            default_limits: input.default_limits.map(|l| Self::limits_to_json(&Some(l))),
            billing_plan: input.billing_plan,
            updated_at: Utc::now(),
        };
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            UPDATE projects
            SET
              name = COALESCE($1, name),
              allowed_models = CASE WHEN $2 THEN $3 ELSE allowed_models END,
              default_limits = COALESCE($4, default_limits),
              billing_plan = COALESCE($5, billing_plan),
              updated_at = $6
            FROM account_memberships
            WHERE projects.account_id = account_memberships.account_id
              AND projects.id = $7
              AND account_memberships.subject = $8
            RETURNING
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.status,
              projects.created_at,
              projects.updated_at
            "#,
        )
        .bind(changes.name)
        .bind(allowed_models_supplied)
        .bind(changes.allowed_models)
        .bind(changes.default_limits)
        .bind(changes.billing_plan)
        .bind(changes.updated_at)
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_project(&self, subject: &str, project_id: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM projects
            USING account_memberships
            WHERE projects.account_id = account_memberships.account_id
              AND projects.id = $1
              AND account_memberships.subject = $2
            "#,
        )
        .bind(project_id)
        .bind(subject)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn create_api_key(&self, subject: &str, input: NewApiKeyRow) -> Result<ApiKey> {
        let row: Option<ApiKeyRow> = sqlx::query_as(
            r#"
            WITH project_auth AS (
                SELECT projects.id AS project_id
                FROM projects
                JOIN account_memberships ON account_memberships.account_id = projects.account_id
                WHERE projects.id = $1
                  AND account_memberships.subject = $2
            )
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan
            )
            SELECT $3, project_auth.project_id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
            FROM project_auth
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(input.project_id)
        .bind(subject)
        .bind(input.id)
        .bind(input.name)
        .bind(input.key_prefix)
        .bind(input.key_hash)
        .bind(input.created_at)
        .bind(input.expires_at)
        .bind(input.status)
        .bind(input.last_used_at)
        .bind(input.last_ip)
        .bind(input.revoked_at)
        .bind(input.billing_plan)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn list_api_keys(
        &self,
        subject: &str,
        project_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>> {
        let rows: Vec<ApiKeyRow> = sqlx::query_as(
            r#"
            SELECT
              api_keys.id,
              api_keys.project_id,
              api_keys.name,
              api_keys.key_prefix,
              api_keys.key_hash,
              api_keys.created_at,
              api_keys.expires_at,
              api_keys.status,
              api_keys.last_used_at,
              api_keys.last_ip,
              api_keys.revoked_at,
              api_keys.billing_plan,
              api_keys.updated_at
            FROM api_keys
            JOIN projects ON projects.id = api_keys.project_id
            WHERE api_keys.project_id = $1
              AND EXISTS (
                SELECT 1
                FROM account_memberships
                WHERE account_memberships.account_id = projects.account_id
                  AND account_memberships.subject = $2
              )
            ORDER BY api_keys.created_at DESC
            LIMIT $3
            OFFSET $4
            "#,
        )
        .bind(project_id)
        .bind(subject)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_api_key).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_api_key(&self, subject: &str, key_id: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              api_keys.id,
              api_keys.project_id,
              api_keys.name,
              api_keys.key_prefix,
              api_keys.key_hash,
              api_keys.created_at,
              api_keys.expires_at,
              api_keys.status,
              api_keys.last_used_at,
              api_keys.last_ip,
              api_keys.revoked_at,
              api_keys.billing_plan,
              api_keys.updated_at
            FROM api_keys
            JOIN projects ON projects.id = api_keys.project_id
            WHERE api_keys.id = $1
              AND EXISTS (
                SELECT 1
                FROM account_memberships
                WHERE account_memberships.account_id = projects.account_id
                  AND account_memberships.subject = $2
              )
            "#,
        )
        .bind(key_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_api_key))
    }

    #[instrument(skip(self))]
    pub async fn update_api_key(
        &self,
        subject: &str,
        key_id: &str,
        input: UpdateApiKey,
    ) -> Result<ApiKey> {
        let changes = ApiKeyChangeset {
            name: input.name,
            expires_at: input.expires_at,
            status: None,
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        };
        let row: Option<ApiKeyRow> = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              name = COALESCE($1, api_keys.name),
              expires_at = COALESCE($2, api_keys.expires_at)
            FROM projects
            JOIN account_memberships ON account_memberships.account_id = projects.account_id
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $3
              AND account_memberships.subject = $4
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(changes.name)
        .bind(changes.expires_at)
        .bind(key_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn set_account_status(
        &self,
        subject: &str,
        account_id: &str,
        status: ResourceStatus,
    ) -> Result<Account> {
        let result = sqlx::query(
            r#"
            UPDATE accounts
            SET status = $1, updated_at = $2
            FROM account_memberships
            WHERE accounts.id = account_memberships.account_id
              AND accounts.id = $3
              AND account_memberships.subject = $4
            "#,
        )
        .bind(status.to_string())
        .bind(Utc::now())
        .bind(account_id)
        .bind(subject)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }
        let row = self.load_account_with_members_row(account_id).await?;
        Ok(Self::to_account(row))
    }

    #[instrument(skip(self))]
    pub async fn set_project_status(
        &self,
        subject: &str,
        project_id: &str,
        status: ResourceStatus,
    ) -> Result<Project> {
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            UPDATE projects
            SET status = $1, updated_at = $2
            FROM account_memberships
            WHERE projects.account_id = account_memberships.account_id
              AND projects.id = $3
              AND account_memberships.subject = $4
            RETURNING
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.status,
              projects.created_at,
              projects.updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(Utc::now())
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    /// Read the effective validity of an API key from the `api_key_validation` view (one indexed
    /// lookup by `key_hash`), with the account -> project -> key status cascade resolved by the DB.
    #[instrument(skip(self, key_hash))]
    pub async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<ApiKeyValidation>> {
        let row: Option<ApiKeyValidationRow> = sqlx::query_as(
            r#"
            SELECT
              api_key_id,
              key_hash,
              project_id,
              account_id,
              api_key_status,
              project_status,
              account_status,
              expires_at,
              effective_status
            FROM api_key_validation
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|row| ApiKeyValidation {
            api_key_id: row.api_key_id,
            key_hash: row.key_hash,
            project_id: row.project_id,
            account_id: row.account_id,
            api_key_status: row.api_key_status,
            project_status: row.project_status,
            account_status: row.account_status,
            expires_at: row.expires_at,
            effective_status: row.effective_status,
        }))
    }

    #[instrument(skip(self))]
    pub async fn set_api_key_status(
        &self,
        subject: &str,
        key_id: &str,
        status: ApiKeyStatus,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey> {
        let row: Option<ApiKeyRow> = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              status = $1,
              revoked_at = COALESCE($2, revoked_at),
              expires_at = COALESCE($3, expires_at)
            FROM projects
            JOIN account_memberships ON account_memberships.account_id = projects.account_id
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $4
              AND account_memberships.subject = $5
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(revoked_at)
        .bind(expires_at)
        .bind(key_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn rotate_api_key_transaction(
        &self,
        subject: &str,
        key_id: &str,
        status: ApiKeyStatus,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
        new_key: NewApiKeyRow,
    ) -> Result<ApiKey> {
        let mut tx = self.pool().begin().await?;
        let existing_update = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            UPDATE api_keys
            SET
              status = $1,
              revoked_at = COALESCE($2, revoked_at),
              expires_at = COALESCE($3, expires_at)
            FROM projects
            JOIN account_memberships ON account_memberships.account_id = projects.account_id
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $4
              AND account_memberships.subject = $5
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(revoked_at)
        .bind(expires_at)
        .bind(key_id)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await?;
        existing_update.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        let new_row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            WITH project_auth AS (
                SELECT projects.id AS project_id
                FROM projects
                JOIN account_memberships ON account_memberships.account_id = projects.account_id
                WHERE projects.id = $1
                  AND account_memberships.subject = $2
            )
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan
            )
            SELECT $3, project_auth.project_id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
            FROM project_auth
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at, api_keys.billing_plan, api_keys.updated_at
            "#,
        )
        .bind(new_key.project_id)
        .bind(subject)
        .bind(new_key.id)
        .bind(new_key.name)
        .bind(new_key.key_prefix)
        .bind(new_key.key_hash)
        .bind(new_key.created_at)
        .bind(new_key.expires_at)
        .bind(new_key.status)
        .bind(new_key.last_used_at)
        .bind(new_key.last_ip)
        .bind(new_key.revoked_at)
        .bind(new_key.billing_plan)
        .fetch_optional(&mut *tx)
        .await?;
        let row = new_row.ok_or_else(|| lightbridge_authz_core::error::Error::NotFound)?;
        tx.commit().await?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_api_key(&self, subject: &str, key_id: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM api_keys
            USING projects, account_memberships
            WHERE api_keys.project_id = projects.id
              AND projects.account_id = account_memberships.account_id
              AND api_keys.id = $1
              AND account_memberships.subject = $2
            "#,
        )
        .bind(key_id)
        .bind(subject)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self, key_hash))]
    pub async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, updated_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_api_key))
    }

    #[instrument(skip(self))]
    pub async fn record_api_key_usage(
        &self,
        key_id: &str,
        last_ip: Option<String>,
    ) -> Result<ApiKey> {
        let changes = ApiKeyChangeset {
            name: None,
            expires_at: None,
            status: None,
            last_used_at: Some(Utc::now()),
            last_ip,
            revoked_at: None,
        };
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              last_used_at = $1,
              last_ip = $2
            WHERE id = $3
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, updated_at
            "#,
        )
        .bind(changes.last_used_at)
        .bind(changes.last_ip)
        .bind(key_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn get_active_signing_key(&self) -> Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SigningKeyRow>(
            r#"
            SELECT kid, algorithm, private_key_pem, public_jwk, status, created_at, retired_at
            FROM signing_keys
            WHERE status = 'active'
            LIMIT 1
            "#,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    #[instrument(skip(self))]
    pub async fn list_verification_jwks(&self) -> Result<Vec<Value>> {
        let rows: Vec<(Value,)> = sqlx::query_as(
            r#"
            SELECT public_jwk
            FROM signing_keys
            ORDER BY status = 'active' DESC, created_at DESC
            "#,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|(jwk,)| jwk).collect())
    }

    /// Idempotently ensures there is an active signing key, rotating (marking the current
    /// active stale + activating `candidate`) when it is missing or older than `max_age_cutoff`.
    /// A transaction-scoped advisory lock serializes this across replicas so only one key wins.
    #[instrument(skip(self, candidate))]
    pub async fn ensure_active_signing_key(
        &self,
        candidate: NewSigningKey,
        max_age_cutoff: DateTime<Utc>,
    ) -> Result<SigningKeyRow> {
        const SIGNING_KEY_LOCK: i64 = 0x5369_676E_4B65_7973;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(SIGNING_KEY_LOCK)
            .execute(&mut *tx)
            .await?;

        let active: Option<SigningKeyRow> = sqlx::query_as(
            r#"
            SELECT kid, algorithm, private_key_pem, public_jwk, status, created_at, retired_at
            FROM signing_keys
            WHERE status = 'active'
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let needs_rotation = match &active {
            None => true,
            Some(current) => current.created_at <= max_age_cutoff,
        };

        if !needs_rotation {
            let current = active.expect("active key present when no rotation needed");
            tx.commit().await?;
            return Ok(current);
        }

        if let Some(current) = &active {
            sqlx::query(
                r#"
                UPDATE signing_keys
                SET status = 'stale', retired_at = $2
                WHERE kid = $1
                "#,
            )
            .bind(&current.kid)
            .bind(candidate.created_at)
            .execute(&mut *tx)
            .await?;
        }

        let inserted: SigningKeyRow = sqlx::query_as(
            r#"
            INSERT INTO signing_keys (kid, algorithm, private_key_pem, public_jwk, status, created_at)
            VALUES ($1, $2, $3, $4, 'active', $5)
            RETURNING kid, algorithm, private_key_pem, public_jwk, status, created_at, retired_at
            "#,
        )
        .bind(candidate.kid)
        .bind(candidate.algorithm)
        .bind(candidate.private_key_pem)
        .bind(candidate.public_jwk)
        .bind(candidate.created_at)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(inserted)
    }
}
