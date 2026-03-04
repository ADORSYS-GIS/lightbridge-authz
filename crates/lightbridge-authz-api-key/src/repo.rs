use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, CreateAccount, CreateProject, DefaultLimits, Project,
    UpdateAccount, UpdateApiKey, UpdateProject,
};
use serde_json::Value;
use sqlx::{Executor, PgPool, Postgres, Transaction};
use tracing::instrument;

use crate::entities::account_row::AccountWithMembersRow;
use crate::entities::api_key_row::{ApiKeyChangeset, ApiKeyRow};
use crate::entities::new_account_row::NewAccountRow;
use crate::entities::new_api_key_row::NewApiKeyRow;
use crate::entities::new_project_row::NewProjectRow;
use crate::entities::project_row::{ProjectChangeset, ProjectRow};

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
            RETURNING id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
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
              last_used_at, last_ip, revoked_at
            )
            SELECT $3, project_auth.project_id, $4, $5, $6, $7, $8, $9, $10, $11, $12
            FROM project_auth
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at
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
              api_keys.revoked_at
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
              api_keys.revoked_at
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
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at
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
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at
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
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at
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
              last_used_at, last_ip, revoked_at
            )
            SELECT $3, project_auth.project_id, $4, $5, $6, $7, $8, $9, $10, $11, $12
            FROM project_auth
            RETURNING
              api_keys.id, api_keys.project_id, api_keys.name, api_keys.key_prefix, api_keys.key_hash, api_keys.created_at, api_keys.expires_at, api_keys.status,
              api_keys.last_used_at, api_keys.last_ip, api_keys.revoked_at
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
              last_used_at, last_ip, revoked_at
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
              last_used_at, last_ip, revoked_at
            "#,
        )
        .bind(changes.last_used_at)
        .bind(changes.last_ip)
        .bind(key_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }
}
