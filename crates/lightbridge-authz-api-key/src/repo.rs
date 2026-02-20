use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, CreateAccount, CreateProject, Project, UpdateAccount,
    UpdateApiKey, UpdateProject,
};
use serde_json::Value;
use sqlx::PgPool;
use tracing::instrument;

use crate::entities::account_row::{AccountChangeset, AccountRow};
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

    fn to_account(row: AccountRow) -> Account {
        Account {
            id: row.id,
            billing_identity: row.billing_identity,
            owners_admins: Self::json_to_vec(&Some(row.owners_admins)).unwrap_or_default(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    fn to_project(row: ProjectRow) -> Project {
        Project {
            id: row.id,
            account_id: row.account_id,
            name: row.name,
            allowed_models: Self::json_to_vec(&row.allowed_models),
            default_limits: row.default_limits,
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
    pub async fn create_account(&self, input: CreateAccount, id: String) -> Result<Account> {
        let now = Utc::now();
        let new_account = NewAccountRow {
            id,
            billing_identity: input.billing_identity,
            owners_admins: Self::vec_to_json(&Some(input.owners_admins)),
            created_at: now,
            updated_at: now,
        };

        let row: AccountRow = sqlx::query_as(
            r#"
            INSERT INTO accounts (id, billing_identity, owners_admins, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, billing_identity, owners_admins, created_at, updated_at
            "#,
        )
        .bind(new_account.id)
        .bind(new_account.billing_identity.clone())
        .bind(new_account.owners_admins)
        .bind(new_account.created_at)
        .bind(new_account.updated_at)
        .fetch_one(self.pool())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.code().as_deref() == Some("23505") {
                    return lightbridge_authz_core::error::Error::Conflict(format!(
                        "Account with billing identity '{}' already exists",
                        new_account.billing_identity
                    ));
                }
            }
            e.into()
        })?;

        Ok(Self::to_account(row))
    }

    #[instrument(skip(self))]
    pub async fn list_accounts(&self) -> Result<Vec<Account>> {
        let rows: Vec<AccountRow> = sqlx::query_as(
            r#"
            SELECT id, billing_identity, owners_admins, created_at, updated_at
            FROM accounts
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_account).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_account(&self, account_id: &str) -> Result<Option<Account>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, billing_identity, owners_admins, created_at, updated_at
            FROM accounts
            WHERE id = $1
            "#,
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_account))
    }

    #[instrument(skip(self))]
    pub async fn update_account(&self, account_id: &str, input: UpdateAccount) -> Result<Account> {
        let changes = AccountChangeset {
            billing_identity: input.billing_identity,
            owners_admins: input.owners_admins.map(|v| Self::vec_to_json(&Some(v))),
            updated_at: Utc::now(),
        };

        let row: AccountRow = sqlx::query_as(
            r#"
            UPDATE accounts
            SET
              billing_identity = COALESCE($1, billing_identity),
              owners_admins = COALESCE($2, owners_admins),
              updated_at = $3
            WHERE id = $4
            RETURNING id, billing_identity, owners_admins, created_at, updated_at
            "#,
        )
        .bind(changes.billing_identity)
        .bind(changes.owners_admins)
        .bind(changes.updated_at)
        .bind(account_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_account(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_account(&self, account_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn create_project(
        &self,
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
            default_limits: input.default_limits,
            billing_plan: input.billing_plan,
            created_at: now,
            updated_at: now,
        };
        let row: ProjectRow = sqlx::query_as(
            r#"
            INSERT INTO projects (
              id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
            "#,
        )
        .bind(new_project.id)
        .bind(new_project.account_id)
        .bind(new_project.name)
        .bind(new_project.allowed_models)
        .bind(new_project.default_limits)
        .bind(new_project.billing_plan)
        .bind(new_project.created_at)
        .bind(new_project.updated_at)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn list_projects(&self, account_id: &str) -> Result<Vec<Project>> {
        let rows: Vec<ProjectRow> = sqlx::query_as(
            r#"
            SELECT id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
            FROM projects
            WHERE account_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_project).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_project(&self, project_id: &str) -> Result<Option<Project>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
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
    pub async fn update_project(&self, project_id: &str, input: UpdateProject) -> Result<Project> {
        let changes = ProjectChangeset {
            name: input.name,
            allowed_models: input.allowed_models.map(|v| Self::vec_to_json(&v)),
            default_limits: input.default_limits,
            billing_plan: input.billing_plan,
            updated_at: Utc::now(),
        };
        let row: ProjectRow = sqlx::query_as(
            r#"
            UPDATE projects
            SET
              name = COALESCE($1, name),
              allowed_models = COALESCE($2, allowed_models),
              default_limits = COALESCE($3, default_limits),
              billing_plan = COALESCE($4, billing_plan),
              updated_at = $5
            WHERE id = $6
            RETURNING id, account_id, name, allowed_models, default_limits, billing_plan, created_at, updated_at
            "#,
        )
        .bind(changes.name)
        .bind(changes.allowed_models)
        .bind(changes.default_limits)
        .bind(changes.billing_plan)
        .bind(changes.updated_at)
        .bind(project_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_project(&self, project_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn create_api_key(&self, input: NewApiKeyRow) -> Result<ApiKey> {
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at
            "#,
        )
        .bind(input.id)
        .bind(input.project_id)
        .bind(input.name)
        .bind(input.key_prefix)
        .bind(input.key_hash)
        .bind(input.created_at)
        .bind(input.expires_at)
        .bind(input.status)
        .bind(input.last_used_at)
        .bind(input.last_ip)
        .bind(input.revoked_at)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn list_api_keys(&self, project_id: &str) -> Result<Vec<ApiKey>> {
        let rows: Vec<ApiKeyRow> = sqlx::query_as(
            r#"
            SELECT
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at
            FROM api_keys
            WHERE project_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_api_key).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_api_key(&self, key_id: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(key_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_api_key))
    }

    #[instrument(skip(self))]
    pub async fn update_api_key(&self, key_id: &str, input: UpdateApiKey) -> Result<ApiKey> {
        let changes = ApiKeyChangeset {
            name: input.name,
            expires_at: input.expires_at,
            status: None,
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
        };
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              name = COALESCE($1, name),
              expires_at = COALESCE($2, expires_at)
            WHERE id = $3
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at
            "#,
        )
        .bind(changes.name)
        .bind(changes.expires_at)
        .bind(key_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn set_api_key_status(
        &self,
        key_id: &str,
        status: ApiKeyStatus,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey> {
        let changes = ApiKeyChangeset {
            name: None,
            expires_at,
            status: Some(status.to_string()),
            last_used_at: None,
            last_ip: None,
            revoked_at,
        };
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            UPDATE api_keys
            SET
              status = $1,
              revoked_at = COALESCE($2, revoked_at),
              expires_at = COALESCE($3, expires_at)
            WHERE id = $4
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at
            "#,
        )
        .bind(changes.status)
        .bind(changes.revoked_at)
        .bind(changes.expires_at)
        .bind(key_id)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_api_key(&self, key_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(key_id)
            .execute(self.pool())
            .await?;
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
