use std::sync::Arc;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::OptionalExtension;
use diesel_async::RunQueryDsl;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, CreateAccount, CreateProject, Project, UpdateAccount,
    UpdateApiKey, UpdateProject,
};
use serde_json::Value;

use crate::entities::account_row::{AccountChangeset, AccountRow};
use crate::entities::api_key_row::{ApiKeyChangeset, ApiKeyRow};
use crate::entities::new_account_row::NewAccountRow;
use crate::entities::new_api_key_row::NewApiKeyRow;
use crate::entities::new_project_row::NewProjectRow;
use crate::entities::project_row::{ProjectChangeset, ProjectRow};
use crate::entities::schema::{accounts, api_keys, projects};

#[derive(Debug, Clone)]
pub struct StoreRepo {
    pub pool: Arc<dyn DbPoolTrait>,
}

impl StoreRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn vec_to_json(values: &[String]) -> Value {
        serde_json::json!(values)
    }

    fn json_to_vec(value: &Value) -> Vec<String> {
        value
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn to_account(row: AccountRow) -> Account {
        Account {
            id: row.id,
            billing_identity: row.billing_identity,
            owners_admins: Self::json_to_vec(&row.owners_admins),
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
            last_region: row.last_region,
            revoked_at: row.revoked_at,
        }
    }

    pub async fn create_account(&self, input: CreateAccount, id: String) -> Result<Account> {
        let mut conn = self.pool.get().await?;
        let now = Utc::now();
        let new_account = NewAccountRow {
            id,
            billing_identity: input.billing_identity,
            owners_admins: Self::vec_to_json(&input.owners_admins),
            created_at: now,
            updated_at: now,
        };

        let row: AccountRow = diesel::insert_into(accounts::table)
            .values(&new_account)
            .get_result(&mut conn)
            .await?;

        Ok(Self::to_account(row))
    }

    pub async fn list_accounts(&self) -> Result<Vec<Account>> {
        let mut conn = self.pool.get().await?;
        let rows: Vec<AccountRow> = accounts::table
            .order(accounts::created_at.asc())
            .load(&mut conn)
            .await?;
        Ok(rows.into_iter().map(Self::to_account).collect())
    }

    pub async fn get_account(&self, account_id: &str) -> Result<Option<Account>> {
        let mut conn = self.pool.get().await?;
        let row = accounts::table
            .filter(accounts::id.eq(account_id))
            .first::<AccountRow>(&mut conn)
            .await
            .optional()?;
        Ok(row.map(Self::to_account))
    }

    pub async fn update_account(
        &self,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account> {
        let mut conn = self.pool.get().await?;
        let changes = AccountChangeset {
            billing_identity: input.billing_identity,
            owners_admins: input.owners_admins.map(|v| Self::vec_to_json(&v)),
            updated_at: Utc::now(),
        };
        let row: AccountRow = diesel::update(accounts::table.filter(accounts::id.eq(account_id)))
            .set(changes)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_account(row))
    }

    pub async fn delete_account(&self, account_id: &str) -> Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::delete(accounts::table.filter(accounts::id.eq(account_id)))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn create_project(
        &self,
        account_id: &str,
        input: CreateProject,
        id: String,
    ) -> Result<Project> {
        let mut conn = self.pool.get().await?;
        let now = Utc::now();
        let new_project = NewProjectRow {
            id,
            account_id: account_id.to_string(),
            name: input.name,
            allowed_models: Self::vec_to_json(&input.allowed_models),
            default_limits: input.default_limits,
            billing_plan: input.billing_plan,
            created_at: now,
            updated_at: now,
        };
        let row: ProjectRow = diesel::insert_into(projects::table)
            .values(new_project)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_project(row))
    }

    pub async fn list_projects(&self, account_id: &str) -> Result<Vec<Project>> {
        let mut conn = self.pool.get().await?;
        let rows: Vec<ProjectRow> = projects::table
            .filter(projects::account_id.eq(account_id))
            .order(projects::created_at.asc())
            .load(&mut conn)
            .await?;
        Ok(rows.into_iter().map(Self::to_project).collect())
    }

    pub async fn get_project(&self, project_id: &str) -> Result<Option<Project>> {
        let mut conn = self.pool.get().await?;
        let row = projects::table
            .filter(projects::id.eq(project_id))
            .first::<ProjectRow>(&mut conn)
            .await
            .optional()?;
        Ok(row.map(Self::to_project))
    }

    pub async fn update_project(
        &self,
        project_id: &str,
        input: UpdateProject,
    ) -> Result<Project> {
        let mut conn = self.pool.get().await?;
        let changes = ProjectChangeset {
            name: input.name,
            allowed_models: input.allowed_models.map(|v| Self::vec_to_json(&v)),
            default_limits: input.default_limits,
            billing_plan: input.billing_plan,
            updated_at: Utc::now(),
        };
        let row: ProjectRow = diesel::update(projects::table.filter(projects::id.eq(project_id)))
            .set(changes)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_project(row))
    }

    pub async fn delete_project(&self, project_id: &str) -> Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::delete(projects::table.filter(projects::id.eq(project_id)))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn create_api_key(&self, input: NewApiKeyRow) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;
        let row: ApiKeyRow = diesel::insert_into(api_keys::table)
            .values(input)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_api_key(row))
    }

    pub async fn list_api_keys(&self, project_id: &str) -> Result<Vec<ApiKey>> {
        let mut conn = self.pool.get().await?;
        let rows: Vec<ApiKeyRow> = api_keys::table
            .filter(api_keys::project_id.eq(project_id))
            .order(api_keys::created_at.desc())
            .load(&mut conn)
            .await?;
        Ok(rows.into_iter().map(Self::to_api_key).collect())
    }

    pub async fn get_api_key(&self, key_id: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.pool.get().await?;
        let row = api_keys::table
            .filter(api_keys::id.eq(key_id))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()?;
        Ok(row.map(Self::to_api_key))
    }

    pub async fn update_api_key(&self, key_id: &str, input: UpdateApiKey) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;
        let changes = ApiKeyChangeset {
            name: input.name,
            expires_at: input.expires_at,
            status: None,
            last_used_at: None,
            last_ip: None,
            last_region: None,
            revoked_at: None,
        };
        let row: ApiKeyRow = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(changes)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_api_key(row))
    }

    pub async fn set_api_key_status(
        &self,
        key_id: &str,
        status: ApiKeyStatus,
        revoked_at: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;
        let changes = ApiKeyChangeset {
            name: None,
            expires_at,
            status: Some(status.to_string()),
            last_used_at: None,
            last_ip: None,
            last_region: None,
            revoked_at,
        };
        let row: ApiKeyRow = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(changes)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_api_key(row))
    }

    pub async fn delete_api_key(&self, key_id: &str) -> Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::delete(api_keys::table.filter(api_keys::id.eq(key_id)))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.pool.get().await?;
        let row = api_keys::table
            .filter(api_keys::key_hash.eq(key_hash))
            .first::<ApiKeyRow>(&mut conn)
            .await
            .optional()?;
        Ok(row.map(Self::to_api_key))
    }

    pub async fn record_api_key_usage(
        &self,
        key_id: &str,
        last_ip: Option<String>,
        last_region: Option<String>,
    ) -> Result<ApiKey> {
        let mut conn = self.pool.get().await?;
        let changes = ApiKeyChangeset {
            name: None,
            expires_at: None,
            status: None,
            last_used_at: Some(Utc::now()),
            last_ip,
            last_region,
            revoked_at: None,
        };
        let row: ApiKeyRow = diesel::update(api_keys::table.filter(api_keys::id.eq(key_id)))
            .set(changes)
            .get_result(&mut conn)
            .await?;
        Ok(Self::to_api_key(row))
    }
}
