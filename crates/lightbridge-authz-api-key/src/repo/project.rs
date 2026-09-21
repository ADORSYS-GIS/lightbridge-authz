use chrono::Utc;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateProject, Project, ResourceStatus, UpdateProject};
use sqlx::{Postgres, Transaction};
use tracing::instrument;

use crate::entities::new_project_row::NewProjectRow;
use crate::entities::project_row::{ProjectChangeset, ProjectRow};
use crate::repo::StoreRepo;

impl StoreRepo {
    #[instrument(skip(self))]
    pub async fn create_project(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
        input: CreateProject,
        id: String,
    ) -> Result<Project> {
        let now = Utc::now();
        let new_project = NewProjectRow {
            id,
            account_id: account_id.to_string(),
            name: input.name,
            allowed_models: Self::vec_to_json(&input.allowed_models),
            default_limits: Self::limits_to_json(&input.default_limits),
            billing_plan: input.billing_plan,
            billing_identity: input.billing_identity,
            project_quota: input.project_quota,
            created_at: now,
            updated_at: now,
        };
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            WITH account_auth AS (
                SELECT id AS account_id
                FROM accounts
                WHERE id = $1
                  AND user_id = (SELECT user_id FROM accounts WHERE id = $2)
            )
            INSERT INTO projects (
              id, account_id, name, allowed_models, default_limits, billing_plan, billing_identity,
              project_quota, created_at, updated_at
            )
            SELECT $3, account_auth.account_id, $4, $5, $6, $7, $8, $9, $10, $11
            FROM account_auth
            RETURNING id, account_id, name, allowed_models, default_limits, billing_plan,
              billing_identity, project_quota, status, is_default, model_policy, created_at,
              updated_at
            "#,
        )
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .bind(new_project.id)
        .bind(new_project.name)
        .bind(new_project.allowed_models)
        .bind(new_project.default_limits)
        .bind(new_project.billing_plan)
        .bind(new_project.billing_identity.clone())
        .bind(new_project.project_quota)
        .bind(new_project.created_at)
        .bind(new_project.updated_at)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict(format!(
                    "a project with billing identity '{}' already exists",
                    new_project.billing_identity
                ));
            }
            Error::from(e)
        })?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self, account_id))]
    pub async fn find_default_project_id(&self, account_id: &AccountId) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT id
            FROM projects
            WHERE account_id = $1
              AND is_default = true
            "#,
        )
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|(id,)| id))
    }

    #[instrument(skip(self))]
    pub async fn list_projects(
        &self,
        acting_account_id: &AccountId,
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
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
              projects.created_at,
              projects.updated_at
            FROM projects
            WHERE projects.account_id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            ORDER BY projects.created_at ASC
            LIMIT $3
            OFFSET $4
            "#,
        )
        .bind(account_id)
        .bind(acting_account_id.as_str())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_project).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_project(
        &self,
        account_id: &AccountId,
        project_id: &str,
    ) -> Result<Option<Project>> {
        let row = sqlx::query_as(
            r#"
            SELECT
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
              projects.created_at,
              projects.updated_at
            FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
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
              billing_identity,
              project_quota,
              status,
              is_default,
              model_policy,
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
        account_id: &AccountId,
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
            WHERE projects.id = $7
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $8)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $8
                )
              )
            RETURNING
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
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
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn delete_project(&self, account_id: &AccountId, project_id: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn set_project_status(
        &self,
        account_id: &AccountId,
        project_id: &str,
        status: ResourceStatus,
    ) -> Result<Project> {
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            UPDATE projects
            SET status = $1, updated_at = $2
            WHERE projects.id = $3
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $4)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $4
                )
              )
            RETURNING
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
              projects.created_at,
              projects.updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(Utc::now())
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn set_project_quota(
        &self,
        account_id: &AccountId,
        project_id: &str,
        project_quota: Option<&str>,
    ) -> Result<Project> {
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            UPDATE projects
            SET project_quota = $1, updated_at = $2
            WHERE projects.id = $3
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $4)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $4
                )
              )
            RETURNING
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
              projects.created_at,
              projects.updated_at
            "#,
        )
        .bind(project_quota)
        .bind(Utc::now())
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn set_project_allowed_models(
        &self,
        account_id: &AccountId,
        project_id: &str,
        allowed_models: Option<Vec<String>>,
    ) -> Result<Project> {
        let allowed_models_json = Self::vec_to_json(&allowed_models);
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            UPDATE projects
            SET allowed_models = $1, updated_at = $2
            WHERE projects.id = $3
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $4)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $4
                )
              )
            RETURNING
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
              projects.created_at,
              projects.updated_at
            "#,
        )
        .bind(allowed_models_json)
        .bind(Utc::now())
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_project(row))
    }

    /// Sets `Project.modelPolicy` (ADR-0018 Decision 5 follow-up, #415's own tracked next step).
    /// Backs `AuthzStoreImpl::set_project_model_policy` -- `model_policy` is validated to be one of
    /// the three canonical wire strings there (`ModelPolicy::parse_strict`) before this method is
    /// ever called, so `model_policy` here is trusted input, same layering as `set_project_quota`/
    /// `set_project_allowed_models` above.
    ///
    /// Runs in a transaction, unlike the two setters immediately above, because this method also
    /// enforces a business rule this repo's owner decided is a refusal, not a warning or a
    /// silent allow (see the schema doc comment on `setProjectModelPolicy` for the full
    /// reasoning): switching to `allowlist` while `allowed_models` is empty/absent would silently
    /// deny every model -- a lockout by configuration, the same class of footgun ADR-0018 Decision
    /// 5 already closed for a typo'd model id. That check needs to read the row's *current*
    /// `allowed_models` under lock (`FOR UPDATE`) so a concurrent `set_project_allowed_models` call
    /// racing this one cannot slip an empty list past the guard between the check and the write --
    /// same transactional-invariant shape as `set_default_project` below, just guarding a business
    /// rule instead of the "at most one default project" structural invariant.
    pub async fn set_project_model_policy(
        &self,
        account_id: &AccountId,
        project_id: &str,
        model_policy: &str,
    ) -> Result<Project> {
        let mut tx: Transaction<'_, Postgres> = self.pool().begin().await?;

        let current: Option<ProjectRow> = sqlx::query_as(
            r#"
            SELECT
              projects.id,
              projects.account_id,
              projects.name,
              projects.allowed_models,
              projects.default_limits,
              projects.billing_plan,
              projects.billing_identity,
              projects.project_quota,
              projects.status,
              projects.is_default,
              projects.model_policy,
              projects.created_at,
              projects.updated_at
            FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            FOR UPDATE
            "#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let current = current.ok_or(Error::NotFound)?;
        let current = Self::to_project(current);

        if model_policy == "allowlist"
            && current
                .allowed_models
                .as_deref()
                .is_none_or(<[String]>::is_empty)
        {
            return Err(Error::BadRequest(
                "cannot set modelPolicy to 'allowlist' while allowedModels is empty -- this would \
                 silently deny every model; populate allowedModels via setProjectAllowedModels \
                 first, or use 'deny_all' if blocking every model is actually intended"
                    .to_string(),
            ));
        }

        let row: ProjectRow = sqlx::query_as(
            r#"
            UPDATE projects
            SET model_policy = $1, updated_at = $2
            WHERE id = $3
            RETURNING
              id,
              account_id,
              name,
              allowed_models,
              default_limits,
              billing_plan,
              billing_identity,
              project_quota,
              status,
              is_default,
              model_policy,
              created_at,
              updated_at
            "#,
        )
        .bind(model_policy)
        .bind(Utc::now())
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Self::to_project(row))
    }

    #[instrument(skip(self))]
    pub async fn set_default_project(
        &self,
        acting_account_id: &AccountId,
        project_id: &str,
    ) -> Result<Project> {
        let mut tx: Transaction<'_, Postgres> = self.pool().begin().await?;

        let account_id: Option<String> = sqlx::query_scalar(
            r#"
            SELECT projects.account_id
            FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id IN (
                  SELECT owned.id FROM accounts owned
                  WHERE owned.user_id = (SELECT user_id FROM accounts WHERE id = $2)
                )
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(acting_account_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let account_id = account_id.ok_or(Error::NotFound)?;

        sqlx::query(
            r#"
            UPDATE projects
            SET is_default = false, updated_at = $1
            WHERE account_id = $2 AND is_default = true AND id != $3
            "#,
        )
        .bind(Utc::now())
        .bind(&account_id)
        .bind(project_id)
        .execute(&mut *tx)
        .await?;

        let row: ProjectRow = sqlx::query_as(
            r#"
            UPDATE projects SET is_default = true, updated_at = $1
            WHERE id = $2
            RETURNING id, account_id, name, allowed_models, default_limits, billing_plan,
              billing_identity, project_quota, status, is_default, model_policy, created_at,
              updated_at
            "#,
        )
        .bind(Utc::now())
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Self::to_project(row))
    }
}
