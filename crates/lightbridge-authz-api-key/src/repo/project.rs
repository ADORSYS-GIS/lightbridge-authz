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
    /// Creation stays account-owner-only (`account.id == auth().id`, per the schema's
    /// `@@allow("create", ...)` on `Project`) -- not the broader "owner or any project member" rule
    /// the mechanical rescoping below applies to read/update/delete, since a project's own roster
    /// can't authorize creating a *different* project under someone else's account. `billing_identity`
    /// and `project_quota` are now caller-supplied per ADR-0006 (billing identity moved here from
    /// `Account`); a duplicate `billing_identity` hits `idx_projects_billing_identity` and is
    /// surfaced as `Conflict`, mirroring `create_account`'s 23505 handling.
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

    /// Resolves `subject`'s own auto-provisioned default project (`projects.is_default`), used by
    /// the native token-exchange grant (`oauth2_op::store::TokenExchangeOpStore::handle_token_exchange`)
    /// when the caller omits `project_id` -- a first-time caller has no way to know their project
    /// id yet. Since `accounts.id` IS the subject (ADR-0006), "subject's own default project" is
    /// exactly the project row with `account_id = subject AND is_default = true`; at most one such
    /// row can exist (`projects_account_id_default_uidx`, migration
    /// `20260725000001_default_account_project.sql`), so `fetch_optional` is unambiguous. Returns
    /// `None` when the account has zero projects yet -- a real, reachable state (account creation
    /// and the bootstrap "ensure default project" flow are two separate calls) -- callers must
    /// treat that identically to `resolve_context`'s own `NotFound`, not as a distinct error class,
    /// to preserve the same non-leaking behavior.
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

    /// Project-scoped rule (see the module-level mechanical rescoping this whole file follows):
    /// visible when `subject` owns the project's account OR holds ANY `project_members` row on it,
    /// matching the schema's `@@allow("read", account.id==auth().id || members.some.accountId==
    /// auth().id)` -- unlike `create_project`, any member (not just the owner) may list/read.
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

    /// Project-scoped rule, same visibility boundary as `list_projects`/`get_project` (owner or any
    /// member may update). `billing_identity`/`project_quota` are intentionally NOT part of this
    /// hand-written update path -- only `create_project` accepts them; changing a project's billing
    /// identity or pooled quota post-creation is out of this phase's scope (see the generic
    /// cratestack-generated `model.Project.update` verb for that, which reads the schema's own
    /// field-level policy independently of this method).
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

    /// Project-scoped rule, same visibility boundary as `list_projects`/`get_project`/
    /// `update_project` (owner or any member may delete) -- preserved unchanged from the
    /// pre-ADR-0006 behavior (any account member, of any role, could already delete a project; this
    /// method never enforced an owner-only or non-default restriction, unlike the generic
    /// cratestack-generated `model.Project.delete` verb's stricter `isDefault != true &&
    /// account.id == auth().id` schema policy, which is a separate code path this method does not
    /// back).
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

    /// Suspend/resume a project. Project-scoped rule -- the project's account owner or ANY
    /// `project_members` row authorizes this (not lead-gated), matching the cstack schema doc's
    /// `disableProject`/`enableProject` contract.
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

    /// Sets `Project.projectQuota` (#379, completing #177/#375). Backs `setProjectQuota` -- the
    /// sole write path left now that `Project.projectQuota` is `@readonly` on both generic
    /// `model.Project.create`/`.update` verbs. Project-scoped rule, same as `set_project_status`:
    /// the project's account owner or ANY `project_members` row authorizes this (not lead-gated,
    /// matching `model.Project.update`'s own dropped `@@allow` policy exactly rather than the
    /// lead-only roster procedures' narrower rule); a non-authorized subject or unknown project is
    /// `NotFound`. The tier value itself is NOT validated against the operator-configured
    /// quota-tier catalogue here -- same layering as `set_project_member_quota_tier`: that check
    /// happens in `AuthzStoreImpl::set_project_quota`, before this method is ever called.
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

    /// Project-scoped rule, identical to `set_project_quota` immediately above (owner or any
    /// roster member; a non-authorized subject or unknown project is `NotFound`). Backs
    /// `AuthzStoreImpl::set_project_allowed_models` (#415, ADR-0018 Decision 5). The catalogue
    /// check itself does NOT happen here -- same layering as `set_project_quota`: it happens in
    /// `AuthzStoreImpl::set_project_allowed_models`, before this method is ever called. `None` maps
    /// to SQL `NULL` (via `Self::vec_to_json`, the same mapping `create_project`/`update_project`
    /// already use) -- see that helper's own doc comment for why NULL, not jsonb `null`.
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

    /// Promote `project_id` to be its account's new default project, atomically demoting whichever
    /// project is currently default for that account. Relies on `projects_account_id_default_uidx`
    /// (a partial unique index on `(account_id) WHERE is_default`) to guarantee the invariant even
    /// under a race -- a concurrent reassignment targeting a different project for the same account
    /// fails the unset-then-set with a unique-violation instead of silently producing two defaults.
    /// Project-scoped rule, same as `set_project_status`: the project's account owner or ANY
    /// `project_members` row authorizes this; a non-authorized subject or unknown project is
    /// `NotFound`. (The deleted `set_default_account` had no such column left to reassign at all --
    /// ADR-0006 dropped `accounts.is_default` outright once one subject could only ever have one
    /// account, so "default account" stopped being a meaningful concept.)
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
