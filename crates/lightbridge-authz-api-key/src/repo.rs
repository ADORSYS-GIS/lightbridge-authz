use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, ApiKeyValidation, CreateAccount, CreateProject, DefaultLimits,
    ModelPolicy, Project, ProjectMember, ResolvedContext, ResourceStatus, UpdateAccount,
    UpdateApiKey, UpdateProject,
};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use tracing::instrument;

use crate::entities::account_row::AccountRow;
use crate::entities::api_key_row::{ApiKeyChangeset, ApiKeyRow};
use crate::entities::api_key_validation_row::ApiKeyValidationRow;
use crate::entities::exchange_refresh_token_row::{
    ExchangeRefreshTokenRow, NewExchangeRefreshToken,
};
use crate::entities::new_account_row::NewAccountRow;
use crate::entities::new_api_key_row::NewApiKeyRow;
use crate::entities::new_project_row::NewProjectRow;
use crate::entities::project_member_row::ProjectMemberRow;
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

    /// Map an optional model list to the value stored in `projects.allowed_models`. `None` maps to
    /// SQL `NULL` (bound as `Option::None`), NOT the jsonb `null` literal: cratestack's
    /// `allowedModels Json?` decode fails on `'null'::jsonb` (see migration
    /// `20260723000001_normalize_allowed_models_json_null`). Both SQL NULL and `[]` mean "all models
    /// allowed"; SQL NULL is the shape cratestack reads cleanly.
    fn vec_to_json(values: &Option<Vec<String>>) -> Option<Value> {
        values.as_ref().map(|v| serde_json::json!(v))
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

    fn to_account(row: AccountRow) -> Account {
        Account {
            id: row.id,
            default_quota: row.default_quota,
            status: ResourceStatus::from(row.status),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    /// The valid `project_members.role` values, matching the DB `CHECK` constraint
    /// (migrations/20260727000001_create_project_members.sql). Used to reject an invalid role
    /// early (`BadRequest`) instead of surfacing a raw constraint-violation error. Replaces the
    /// removed `validate_membership_role`/`VALID_MEMBERSHIP_ROLES` (ADR-0006 dropped the
    /// three-role `owner`/`admin`/`member` account scheme in favour of this two-role project one).
    const VALID_PROJECT_ROLES: [&'static str; 2] = ["lead", "member"];

    fn validate_project_role(role: &str) -> Result<()> {
        if Self::VALID_PROJECT_ROLES.contains(&role) {
            Ok(())
        } else {
            Err(Error::BadRequest(format!(
                "invalid project role '{role}', must be one of {:?}",
                Self::VALID_PROJECT_ROLES
            )))
        }
    }

    /// `subject`'s `role` on `project_id`'s roster, or `None` if they hold no `project_members` row
    /// there at all. Replaces the removed `member_role` (account-scoped); note this does NOT check
    /// the project's account owner -- callers that need to treat the owner as implicitly authorized
    /// (every lead-gated procedure does) go through `authorize_project_lead` instead, which layers
    /// that check on top of this one.
    ///
    /// `pub`: also read by `authz-opa`'s introspection handler (`OpaRepoTrait::project_member_role`)
    /// to resolve the `role` claim for a native RFC 8693 exchange session at introspection time,
    /// the human/OIDC-plane mirror of `project_member_quota_tier` below (ADR-0017's same
    /// reasoning applies here).
    #[instrument(skip(self, subject))]
    pub async fn project_member_role(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>> {
        let role: Option<String> = sqlx::query_scalar(
            r#"SELECT role FROM project_members WHERE project_id = $1 AND account_id = $2"#,
        )
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(role)
    }

    /// Authorizes a lead-gated roster mutation (`add_project_member`, `remove_project_member`,
    /// `set_project_member_role`, `set_project_member_quota_tier`) or lead-gated `create_api_key`:
    /// `subject` must be either the project's account owner (`projects.account_id = subject`) or
    /// hold a `project_members` row with `role = 'lead'` on `project_id`. There is no last-lead
    /// lockout to guard here (unlike the deleted `remove_account_member`/`set_account_member_role`'s
    /// last-owner guards) -- the account owner is always a standing alternate authority over the
    /// roster, so a project can never be left with nobody able to manage it the way an account
    /// could before ADR-0006 removed account-level membership entirely.
    ///
    /// Mirrors the deleted `add_account_member`'s NotFound/Forbidden split: a subject with no
    /// visibility into the project at all (not the owner, not on the roster in any role) gets
    /// `NotFound` so project existence isn't leaked; a subject who can see the project as a plain
    /// `member` but lacks lead standing gets `Forbidden`.
    async fn authorize_project_lead(&self, project_id: &str, subject: &str) -> Result<()> {
        let project_account_id: Option<String> =
            sqlx::query_scalar(r#"SELECT account_id FROM projects WHERE id = $1"#)
                .bind(project_id)
                .fetch_optional(self.pool())
                .await?;
        let Some(project_account_id) = project_account_id else {
            return Err(Error::NotFound);
        };
        if project_account_id == subject {
            return Ok(());
        }
        match self
            .project_member_role(project_id, subject)
            .await?
            .as_deref()
        {
            Some("lead") => Ok(()),
            Some(_) => Err(Error::Forbidden(
                "only the project's account owner or a lead can manage its roster".to_string(),
            )),
            None => Err(Error::NotFound),
        }
    }

    async fn load_account_row(&self, account_id: &str) -> Result<AccountRow> {
        let row = self.load_account_row_optional(account_id).await?;
        row.ok_or(Error::NotFound)
    }

    async fn load_account_row_optional(&self, account_id: &str) -> Result<Option<AccountRow>> {
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT id, default_quota, status, created_at, updated_at
            FROM accounts
            WHERE id = $1
            "#,
        )
        .bind(account_id)
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
            billing_identity: row.billing_identity,
            project_quota: row.project_quota,
            status: ResourceStatus::from(row.status),
            is_default: row.is_default,
            model_policy: ModelPolicy::from(row.model_policy),
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

    /// `id` **is** `subject` per ADR-0006 -- there is no more server-generated or caller-supplied
    /// account id, and no membership row to insert alongside it (one account = one person, no
    /// account-level membership of any kind). A second call for the same subject hits the `accounts`
    /// primary key and is surfaced as `Conflict`, matching the cstack schema doc's stated contract
    /// ("a second call for the same subject is `Error::Conflict`, not an upsert").
    #[instrument(skip(self))]
    pub async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account> {
        let now = Utc::now();
        let new_account = NewAccountRow {
            id: subject.to_string(),
            default_quota: input.default_quota,
            created_at: now,
            updated_at: now,
        };

        sqlx::query(
            r#"
            INSERT INTO accounts (id, default_quota, created_at, updated_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(new_account.id.clone())
        .bind(new_account.default_quota.clone())
        .bind(new_account.created_at)
        .bind(new_account.updated_at)
        .execute(self.pool())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict(format!("account already exists for subject '{subject}'"));
            }
            Error::from(e)
        })?;

        let account = self.load_account_row(&new_account.id).await?;
        Ok(Self::to_account(account))
    }

    /// Lists accounts visible to `subject`. Per ADR-0006 `accounts.id` IS the subject, so this
    /// returns at most the caller's own single account (there is no membership fan-out left to
    /// enumerate); kept as a list for API-shape compatibility with the generic `model.Account.list`
    /// verb it backs.
    #[instrument(skip(self))]
    pub async fn list_accounts(
        &self,
        subject: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Account>> {
        let rows: Vec<AccountRow> = sqlx::query_as(
            r#"
            SELECT id, default_quota, status, created_at, updated_at
            FROM accounts
            WHERE id = $1
            ORDER BY created_at ASC
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
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT id, default_quota, status, created_at, updated_at
            FROM accounts
            WHERE id = $1 AND id = $2
            "#,
        )
        .bind(account_id)
        .bind(subject)
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
        subject: &str,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account> {
        let now = Utc::now();
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET default_quota = COALESCE($1, default_quota), updated_at = $2
            WHERE id = $3 AND id = $4
            RETURNING id, default_quota, status, created_at, updated_at
            "#,
        )
        .bind(input.default_quota)
        .bind(now)
        .bind(account_id)
        .bind(subject)
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
    #[instrument(skip(self))]
    pub async fn delete_account(&self, subject: &str, account_id: &str) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            DELETE FROM accounts
            WHERE id = $1 AND id = $2
            RETURNING id, default_quota, status, created_at, updated_at
            "#,
        )
        .bind(account_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
    }

    /// Adds `target_account_id` to `project_id`'s roster with `role` (defaults to `"member"` when
    /// `None`, matching the schema's `AddProjectMemberInput.role` doc). Lead-gated via
    /// `authorize_project_lead`. Idempotent like the deleted `add_account_member`: re-adding an
    /// existing member is a no-op that leaves their current role untouched -- use
    /// `set_project_member_role` to change it.
    #[instrument(skip(self))]
    pub async fn add_project_member(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        role: Option<&str>,
    ) -> Result<Project> {
        let role = role.unwrap_or("member");
        Self::validate_project_role(role)?;
        self.authorize_project_lead(project_id, subject).await?;

        sqlx::query(
            r#"
            INSERT INTO project_members (project_id, account_id, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (project_id, account_id) DO NOTHING
            "#,
        )
        .bind(project_id)
        .bind(target_account_id)
        .bind(role)
        .execute(self.pool())
        .await?;

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

    /// Lists `project_id`'s roster. Backs `listProjectRoster`, the roster's only read path.
    ///
    /// Authorization is deliberately WIDER than the four mutations above: any member of the
    /// project may read it, plus the owning account. Leads are not privileged here -- knowing who
    /// you are working alongside is not a management capability, and gating it on `lead` would
    /// leave plain members unable to see the roster they are on. A caller with no standing at all
    /// gets `NotFound`, matching `authorize_project_lead`'s no-existence-leak contract rather than
    /// distinguishing "no such project" from "not yours".
    ///
    /// `id` is synthesised from the composite primary key. The real `project_members` table is
    /// keyed `(project_id, account_id)` and has no `id` column -- the schema's `ProjectMember.id`
    /// exists only because cratestack requires exactly one scalar `@id` -- so this is the one
    /// place that has to invent it, and it must stay stable for a given row because clients use
    /// it as a list key.
    #[instrument(skip(self))]
    pub async fn list_project_roster(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<Vec<ProjectMember>> {
        let project_account_id: Option<String> =
            sqlx::query_scalar(r#"SELECT account_id FROM projects WHERE id = $1"#)
                .bind(project_id)
                .fetch_optional(self.pool())
                .await?;
        let Some(project_account_id) = project_account_id else {
            return Err(Error::NotFound);
        };
        if project_account_id != subject
            && self
                .project_member_role(project_id, subject)
                .await?
                .is_none()
        {
            return Err(Error::NotFound);
        }

        let rows = sqlx::query_as::<_, ProjectMemberRow>(
            r#"
            SELECT project_id, account_id, role, quota_tier, created_at
            FROM project_members
            WHERE project_id = $1
            ORDER BY created_at ASC, account_id ASC
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool())
        .await?;

        Ok(rows.into_iter().map(ProjectMember::from).collect())
    }

    /// Removes `target_account_id` from `project_id`'s roster. Lead-gated via
    /// `authorize_project_lead`. Removing a non-member is a no-op (matches the deleted
    /// `remove_account_member`'s behavior for the analogous case). Unlike that method, there is no
    /// last-member/last-owner lockout to enforce: the project's account owner is always a standing
    /// alternate authority over the roster (see `authorize_project_lead`), so a project can never be
    /// left ownerless the way an account with zero memberships could before ADR-0006.
    #[instrument(skip(self))]
    pub async fn remove_project_member(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
    ) -> Result<Project> {
        self.authorize_project_lead(project_id, subject).await?;

        sqlx::query(r#"DELETE FROM project_members WHERE project_id = $1 AND account_id = $2"#)
            .bind(project_id)
            .bind(target_account_id)
            .execute(self.pool())
            .await?;

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

    /// Changes `target_account_id`'s role on `project_id`'s roster. Lead-gated via
    /// `authorize_project_lead`. `target_account_id` must already be on the roster (`NotFound`
    /// otherwise, distinct from `remove_project_member`'s no-op-on-non-member, since setting a role
    /// for a nonexistent membership row is meaningless rather than idempotent) -- mirrors the
    /// deleted `set_account_member_role`'s contract exactly, minus its last-owner demotion guard
    /// (no such invariant exists here, see `remove_project_member`).
    #[instrument(skip(self))]
    pub async fn set_project_member_role(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        role: &str,
    ) -> Result<Project> {
        Self::validate_project_role(role)?;
        self.authorize_project_lead(project_id, subject).await?;

        let result = sqlx::query(
            r#"UPDATE project_members SET role = $1 WHERE project_id = $2 AND account_id = $3"#,
        )
        .bind(role)
        .bind(project_id)
        .bind(target_account_id)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

    /// Changes `target_account_id`'s per-member quota tier on `project_id`. Lead-gated via
    /// `authorize_project_lead`; `target_account_id` must already be on the roster (`NotFound`
    /// otherwise, same reasoning as `set_project_member_role`). The tier value itself is NOT
    /// validated against the operator-configured quota-tier catalogue here -- same as
    /// `Project.billing_plan`/`billingPlan`, that catalogue check happens where the request is
    /// first accepted, not in the repository, so an empty/absent catalogue transparently accepts
    /// any value with no special casing needed at this layer. As of #177 that check is real, not
    /// aspirational: `AuthzStoreImpl::set_project_member_quota_tier` (the procedure/handler layer
    /// that holds the loaded `Config`) calls `QuotaTiers::is_allowed` before ever reaching this
    /// method -- see that call site for the enforcement itself and
    /// `crates/lightbridge-authz-rest/tests/quota_tier_it_tests.rs` for live-DB coverage.
    #[instrument(skip(self))]
    pub async fn set_project_member_quota_tier(
        &self,
        subject: &str,
        project_id: &str,
        target_account_id: &str,
        quota_tier: Option<&str>,
    ) -> Result<Project> {
        self.authorize_project_lead(project_id, subject).await?;

        let result = sqlx::query(
            r#"UPDATE project_members SET quota_tier = $1 WHERE project_id = $2 AND account_id = $3"#,
        )
        .bind(quota_tier)
        .bind(project_id)
        .bind(target_account_id)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        let project = self.get_project_by_id(project_id).await?;
        project.ok_or(Error::NotFound)
    }

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
                  AND id = $2
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
        .bind(subject)
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
    #[instrument(skip(self, subject))]
    pub async fn find_default_project_id(&self, subject: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT id
            FROM projects
            WHERE account_id = $1
              AND is_default = true
            "#,
        )
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Resolves the `{account_id, project_id}` context for a subject + project on behalf of the
    /// `lightbridge-keycloak-spi` token-exchange adapter. Authorized when `subject` is the
    /// project's account owner OR holds ANY `project_members` row on it (not lead-gated -- this is
    /// a read, same visibility boundary as `Project`'s `@@allow("read", ...)`). Deliberately a
    /// single query with one `NotFound` branch: "unknown project" and "known project the subject
    /// can't see" must resolve identically so this endpoint never leaks project existence to a
    /// non-member -- do not split these cases.
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
            WHERE projects.id = $1
              AND (
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let (account_id, project_id) = row.ok_or(Error::NotFound)?;
        Ok(ResolvedContext {
            account_id,
            project_id,
        })
    }

    /// Resolves the acting `subject`'s per-member `quota_tier` on `project_id` (ADR-0017), the
    /// human/OIDC-plane mirror of the API-key plane's `owner_quota_tier`
    /// (`api_key_validation` view, `migrations/20260731000001_api_keys_owner_account.sql`).
    /// Deliberately keyed on `subject` (the acting person), not the project's owning account --
    /// same reasoning as that view's `pm.account_id = k.owner_account_id` join: a lead acting on a
    /// project someone else owns is governed by their OWN roster row, not the owner's.
    ///
    /// `Ok(None)` covers two states the caller must NOT distinguish, matching the view's own
    /// documented NULL semantics verbatim: no `project_members` row at all (the common case for a
    /// project's owning account, which normally holds none), or a row whose `quota_tier` column is
    /// NULL. Both mean "no per-member ceiling, the caller is bounded by the pooled
    /// `projects.project_quota` alone" -- a resolved, legitimate answer, not a failure.
    ///
    /// `Err` means the lookup itself could not be completed (e.g. the database is unreachable) --
    /// distinct in kind from `Ok(None)`, and callers MUST NOT collapse the two: a database outage
    /// must never be represented on the wire the same way as "no per-member ceiling", or an
    /// availability failure becomes a quota bypass. See `TokenExchangeOpStore::resolve_quota_tier`
    /// for how the token-exchange/refresh call sites act on that distinction (refuse the mint
    /// rather than omit the claim).
    #[instrument(skip(self, subject))]
    pub async fn project_member_quota_tier(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>> {
        let quota_tier: Option<Option<String>> = sqlx::query_scalar(
            r#"SELECT quota_tier FROM project_members WHERE project_id = $1 AND account_id = $2"#,
        )
        .bind(project_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        Ok(quota_tier.flatten())
    }

    pub async fn create_exchange_refresh_token(
        &self,
        input: NewExchangeRefreshToken,
    ) -> Result<ExchangeRefreshTokenRow> {
        let row: ExchangeRefreshTokenRow = sqlx::query_as(
            r#"
            INSERT INTO exchange_refresh_tokens
              (id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10, $11, $12, $13, $14)
            RETURNING id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, created_at, expires_at, last_used_at
            "#,
        )
        .bind(input.id)
        .bind(input.subject)
        .bind(input.account_id)
        .bind(input.project_id)
        .bind(input.client_id)
        .bind(input.token_hash)
        .bind(input.scope)
        .bind(input.email)
        .bind(input.email_verified)
        .bind(input.auth_time)
        .bind(input.chain_id)
        .bind(input.chain_expires_at)
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
            SELECT id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, created_at, expires_at, last_used_at
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

    /// Unconditional lookup by hash -- no `status`/`expires_at` filter. Used only to classify why
    /// a CAS consume (`consume_exchange_refresh_token`) just returned `None`: distinguishing "this
    /// hash names a token that was already rotated" (a replay of a superseded token -- RFC 6819
    /// §5.2.2.3 reuse detection, which must cascade-revoke the whole chain) from "no such token" /
    /// "expired" / "already revoked" (a plain `invalid_grant`, no cascade). Never used to decide
    /// whether to honor a refresh -- the CAS `UPDATE ... WHERE status = 'active'` remains the only
    /// source of truth for that.
    pub async fn find_exchange_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<ExchangeRefreshTokenRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, created_at, expires_at, last_used_at
            FROM exchange_refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Cascade-revokes an entire refresh-token family (RFC 6819 §5.2.2.3): flips every
    /// still-`active` row sharing `chain_id` to `revoked`. Called when a token that was already
    /// rotated (superseded) is presented again -- the strongest signal this codebase has that a
    /// refresh token was stolen, since a legitimate client never re-presents a token it already
    /// exchanged for a successor. A no-op (not an error) when nothing in the chain is still
    /// active, matching `revoke_exchange_refresh_token`'s own idempotent-no-op convention.
    pub async fn revoke_exchange_refresh_token_chain(&self, chain_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE chain_id = $1
              AND status = 'active'
            "#,
        )
        .bind(chain_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Atomically consumes a refresh token (single-use enforcement, backing
    /// `authkestra_op::refresh::RefreshTokenStore::consume_token`): flips the presented token from
    /// `active` to `rotated` and returns the row that was consumed, or `None` if it was not
    /// active/live (already used, revoked, expired) so the caller rejects those cases uniformly.
    /// A single `UPDATE ... WHERE status = 'active' ... RETURNING` is its own compare-and-swap --
    /// Postgres holds the row lock for the statement's duration, so two concurrent presentations
    /// of the same token can never both observe `status = 'active'` and both succeed. Unlike the
    /// combined rotate-and-insert this replaces, minting the successor is a separate call
    /// (`create_exchange_refresh_token`, driving `RefreshTokenStore::store_token`) -- the trait
    /// splits "atomically revoke" from "store a new one" into two methods, so this mirrors that
    /// shape rather than reintroducing the old single-transaction combo.
    pub async fn consume_exchange_refresh_token(
        &self,
        presented_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ExchangeRefreshTokenRow>> {
        let row: Option<ExchangeRefreshTokenRow> = sqlx::query_as(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'rotated', last_used_at = $2
            WHERE token_hash = $1
              AND status = 'active'
              AND expires_at > $2
            RETURNING id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, created_at, expires_at, last_used_at
            "#,
        )
        .bind(presented_hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Unconditionally revokes a refresh token by its hash (backing
    /// `authkestra_op::refresh::RefreshTokenStore::revoke_token`). A no-op (not an error) when the
    /// hash does not match an active row -- revoking something already gone is not a failure.
    pub async fn revoke_exchange_refresh_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE token_hash = $1
              AND status = 'active'
            "#,
        )
        .bind(token_hash)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Revokes a refresh token by its hash, scoped to `client_id` (backs `POST /oauth2/revoke`,
    /// RFC 7009). Same idempotent, no-op-if-no-match semantics as
    /// [`Self::revoke_exchange_refresh_token`], with one addition: a hash that matches a row
    /// belonging to a *different* client is also treated as "nothing to do", never as an error --
    /// RFC 7009 §2.2 requires the endpoint to return success uniformly for an unknown, already-
    /// revoked, *or* out-of-scope token, so a client can never use this endpoint to probe whether
    /// a given token string belongs to another client.
    pub async fn revoke_exchange_refresh_token_for_client(
        &self,
        token_hash: &str,
        client_id: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE token_hash = $1
              AND client_id = $2
              AND status = 'active'
            "#,
        )
        .bind(token_hash)
        .bind(client_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Revokes every currently-active refresh-token session for `subject` in one statement,
    /// backing both the self-service "log out everywhere" RPC procedure and the admin offboarding
    /// kill switch (`docs/rbac.md`'s `session:revoke-own`/`session:revoke`) -- previously the only
    /// way to do this was a manual SQL `UPDATE` against prod. Returns how many rows were actually
    /// flipped, so the caller gets confirmation the kill switch did something; `0` (not an error)
    /// when the subject has no active sessions.
    pub async fn revoke_active_exchange_refresh_tokens_for_subject(
        &self,
        subject: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE subject = $1
              AND status = 'active'
            "#,
        )
        .bind(subject)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Project-scoped rule (see the module-level mechanical rescoping this whole file follows):
    /// visible when `subject` owns the project's account OR holds ANY `project_members` row on it,
    /// matching the schema's `@@allow("read", account.id==auth().id || members.some.accountId==
    /// auth().id)` -- unlike `create_project`, any member (not just the owner) may list/read.
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
                projects.account_id = $2
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
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
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
            WHERE projects.id = $7
              AND (
                projects.account_id = $8
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
        .bind(subject)
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
    pub async fn delete_project(&self, subject: &str, project_id: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(subject)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Lead-gated (handoff recommendation #3, ADR-0006): minting a new key requires `subject` to be
    /// either the project's account owner or hold a `project_members` row with `role = 'lead'` on
    /// `input.project_id`, checked via `authorize_project_lead` before the insert -- unlike the
    /// project-scoped read/update rule most of this file's other api-key methods use, any plain
    /// member may NOT create keys. Once authorized, the plain `INSERT` needs no further
    /// project-existence guard (`authorize_project_lead` already confirmed the project exists).
    #[instrument(skip(self))]
    pub async fn create_api_key(&self, subject: &str, input: NewApiKeyRow) -> Result<ApiKey> {
        self.authorize_project_lead(&input.project_id, subject)
            .await?;
        let row: ApiKeyRow = sqlx::query_as(
            r#"
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, owner_account_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, updated_at
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
        .bind(input.billing_plan)
        // The acting subject, not the project's owning account: a lead who is not the owner may
        // mint keys, and it is THEIR per-member ceiling that should bound the key.
        .bind(subject)
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule -- any member (not just leads) may list keys, unlike `create_api_key`.
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
              AND (
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
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
              AND (
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
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
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $3
              AND (
                projects.account_id = $4
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $4
                )
              )
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
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    /// Suspend/resume an account. Per ADR-0006 there is no more owner/admin role to gate this with
    /// -- one account is one person, so authorization collapses to "the caller is this account"
    /// (`id = subject`), enforced directly in the `WHERE` clause. Replaces the deleted
    /// `member_role`-based owner-or-admin check.
    #[instrument(skip(self))]
    pub async fn set_account_status(
        &self,
        subject: &str,
        account_id: &str,
        status: ResourceStatus,
    ) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET status = $1, updated_at = $2
            WHERE id = $3 AND id = $4
            RETURNING id, default_quota, status, created_at, updated_at
            "#,
        )
        .bind(status.to_string())
        .bind(Utc::now())
        .bind(account_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
    }

    /// Suspend/resume a project. Project-scoped rule -- the project's account owner or ANY
    /// `project_members` row authorizes this (not lead-gated), matching the cstack schema doc's
    /// `disableProject`/`enableProject` contract.
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
            WHERE projects.id = $3
              AND (
                projects.account_id = $4
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
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_project(row))
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
        subject: &str,
        account_id: &str,
        default_quota: Option<&str>,
    ) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            UPDATE accounts
            SET default_quota = $1, updated_at = $2
            WHERE id = $3 AND id = $4
            RETURNING id, default_quota, status, created_at, updated_at
            "#,
        )
        .bind(default_quota)
        .bind(Utc::now())
        .bind(account_id)
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_account(row))
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
        subject: &str,
        project_id: &str,
        project_quota: Option<&str>,
    ) -> Result<Project> {
        let row: Option<ProjectRow> = sqlx::query_as(
            r#"
            UPDATE projects
            SET project_quota = $1, updated_at = $2
            WHERE projects.id = $3
              AND (
                projects.account_id = $4
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
        .bind(subject)
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
        subject: &str,
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
                projects.account_id = $4
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
        .bind(subject)
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
    #[instrument(skip(self))]
    pub async fn set_project_model_policy(
        &self,
        subject: &str,
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
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            FOR UPDATE
            "#,
        )
        .bind(project_id)
        .bind(subject)
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
    pub async fn set_default_project(&self, subject: &str, project_id: &str) -> Result<Project> {
        let mut tx: Transaction<'_, Postgres> = self.pool().begin().await?;

        let account_id: Option<String> = sqlx::query_scalar(
            r#"
            SELECT projects.account_id
            FROM projects
            WHERE projects.id = $1
              AND (
                projects.account_id = $2
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $2
                )
              )
            "#,
        )
        .bind(project_id)
        .bind(subject)
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
              owner_account_id,
              owner_role,
              owner_quota_tier,
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
            owner_account_id: row.owner_account_id,
            owner_role: row.owner_role,
            owner_quota_tier: row.owner_quota_tier,
            api_key_status: row.api_key_status,
            project_status: row.project_status,
            account_status: row.account_status,
            expires_at: row.expires_at,
            effective_status: row.effective_status,
        }))
    }

    /// Project-scoped rule (not lead-gated, unlike `create_api_key`) -- this backs both direct
    /// revoke/reactivate and the "revoke the old key" half of `rotate_api_key_transaction` below.
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
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $4
              AND (
                projects.account_id = $5
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $5
                )
              )
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
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule for both halves (not lead-gated, unlike `create_api_key`): revoking the
    /// presented key and minting its successor both require `subject` to own the project's account
    /// or hold ANY `project_members` row on it.
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
            WHERE api_keys.project_id = projects.id
              AND api_keys.id = $4
              AND (
                projects.account_id = $5
                OR EXISTS (
                  SELECT 1 FROM project_members pm
                  WHERE pm.project_id = projects.id AND pm.account_id = $5
                )
              )
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
        existing_update.ok_or(Error::NotFound)?;
        let new_row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            WITH project_auth AS (
                SELECT projects.id AS project_id
                FROM projects
                WHERE projects.id = $1
                  AND (
                    projects.account_id = $2
                    OR EXISTS (
                      SELECT 1 FROM project_members pm
                      WHERE pm.project_id = projects.id AND pm.account_id = $2
                    )
                  )
            )
            INSERT INTO api_keys (
              id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
              last_used_at, last_ip, revoked_at, billing_plan, owner_account_id
            )
            -- `$2` is the rotating subject, reused as the new key's owner: rotation re-mints for
            -- whoever performs it, so the per-member ceiling follows the rotator rather than being
            -- inherited from the key being replaced.
            SELECT $3, project_auth.project_id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $2
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
        let row = new_row.ok_or(Error::NotFound)?;
        tx.commit().await?;
        Ok(Self::to_api_key(row))
    }

    // `delete_api_key` (a hand-written hard `DELETE FROM api_keys`) was removed here (PR #429
    // follow-up): it had no production caller -- `delete-api-key`'s MCP tool and the RPC
    // `model.ApiKey.delete` verb both go through cratestack's generated soft-delete
    // (`deleted_at`), per `migrations/20260721000001_cratestack_soft_delete_audit_defaults.sql`
    // -- and its semantics were actively unsafe alongside self-issued-token introspection
    // (`handlers::exchange_token`): a hard delete leaves NO `api_keys` row behind, and
    // `verify_self_issued_token`'s `azp` check is what keeps a hard-deleted key's
    // still-cryptographically-valid JWT from being reinterpreted as an active exchange session,
    // not the row's mere absence (see that function's doc comment). A dead method whose only
    // effect, if ever wired up again, is to reopen a revocation bypass is worse than no method;
    // do not reintroduce a hand-written hard delete for `api_keys` without re-reading that
    // function's doc comment first.

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
    /// A transaction-scoped advisory lock serializes this across replicas so only one key wins --
    /// this is the chokepoint every bootstrapping caller shares (`authz-api`, `lightbridge-mcp`,
    /// and, since ADR-0012, `authz-idp`; see `lightbridge_authz_rest::signing::bootstrap_signing_key`'s
    /// doc comment for the full concurrent-bootstrap and `max_key_age_days`-disagreement analysis).
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
