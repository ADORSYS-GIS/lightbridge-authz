use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
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
use crate::entities::authorization_code_row::{AuthorizationCodeRow, NewAuthorizationCode};
use crate::entities::device_authorization_row::{DeviceAuthorizationRow, NewDeviceAuthorization};
use crate::entities::exchange_refresh_token_row::{
    ExchangeRefreshTokenRow, NewExchangeRefreshToken,
};
use crate::entities::federated_identity_row::{FederatedIdentityRow, UpsertFederatedIdentity};
use crate::entities::new_account_row::NewAccountRow;
use crate::entities::new_api_key_row::NewApiKeyRow;
use crate::entities::new_project_row::NewProjectRow;
use crate::entities::project_member_row::ProjectMemberRow;
use crate::entities::project_row::{ProjectChangeset, ProjectRow};
use crate::entities::session_row::{
    BrowserSessionContextRow, NewSession, SessionRow, SessionStatusRow,
};
use crate::entities::signing_key_row::{NewSigningKey, SigningKeyRow};

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

    pub async fn create_authorization_code(&self, input: NewAuthorizationCode) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO authorization_codes
              (id, code_hash, client_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, identity, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(input.id)
        .bind(input.code_hash)
        .bind(input.client_id)
        .bind(input.redirect_uri)
        .bind(input.scope)
        .bind(input.code_challenge)
        .bind(input.code_challenge_method)
        .bind(input.nonce)
        .bind(input.identity)
        .bind(input.expires_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn consume_authorization_code(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthorizationCodeRow>> {
        let row = sqlx::query_as(
            r#"
            UPDATE authorization_codes
            SET consumed_at = $2
            WHERE code_hash = $1
              AND consumed_at IS NULL
              AND expires_at > $2
            RETURNING id, code_hash, client_id, redirect_uri, scope, code_challenge,
                      code_challenge_method, nonce, identity, created_at, expires_at, consumed_at
            "#,
        )
        .bind(code_hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Stores a sealed, single-use secret claim (GHSA-9pc6-965v-2c44, #538). ADR-0038
    /// persistence exception, same class as `authorization_codes`: see the migration's own
    /// comment and `consume_secret_claim` below for why redemption cannot be generated CRUD.
    pub async fn create_secret_claim(
        &self,
        id: &str,
        token_hash: &str,
        subject: &str,
        sealed_secret: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO secret_claims (id, token_hash, subject, sealed_secret, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(id)
        .bind(token_hash)
        .bind(subject)
        .bind(sealed_secret)
        .bind(expires_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Claims a secret exactly once, for `subject` only, returning the sealed envelope.
    ///
    /// `subject` is in the `WHERE` clause, not checked afterwards, and that placement is the
    /// whole point: a wrong-subject attempt matches no row, so `consumed_at` is never written and
    /// the legitimate owner's claim survives. Consuming first and comparing second would let
    /// anyone holding the token -- including the model it travelled through -- burn the owner's
    /// one chance to collect their key.
    ///
    /// Single-statement CAS, mirroring `consume_authorization_code`: concurrent redemptions by
    /// the same subject cannot both win, because only the first sees `consumed_at IS NULL`.
    pub async fn consume_secret_claim(
        &self,
        token_hash: &str,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let sealed = sqlx::query_scalar(
            r#"
            UPDATE secret_claims
            SET consumed_at = $3
            WHERE token_hash = $1
              AND subject = $2
              AND consumed_at IS NULL
              AND expires_at > $3
            RETURNING sealed_secret
            "#,
        )
        .bind(token_hash)
        .bind(subject)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(sealed)
    }

    pub async fn authorization_code_matches(
        &self,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let matches = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM authorization_codes
                WHERE code_hash = $1
                  AND client_id = $2
                  AND redirect_uri = $3
                  AND consumed_at IS NULL
                  AND expires_at > $4
            )
            "#,
        )
        .bind(code_hash)
        .bind(client_id)
        .bind(redirect_uri)
        .bind(now)
        .fetch_one(self.pool())
        .await?;
        Ok(matches)
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
    #[instrument(skip(self, account_id))]
    pub async fn project_member_role(
        &self,
        project_id: &str,
        account_id: &AccountId,
    ) -> Result<Option<String>> {
        let role: Option<String> = sqlx::query_scalar(
            r#"SELECT role FROM project_members WHERE project_id = $1 AND account_id = $2"#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
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
    async fn authorize_project_lead(&self, project_id: &str, account_id: &AccountId) -> Result<()> {
        let project_account_id: Option<String> =
            sqlx::query_scalar(r#"SELECT account_id FROM projects WHERE id = $1"#)
                .bind(project_id)
                .fetch_optional(self.pool())
                .await?;
        let Some(project_account_id) = project_account_id else {
            return Err(Error::NotFound);
        };
        if project_account_id == account_id.as_str() {
            return Ok(());
        }
        match self
            .project_member_role(project_id, account_id)
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
        account_id: &AccountId,
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
        .bind(account_id.as_str())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_account).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_account(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
    ) -> Result<Option<Account>> {
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT id, default_quota, status, created_at, updated_at
            FROM accounts
            WHERE id = $1 AND id = $2
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
            WHERE id = $3 AND id = $4
            RETURNING id, default_quota, status, created_at, updated_at
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
    #[instrument(skip(self))]
    pub async fn delete_account(
        &self,
        acting_account_id: &AccountId,
        account_id: &str,
    ) -> Result<Account> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"
            DELETE FROM accounts
            WHERE id = $1 AND id = $2
            RETURNING id, default_quota, status, created_at, updated_at
            "#,
        )
        .bind(account_id)
        .bind(acting_account_id.as_str())
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
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
        role: Option<&str>,
    ) -> Result<Project> {
        let role = role.unwrap_or("member");
        Self::validate_project_role(role)?;
        self.authorize_project_lead(project_id, account_id).await?;

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
        account_id: &AccountId,
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
        if project_account_id != account_id.as_str()
            && self
                .project_member_role(project_id, account_id)
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
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
    ) -> Result<Project> {
        self.authorize_project_lead(project_id, account_id).await?;

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
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
        role: &str,
    ) -> Result<Project> {
        Self::validate_project_role(role)?;
        self.authorize_project_lead(project_id, account_id).await?;

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
        account_id: &AccountId,
        project_id: &str,
        target_account_id: &str,
        quota_tier: Option<&str>,
    ) -> Result<Project> {
        self.authorize_project_lead(project_id, account_id).await?;

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

    /// Resolves the `{account_id, project_id}` context for an (already-translated, ADR-0025) acting
    /// account id + project on behalf of the `lightbridge-keycloak-spi` token-exchange adapter.
    /// Authorized when `account_id` is the project's account owner OR holds ANY `project_members`
    /// row on it (not lead-gated -- this is a read, same visibility boundary as `Project`'s
    /// `@@allow("read", ...)`). Deliberately a single query with one `NotFound` branch: "unknown
    /// project" and "known project the caller can't see" must resolve identically so this endpoint
    /// never leaks project existence to a non-member -- do not split these cases.
    #[instrument(skip(self, account_id))]
    pub async fn resolve_context(
        &self,
        account_id: &AccountId,
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
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let (account_id, project_id) = row.ok_or(Error::NotFound)?;
        Ok(ResolvedContext {
            account_id,
            project_id,
        })
    }

    /// Enforces the Active-status gate `resolve_context` itself deliberately does not apply (that
    /// function only checks ownership/membership). Single source of truth for every grant/session
    /// path that must refuse a suspended account or an inactive project rather than silently
    /// admitting it: browser SSO (`KeycloakRelyingParty::complete`/`resolve_authorized_context`),
    /// the device-code grant (`issue_device_tokens`), the refresh grant (`handle_refresh_token`),
    /// and the RFC 8693 token-exchange grant (`handle_token_exchange`) all route through this (or
    /// through [`Self::resolve_active_context`] below, which also resolves the context). Returns
    /// the fetched [`Project`] because two of those four callers (`issue_device_tokens`,
    /// `handle_refresh_token`) need `allowed_models`/`model_policy` off the SAME row right after
    /// this check and would otherwise pay for a second, redundant query to get it.
    ///
    /// Fail-closed, unconditionally: a lookup ERROR refuses (`Error::Server`), never falls through
    /// to permit. An inactive project or a suspended account refuses (`Error::Forbidden`). This is
    /// the exact asymmetry that let `handle_token_exchange` silently admit a suspended account
    /// through the RFC 8693 grant while `issue_device_tokens`/`handle_refresh_token` already
    /// refused it -- callers translate the `Result` into their own OAuth error shape (some grants
    /// use a specific `access_denied`, the refresh grant deliberately uses a uniform
    /// `invalid_grant` for both "inactive" and "not authorized" so as not to reveal which applied),
    /// but the underlying check must never drift between them again.
    pub async fn require_active_project_and_account(
        &self,
        project_id: &str,
        account_id: &str,
    ) -> Result<Project> {
        let project = match self.get_project_by_id(project_id).await {
            Ok(Some(project)) if project.status == ResourceStatus::Active => project,
            Ok(_) => return Err(Error::Forbidden("project is not active".to_string())),
            Err(_) => return Err(Error::Server("project lookup failed".to_string())),
        };
        match self.get_account_by_id(account_id).await {
            Ok(Some(account)) if account.status == ResourceStatus::Active => {}
            Ok(_) => return Err(Error::Forbidden("account is suspended".to_string())),
            Err(_) => return Err(Error::Server("account lookup failed".to_string())),
        }
        Ok(project)
    }

    /// `resolve_context` followed immediately by [`Self::require_active_project_and_account`], for
    /// the callers (browser SSO's session creation and cross-project re-resolution) that only need
    /// the resolved ids, not the fetched `Project` value itself.
    pub async fn resolve_active_context(
        &self,
        account_id: &AccountId,
        project_id: &str,
    ) -> Result<ResolvedContext> {
        let context = self.resolve_context(account_id, project_id).await?;
        self.require_active_project_and_account(&context.project_id, &context.account_id)
            .await?;
        Ok(context)
    }

    /// Resolves the acting account's per-member `quota_tier` on `project_id` (ADR-0017), the
    /// human/OIDC-plane mirror of the API-key plane's `owner_quota_tier`
    /// (`api_key_validation` view, `migrations/20260731000001_api_keys_owner_account.sql`).
    /// Deliberately keyed on `account_id` (the acting person), not the project's owning account --
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
    #[instrument(skip(self, account_id))]
    pub async fn project_member_quota_tier(
        &self,
        project_id: &str,
        account_id: &AccountId,
    ) -> Result<Option<String>> {
        let quota_tier: Option<Option<String>> = sqlx::query_scalar(
            r#"SELECT quota_tier FROM project_members WHERE project_id = $1 AND account_id = $2"#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
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
              (id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, session_id, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at
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
        .bind(input.session_id)
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
            SELECT id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at
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
            SELECT id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at
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
            RETURNING id, subject, account_id, project_id, client_id, token_hash, scope, status, email, email_verified, auth_time, chain_id, chain_expires_at, session_id, created_at, expires_at, last_used_at
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

    /// Inserts a new `sessions` row (ADR-0020 Decision 1). Every call site this PR touches mints
    /// `kind = "token"` -- see [`NewSession`]'s own doc comment.
    pub async fn create_session(&self, input: NewSession) -> Result<SessionRow> {
        let row: SessionRow = sqlx::query_as(
            r#"
            INSERT INTO sessions
              (id, account_id, project_id, client_id, kind, status, expires_at, subject)
            VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
            RETURNING id, account_id, project_id, client_id, kind, status, created_at, updated_at, last_used_at, expires_at, user_agent, subject
            "#,
        )
        .bind(input.id)
        .bind(input.account_id)
        .bind(input.project_id)
        .bind(input.client_id)
        .bind(input.kind)
        .bind(input.expires_at)
        .bind(input.subject)
        .fetch_one(self.pool())
        .await?;
        Ok(row)
    }

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
                    last_authenticated_at = now(),
                    updated_at = now()
                WHERE id = $6
                RETURNING id, issuer, subject, account_id, token_envelope,
                          token_sealed_at, access_expires_at, refresh_expires_at, scope,
                          last_authenticated_at, created_at, updated_at
                "#,
            )
            .bind(&input.token_envelope)
            .bind(input.token_sealed_at)
            .bind(input.access_expires_at)
            .bind(input.refresh_expires_at)
            .bind(&input.scope)
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
                   access_expires_at, refresh_expires_at, scope)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id, issuer, subject, account_id, token_envelope,
                          token_sealed_at, access_expires_at, refresh_expires_at, scope,
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

    /// Read-side counterpart to [`Self::upsert_federated_identity`]. Not yet wired to any RPC
    /// surface -- ADR-0024's Follow-ups list "refreshing stored tokens" as a later consumer; this
    /// exists now so that consumer does not also need a new repo method.
    #[instrument(skip(self, subject))]
    pub async fn find_federated_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<FederatedIdentityRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, issuer, subject, account_id, token_envelope, token_sealed_at,
                   access_expires_at, refresh_expires_at, scope, last_authenticated_at,
                   created_at, updated_at
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

    /// Looks the adopted federated identity up by the ACCOUNT it adopted, rather than by the
    /// `(issuer, subject)` federation key [`Self::find_federated_identity`] takes. That is the
    /// direction `/authorize` needs: a browser session persists the ADR-0025-resolved acting
    /// account id in `sessions.subject` (`relying_party::KeycloakRelyingParty::complete` stamps
    /// `identity.account_id` there), never the raw upstream subject, so the federation key is not
    /// available at that call site at all.
    ///
    /// At most one row can ever match: `federated_identities_account_uidx`
    /// (`migrations/20260825000001_users_and_federated_identities.sql:108`, a partial unique index
    /// on `account_id`) is what enforces ADR-0024's "an account is adopted by AT MOST ONE
    /// federated identity ever".
    #[instrument(skip(self))]
    pub async fn find_federated_identity_by_account(
        &self,
        account_id: &str,
    ) -> Result<Option<FederatedIdentityRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, issuer, subject, account_id, token_envelope, token_sealed_at,
                   access_expires_at, refresh_expires_at, scope, last_authenticated_at,
                   created_at, updated_at
            FROM federated_identities
            WHERE account_id = $1
            "#,
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// ADR-0020 Decision 4 / #437: the current `status`/`expires_at` of the `sessions` row named
    /// `session_id`, for introspection's fail-closed status check. `Ok(None)` (never an error) for
    /// an unrecognized `session_id` -- distinguishing "not found" from a real DB error is exactly
    /// what lets the caller (`resolve_exchange_token_context`) tell "session doesn't exist" (fail
    /// to `active: false`) apart from "couldn't check" (fail the whole call closed, propagate
    /// `Err`).
    pub async fn find_session_status(&self, session_id: &str) -> Result<Option<SessionStatusRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT status, expires_at
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_active_browser_session(
        &self,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserSessionContextRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT account_id, project_id, subject
            FROM sessions
            WHERE id = $1
              AND kind = 'browser'
              AND status = 'active'
              AND expires_at > $2
            "#,
        )
        .bind(session_id)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Revokes every currently-active session for `subject` -- of EITHER `kind` (ADR-0021
    /// Decision 3: the query is deliberately `kind`-blind, which is exactly what makes it cover
    /// both `kind = 'token'` and `kind = 'browser'` rows in one call) -- and cascades to revoke
    /// every `exchange_refresh_tokens` row chained under one of those sessions (ADR-0020 Decision
    /// 9), so a bulk "log out everywhere" cannot leave a live refresh token behind for a session
    /// it just killed. Backs both the self-service "log out everywhere" RPC procedure and the
    /// admin offboarding kill switch (`docs/rbac.md`'s `session:revoke-own`/`session:revoke`).
    /// Returns how many SESSIONS were revoked (not refresh-token rows), so the caller gets
    /// confirmation the kill switch did something; `0` (not an error) when the subject has no
    /// active sessions of either kind. Two statements in one transaction, not a single query --
    /// see the module doc comment on why this repo keeps this operation hand-written rather than
    /// cratestack-generated (ADR-0020 Decision 9).
    ///
    /// Matches on `sessions.subject` (the real authenticated actor), never `sessions.account_id`
    /// (#492): `account_id` always holds the PROJECT's OWNING account (`resolve_context`'s
    /// documented behavior), identical for every session ever minted against a given project
    /// regardless of which real person -- owner or roster member -- minted it. Keying this query
    /// on `account_id` mixed up "which project" with "which person": a roster member's own
    /// "log out everywhere" silently no-opped on their own session (it never matched), while the
    /// project owner's own "log out everywhere" collaterally revoked every OTHER member's session
    /// on a shared project too (it always matched). `subject` is populated for every session this
    /// repo creates -- `kind = 'browser'` rows since
    /// `migrations/20260824000003_sessions_add_subject.sql`, `kind = 'token'` rows since this
    /// fix's companion change to `oauth2_op::store::TokenExchangeOpStore`'s two `create_session`
    /// call sites -- so only sessions minted before this fix (`subject IS NULL`) go unmatched
    /// here; those are TTL-bounded and self-heal on their own expiry, the same trade-off the
    /// nullable-column migration already made for pre-migration browser rows.
    pub async fn revoke_sessions_and_cascade(&self, account_id: &AccountId) -> Result<u64> {
        let mut tx = self.pool().begin().await?;
        let revoked_sessions = sqlx::query(
            r#"
            UPDATE sessions
            SET status = 'revoked', updated_at = now()
            WHERE subject = $1
              AND status = 'active'
            "#,
        )
        .bind(account_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE exchange_refresh_tokens
            SET status = 'revoked'
            WHERE status = 'active'
              AND session_id IN (SELECT id FROM sessions WHERE subject = $1)
            "#,
        )
        .bind(account_id.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(revoked_sessions.rows_affected())
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
                projects.account_id = $2
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
                projects.account_id = $2
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

    /// Lead-gated (handoff recommendation #3, ADR-0006): minting a new key requires `subject` to be
    /// either the project's account owner or hold a `project_members` row with `role = 'lead'` on
    /// `input.project_id`, checked via `authorize_project_lead` before the insert -- unlike the
    /// project-scoped read/update rule most of this file's other api-key methods use, any plain
    /// member may NOT create keys. Once authorized, the plain `INSERT` needs no further
    /// project-existence guard (`authorize_project_lead` already confirmed the project exists).
    #[instrument(skip(self))]
    pub async fn create_api_key(
        &self,
        account_id: &AccountId,
        input: NewApiKeyRow,
    ) -> Result<ApiKey> {
        self.authorize_project_lead(&input.project_id, account_id)
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
        // The acting account, not the project's owning account: a lead who is not the owner may
        // mint keys, and it is THEIR per-member ceiling that should bound the key.
        .bind(account_id.as_str())
        .fetch_one(self.pool())
        .await?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule -- any member (not just leads) may list keys, unlike `create_api_key`.
    #[instrument(skip(self))]
    pub async fn list_api_keys(
        &self,
        account_id: &AccountId,
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
        .bind(account_id.as_str())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(Self::to_api_key).collect())
    }

    #[instrument(skip(self))]
    pub async fn get_api_key(
        &self,
        account_id: &AccountId,
        key_id: &str,
    ) -> Result<Option<ApiKey>> {
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
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(Self::to_api_key))
    }

    #[instrument(skip(self))]
    pub async fn update_api_key(
        &self,
        account_id: &AccountId,
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
        .bind(account_id.as_str())
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
        acting_account_id: &AccountId,
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
        .bind(acting_account_id.as_str())
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
        .bind(account_id.as_str())
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
        acting_account_id: &AccountId,
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
        .bind(acting_account_id.as_str())
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
    #[instrument(skip(self))]
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
                projects.account_id = $2
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
        account_id: &AccountId,
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
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(Error::NotFound)?;
        Ok(Self::to_api_key(row))
    }

    /// Project-scoped rule for both halves (not lead-gated, unlike `create_api_key`): revoking the
    /// presented key and minting its successor both require `account_id` to own the project's
    /// account or hold ANY `project_members` row on it.
    #[instrument(skip(self))]
    pub async fn rotate_api_key_transaction(
        &self,
        account_id: &AccountId,
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
        .bind(account_id.as_str())
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
        .bind(account_id.as_str())
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

    /// Inserts a fresh `pending` `device_authorizations` row (ADR-0012 Decision 7 / #423). A
    /// `user_code` collision (the table's unique index) surfaces as `Error::Conflict`, same
    /// convention as [`Self::create_account`]'s `23505` handling -- the caller (see
    /// `oauth2_op::device_store::create_pending_device_authorization`) is expected to regenerate
    /// the code and retry, per the ticket's own "unique index + retry-on-conflict at insert time,
    /// not a pre-check-then-insert race" risk mitigation. A `device_code` collision (astronomically
    /// unlikely given its entropy) surfaces the same way; this method does not attempt to tell the
    /// two apart, since both are handled identically by the caller (retry with fresh values).
    #[instrument(skip(self, input))]
    pub async fn create_device_authorization(
        &self,
        input: NewDeviceAuthorization,
    ) -> Result<DeviceAuthorizationRow> {
        let row: DeviceAuthorizationRow = sqlx::query_as(
            r#"
            INSERT INTO device_authorizations
              (id, device_code, user_code, client_id, project_id, scope, status, interval_secs, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(input.id)
        .bind(input.device_code)
        .bind(input.user_code)
        .bind(input.client_id)
        .bind(input.project_id)
        .bind(input.scope)
        .bind(input.interval_secs)
        .bind(input.expires_at)
        .fetch_one(self.pool())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                && db_err.code().as_deref() == Some("23505")
            {
                return Error::Conflict(
                    "device_code or user_code already in use, caller should retry with fresh \
                     values"
                        .to_string(),
                );
            }
            Error::from(e)
        })?;
        Ok(row)
    }

    /// Looks up a still-live `device_authorizations` row by `device_code` (backs
    /// `authkestra_op::device::DeviceCodeStore::get_device_code`/`consume_device_code`'s
    /// pre-checks). "Live" means not expired AND not already `consumed` -- a consumed row is
    /// treated as gone for every read path, exactly like an expired one (ADR-0012 Decision 7: "a
    /// device code must be atomically claimed exactly once"; once claimed, later reads of the same
    /// code see nothing, matching `find_active_exchange_refresh_token`'s posture on `expires_at`).
    /// `Ok(None)` covers unknown/expired/consumed uniformly -- callers must not try to distinguish
    /// them from this call alone.
    pub async fn find_active_device_authorization_by_device_code(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            FROM device_authorizations
            WHERE device_code = $1
              AND status <> 'consumed'
              AND expires_at > $2
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Reads a device authorization without treating expiry or consumption as absence. The token
    /// endpoint uses this to return RFC 8628's distinct `expired_token` response while keeping all
    /// other lookup paths enumeration-safe.
    pub async fn find_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            FROM device_authorizations
            WHERE device_code = $1
            "#,
        )
        .bind(device_code)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Same as [`Self::find_active_device_authorization_by_device_code`], keyed by `user_code`
    /// instead (the verification-page submission path -- RFC 8628 §6.1). Callers MUST upper-case
    /// `user_code` before calling (matching `generate_user_code`'s always-upper-case output and
    /// the migration's case-insensitive-by-convention unique index) -- this method does no
    /// normalization of its own.
    pub async fn find_active_device_authorization_by_user_code(
        &self,
        user_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row = sqlx::query_as(
            r#"
            SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            FROM device_authorizations
            WHERE user_code = $1
              AND status <> 'consumed'
              AND expires_at > $2
            "#,
        )
        .bind(user_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// CAS-updates `last_polled_at` on a still-`pending` row (backs
    /// `authkestra_op::device::DeviceCodeStore::store_device_code`'s re-store-while-polling call
    /// site -- see `oauth2_op::device_store`'s doc comment for why that trait method is called a
    /// second time with the same `device_code` during ordinary polling). Deliberately does NOT
    /// touch `status`/`subject` -- unlike [`Self::approve_device_authorization`]/
    /// [`Self::deny_device_authorization`], this is not a state transition, just a liveness
    /// timestamp, so the `WHERE status = 'pending'` guard exists only to make this a safe no-op
    /// once the row has moved on (never to let a stale "store" call clobber an already-decided
    /// row). `Ok(None)` (not an error) when the row is gone/expired/already transitioned.
    pub async fn touch_device_authorization_poll(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            UPDATE device_authorizations
            SET last_polled_at = $2
            WHERE device_code = $1
              AND status = 'pending'
              AND expires_at > $2
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Atomically transitions a `pending` row to `approved`, stamping `subject` (ADR-0025: the
    /// resolved acting account id, never the raw Keycloak `sub` directly) in the same statement --
    /// a single `UPDATE ... WHERE status = 'pending' ... RETURNING` is its own compare-and-swap,
    /// mirroring [`Self::consume_exchange_refresh_token`] exactly: Postgres holds the row lock for
    /// the statement's duration, so two concurrent approval attempts (or an approve racing a deny,
    /// see [`Self::deny_device_authorization`]) can never both observe `status = 'pending'` and
    /// both succeed. `Ok(None)` when the row is gone/expired/already decided -- the caller (a
    /// future verification-page ticket) must treat that as "someone already acted on this code",
    /// not a generic failure.
    pub async fn approve_device_authorization(
        &self,
        device_code: &str,
        account_id: &AccountId,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            UPDATE device_authorizations
            SET status = 'approved', subject = $2
            WHERE device_code = $1
              AND status = 'pending'
              AND expires_at > $3
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(account_id.as_str())
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// The `deny` mirror of [`Self::approve_device_authorization`] -- same single-statement CAS
    /// shape, `WHERE status = 'pending'` guard, `Ok(None)` on an already-decided/gone row. Leaves
    /// `subject` `NULL` (the migration's `device_authorizations_subject_only_when_approved` CHECK
    /// constraint enforces this at the database level too).
    pub async fn deny_device_authorization(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            UPDATE device_authorizations
            SET status = 'denied'
            WHERE device_code = $1
              AND status = 'pending'
              AND expires_at > $2
            RETURNING id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Atomically consumes an `approved`/`denied` row exactly once (backs
    /// `authkestra_op::device::DeviceCodeStore::consume_device_code`, called from the CLI's
    /// `/oauth2/token` poll once it observes a non-`pending` status). Single-use enforcement, same
    /// CAS guard as [`Self::consume_exchange_refresh_token`] (`WHERE status IN ('approved',
    /// 'denied') ...`), so two concurrent polls presenting the same `device_code` can never both
    /// observe a claimable status and both succeed -- exactly one call ever gets `Some(..)` back;
    /// every other concurrent or later call gets `Ok(None)`.
    ///
    /// Unlike every other CAS method in this file, this one is a `WITH ... FOR UPDATE` CTE feeding
    /// an `UPDATE ... FROM`, not a plain `UPDATE ... RETURNING` -- deliberately, because the
    /// caller needs the row's PRE-consume `status`/`subject` (to know whether the device code was
    /// approved or denied, and by whom) and plain `RETURNING` only ever exposes the POST-update
    /// row, which would come back as `status = 'consumed'` -- a value
    /// `oauth2_op::device_store::row_to_session` has no way to map back onto the upstream
    /// `DeviceCodeStatus` enum (only `Pending`/`Approved`/`Denied` exist there; this was caught by
    /// this repo's own it-tests, not by inspection -- see #423's PR description). The `FOR UPDATE`
    /// inside the CTE still holds the row lock for the whole statement's duration -- the second of
    /// two concurrent callers blocks on it until the first's `UPDATE` commits, then re-evaluates
    /// the CTE's `WHERE status IN (...)` and finds nothing, so this remains a single atomic
    /// statement and the CAS property holds exactly as it does everywhere else in this file.
    ///
    /// Kept as a `status = 'consumed'` flip rather than a hard `DELETE` -- consistent with this
    /// codebase's ledger-like convention for CAS-consumed rows (`exchange_refresh_tokens` does the
    /// same) -- and every read path already treats `consumed` as absent (see
    /// [`Self::find_active_device_authorization_by_device_code`]), so the row is functionally
    /// "consumed-and-gone" per ADR-0012 Decision 7 even though the audit trail survives.
    pub async fn consume_device_authorization(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceAuthorizationRow>> {
        let row: Option<DeviceAuthorizationRow> = sqlx::query_as(
            r#"
            WITH claimable AS (
                SELECT id, device_code, user_code, client_id, project_id, scope, status, subject, interval_secs, created_at, expires_at, last_polled_at
                FROM device_authorizations
                WHERE device_code = $1
                  AND status IN ('approved', 'denied')
                  AND expires_at > $2
                FOR UPDATE
            )
            UPDATE device_authorizations d
            SET status = 'consumed'
            FROM claimable
            WHERE d.id = claimable.id
            RETURNING claimable.id, claimable.device_code, claimable.user_code, claimable.client_id, claimable.project_id, claimable.scope, claimable.status, claimable.subject, claimable.interval_secs, claimable.created_at, claimable.expires_at, claimable.last_polled_at
            "#,
        )
        .bind(device_code)
        .bind(now)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Unconditional hard delete, backing
    /// `authkestra_op::device::DeviceCodeStore::delete_device_code`. A no-op (not an error) when
    /// the row is already gone -- deleting something already absent is not a failure, matching
    /// every other unconditional-delete/revoke convention in this file.
    pub async fn delete_device_authorization(&self, device_code: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM device_authorizations
            WHERE device_code = $1
            "#,
        )
        .bind(device_code)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
