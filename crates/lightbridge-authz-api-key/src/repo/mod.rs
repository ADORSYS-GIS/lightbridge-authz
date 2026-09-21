use std::sync::Arc;

use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::Result;
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeyStatus, DefaultLimits, ModelPolicy, Project, ResourceStatus,
};
use serde_json::Value;
use sqlx::PgPool;

use crate::entities::account_row::AccountRow;
use crate::entities::api_key_row::ApiKeyRow;
use crate::entities::project_row::ProjectRow;

pub mod account;
pub mod api_key;
pub mod authorization_code;
pub mod context;
pub mod device_authorization;
pub mod exchange_refresh_token;
pub mod federated_identity;
pub mod project;
pub mod project_member;
pub mod session;
pub mod signing_key;

pub use federated_identity::FederatedResolution;

#[derive(Debug, Clone)]
pub struct StoreRepo {
    pub pool: Arc<dyn DbPoolTrait>,
}

impl StoreRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    /// Map an optional model list to the value stored in `projects.allowed_models`. `None` maps to
    /// SQL `NULL` (bound as `Option::None`), NOT the jsonb `null` literal: cratestack's
    /// `allowedModels Json?` decode fails on `'null'::jsonb` (see migration
    /// `20260723000001_normalize_allowed_models_json_null`). Both SQL NULL and `[]` mean "all models
    /// allowed"; SQL NULL is the shape cratestack reads cleanly.
    pub(super) fn vec_to_json(values: &Option<Vec<String>>) -> Option<Value> {
        values.as_ref().map(|v| serde_json::json!(v))
    }

    pub(super) fn json_to_vec(value: &Option<Value>) -> Option<Vec<String>> {
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

    pub(super) fn limits_to_json(limits: &Option<DefaultLimits>) -> Value {
        match limits {
            Some(l) => serde_json::to_value(l).unwrap_or_else(|_| serde_json::json!({})),
            None => serde_json::json!({}),
        }
    }

    pub(super) fn json_to_limits(value: &Value) -> Option<DefaultLimits> {
        if value.is_null() {
            None
        } else {
            serde_json::from_value(value.clone()).ok()
        }
    }

    pub(super) fn to_account(row: AccountRow) -> Account {
        Account {
            id: row.id,
            default_quota: row.default_quota,
            status: ResourceStatus::from(row.status),
            name: row.name,
            user_id: row.user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    pub(super) fn to_project(row: ProjectRow) -> Project {
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

    pub(super) fn to_api_key(row: ApiKeyRow) -> ApiKey {
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

    pub(super) async fn load_account_row_optional(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountRow>> {
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT id, default_quota, status, name, user_id, created_at, updated_at
            FROM accounts
            WHERE id = $1
            "#,
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
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
    pub(super) async fn authorize_project_lead(
        &self,
        project_id: &str,
        account_id: &AccountId,
    ) -> Result<()> {
        let owns_project: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(
                a.user_id = (SELECT user_id FROM accounts WHERE id = $2),
                false
            )
            FROM projects p
            JOIN accounts a ON a.id = p.account_id
            WHERE p.id = $1
            "#,
        )
        .bind(project_id)
        .bind(account_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        let Some(owns_project) = owns_project else {
            return Err(lightbridge_authz_core::error::Error::NotFound);
        };
        if owns_project {
            return Ok(());
        }
        match self
            .project_member_role(project_id, account_id)
            .await?
            .as_deref()
        {
            Some("lead") => Ok(()),
            Some(_) => Err(lightbridge_authz_core::error::Error::Forbidden(
                "only the project's account owner or a lead can manage its roster".to_string(),
            )),
            None => Err(lightbridge_authz_core::error::Error::NotFound),
        }
    }
}
