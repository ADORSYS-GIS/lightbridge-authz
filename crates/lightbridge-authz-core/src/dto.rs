use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use utoipa::ToSchema;

const ACTIVE: &str = "active";
const REVOKED: &str = "revoked";
const SUSPENDED: &str = "suspended";

/// Lifecycle state of an account or project. `Suspended` is a soft-disable: the row and its
/// descendants are kept, but every API key beneath a suspended account/project fails validation.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResourceStatus {
    #[default]
    Active,
    Suspended,
}

impl Display for ResourceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            ResourceStatus::Active => ACTIVE,
            ResourceStatus::Suspended => SUSPENDED,
        };
        write!(f, "{}", r)
    }
}

impl From<String> for ResourceStatus {
    /// Fails safe: only the exact `active` string is treated as active; any other value (including
    /// a future/unknown status or corrupted data) maps to the restricted `Suspended` state,
    /// matching the SQL view's `status <> 'active'` deny semantics.
    fn from(s: String) -> Self {
        match s.as_str() {
            ACTIVE => ResourceStatus::Active,
            _ => ResourceStatus::Suspended,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default, PartialEq, Eq)]
pub struct DefaultLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_day: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent_requests: Option<i32>,
}

/// Per ADR-0006, `id` IS the account's owning JWT subject -- one account, one person, with no
/// account-level membership of any kind. `billing_identity`/`owners_admins`/`is_default` are gone
/// (billing identity moved to `Project`; membership moved to `ProjectMember`; "default account" has
/// no meaning once a subject can only ever have one account). `default_quota` is the new
/// tier-catalog-validated governance ceiling for usage under the account's own default project
/// (which has no roster to hang a per-member quota on).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub default_quota: Option<String>,
    #[serde(default)]
    pub status: ResourceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Body for `createAccount`. No `id` -- the caller's JWT subject is used directly (never trusted
/// from the request body). `default_quota` is optional and, like `Project.billing_plan`, validated
/// against the operator-configured tier catalogue at write time; an empty/absent catalogue accepts
/// any value.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateAccount {
    #[serde(default)]
    pub default_quota: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateAccount {
    pub default_quota: Option<String>,
}

/// Per ADR-0006, `Project` gains `billing_identity` (moved from `Account` -- one project, one
/// billing identity, so a single account can bill several projects to different parties) and
/// `project_quota` (the pooled, tier-catalog-validated ceiling shared by everyone on the project).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Project {
    pub id: String,
    pub account_id: String,
    pub name: String,
    #[serde(default)]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub default_limits: Option<DefaultLimits>,
    pub billing_plan: String,
    pub billing_identity: String,
    #[serde(default)]
    pub project_quota: Option<String>,
    #[serde(default)]
    pub status: ResourceStatus,
    #[serde(default)]
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateProject {
    pub name: String,
    #[serde(default)]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub default_limits: Option<DefaultLimits>,
    pub billing_plan: String,
    pub billing_identity: String,
    #[serde(default)]
    pub project_quota: Option<String>,
}

/// A single `project_members` row (ADR-0006, replacing `AccountMembership`): `{project, account,
/// role: lead|member, quotaTier}`. Unlike the old `account_memberships`, `account_id` is a real FK
/// to `Account` -- a project member IS an account, per the vision. Read-only from the RPC surface
/// (no create/update/delete `@@allow` on the schema model); roster mutations go exclusively through
/// the hand-written `addProjectMember`/`removeProjectMember`/`setProjectMemberRole`/
/// `setProjectMemberQuotaTier` procedures.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProjectMember {
    pub project_id: String,
    pub account_id: String,
    pub role: String,
    #[serde(default)]
    pub quota_tier: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub allowed_models: Option<Option<Vec<String>>>,
    pub default_limits: Option<DefaultLimits>,
    pub billing_plan: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyStatus {
    #[default]
    Active,
    Revoked,
}

impl Display for ApiKeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            ApiKeyStatus::Active => ACTIVE,
            ApiKeyStatus::Revoked => REVOKED,
        };
        write!(f, "{}", r)
    }
}

impl From<String> for ApiKeyStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            REVOKED => ApiKeyStatus::Revoked,
            _ => ApiKeyStatus::Active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKey {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub key_prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: ApiKeyStatus,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Billing plan this key is minted on. Chosen at creation from the operator-configured
    /// (env-driven) plan set; preserved across rotation.
    pub billing_plan: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateApiKey {
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    /// Billing plan for the key. Required, and must be one of the operator-configured
    /// (env-driven) billing plans, otherwise creation is rejected with `400 Bad Request`.
    pub billing_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateApiKey {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Rotation mints a fresh secret for an existing key. It does not carry a `billing_plan`: a key's
/// plan is fixed at creation and preserved across rotation (there is no supported path to change a
/// key's plan — create a new key on the desired plan instead).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RotateApiKey {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub grace_period_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeySecret {
    pub api_key: ApiKey,
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_url: Option<String>,
}

/// Request body sent by the IdP adapter to resolve the business context for a subject + project.
///
/// Both fields are required for a successful resolution but are modelled as optional so a
/// malformed/partial body resolves to a uniform `404` (an authz miss) rather than a `422`. Any
/// extra fields the adapter sends (e.g. `realm`) are accepted and ignored.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResolveContextRequest {
    /// Authenticated subject the token is being issued for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Project the token context is scoped to. The subject must be a member of the project's
    /// account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_status_from_string_fails_safe() {
        assert_eq!(
            ResourceStatus::from("active".to_string()),
            ResourceStatus::Active
        );
        assert_eq!(
            ResourceStatus::from("suspended".to_string()),
            ResourceStatus::Suspended
        );
        assert_eq!(
            ResourceStatus::from("pending".to_string()),
            ResourceStatus::Suspended
        );
        assert_eq!(
            ResourceStatus::from(String::new()),
            ResourceStatus::Suspended
        );
    }
}

/// Business context resolved for a subject + project.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResolvedContext {
    pub account_id: String,
    pub project_id: String,
}

/// One row of the `api_key_validation` view: an API key's effective validity with the full
/// account -> project -> key status cascade already resolved by the database. `effective_status`
/// is `"active"` when the key is usable, otherwise it is the deny reason (`key_revoked`,
/// `key_expired`, `project_suspended`, `account_suspended`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyValidation {
    pub api_key_id: String,
    pub key_hash: String,
    pub project_id: String,
    pub account_id: String,
    pub api_key_status: String,
    pub project_status: String,
    pub account_status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub effective_status: String,
}

impl ApiKeyValidation {
    /// Whether the key is usable (the cascade resolved to `active`).
    pub fn is_active(&self) -> bool {
        self.effective_status == ACTIVE
    }
}
