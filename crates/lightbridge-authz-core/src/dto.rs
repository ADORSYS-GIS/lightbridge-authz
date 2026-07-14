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

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Account {
    pub id: String,
    pub billing_identity: String,
    #[serde(default)]
    pub owners_admins: Vec<String>,
    #[serde(default)]
    pub status: ResourceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateAccount {
    pub billing_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateAccount {
    pub billing_identity: Option<String>,
    pub owners_admins: Option<Vec<String>>,
}

/// Body for adding a member to an account. `subject` is the member's identity (the Keycloak `sub`),
/// the same value carried on their bearer token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AddAccountMember {
    pub subject: String,
}

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
    #[serde(default)]
    pub status: ResourceStatus,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateApiKey {
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateApiKey {
    pub name: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

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
