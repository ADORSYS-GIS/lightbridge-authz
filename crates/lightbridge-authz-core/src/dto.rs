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
    /// Human-facing display label, so a console has something to render other than `id` (which,
    /// per ADR-0006, IS the caller's opaque JWT subject). `None` means "not named yet" -- a real
    /// state every account predating this field is in, never a placeholder to be invented here;
    /// see `migrations/20260829000001_accounts_add_name.sql`. Not an identifier: not unique, and
    /// no lookup path resolves an account by it.
    #[serde(default)]
    pub name: Option<String>,
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
    /// Optional display label. Blank/whitespace-only input is normalised to `None` by
    /// `AuthzStoreImpl::create_account` rather than rejected, keeping `NULL` the single
    /// representation of "unnamed" all the way down to the DB `CHECK`.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateAccount {
    pub default_quota: Option<String>,
}

/// ADR-0018's three-value access-control policy for which models a project's keys may reach.
/// `AllowAll` is the default -- today's only behavior, and what every pre-existing row backfills
/// to (`migrations/20260821000001_projects_model_policy.sql`). `Allowlist` consults
/// `Project.allowed_models` (an empty list now genuinely means "nothing", unlike the NULL/[] ==
/// "everything" collapse `allowed_models` has on its own). `DenyAll` allows nothing, ignoring
/// `allowed_models` entirely.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelPolicy {
    #[default]
    AllowAll,
    Allowlist,
    DenyAll,
}

const MODEL_POLICY_ALLOW_ALL: &str = "allow_all";
const MODEL_POLICY_ALLOWLIST: &str = "allowlist";
const MODEL_POLICY_DENY_ALL: &str = "deny_all";

impl Display for ModelPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            ModelPolicy::AllowAll => MODEL_POLICY_ALLOW_ALL,
            ModelPolicy::Allowlist => MODEL_POLICY_ALLOWLIST,
            ModelPolicy::DenyAll => MODEL_POLICY_DENY_ALL,
        };
        write!(f, "{}", r)
    }
}

impl From<String> for ModelPolicy {
    /// Fails CLOSED, not open: only the exact `allow_all`/`allowlist` strings map to their
    /// permissive/conditional variants. Anything else -- an unrecognized value, a future variant
    /// this build does not know about yet, corrupted data -- maps to `DenyAll`, the strictest
    /// state. This is the opposite direction from `ResourceStatus::from`'s fail-safe default
    /// (which also fails to the restrictive branch, `Suspended`) but for the same reason: an
    /// unparseable/unknown `model_policy` value must never silently become the *permissive*
    /// `AllowAll`, or corrupted/unexpected DB state would widen access instead of narrowing it.
    fn from(s: String) -> Self {
        match s.as_str() {
            MODEL_POLICY_ALLOW_ALL => ModelPolicy::AllowAll,
            MODEL_POLICY_ALLOWLIST => ModelPolicy::Allowlist,
            _ => ModelPolicy::DenyAll,
        }
    }
}

impl ModelPolicy {
    /// Strictly parses `s` as one of the three canonical wire values, refusing (returning `None`
    /// for) anything else -- the opposite failure mode from `From<String>` above. `From<String>`
    /// exists to read back already-persisted DB state, where there is no caller left to hand an
    /// error to, so it deliberately coerces an unrecognized value to the strictest `DenyAll`
    /// rather than panicking. A *write* has a caller, and the house rule for this procedure
    /// (`setProjectModelPolicy`, ADR-0018 Decision 5 follow-up) is fail-closed in the other
    /// direction: an unrecognized value on the wire must be refused outright, never silently
    /// coerced into a value the caller did not ask for -- `DenyAll` would silently narrow, and
    /// `AllowAll` would (per `From<String>`'s own doc comment) silently widen access. Used by
    /// `AuthzStoreImpl::set_project_model_policy`
    /// (`crates/lightbridge-authz-rest/src/handlers/mod.rs`) to validate `setProjectModelPolicy`'s
    /// wire input before any DB write.
    pub fn parse_strict(s: &str) -> Option<Self> {
        match s {
            MODEL_POLICY_ALLOW_ALL => Some(ModelPolicy::AllowAll),
            MODEL_POLICY_ALLOWLIST => Some(ModelPolicy::Allowlist),
            MODEL_POLICY_DENY_ALL => Some(ModelPolicy::DenyAll),
            _ => None,
        }
    }
}

#[cfg(test)]
mod model_policy_tests {
    use super::ModelPolicy;

    #[test]
    fn from_string_round_trips_known_values() {
        assert_eq!(
            ModelPolicy::from("allow_all".to_string()),
            ModelPolicy::AllowAll
        );
        assert_eq!(
            ModelPolicy::from("allowlist".to_string()),
            ModelPolicy::Allowlist
        );
        assert_eq!(
            ModelPolicy::from("deny_all".to_string()),
            ModelPolicy::DenyAll
        );
    }

    #[test]
    fn from_string_fails_closed_on_unknown_values() {
        assert_eq!(ModelPolicy::from("bogus".to_string()), ModelPolicy::DenyAll);
        assert_eq!(ModelPolicy::from(String::new()), ModelPolicy::DenyAll);
        assert_eq!(
            ModelPolicy::from("ALLOW_ALL".to_string()),
            ModelPolicy::DenyAll,
            "must not case-fold into the permissive variant"
        );
        assert_eq!(
            ModelPolicy::from("allow-all".to_string()),
            ModelPolicy::DenyAll,
            "a near-miss spelling must not silently become allow_all"
        );
    }

    #[test]
    fn default_is_allow_all() {
        assert_eq!(ModelPolicy::default(), ModelPolicy::AllowAll);
    }

    #[test]
    fn display_matches_the_wire_strings_from_from_round_trips_back() {
        for policy in [
            ModelPolicy::AllowAll,
            ModelPolicy::Allowlist,
            ModelPolicy::DenyAll,
        ] {
            assert_eq!(ModelPolicy::from(policy.to_string()), policy);
        }
    }

    #[test]
    fn parse_strict_accepts_known_values() {
        assert_eq!(
            ModelPolicy::parse_strict("allow_all"),
            Some(ModelPolicy::AllowAll)
        );
        assert_eq!(
            ModelPolicy::parse_strict("allowlist"),
            Some(ModelPolicy::Allowlist)
        );
        assert_eq!(
            ModelPolicy::parse_strict("deny_all"),
            Some(ModelPolicy::DenyAll)
        );
    }

    #[test]
    fn parse_strict_refuses_unknown_values_instead_of_coercing() {
        assert_eq!(ModelPolicy::parse_strict("bogus"), None);
        assert_eq!(ModelPolicy::parse_strict(""), None);
        assert_eq!(
            ModelPolicy::parse_strict("ALLOW_ALL"),
            None,
            "must not case-fold into a valid variant"
        );
        assert_eq!(
            ModelPolicy::parse_strict("allow-all"),
            None,
            "a near-miss spelling must not silently become allow_all"
        );
    }
}

/// Per ADR-0006, `Project` gains `billing_identity` (moved from `Account` -- one project, one
/// billing identity, so a single account can bill several projects to different parties) and
/// `project_quota` (the pooled, tier-catalog-validated ceiling shared by everyone on the project).
/// Per ADR-0018, `Project` also gains `model_policy` -- see `ModelPolicy`'s own doc comment.
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
    #[serde(default)]
    pub model_policy: ModelPolicy,
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
    /// ADR-0025 Stage 2: the issuer `subject` was authenticated by. `None` (the legacy
    /// `lightbridge-keycloak-spi` adapter's body shape -- it never sends this field) defaults to
    /// `oauth2.federation.issuer` at the handler, the deployment's one configured issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
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
    pub owner_account_id: String,
    pub owner_role: Option<String>,
    pub owner_quota_tier: Option<String>,
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
