//! Role-based access control (RBAC).
//!
//! Identity is authenticated upstream by Keycloak; this module turns the *grants* carried on a
//! validated JWT (a configurable, flat roles claim — see [`Rbac::roles_claim`]) into a concrete
//! set of [`Permission`]s. Handlers then gate each operation on a single permission via
//! [`PermissionSet::require`].
//!
//! The role → permission mapping is config-driven ([`Rbac::role_permissions`]) with a built-in
//! default ([`default_role_permissions`]) used when the operator supplies none. A grant string is
//! one of:
//!
//! - `*` — every permission (super-admin),
//! - `<resource>:*` — every action on a resource (e.g. `project:*`),
//! - `<resource>:<action>` — a single permission (e.g. `account:delete`).
//!
//! Expansion happens once, at service start, so authorization checks at request time are a plain
//! set lookup with no wildcard evaluation.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// A single capability a caller may hold. The serialized form is the canonical `resource:action`
/// string used everywhere (config, JWT-derived grants, docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    #[serde(rename = "account:create")]
    AccountCreate,
    #[serde(rename = "account:read")]
    AccountRead,
    #[serde(rename = "account:update")]
    AccountUpdate,
    #[serde(rename = "account:delete")]
    AccountDelete,
    #[serde(rename = "account:disable")]
    AccountDisable,

    #[serde(rename = "project:create")]
    ProjectCreate,
    #[serde(rename = "project:read")]
    ProjectRead,
    #[serde(rename = "project:update")]
    ProjectUpdate,
    #[serde(rename = "project:delete")]
    ProjectDelete,
    #[serde(rename = "project:disable")]
    ProjectDisable,
    /// Manage a project's roster: add/remove members and set their role or quota tier. Replaces the
    /// removed `account:member` (ADR-0006) — membership is a project-level concept now, so the
    /// capability moved with it rather than being renamed in place.
    #[serde(rename = "project:member")]
    ProjectMember,

    #[serde(rename = "apikey:create")]
    ApiKeyCreate,
    #[serde(rename = "apikey:read")]
    ApiKeyRead,
    #[serde(rename = "apikey:update")]
    ApiKeyUpdate,
    #[serde(rename = "apikey:delete")]
    ApiKeyDelete,
    #[serde(rename = "apikey:revoke")]
    ApiKeyRevoke,
    #[serde(rename = "apikey:rotate")]
    ApiKeyRotate,
    #[serde(rename = "apikey:validate")]
    ApiKeyValidate,

    /// Read any budget account's balance/history (admin). Kept distinct from
    /// [`Permission::BudgetReadOwn`] -- same self/admin split as
    /// [`Permission::SessionRevokeOwn`] vs [`Permission::SessionRevoke`] -- because reading your
    /// own budget is a materially different, much lower-risk capability than reading anyone
    /// else's.
    #[serde(rename = "budget:read")]
    BudgetRead,
    /// Read the caller's own current budget balance and own grant-ledger history only. Added
    /// alongside [`Permission::BudgetRead`]/[`Permission::BudgetAuditRead`] rather than reusing
    /// either: those two are the admin, arbitrary-target read permissions (`getBudgetBalance`/
    /// `listBudgetGrants`), and granting either one to every authenticated caller so they could
    /// see their own budget would also let them read every OTHER account's budget -- exactly the
    /// "quietly conflating self and admin access" this permission exists to avoid. Structurally
    /// mirrors [`Permission::SessionRevokeOwn`]: gates `getMyBudgetBalance`/`listMyBudgetGrants`,
    /// procedures with no caller-suppliable target subject at all (see `authz.cstack`).
    #[serde(rename = "budget:read-own")]
    BudgetReadOwn,
    /// Request a self-service budget top-up for the caller's own account.
    #[serde(rename = "budget:self-refill")]
    BudgetSelfRefill,
    /// Review a pending budget augmentation request (approve/cap/deny it).
    #[serde(rename = "budget:review")]
    BudgetReview,
    /// Grant budget directly, bypassing self-service policy evaluation.
    #[serde(rename = "budget:grant")]
    BudgetGrant,
    #[serde(rename = "budget:revoke")]
    BudgetRevoke,
    #[serde(rename = "budget:audit-read")]
    BudgetAuditRead,
    #[serde(rename = "budget:policy-read")]
    BudgetPolicyRead,
    /// Author (write) budget policy rules. Kept distinct from
    /// [`Permission::BudgetPolicyActivate`] per ADR-0007: with arbitrary Rego, writing means
    /// shipping executable code into the decision path, which should not be the same identity
    /// that activates it.
    #[serde(rename = "budget:policy-write")]
    BudgetPolicyWrite,
    #[serde(rename = "budget:policy-simulate")]
    BudgetPolicySimulate,
    /// Activate a budget policy revision. Kept distinct from [`Permission::BudgetPolicyWrite`];
    /// see that variant's doc comment.
    #[serde(rename = "budget:policy-activate")]
    BudgetPolicyActivate,

    /// Revoke all of the caller's own refresh-token sessions ("log out everywhere"). Kept
    /// distinct from [`Permission::SessionRevoke`] -- same self/admin split as
    /// [`Permission::BudgetSelfRefill`] vs [`Permission::BudgetReview`] -- because acting on your
    /// own sessions is a materially different capability from acting on someone else's.
    #[serde(rename = "session:revoke-own")]
    SessionRevokeOwn,
    /// Revoke every active refresh-token session for another subject: the offboarding kill switch
    /// that otherwise requires a manual SQL `UPDATE` against prod.
    #[serde(rename = "session:revoke")]
    SessionRevoke,
}

impl Permission {
    /// Every permission, in declaration order. The single source of truth for wildcard expansion
    /// and documentation.
    pub const ALL: [Permission; 31] = [
        Permission::AccountCreate,
        Permission::AccountRead,
        Permission::AccountUpdate,
        Permission::AccountDelete,
        Permission::AccountDisable,
        Permission::ProjectCreate,
        Permission::ProjectRead,
        Permission::ProjectUpdate,
        Permission::ProjectDelete,
        Permission::ProjectDisable,
        Permission::ProjectMember,
        Permission::ApiKeyCreate,
        Permission::ApiKeyRead,
        Permission::ApiKeyUpdate,
        Permission::ApiKeyDelete,
        Permission::ApiKeyRevoke,
        Permission::ApiKeyRotate,
        Permission::ApiKeyValidate,
        Permission::BudgetRead,
        Permission::BudgetReadOwn,
        Permission::BudgetSelfRefill,
        Permission::BudgetReview,
        Permission::BudgetGrant,
        Permission::BudgetRevoke,
        Permission::BudgetAuditRead,
        Permission::BudgetPolicyRead,
        Permission::BudgetPolicyWrite,
        Permission::BudgetPolicySimulate,
        Permission::BudgetPolicyActivate,
        Permission::SessionRevokeOwn,
        Permission::SessionRevoke,
    ];

    /// Canonical `resource:action` string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Permission::AccountCreate => "account:create",
            Permission::AccountRead => "account:read",
            Permission::AccountUpdate => "account:update",
            Permission::AccountDelete => "account:delete",
            Permission::AccountDisable => "account:disable",
            Permission::ProjectCreate => "project:create",
            Permission::ProjectRead => "project:read",
            Permission::ProjectUpdate => "project:update",
            Permission::ProjectDelete => "project:delete",
            Permission::ProjectDisable => "project:disable",
            Permission::ProjectMember => "project:member",
            Permission::ApiKeyCreate => "apikey:create",
            Permission::ApiKeyRead => "apikey:read",
            Permission::ApiKeyUpdate => "apikey:update",
            Permission::ApiKeyDelete => "apikey:delete",
            Permission::ApiKeyRevoke => "apikey:revoke",
            Permission::ApiKeyRotate => "apikey:rotate",
            Permission::ApiKeyValidate => "apikey:validate",
            Permission::BudgetRead => "budget:read",
            Permission::BudgetReadOwn => "budget:read-own",
            Permission::BudgetSelfRefill => "budget:self-refill",
            Permission::BudgetReview => "budget:review",
            Permission::BudgetGrant => "budget:grant",
            Permission::BudgetRevoke => "budget:revoke",
            Permission::BudgetAuditRead => "budget:audit-read",
            Permission::BudgetPolicyRead => "budget:policy-read",
            Permission::BudgetPolicyWrite => "budget:policy-write",
            Permission::BudgetPolicySimulate => "budget:policy-simulate",
            Permission::BudgetPolicyActivate => "budget:policy-activate",
            Permission::SessionRevokeOwn => "session:revoke-own",
            Permission::SessionRevoke => "session:revoke",
        }
    }

    /// The resource half of the `resource:action` string (e.g. `account`).
    fn resource(&self) -> &'static str {
        self.as_str().split(':').next().unwrap_or_default()
    }
}

/// The set of permissions a caller holds. Built once per request from JWT grants; checked with
/// [`PermissionSet::require`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet(HashSet<Permission>);

impl PermissionSet {
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    pub fn contains(&self, permission: Permission) -> bool {
        self.0.contains(&permission)
    }

    pub fn insert(&mut self, permission: Permission) {
        self.0.insert(permission);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = Permission> + '_ {
        self.0.iter().copied()
    }

    /// Returns `Ok(())` when the caller holds `permission`, otherwise a [`Error::Forbidden`]
    /// carrying the missing permission (mapped to HTTP 403 by the REST layer).
    pub fn require(&self, permission: Permission) -> Result<(), Error> {
        if self.contains(permission) {
            Ok(())
        } else {
            Err(Error::Forbidden(format!(
                "missing required permission: {}",
                permission.as_str()
            )))
        }
    }
}

impl FromIterator<Permission> for PermissionSet {
    fn from_iter<I: IntoIterator<Item = Permission>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Expand a single grant string into the permissions it confers. Unknown grants expand to nothing
/// (and are logged by [`Rbac::compile`]); they never widen access.
pub fn expand_grant(grant: &str) -> Vec<Permission> {
    let grant = grant.trim();
    if grant.is_empty() {
        return Vec::new();
    }
    if grant == "*" {
        return Permission::ALL.to_vec();
    }
    if let Some(resource) = grant.strip_suffix(":*") {
        return Permission::ALL
            .iter()
            .copied()
            .filter(|permission| permission.resource() == resource)
            .collect();
    }
    Permission::ALL
        .iter()
        .copied()
        .filter(|permission| permission.as_str() == grant)
        .collect()
}

/// RBAC configuration (lives under `oauth2.rbac`).
#[derive(Debug, Clone, Deserialize)]
pub struct Rbac {
    /// Top-level JWT claim carrying the caller's grants (roles). Its value may be a JSON array of
    /// strings or a single space-delimited string. Defaults to `roles`.
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    /// Maps each role string found in the claim to the grant strings it confers. When empty, the
    /// built-in [`default_role_permissions`] mapping is used instead.
    #[serde(default)]
    pub role_permissions: HashMap<String, Vec<String>>,
    /// Grant strings applied on behalf of any role string that appears in a caller's claim but
    /// does not match an entry in `role_permissions`. Empty by default -- an existing config that
    /// never sets this keeps today's behavior exactly (an unrecognized role contributes nothing).
    /// Populate it (e.g. `default_grants: ["budget:read"]`) to give every authenticated caller a
    /// safe minimum even when their specific role isn't configured -- this is what lets an
    /// unrecognized/garbled role still see their own budget rather than nothing at all.
    #[serde(default)]
    pub default_grants: Vec<String>,
}

impl Default for Rbac {
    fn default() -> Self {
        Self {
            roles_claim: default_roles_claim(),
            role_permissions: HashMap::new(),
            default_grants: Vec::new(),
        }
    }
}

/// The result of [`Rbac::compile`]: each configured role's expanded permission set, plus the
/// expanded `default_grants` set applied to any role string that matches none of them.
#[derive(Debug, Clone)]
pub struct CompiledRbac {
    pub roles: HashMap<String, PermissionSet>,
    pub default: PermissionSet,
}

impl Rbac {
    /// Compile the configured (or default) role → grant mapping into concrete permission sets,
    /// expanding wildcards once, plus the compiled `default_grants` fallback set. Unknown grant
    /// strings are logged and skipped.
    pub fn compile(&self) -> CompiledRbac {
        let source = if self.role_permissions.is_empty() {
            default_role_permissions()
        } else {
            self.role_permissions.clone()
        };

        let roles = source
            .into_iter()
            .map(|(role, grants)| {
                let mut set = PermissionSet::new();
                for grant in &grants {
                    let expanded = expand_grant(grant);
                    if expanded.is_empty() {
                        tracing::warn!(
                            role = %role,
                            grant = %grant,
                            "rbac: ignoring unknown permission grant"
                        );
                    }
                    for permission in expanded {
                        set.insert(permission);
                    }
                }
                (role, set)
            })
            .collect();

        let mut default = PermissionSet::new();
        for grant in &self.default_grants {
            let expanded = expand_grant(grant);
            if expanded.is_empty() {
                tracing::warn!(
                    grant = %grant,
                    "rbac: ignoring unknown default permission grant"
                );
            }
            for permission in expanded {
                default.insert(permission);
            }
        }

        CompiledRbac { roles, default }
    }

    /// Validates `default_grants`: every grant string must expand to at least one real
    /// permission. Does NOT retroactively validate the pre-existing `role_permissions` map's
    /// tolerant behavior (an unknown grant there is still just logged and skipped, unchanged) --
    /// this method exists specifically because an operator who configures `default_grants` wrong
    /// should find out at startup, not discover it later as "some users can't see their own
    /// budget". An unset/empty `default_grants` is always valid (there's nothing to misconfigure
    /// if you haven't configured anything).
    pub fn validate(&self) -> Result<(), Error> {
        for grant in &self.default_grants {
            if expand_grant(grant).is_empty() {
                return Err(Error::Server(format!(
                    "oauth2.rbac.default_grants contains an unrecognized grant: '{grant}'"
                )));
            }
        }
        Ok(())
    }
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

/// Built-in role → grant mapping used when `oauth2.rbac.role_permissions` is not configured. Keep
/// this in sync with `docs/rbac.md`.
pub fn default_role_permissions() -> HashMap<String, Vec<String>> {
    HashMap::from([
        ("lightbridge-admin".to_string(), vec!["*".to_string()]),
        (
            "lightbridge-editor".to_string(),
            vec![
                "account:create".to_string(),
                "account:read".to_string(),
                "project:*".to_string(),
                "apikey:*".to_string(),
                "session:revoke-own".to_string(),
                "budget:read-own".to_string(),
            ],
        ),
        (
            "lightbridge-viewer".to_string(),
            vec![
                "account:create".to_string(),
                "account:read".to_string(),
                "project:read".to_string(),
                "apikey:read".to_string(),
                "session:revoke-own".to_string(),
                "budget:read-own".to_string(),
            ],
        ),
    ])
}

/// Resolve the permission set for a caller given the raw role strings extracted from their JWT and
/// a precompiled [`CompiledRbac`]. Applied per role: a role string matching a configured entry
/// contributes that role's permissions; a role string matching none of them contributes
/// `compiled.default` instead. A caller holding a mix of recognized and unrecognized roles gets
/// the union of both -- the fallback composes per unmatched role, not all-or-nothing.
pub fn permissions_for_roles(roles: &[String], compiled: &CompiledRbac) -> PermissionSet {
    let mut set = PermissionSet::new();
    for role in roles {
        match compiled.roles.get(role) {
            Some(role_permissions) => {
                for permission in role_permissions.iter() {
                    set.insert(permission);
                }
            }
            None => {
                for permission in compiled.default.iter() {
                    set.insert(permission);
                }
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_expands_to_all() {
        assert_eq!(expand_grant("*").len(), Permission::ALL.len());
    }

    #[test]
    fn resource_wildcard_expands_to_resource_actions() {
        let project = expand_grant("project:*");
        // Six since ADR-0006, not five: `project:member` joined the project group when roster
        // management moved off the account. That makes `project:*` confer roster management --
        // a deliberate privilege widening, called out in the PR and mirrored in
        // converse-frontends' `DEFAULT_ROLE_PERMISSIONS`, where it reaches `lightbridge-editor`.
        // Asserted explicitly so the widening cannot happen again silently.
        assert_eq!(project.len(), 6);
        assert!(project.contains(&Permission::ProjectCreate));
        assert!(project.contains(&Permission::ProjectDelete));
        assert!(project.contains(&Permission::ProjectDisable));
        assert!(project.contains(&Permission::ProjectMember));
        assert!(!project.contains(&Permission::AccountCreate));
    }

    #[test]
    fn exact_grant_expands_to_single_permission() {
        assert_eq!(
            expand_grant("account:delete"),
            vec![Permission::AccountDelete]
        );
    }

    #[test]
    fn unknown_grant_expands_to_nothing() {
        assert!(expand_grant("account:teleport").is_empty());
        assert!(expand_grant("nonsense").is_empty());
        assert!(expand_grant("   ").is_empty());
    }

    #[test]
    fn default_admin_role_grants_everything() {
        let compiled = Rbac::default().compile();
        let admin = compiled
            .roles
            .get("lightbridge-admin")
            .expect("admin role present");
        assert_eq!(admin.len(), Permission::ALL.len());
        assert!(admin.contains(Permission::AccountDelete));
    }

    #[test]
    fn viewer_role_is_read_only() {
        let compiled = Rbac::default().compile();
        let viewer = compiled
            .roles
            .get("lightbridge-viewer")
            .expect("viewer role present");
        assert!(viewer.contains(Permission::ProjectRead));
        assert!(!viewer.contains(Permission::ProjectCreate));
        assert!(!viewer.contains(Permission::AccountDelete));
    }

    #[test]
    fn session_wildcard_expands_to_both_actions() {
        let session = expand_grant("session:*");
        assert_eq!(session.len(), 2);
        assert!(session.contains(&Permission::SessionRevokeOwn));
        assert!(session.contains(&Permission::SessionRevoke));
    }

    #[test]
    fn editor_and_viewer_get_self_revoke_but_not_admin_revoke() {
        let compiled = Rbac::default().compile();
        for role in ["lightbridge-editor", "lightbridge-viewer"] {
            let set = compiled.roles.get(role).expect("role present");
            assert!(
                set.contains(Permission::SessionRevokeOwn),
                "{role} should be able to log itself out everywhere"
            );
            assert!(
                !set.contains(Permission::SessionRevoke),
                "{role} must not be able to revoke another subject's sessions"
            );
        }
        let admin = compiled
            .roles
            .get("lightbridge-admin")
            .expect("admin role present");
        assert!(admin.contains(Permission::SessionRevokeOwn));
        assert!(admin.contains(Permission::SessionRevoke));
    }

    #[test]
    fn configured_mapping_overrides_defaults() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::from([(
                "billing".to_string(),
                vec!["account:read".to_string()],
            )]),
            default_grants: Vec::new(),
        };
        let compiled = rbac.compile();
        assert!(!compiled.roles.contains_key("lightbridge-admin"));
        let billing = compiled.roles.get("billing").expect("billing role present");
        assert!(billing.contains(Permission::AccountRead));
        assert_eq!(billing.len(), 1);
    }

    #[test]
    fn permissions_for_roles_unions_grants() {
        let compiled = Rbac::default().compile();
        let set = permissions_for_roles(
            &["lightbridge-viewer".to_string(), "unknown-role".to_string()],
            &compiled,
        );
        assert!(set.contains(Permission::ProjectRead));
        assert!(!set.contains(Permission::ProjectDelete));
    }

    #[test]
    fn require_reports_missing_permission() {
        let set = PermissionSet::from_iter([Permission::AccountRead]);
        assert!(set.require(Permission::AccountRead).is_ok());
        let err = set.require(Permission::AccountDelete).unwrap_err();
        assert!(matches!(err, Error::Forbidden(_)));
        assert!(err.to_string().contains("account:delete"));
    }

    #[test]
    fn empty_default_grants_matches_todays_behavior() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::new(),
            default_grants: Vec::new(),
        };
        let compiled = rbac.compile();
        let set = permissions_for_roles(&["totally-unrecognized-role".to_string()], &compiled);
        assert!(set.is_empty());
    }

    #[test]
    fn unknown_role_falls_back_to_default_grants() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::new(),
            default_grants: vec!["budget:read".to_string()],
        };
        let compiled = rbac.compile();
        let set = permissions_for_roles(&["totally-unrecognized-role".to_string()], &compiled);
        assert_eq!(set.len(), 1);
        assert!(set.contains(Permission::BudgetRead));
    }

    #[test]
    fn recognized_role_does_not_receive_default_grants_it_wasnt_given() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::new(),
            default_grants: vec!["budget:read".to_string()],
        };
        let compiled = rbac.compile();
        let set = permissions_for_roles(&["lightbridge-viewer".to_string()], &compiled);
        assert!(set.contains(Permission::ProjectRead));
        assert!(!set.contains(Permission::BudgetRead));
    }

    #[test]
    fn mixed_recognized_and_unrecognized_roles_compose() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::new(),
            default_grants: vec!["budget:read".to_string()],
        };
        let compiled = rbac.compile();
        let set = permissions_for_roles(
            &[
                "lightbridge-viewer".to_string(),
                "totally-unrecognized-role".to_string(),
            ],
            &compiled,
        );
        assert!(set.contains(Permission::ProjectRead));
        assert!(set.contains(Permission::AccountRead));
        assert!(set.contains(Permission::ApiKeyRead));
        assert!(set.contains(Permission::BudgetRead));
        assert!(!set.contains(Permission::ProjectDelete));
    }

    #[test]
    fn malformed_default_grants_fails_validation() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::new(),
            default_grants: vec!["not:a:real:permission".to_string()],
        };
        assert!(rbac.validate().is_err());
    }

    #[test]
    fn empty_default_grants_always_validates() {
        assert!(Rbac::default().validate().is_ok());
    }
}
