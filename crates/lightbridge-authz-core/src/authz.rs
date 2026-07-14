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

    #[serde(rename = "project:create")]
    ProjectCreate,
    #[serde(rename = "project:read")]
    ProjectRead,
    #[serde(rename = "project:update")]
    ProjectUpdate,
    #[serde(rename = "project:delete")]
    ProjectDelete,

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
}

impl Permission {
    /// Every permission, in declaration order. The single source of truth for wildcard expansion
    /// and documentation.
    pub const ALL: [Permission; 15] = [
        Permission::AccountCreate,
        Permission::AccountRead,
        Permission::AccountUpdate,
        Permission::AccountDelete,
        Permission::ProjectCreate,
        Permission::ProjectRead,
        Permission::ProjectUpdate,
        Permission::ProjectDelete,
        Permission::ApiKeyCreate,
        Permission::ApiKeyRead,
        Permission::ApiKeyUpdate,
        Permission::ApiKeyDelete,
        Permission::ApiKeyRevoke,
        Permission::ApiKeyRotate,
        Permission::ApiKeyValidate,
    ];

    /// Canonical `resource:action` string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Permission::AccountCreate => "account:create",
            Permission::AccountRead => "account:read",
            Permission::AccountUpdate => "account:update",
            Permission::AccountDelete => "account:delete",
            Permission::ProjectCreate => "project:create",
            Permission::ProjectRead => "project:read",
            Permission::ProjectUpdate => "project:update",
            Permission::ProjectDelete => "project:delete",
            Permission::ApiKeyCreate => "apikey:create",
            Permission::ApiKeyRead => "apikey:read",
            Permission::ApiKeyUpdate => "apikey:update",
            Permission::ApiKeyDelete => "apikey:delete",
            Permission::ApiKeyRevoke => "apikey:revoke",
            Permission::ApiKeyRotate => "apikey:rotate",
            Permission::ApiKeyValidate => "apikey:validate",
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
}

impl Default for Rbac {
    fn default() -> Self {
        Self {
            roles_claim: default_roles_claim(),
            role_permissions: HashMap::new(),
        }
    }
}

impl Rbac {
    /// Compile the configured (or default) role → grant mapping into concrete permission sets,
    /// expanding wildcards once. Unknown grant strings are logged and skipped.
    pub fn compile(&self) -> HashMap<String, PermissionSet> {
        let source = if self.role_permissions.is_empty() {
            default_role_permissions()
        } else {
            self.role_permissions.clone()
        };

        source
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
            .collect()
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
                "account:read".to_string(),
                "project:*".to_string(),
                "apikey:*".to_string(),
            ],
        ),
        (
            "lightbridge-viewer".to_string(),
            vec![
                "account:read".to_string(),
                "project:read".to_string(),
                "apikey:read".to_string(),
            ],
        ),
    ])
}

/// Resolve the permission set for a caller given the raw role strings extracted from their JWT and
/// a precompiled role → permission map.
pub fn permissions_for_roles(
    roles: &[String],
    compiled: &HashMap<String, PermissionSet>,
) -> PermissionSet {
    let mut set = PermissionSet::new();
    for role in roles {
        if let Some(role_permissions) = compiled.get(role) {
            for permission in role_permissions.iter() {
                set.insert(permission);
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
        assert_eq!(project.len(), 4);
        assert!(project.contains(&Permission::ProjectCreate));
        assert!(project.contains(&Permission::ProjectDelete));
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
            .get("lightbridge-admin")
            .expect("admin role present");
        assert_eq!(admin.len(), Permission::ALL.len());
        assert!(admin.contains(Permission::AccountDelete));
    }

    #[test]
    fn viewer_role_is_read_only() {
        let compiled = Rbac::default().compile();
        let viewer = compiled
            .get("lightbridge-viewer")
            .expect("viewer role present");
        assert!(viewer.contains(Permission::ProjectRead));
        assert!(!viewer.contains(Permission::ProjectCreate));
        assert!(!viewer.contains(Permission::AccountDelete));
    }

    #[test]
    fn configured_mapping_overrides_defaults() {
        let rbac = Rbac {
            roles_claim: "roles".to_string(),
            role_permissions: HashMap::from([(
                "billing".to_string(),
                vec!["account:read".to_string()],
            )]),
        };
        let compiled = rbac.compile();
        assert!(!compiled.contains_key("lightbridge-admin"));
        let billing = compiled.get("billing").expect("billing role present");
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
}
