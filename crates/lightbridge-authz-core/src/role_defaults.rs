//! The built-in role → grant mapping ([`default_role_permissions`]), used when
//! `oauth2.rbac.role_permissions` is not configured.
//!
//! Lives in its own module rather than beside [`crate::authz::Permission`] itself because
//! `authz.rs` sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be
//! touched but not grown — the same reason `PermissionSet` moved to
//! [`crate::permission_set`] in #647. Moved verbatim, and `authz` re-exports it, so every existing
//! `lightbridge_authz_core::authz::default_role_permissions` path still resolves.

use std::collections::HashMap;

/// Built-in role → grant mapping used when `oauth2.rbac.role_permissions` is not configured. Keep
/// this in sync with `docs/rbac.md`.
///
/// `session:read-own` is granted to BOTH non-admin roles (and, via `*`, to admins) for the same
/// reason `session:revoke-own` and `budget:read-own` beside it are: "which devices am I signed in
/// on, and log that one out" is self-service, not administration. Its estate-wide sibling
/// `session:read` is deliberately absent from both lists — enumerating other people's sessions
/// exposes their user agents, client ids and activity times, which is an operator capability, so
/// it arrives only through `lightbridge-admin`'s `*`.
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
                "session:read-own".to_string(),
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
                "session:read-own".to_string(),
                "session:revoke-own".to_string(),
                "budget:read-own".to_string(),
            ],
        ),
    ])
}
