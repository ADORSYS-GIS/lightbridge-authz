//! The built-in role → grant defaults (`lightbridge_authz_core::role_defaults`).
//!
//! A dedicated test binary rather than more `#[cfg(test)]` inside `authz.rs`: that file sits on
//! its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be touched but not grown,
//! and AGENTS.md's own "dedicated test files" rule points new tests at `tests/` anyway.

use lightbridge_authz_core::Permission;
use lightbridge_authz_core::authz::Rbac;

/// A4/#649: every default non-admin role sees its OWN sessions, and neither can enumerate anyone
/// else's. Asserted in BOTH directions so a future widening of `session:read` into a default role
/// cannot land silently — the whole point of splitting the two permissions is that the estate-wide
/// half stays behind `lightbridge-admin`'s `*`.
#[test]
fn editor_and_viewer_get_session_read_own_but_not_estate_wide_session_read() {
    let compiled = Rbac::default().compile();
    for role in ["lightbridge-editor", "lightbridge-viewer"] {
        let set = compiled.roles.get(role).expect("role present");
        assert!(
            set.contains(Permission::SessionReadOwn),
            "{role} should be able to list its own sessions"
        );
        assert!(
            !set.contains(Permission::SessionRead),
            "{role} must not be able to enumerate another subject's sessions"
        );
    }
    let admin = compiled
        .roles
        .get("lightbridge-admin")
        .expect("admin role present");
    assert!(admin.contains(Permission::SessionRead));
    assert!(admin.contains(Permission::SessionReadOwn));
}

/// The three self-service "own" permissions travel together on both non-admin roles. Pinned as one
/// set because they are granted for one reason ("my own account is not administration"), so a
/// future edit that drops one of them should have to argue with this test.
#[test]
fn both_non_admin_roles_carry_the_full_self_service_own_set() {
    let compiled = Rbac::default().compile();
    for role in ["lightbridge-editor", "lightbridge-viewer"] {
        let set = compiled.roles.get(role).expect("role present");
        for permission in [
            Permission::SessionReadOwn,
            Permission::SessionRevokeOwn,
            Permission::BudgetReadOwn,
        ] {
            assert!(
                set.contains(permission),
                "{role} lost the self-service permission {}",
                permission.as_str()
            );
        }
    }
}
