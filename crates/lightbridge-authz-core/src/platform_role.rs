//! The platform-role catalogue: which role names `platform_role_grants` may hold (ADR-0033).
//!
//! There is deliberately no enum and no database `CHECK` here. The set of real roles is operator
//! configuration -- `oauth2.rbac.role_permissions`, defaulting to [`default_role_permissions`] --
//! so the only honest validation is "is this one of the roles THIS deployment has configured".
//! Baking a list into the schema or into a Rust enum would hard-code one deployment's config, and
//! skipping validation entirely would let `rbac grant --role lightbridge-admn` write a row that
//! silently confers nothing: `permissions_for_roles` maps an unrecognized role to the (empty by
//! default) `default_grants` set, so the typo would look exactly like a successful grant right up
//! until the person it was for could not do anything.
//!
//! Both writers -- the `grantPlatformRole` procedure and the `lightbridge-authz rbac grant` CLI --
//! validate through [`validate_platform_role`] against the SAME catalogue, so neither can create a
//! row the other would refuse.

use crate::authz::{Rbac, default_role_permissions};
use crate::error::{Error, Result};

/// Every role name this deployment recognizes, sorted for a stable error message and a stable
/// `--help`-style listing. Mirrors [`Rbac::compile`]'s own source selection exactly: the configured
/// `role_permissions` map when it is non-empty, the built-in defaults otherwise -- so the
/// catalogue can never disagree with the map the server actually enforces.
pub fn known_platform_roles(rbac: &Rbac) -> Vec<String> {
    let mut roles: Vec<String> = if rbac.role_permissions.is_empty() {
        default_role_permissions().into_keys().collect()
    } else {
        rbac.role_permissions.keys().cloned().collect()
    };
    roles.sort();
    roles
}

/// Normalizes and checks a caller-supplied role name against `known`.
///
/// Returns the TRIMMED role on success, so a stray newline from a `kubectl exec` heredoc cannot
/// produce a `"lightbridge-admin\n"` row that no claim mapper will ever match. Refuses -- rather
/// than silently accepting -- an unknown name, and names the catalogue in the error so an operator
/// who typo'd can see the real options without going to read a values file.
///
/// Case-SENSITIVE on purpose: the role string ends up in a JWT claim that
/// `permissions_for_roles` looks up by exact key, so accepting `Lightbridge-Admin` here would
/// create a grant that mints a claim value matching nothing.
pub fn validate_platform_role(role: &str, known: &[String]) -> Result<String> {
    let trimmed = role.trim();
    if trimmed.is_empty() {
        return Err(Error::BadRequest("role must not be empty".to_string()));
    }
    if !known.iter().any(|candidate| candidate == trimmed) {
        return Err(Error::BadRequest(format!(
            "unknown role '{trimmed}'; configured roles are: {}",
            known.join(", ")
        )));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn an_unconfigured_deployment_falls_back_to_the_built_in_roles() {
        let roles = known_platform_roles(&Rbac::default());
        assert_eq!(
            roles,
            vec![
                "lightbridge-admin".to_string(),
                "lightbridge-editor".to_string(),
                "lightbridge-viewer".to_string(),
            ]
        );
    }

    #[test]
    fn a_configured_map_replaces_the_defaults_entirely() {
        let rbac = Rbac {
            role_permissions: HashMap::from([(
                "platform-owner".to_string(),
                vec!["*".to_string()],
            )]),
            ..Rbac::default()
        };
        assert_eq!(
            known_platform_roles(&rbac),
            vec!["platform-owner".to_string()]
        );
        // The built-in name is NOT valid here: this deployment does not configure it, so a grant
        // for it would confer nothing.
        assert!(validate_platform_role("lightbridge-admin", &known_platform_roles(&rbac)).is_err());
    }

    #[test]
    fn whitespace_is_trimmed_and_case_is_significant() {
        let known = known_platform_roles(&Rbac::default());
        assert_eq!(
            validate_platform_role("  lightbridge-admin\n", &known).unwrap(),
            "lightbridge-admin"
        );
        assert!(validate_platform_role("Lightbridge-Admin", &known).is_err());
        assert!(validate_platform_role("   ", &known).is_err());
    }

    #[test]
    fn the_refusal_names_the_configured_catalogue() {
        let known = known_platform_roles(&Rbac::default());
        let err = validate_platform_role("lightbridge-admn", &known).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("lightbridge-admn"), "{message}");
        assert!(message.contains("lightbridge-viewer"), "{message}");
    }
}
