//! [`PermissionSet`] — the set of [`Permission`]s a caller holds.
//!
//! Lives in its own module rather than alongside [`Permission`] in `authz.rs` purely because that
//! file sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be touched
//! but not grown — the same reason `lightbridge-authz-api-key`'s `session_revocation.rs` is
//! separate from its `repo.rs`. Moved verbatim; `authz.rs` re-exports it, so every existing
//! `lightbridge_authz_core::authz::PermissionSet` path still resolves.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::authz::Permission;
use crate::error::Error;

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
