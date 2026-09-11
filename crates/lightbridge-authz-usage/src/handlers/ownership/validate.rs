//! Common query-request validation for the shared ownership gate. Split out of
//! `handlers::ownership` to satisfy the LoC gate (lightbridge-governance#172); the pairing with
//! `auth.rs`/`scope.rs` is unchanged.

use crate::models::UsageScope;
use lightbridge_authz_core::Error;
use tracing::warn;

/// Validates the common query-request invariants shared across all grains:
/// - `scope_id` is present for non-`All` scopes
/// - `limit > 0`
///
/// Returns `Error::BadRequest` for any violation. Call this AFTER authentication but BEFORE
/// scope authorization, matching the existing `query_usage` convention (body validation runs
/// after auth, so an unauthenticated caller never learns whether a well-formed body was accepted).
///
/// Time-range validation (`start_time < end_time`) is intentionally NOT included here: the field
/// types differ per grain (some use `DateTime<Utc>`, future grains may use other representations),
/// so callers validate their own time types before calling this function.
pub fn validate_common_request(
    scope: &UsageScope,
    scope_id: &str,
    limit: u32,
) -> Result<(), Error> {
    if !matches!(scope, UsageScope::All) && scope_id.trim().is_empty() {
        warn!("missing scope_id for usage query");
        return Err(Error::BadRequest(
            "scope_id is required for usage queries".to_string(),
        ));
    }

    if limit == 0 {
        warn!("invalid limit for usage query: limit=0");
        return Err(Error::BadRequest(
            "limit must be greater than zero".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_common_request_rejects_empty_scope_id_for_non_all() {
        let result = validate_common_request(&UsageScope::Account, "", 100);
        assert!(matches!(result, Err(Error::BadRequest(_))));
    }

    #[test]
    fn validate_common_request_accepts_empty_scope_id_for_all() {
        let result = validate_common_request(&UsageScope::All, "", 100);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_common_request_rejects_zero_limit() {
        let result = validate_common_request(&UsageScope::Account, "acct-1", 0);
        assert!(matches!(result, Err(Error::BadRequest(_))));
    }
}
