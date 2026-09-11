//! Scope-authorization tests for the shared ownership gate (`handlers::ownership::authorize_scope`).
//!
//! These live in the integration-test tree rather than `src/handlers/ownership/scope.rs` because
//! the LoC gate (lightbridge-governance#172) reports -- but never fails -- files under a `tests/`
//! directory, and the scope × permission matrix is too large to keep `scope.rs` under the
//! 200-line ceiling with its tests inline. The tests are verbatim relocations of the original
//! `#[cfg(test)] mod tests` block from `handlers/ownership.rs`; only the import path changed.

use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::authz::PermissionSet;
use lightbridge_authz_core::{Permission, async_trait};
use lightbridge_authz_usage_rest::handlers::ownership::{
    GrainScope, ScopeAuthOutcome, authorize_scope,
};
use lightbridge_authz_usage_rest::models::UsageScope;
use lightbridge_authz_usage_rest::scope_authority::ScopeAuthority;

fn token_info(sub: &str, permissions: PermissionSet) -> TokenInfo {
    TokenInfo {
        active: true,
        sub: sub.to_string(),
        iss: "https://issuer.test".to_string(),
        exp: 9_999_999_999,
        aud: vec![],
        roles: vec![],
        permissions,
        caller_kind: None,
        access_token: "token".to_string(),
    }
}

fn plain_token(sub: &str) -> TokenInfo {
    token_info(sub, PermissionSet::default())
}

fn admin_token(sub: &str) -> TokenInfo {
    token_info(sub, PermissionSet::from_iter([Permission::UsageReadAll]))
}

/// A `ScopeAuthority` that authorizes everything -- proves the DaySeat model never consults
/// the authority for `user`/`all` (they are decided from the token alone), and that
/// `api_key` stays refused even when the authority would say yes.
struct AuthorizeEverything;

#[async_trait]
impl ScopeAuthority for AuthorizeEverything {
    async fn authorize(
        &self,
        _issuer: &str,
        _subject: &str,
        _scope: &UsageScope,
        _scope_id: &str,
    ) -> lightbridge_authz_core::Result<bool> {
        Ok(true)
    }
}

/// A `ScopeAuthority` that refuses everything -- the fail-closed default.
struct RefuseEverything;

#[async_trait]
impl ScopeAuthority for RefuseEverything {
    async fn authorize(
        &self,
        _issuer: &str,
        _subject: &str,
        _scope: &UsageScope,
        _scope_id: &str,
    ) -> lightbridge_authz_core::Result<bool> {
        Ok(false)
    }
}

// -----------------------------------------------------------------------
// authorize_scope -- GrainScope::DaySeat (the two-scope model #586)
// -----------------------------------------------------------------------

#[tokio::test]
async fn day_seat_user_scope_authorizes_the_callers_own_subject() {
    let outcome = authorize_scope(
        &RefuseEverything,
        &plain_token("sub-a"),
        &UsageScope::User,
        "sub-a",
        GrainScope::DaySeat,
    )
    .await;
    assert!(
        matches!(outcome, ScopeAuthOutcome::Authorized),
        "scope=user with the caller's own subject must be authorized, got {outcome:?}"
    );
}

#[tokio::test]
async fn day_seat_user_scope_refuses_another_subject() {
    let outcome = authorize_scope(
        &AuthorizeEverything,
        &plain_token("sub-a"),
        &UsageScope::User,
        "sub-victim",
        GrainScope::DaySeat,
    )
    .await;
    assert!(
        matches!(outcome, ScopeAuthOutcome::Forbidden(_)),
        "scope=user for another subject must be refused even when the authority says yes"
    );
}

#[tokio::test]
async fn day_seat_user_scope_allows_usage_read_all_for_any_subject() {
    let outcome = authorize_scope(
        &RefuseEverything,
        &admin_token("sub-admin"),
        &UsageScope::User,
        "sub-someone-else",
        GrainScope::DaySeat,
    )
    .await;
    assert!(
        matches!(outcome, ScopeAuthOutcome::Authorized),
        "a usage:read-all holder may read any subject's day/seat user scope"
    );
}

#[tokio::test]
async fn day_seat_all_scope_requires_usage_read_all() {
    let refused = authorize_scope(
        &AuthorizeEverything,
        &plain_token("sub-a"),
        &UsageScope::All,
        "",
        GrainScope::DaySeat,
    )
    .await;
    assert!(
        matches!(refused, ScopeAuthOutcome::Forbidden(_)),
        "scope=all without usage:read-all must be refused"
    );

    let allowed = authorize_scope(
        &RefuseEverything,
        &admin_token("sub-admin"),
        &UsageScope::All,
        "",
        GrainScope::DaySeat,
    )
    .await;
    assert!(
        matches!(allowed, ScopeAuthOutcome::Authorized),
        "scope=all with usage:read-all must be authorized"
    );
}

#[tokio::test]
async fn day_seat_rejects_account_project_and_api_key_scopes_with_bad_request() {
    for scope in [UsageScope::Account, UsageScope::Project, UsageScope::ApiKey] {
        let outcome = authorize_scope(
            &AuthorizeEverything,
            &admin_token("sub-admin"),
            &scope,
            "whatever",
            GrainScope::DaySeat,
        )
        .await;
        assert!(
            matches!(outcome, ScopeAuthOutcome::BadRequest(_)),
            "day/seat grain must reject scope {scope:?} with a 400, got {outcome:?}"
        );
    }
}

// -----------------------------------------------------------------------
// authorize_scope -- GrainScope::Legacy (the existing five-scope model)
// -----------------------------------------------------------------------

#[tokio::test]
async fn legacy_account_scope_consults_the_authority() {
    let authorized = authorize_scope(
        &AuthorizeEverything,
        &plain_token("sub-a"),
        &UsageScope::Account,
        "acct-1",
        GrainScope::Legacy,
    )
    .await;
    assert!(matches!(authorized, ScopeAuthOutcome::Authorized));

    let refused = authorize_scope(
        &RefuseEverything,
        &plain_token("sub-a"),
        &UsageScope::Account,
        "acct-1",
        GrainScope::Legacy,
    )
    .await;
    assert!(matches!(refused, ScopeAuthOutcome::Forbidden(_)));
}

#[tokio::test]
async fn legacy_api_key_scope_is_refused_even_for_usage_read_all() {
    let outcome = authorize_scope(
        &AuthorizeEverything,
        &admin_token("sub-admin"),
        &UsageScope::ApiKey,
        "key_1",
        GrainScope::Legacy,
    )
    .await;
    assert!(
        matches!(outcome, ScopeAuthOutcome::Forbidden(_)),
        "api_key has no ownership authority and must stay refused for everyone"
    );
}

#[tokio::test]
async fn legacy_user_scope_self_ownership_and_admin_bypass() {
    let own = authorize_scope(
        &RefuseEverything,
        &plain_token("sub-a"),
        &UsageScope::User,
        "sub-a",
        GrainScope::Legacy,
    )
    .await;
    assert!(matches!(own, ScopeAuthOutcome::Authorized));

    let other = authorize_scope(
        &AuthorizeEverything,
        &plain_token("sub-a"),
        &UsageScope::User,
        "sub-victim",
        GrainScope::Legacy,
    )
    .await;
    assert!(matches!(other, ScopeAuthOutcome::Forbidden(_)));

    let admin = authorize_scope(
        &RefuseEverything,
        &admin_token("sub-admin"),
        &UsageScope::User,
        "sub-someone-else",
        GrainScope::Legacy,
    )
    .await;
    assert!(matches!(admin, ScopeAuthOutcome::Authorized));
}
