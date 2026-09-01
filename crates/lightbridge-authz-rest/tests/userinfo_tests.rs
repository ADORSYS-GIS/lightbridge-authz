// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Claim projection for `/oauth2/userinfo` (OIDC Core 1.0 §5.3).
//!
//! Two properties, and the second is the one that matters:
//!
//! 1. `sub` is always present, `email`/`email_verified` only under the `email` scope (§5.4).
//! 2. **Authorization data never leaves through this endpoint.** `budget_tier`, `quota_tier`,
//!    `allowed_models`, `model_policy` and the roles claim all sit in the same access token this
//!    function reads from, one `claims.get` away. Nothing but an explicit allow-list stops a
//!    future edit from copying the whole map through, and the moment that happens UserInfo becomes
//!    a second, cacheable source of authorization truth that drifts from the resource server's.
//!    `only_identity_claims_are_projected` is the regression that catches it.
//!
//! Mutation-checked: replacing the body of `user_info_claims` with `Some(claims.clone())` turns
//! `only_identity_claims_are_projected` and `email_claims_require_the_email_scope` red;
//! removing the `scope_grants_email` guard turns the latter red on its own.

use lightbridge_authz_rest::userinfo::user_info_claims;
use serde_json::{Map, Value, json};

/// A human-plane access token's claim set as `oauth2_op::store` actually mints it: identity,
/// tenant context, and the authorization data this endpoint must not echo.
fn access_token_claims(scope: &str) -> Map<String, Value> {
    json!({
        "sub": "acct_alice",
        "scope": scope,
        "azp": "lightbridge-console",
        "typ": "Bearer",
        "email": "alice@example.test",
        "email_verified": true,
        "name": "Alice Example",
        "preferred_username": "alice",
        "account_id": "acct_owner",
        "project_id": "proj_main",
        "sid": "sess_abc",
        "api_key_id": "sess_abc",
        "budget_tier": "tier_2",
        "quota_tier": "gold",
        "model_policy": "allowlist",
        "allowed_models": ["gpt-4"],
        "lightbridge_api_roles": ["lightbridge-admin"],
    })
    .as_object()
    .unwrap()
    .clone()
}

#[test]
fn sub_is_always_projected() {
    let body = user_info_claims(&access_token_claims("openid")).expect("sub present");
    assert_eq!(body.get("sub").and_then(Value::as_str), Some("acct_alice"));
}

/// OIDC Core §5.3.2 makes `sub` REQUIRED. A token without one is malformed, and answering `200`
/// with a subject-less body would leave an RP silently matching the response to the wrong user.
#[test]
fn a_token_without_a_subject_yields_nothing() {
    let mut claims = access_token_claims("openid email");
    claims.remove("sub");
    assert!(user_info_claims(&claims).is_none());
}

#[test]
fn email_claims_require_the_email_scope() {
    let without = user_info_claims(&access_token_claims("openid profile")).expect("sub present");
    assert!(
        !without.contains_key("email") && !without.contains_key("email_verified"),
        "email must not be projected without the email scope, got {without:?}"
    );

    let with = user_info_claims(&access_token_claims("openid email")).expect("sub present");
    assert_eq!(
        with.get("email").and_then(Value::as_str),
        Some("alice@example.test")
    );
    assert_eq!(with.get("email_verified"), Some(&Value::Bool(true)));
}

/// `name`/`preferred_username`'s own version of `email_claims_require_the_email_scope` above:
/// gated on the `profile` scope, not `email`, and independent of it in both directions -- granting
/// one must never leak the other.
#[test]
fn profile_claims_require_the_profile_scope() {
    let without = user_info_claims(&access_token_claims("openid email")).expect("sub present");
    assert!(
        !without.contains_key("name") && !without.contains_key("preferred_username"),
        "profile claims must not be projected without the profile scope, got {without:?}"
    );

    let with = user_info_claims(&access_token_claims("openid profile")).expect("sub present");
    assert_eq!(
        with.get("name").and_then(Value::as_str),
        Some("Alice Example")
    );
    assert_eq!(
        with.get("preferred_username").and_then(Value::as_str),
        Some("alice")
    );
    assert!(
        !with.contains_key("email") && !with.contains_key("email_verified"),
        "the profile scope must not leak email on its own: {with:?}"
    );
}

/// The tenant pair is this deployment's own identity context and is what the console calls this
/// endpoint for; it is not scope-gated because there is no OIDC scope that describes it.
#[test]
fn tenant_context_is_projected() {
    let body = user_info_claims(&access_token_claims("openid")).expect("sub present");
    assert_eq!(
        body.get("account_id").and_then(Value::as_str),
        Some("acct_owner")
    );
    assert_eq!(
        body.get("project_id").and_then(Value::as_str),
        Some("proj_main")
    );
}

/// The allow-list regression. Named individually rather than asserted as "the body is small", so a
/// failure says exactly which claim leaked.
#[test]
fn only_identity_claims_are_projected() {
    let body = user_info_claims(&access_token_claims("openid email profile")).expect("sub present");

    for authorization_claim in [
        "budget_tier",
        "quota_tier",
        "model_policy",
        "allowed_models",
        "lightbridge_api_roles",
    ] {
        assert!(
            !body.contains_key(authorization_claim),
            "{authorization_claim} is authorization data and must not be served from UserInfo -- \
             it belongs to the resource server's per-request decision, not to a cacheable identity \
             response"
        );
    }

    for internal_claim in ["sid", "api_key_id", "azp", "typ", "scope"] {
        assert!(
            !body.contains_key(internal_claim),
            "{internal_claim} is token plumbing, not an identity claim about the end-user"
        );
    }

    let mut projected: Vec<&str> = body.keys().map(String::as_str).collect();
    projected.sort_unstable();
    assert_eq!(
        projected,
        [
            "account_id",
            "email",
            "email_verified",
            "name",
            "preferred_username",
            "project_id",
            "sub",
        ],
        "the projection is an allow-list; adding to it is a deliberate act that updates this test"
    );
}

/// A token carrying no `scope` claim at all -- the shape of a data-plane API-key JWT. The route
/// refuses these before ever calling this function (`insufficient_scope`), but the projection must
/// not hand out email on its own either.
#[test]
fn a_token_with_no_scope_claim_projects_no_email() {
    let mut claims = access_token_claims("openid email");
    claims.remove("scope");
    let body = user_info_claims(&claims).expect("sub present");
    assert!(!body.contains_key("email"));
    assert_eq!(body.get("sub").and_then(Value::as_str), Some("acct_alice"));
}
