//! Shared test doubles for `UsageState::bearer`/`UsageState::scope_authority` (#570), used by
//! several `tests/*.rs` integration-test binaries in this crate. Lives under `tests/support/` (a
//! subdirectory, not a top-level `tests/*.rs` file) specifically so Cargo does not treat it as its
//! own test binary -- each file that wants it declares `#[path = "support/mod.rs"] mod support;`.

#![allow(dead_code)]

use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::authz::PermissionSet;
use lightbridge_authz_usage_rest::models::UsageScope;
use lightbridge_authz_usage_rest::scope_authority::ScopeAuthority;
use std::collections::HashMap;
use std::sync::Arc;

fn token_info(iss: &str, sub: &str, token: &str, permissions: PermissionSet) -> TokenInfo {
    TokenInfo {
        active: true,
        sub: sub.to_string(),
        iss: iss.to_string(),
        exp: 9_999_999_999,
        aud: vec![],
        roles: vec![],
        permissions,
        caller_kind: None,
        access_token: token.to_string(),
    }
}

/// A configurable [`BearerTokenServiceTrait`] test double: known tokens resolve to a fixed
/// `(iss, sub)`, anything else fails validation (the fail-closed default a caller that never
/// registers a token gets for free).
#[derive(Default)]
pub struct FakeBearer {
    tokens: HashMap<String, TokenInfo>,
}

impl FakeBearer {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_token(mut self, token: &str, iss: &str, sub: &str) -> Self {
        self.tokens.insert(
            token.to_string(),
            token_info(iss, sub, token, PermissionSet::default()),
        );
        self
    }

    /// Like [`Self::with_token`], but the resulting caller also holds `permissions` -- for tests
    /// exercising a permission-gated scope (`scope=all`, see [`Permission::UsageReadAll`]).
    #[must_use]
    pub fn with_token_and_permissions(
        mut self,
        token: &str,
        iss: &str,
        sub: &str,
        permissions: PermissionSet,
    ) -> Self {
        self.tokens
            .insert(token.to_string(), token_info(iss, sub, token, permissions));
        self
    }
}

#[async_trait]
impl BearerTokenServiceTrait for FakeBearer {
    async fn validate_bearer_token(&self, token: &str) -> anyhow::Result<TokenInfo> {
        self.tokens
            .get(token)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown token"))
    }
}

/// A [`BearerTokenServiceTrait`] that rejects every token -- for tests that build a
/// `UsageState`/router only to exercise routes that never reach the bearer check (ingest, health
/// probes).
pub fn trust_no_one_bearer() -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(FakeBearer::new())
}

/// A [`BearerTokenServiceTrait`] that accepts exactly `token`, resolving to `(iss, sub)`.
pub fn bearer_with(token: &str, iss: &str, sub: &str) -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(FakeBearer::new().with_token(token, iss, sub))
}

/// Like [`bearer_with`], but the resulting caller also holds `permissions` -- for tests
/// exercising `scope=all` (gated on `Permission::UsageReadAll`).
pub fn bearer_with_permissions(
    token: &str,
    iss: &str,
    sub: &str,
    permissions: PermissionSet,
) -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(FakeBearer::new().with_token_and_permissions(token, iss, sub, permissions))
}

/// A configurable [`ScopeAuthority`] test double: authorizes exactly the `(issuer, subject,
/// scope, scope_id)` tuples registered via [`Self::authorize`], refusing everything else --
/// mirroring the real `RemoteScopeAuthority`'s fail-closed default for an unrecognized
/// combination.
#[derive(Default)]
pub struct FakeScopeAuthority {
    authorized: std::sync::Mutex<Vec<(String, String, String, String)>>,
}

fn scope_key(scope: &UsageScope) -> &'static str {
    match scope {
        UsageScope::Account => "account",
        UsageScope::Project => "project",
        UsageScope::User => "user",
        UsageScope::ApiKey => "api_key",
        UsageScope::All => "all",
    }
}

impl FakeScopeAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn authorizing(
        self,
        issuer: &str,
        subject: &str,
        scope: &UsageScope,
        scope_id: &str,
    ) -> Self {
        self.authorized.lock().expect("lock should work").push((
            issuer.to_string(),
            subject.to_string(),
            scope_key(scope).to_string(),
            scope_id.to_string(),
        ));
        self
    }
}

#[async_trait]
impl ScopeAuthority for FakeScopeAuthority {
    async fn authorize(
        &self,
        issuer: &str,
        subject: &str,
        scope: &UsageScope,
        scope_id: &str,
    ) -> lightbridge_authz_core::Result<bool> {
        let key = (
            issuer.to_string(),
            subject.to_string(),
            scope_key(scope).to_string(),
            scope_id.to_string(),
        );
        Ok(self
            .authorized
            .lock()
            .expect("lock should work")
            .contains(&key))
    }
}

/// A [`ScopeAuthority`] that refuses every request -- the fail-closed default for tests that never
/// exercise `/usage/v1/usage/query`'s ownership check.
pub fn refuse_everything_scope_authority() -> Arc<dyn ScopeAuthority> {
    Arc::new(FakeScopeAuthority::new())
}
