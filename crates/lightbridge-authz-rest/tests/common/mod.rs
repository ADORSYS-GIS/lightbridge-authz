// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Shared helpers for the RPC-surface integration tests (`rpc_router_tests.rs`,
//! `rpc_it_tests.rs`). Not a test binary itself (subdir `mod.rs`), so nothing here is discovered as
//! a test. `dead_code` is allowed because each including binary uses a different subset.
#![allow(dead_code)]

use std::collections::HashMap;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use cratestack_codec_cbor::CborCodec;
use cratestack_codec_json::JsonCodec;
use cratestack_core::CratestackCodec;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::authz::{Permission, PermissionSet};
use lightbridge_authz_core::config::{Oauth2, Oauth2Type};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_rest::auth_provider::SubjectResolver;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

/// A trust-everything [`SubjectResolver`] test double (ADR-0025): resolves any `(iss, sub)` to
/// `AccountId::assert_already_resolved(sub)` unconditionally, never touching a database. Correct for every
/// test that is not itself about resolver behavior (those live in `idp_server_tests.rs`'s own
/// `federated_subject_resolution_tests.rs`-style coverage instead).
pub struct TrustEverythingResolver;

#[async_trait]
impl SubjectResolver for TrustEverythingResolver {
    async fn resolve(
        &self,
        _iss: &str,
        sub: &str,
    ) -> lightbridge_authz_core::error::Result<AccountId> {
        Ok(AccountId::assert_already_resolved(sub))
    }
}

pub fn test_resolver() -> Arc<dyn SubjectResolver> {
    Arc::new(TrustEverythingResolver)
}

/// A bearer service that maps a token *string* to a preconfigured [`TokenInfo`], so a single router
/// can serve several identities (admin / viewer / editor) just by varying the `Authorization`
/// header. Unknown tokens fail validation (→ the gate/auth-provider treat that as 401), mirroring a
/// rejected JWT.
pub struct MapBearer {
    map: HashMap<String, TokenInfo>,
}

impl MapBearer {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn with(mut self, token: &str, info: TokenInfo) -> Self {
        self.map.insert(token.to_owned(), info);
        self
    }
}

#[async_trait]
impl BearerTokenServiceTrait for MapBearer {
    async fn validate_bearer_token(&self, token: &str) -> anyhow::Result<TokenInfo> {
        self.map
            .get(token)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown token"))
    }
}

/// A [`TokenInfo`] for `subject` carrying exactly `perms` (active, no roles). The `access_token`
/// echoes the subject so a procedure that reuses it downstream has something deterministic.
pub fn token_info(subject: &str, perms: PermissionSet) -> TokenInfo {
    TokenInfo {
        active: true,
        sub: subject.to_owned(),
        iss: "https://keycloak.example.test/realms/dev".to_string(),
        exp: 0,
        aud: vec![],
        roles: vec![],
        permissions: perms,
        caller_kind: None,
        access_token: format!("access-{subject}"),
    }
}

/// Like [`token_info`], but stamped with [`lightbridge_authz_bearer::API_KEY_CALLER_KIND`], as an
/// `oauth2.type: self` self-signed API-key JWT -- and, per #419, every human-plane RFC 8693
/// exchange token too -- would be (see `access_token_extra` in `lightbridge-authz-rest::signing`).
/// `requestBudgetRefill` no longer refuses a caller for carrying this signal (#191/#216's gate
/// was deleted by #419: it fired on humans, and was never load-bearing for service accounts to
/// begin with -- see that PR's description). Kept for tests that want to prove a specific caller
/// is served or refused independent of this signal.
pub fn api_key_token_info(subject: &str, perms: PermissionSet) -> TokenInfo {
    TokenInfo {
        caller_kind: Some(lightbridge_authz_bearer::API_KEY_CALLER_KIND.to_owned()),
        ..token_info(subject, perms)
    }
}

/// `lightbridge-admin`-equivalent: every permission.
pub fn admin_perms() -> PermissionSet {
    Permission::ALL.into_iter().collect()
}

/// `lightbridge-viewer`-equivalent: read-only across all three resources.
pub fn viewer_perms() -> PermissionSet {
    [
        Permission::AccountRead,
        Permission::ProjectRead,
        Permission::ApiKeyRead,
    ]
    .into_iter()
    .collect()
}

/// External-mode oauth2 with RBAC defaults — the RPC router only needs it for the self-signed
/// well-known branch, which stays off here.
pub fn external_oauth2() -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url: "http://jwks".to_string(),
        jwks_ca_bundle_path: None,
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience: None,
        signing: None,
        token_exchange: None,
        relying_party: None,
        rbac: Default::default(),
        clients: Vec::new(),
        federation: Some(lightbridge_authz_core::config::Federation {
            issuer: "https://keycloak.example.test/realms/dev".to_string(),
            discovery_url: None,
        }),
    }
}

/// `Cbor` is the only wire format the router actually serves (ADR-0013 — CBOR is the only
/// transport codec). `Json` is kept solely as a negative-path probe: encoding a request with it
/// and expecting the router to reject it (415) is how tests prove the cutover, rather than testing
/// nothing by only ever sending the format the server accepts. `encode`/`decode` go through the
/// *exact* same codecs the server/rejection path uses, so a round-trip is guaranteed faithful (no
/// hand-rolled CBOR).
#[derive(Clone, Copy)]
pub enum Wire {
    /// Rejected by every real router post-ADR-0013 — use only to assert a 415.
    Json,
    Cbor,
}

impl Wire {
    pub fn content_type(&self) -> &'static str {
        match self {
            Wire::Json => "application/json",
            Wire::Cbor => "application/cbor",
        }
    }

    pub fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Vec<u8> {
        match self {
            Wire::Json => JsonCodec.encode(value).expect("json encode"),
            Wire::Cbor => CborCodec.encode(value).expect("cbor encode"),
        }
    }

    pub fn decode<T: for<'de> serde::Deserialize<'de>>(&self, bytes: &[u8]) -> T {
        match self {
            Wire::Json => JsonCodec.decode(bytes).expect("json decode"),
            Wire::Cbor => CborCodec.decode(bytes).expect("cbor decode"),
        }
    }
}

/// `POST /rpc/{op_id}` with `body` encoded via `wire`, optionally bearer-authenticated. Returns the
/// HTTP status and raw response bytes (decode with `wire.decode` on success, or as an `RpcErrorBody`
/// on error). The `Accept` header pins the response codec to the same `wire`.
pub async fn rpc_call<T: Serialize + ?Sized>(
    router: Router,
    op_id: &str,
    wire: Wire,
    body: &T,
    token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    rpc_call_at(router, "", op_id, wire, body, token).await
}

/// Like [`rpc_call`], but against `POST {base_path}/rpc/{op_id}` — for a router mounted under a
/// prefix, e.g. `authz-budget`'s fixed `/budget` (`build_budget_router`) or `authz-api`'s
/// configurable `rpc_base_path`. `base_path` is used verbatim (no leading-slash normalization —
/// callers pass `""` for a root mount, matching [`rpc_call`]'s own behavior).
pub async fn rpc_call_at<T: Serialize + ?Sized>(
    router: Router,
    base_path: &str,
    op_id: &str,
    wire: Wire,
    body: &T,
    token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("{base_path}/rpc/{op_id}"))
        .header("content-type", wire.content_type())
        .header("accept", wire.content_type());
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Body::from(wire.encode(body))).unwrap();
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body readable");
    (status, bytes.to_vec())
}

/// Convenience: decode a success body as `serde_json::Value` regardless of wire (both codecs
/// round-trip through `Value`).
pub fn as_json(wire: Wire, bytes: &[u8]) -> Value {
    wire.decode(bytes)
}
