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
use cratestack_core::CoolCodec;
use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::authz::{Permission, PermissionSet};
use lightbridge_authz_core::config::{Oauth2, Oauth2Type};
use serde::Serialize;
use serde_json::Value;
use tower::ServiceExt;

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
        exp: 0,
        aud: vec![],
        roles: vec![],
        permissions: perms,
        caller_kind: None,
        access_token: format!("access-{subject}"),
    }
}

/// Like [`token_info`], but stamped with [`lightbridge_authz_bearer::API_KEY_CALLER_KIND`], as an
/// `oauth2.type: self` self-signed API-key JWT would be (see `ApiKeyClaims` in
/// `lightbridge-authz-rest::signing`). Used to exercise the caller-kind refusal in
/// `requestBudgetRefill` (#191/#216).
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
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience: None,
        signing: None,
        token_exchange: None,
        rbac: Default::default(),
        clients: Vec::new(),
    }
}

/// The two wire formats the `CodecSet` router serves. `encode`/`decode` go through the *exact* same
/// codecs the server uses, so a round-trip is guaranteed faithful (no hand-rolled CBOR).
#[derive(Clone, Copy)]
pub enum Wire {
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
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/rpc/{op_id}"))
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
