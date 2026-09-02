//! `ConfigClientStore` behavior tests -- relocated out of
//! `crates/lightbridge-authz-rest/src/oauth2_op/client_store.rs`'s own `#[cfg(test)]` module (house
//! rule: tests belong in `tests/`, not `src/`) to make room there for the per-client refresh-TTL
//! fields/lookup without pushing that file over the workspace's 200-LoC default ceiling.

use authkestra_op::{ClientStore, TokenEndpointAuthMethod};
use lightbridge_authz_core::config::{Oauth2TokenExchange, OauthClient, OauthClientType};
use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;

fn client(client_id: &str, client_type: OauthClientType) -> OauthClient {
    OauthClient {
        client_id: client_id.to_string(),
        client_type,
        scopes: vec!["openid".to_string()],
        grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

fn global_cfg() -> Oauth2TokenExchange {
    Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        authorization_code_ttl_seconds: 300,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec!["openid".to_string()],
        refresh_absolute_ttl_seconds: 7_776_000,
        refresh_reuse_grace_seconds: 30,
        device_code_ttl_seconds: 600,
        device_poll_interval_seconds: 5,
        device_verification_uri: "https://authz.example.test/device/verify".to_string(),
        client_credentials_ttl_seconds: 900,
    }
}

#[tokio::test]
async fn finds_a_configured_client() {
    let store = ConfigClientStore::from_config(
        &[client("lightbridge-ss", OauthClientType::Public)],
        &global_cfg(),
    );
    let found = store.find_client("lightbridge-ss").await.unwrap().unwrap();
    assert_eq!(found.client_id, "lightbridge-ss");
    assert_eq!(
        found.token_endpoint_auth_method,
        Some(TokenEndpointAuthMethod::NoAuth)
    );
    assert!(found.redirect_uris.is_empty());
    assert!(found.client_secret_hash.is_none());
}

#[tokio::test]
async fn unknown_client_is_none_not_an_error() {
    let store = ConfigClientStore::from_config(&[], &global_cfg());
    assert!(store.find_client("nope").await.unwrap().is_none());
}

#[tokio::test]
async fn confidential_client_maps_to_private_key_jwt() {
    let store = ConfigClientStore::from_config(
        &[client("lightbridge-mcp", OauthClientType::Confidential)],
        &global_cfg(),
    );
    let found = store.find_client("lightbridge-mcp").await.unwrap().unwrap();
    assert_eq!(
        found.token_endpoint_auth_method,
        Some(TokenEndpointAuthMethod::PrivateKeyJwt)
    );
}

/// #534/ADR-0030: `Service` (`client_credentials`/M2M) clients authenticate identically to
/// `Confidential` -- ADR-0011 Decision 6 draws no exception for machine clients.
#[tokio::test]
async fn service_client_maps_to_private_key_jwt() {
    let store = ConfigClientStore::from_config(
        &[client("it-machine", OauthClientType::Service)],
        &global_cfg(),
    );
    let found = store.find_client("it-machine").await.unwrap().unwrap();
    assert_eq!(
        found.token_endpoint_auth_method,
        Some(TokenEndpointAuthMethod::PrivateKeyJwt)
    );
}
