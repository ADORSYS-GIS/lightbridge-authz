//! Shared test fixtures for the RFC 8252 §7.3 loopback modules.
//!
//! Lives in its own file (gated `#[cfg(test)]` at the `mod` declaration) so that
//! [`super::redirect`] and [`super::code`] can both use these clients and stores without either
//! file carrying the other's setup -- and so neither grows past the 200-LoC house ceiling.

use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::KvStore;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_op::client::{ClientRegistration, GrantType, TokenEndpointAuthMethod};
use authkestra_op::code::AuthorizationCode;
use authkestra_op::config::OpConfig;
use authkestra_op::device::DeviceCodeSession;
use authkestra_op::handlers::AuthorizeRequest;
use authkestra_op::refresh::RefreshToken;
use authkestra_op::store::CompositeOpStore;

/// A public client whose only registration is a real callback URL -- no loopback opt-in.
#[expect(
    deprecated,
    reason = "ClientRegistration::require_pkce is deprecated (authkestra#273) but is still a \
              required field on the struct. These fixtures never exercise it -- PKCE is enforced \
              unconditionally by `/authorize`, before either loopback module is reached."
)]
pub(crate) fn public_client() -> ClientRegistration {
    ClientRegistration {
        client_id: "governance-auth-cli".into(),
        client_secret_hash: None,
        redirect_uris: vec!["https://rp.example.test/callback".into()],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: vec!["openid".into()],
        require_pkce: true,
        allowed_audiences: vec![],
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::NoAuth),
        jwks: None,
    }
}

/// The shape actually deployed today: one fixed loopback port from the pinned block.
pub(crate) fn public_client_with_loopback() -> ClientRegistration {
    ClientRegistration {
        redirect_uris: vec!["http://127.0.0.1:17452/callback".into()],
        ..public_client()
    }
}

pub(crate) fn confidential_client_with_loopback() -> ClientRegistration {
    ClientRegistration {
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        ..public_client_with_loopback()
    }
}

pub(crate) fn op_config() -> OpConfig {
    OpConfig {
        issuer: "https://op.example.test".to_string(),
        scopes_supported: vec!["openid".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: 60,
        access_token_ttl_secs: 3600,
        device_code_ttl_secs: 600,
        token_exchange_enabled: false,
    }
}

pub(crate) fn identity() -> Identity {
    Identity {
        provider_id: "keycloak".to_string(),
        external_id: "subject-1".to_string(),
        email: None,
        username: None,
        attributes: std::collections::HashMap::new(),
    }
}

pub(crate) type TestStore = CompositeOpStore<
    MemoryStore<ClientRegistration>,
    MemoryStore<AuthorizationCode>,
    MemoryStore<RefreshToken>,
    MemoryStore<DeviceCodeSession>,
>;

pub(crate) async fn op_store(client: ClientRegistration) -> TestStore {
    let clients = MemoryStore::<ClientRegistration>::new();
    clients
        .set(
            &client.client_id.clone(),
            client,
            std::time::Duration::from_secs(31_536_000),
        )
        .await
        .expect("registering the test client must not error");
    CompositeOpStore::new(
        clients,
        MemoryStore::<AuthorizationCode>::new(),
        MemoryStore::<RefreshToken>::new(),
        MemoryStore::<DeviceCodeSession>::new(),
    )
}

/// A request for an ephemeral loopback port -- the shape the exact-match registry cannot serve.
pub(crate) fn ephemeral_port_request(client: &ClientRegistration) -> AuthorizeRequest {
    serde_json::from_value(serde_json::json!({
        "client_id": client.client_id,
        "redirect_uri": "http://127.0.0.1:54321/callback",
        "response_type": "code",
        "scope": "openid",
        "state": "xyz",
        "code_challenge": "s256challenge",
        "code_challenge_method": "S256",
    }))
    .expect("the fixture request must deserialize")
}
