//! `authkestra_op::client::ClientStore` backed by the config-defined client list (ADR-0011,
//! Decision 5). Not a database: clients are read once at startup from `oauth2.clients` and held
//! in memory for the process lifetime -- adding or rotating a client is a config change and
//! redeploy, a deliberate limitation (see the ADR's Decision 5 "revisit trigger").

use std::collections::HashMap;

use authkestra_op::{ClientRegistration, ClientStore, GrantType, OpError, TokenEndpointAuthMethod};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{OauthClient, OauthClientType};

/// In-memory `client_id -> ClientRegistration` lookup built once from `oauth2.clients`.
pub struct ConfigClientStore {
    clients: HashMap<String, ClientRegistration>,
}

impl ConfigClientStore {
    pub fn from_config(clients: &[OauthClient]) -> Self {
        let clients = clients
            .iter()
            .map(|c| (c.client_id.clone(), to_registration(c)))
            .collect();
        Self { clients }
    }
}

#[async_trait]
impl ClientStore for ConfigClientStore {
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
        Ok(self.clients.get(client_id).cloned())
    }
}

/// Maps our config shape onto `authkestra_op::client::ClientRegistration`'s 9 fields.
/// `client_secret_hash` is always `None`; browser registration settings are sourced directly from
/// the reviewed config. `Service` (#534, ADR-0030: `client_credentials`/M2M clients) maps to the
/// SAME `PrivateKeyJwt` method as `Confidential` -- ADR-0011 Decision 6 draws no exception for
/// machine clients, so the two variants only differ at the config-review layer, never here.
#[expect(
    deprecated,
    reason = "ClientRegistration::require_pkce is deprecated (authkestra#273) because PKCE is \
              mandatory for every authorization_code client and no longer read by upstream's \
              handlers. The field is still required and retained for wire/storage compatibility, \
              so we keep writing it from config; this repo's own PKCE enforcement is the \
              unconditional /authorize and token-endpoint checks, not this field."
)]
fn to_registration(client: &OauthClient) -> ClientRegistration {
    ClientRegistration {
        client_id: client.client_id.clone(),
        client_secret_hash: None,
        redirect_uris: client.redirect_uris.clone(),
        grant_types: client
            .grant_types
            .iter()
            .map(|g| parse_grant_type(g))
            .collect(),
        scopes: client.scopes.clone(),
        require_pkce: client.require_pkce,
        allowed_audiences: client.allowed_audiences.clone(),
        token_endpoint_auth_method: Some(match client.client_type {
            OauthClientType::Public => TokenEndpointAuthMethod::NoAuth,
            OauthClientType::Confidential | OauthClientType::Service => {
                TokenEndpointAuthMethod::PrivateKeyJwt
            }
        }),
        jwks: client.jwks.clone(),
    }
}

/// Mirrors `authkestra_op::client::GrantType`'s private `Deserialize` impl (the same match arms,
/// applied to a plain config string instead of through serde) -- duplicated rather than reused
/// because that impl is not exposed as a standalone string-parsing function.
fn parse_grant_type(raw: &str) -> GrantType {
    match raw {
        "authorization_code" => GrantType::AuthorizationCode,
        "refresh_token" => GrantType::RefreshToken,
        "client_credentials" => GrantType::ClientCredentials,
        "urn:ietf:params:oauth:grant-type:device_code" => GrantType::DeviceCode,
        "urn:ietf:params:oauth:grant-type:token-exchange" => GrantType::TokenExchange,
        other => GrantType::Custom(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
    }

    #[tokio::test]
    async fn finds_a_configured_client() {
        let store =
            ConfigClientStore::from_config(&[client("lightbridge-ss", OauthClientType::Public)]);
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
        let store = ConfigClientStore::from_config(&[]);
        assert!(store.find_client("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn confidential_client_maps_to_private_key_jwt() {
        let store = ConfigClientStore::from_config(&[client(
            "lightbridge-mcp",
            OauthClientType::Confidential,
        )]);
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
        let store =
            ConfigClientStore::from_config(&[client("it-machine", OauthClientType::Service)]);
        let found = store.find_client("it-machine").await.unwrap().unwrap();
        assert_eq!(
            found.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
    }
}
