//! `authkestra_op::client::ClientStore` backed by the config-defined client list (ADR-0011,
//! Decision 5). Not a database: clients are read once at startup from `oauth2.clients` and held
//! in memory for the process lifetime -- adding or rotating a client is a config change and
//! redeploy, a deliberate limitation (see the ADR's Decision 5 "revisit trigger").

use std::collections::HashMap;

use authkestra_op::{ClientRegistration, ClientStore, GrantType, OpError, TokenEndpointAuthMethod};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{Oauth2TokenExchange, OauthClient, OauthClientType};

use super::refresh_ttl::effective_refresh_ttls;

/// In-memory `client_id -> ClientRegistration` lookup built once from `oauth2.clients`, plus the
/// per-client refresh-token TTL resolution (repo owner request: "the duration of a refresh token
/// should be configurable on the client entry in the .yaml config file") -- a parallel map instead
/// of threading `Oauth2TokenExchange` itself into `TokenExchangeOpStore`'s per-request paths.
pub struct ConfigClientStore {
    clients: HashMap<String, ClientRegistration>,
    /// `client_id -> (refresh_ttl_seconds, refresh_absolute_ttl_seconds)`, each pair already
    /// resolved (client override, or the server-wide `Oauth2TokenExchange` fallback) once here at
    /// construction time -- see [`Self::refresh_ttls`].
    refresh_ttls: HashMap<String, (i64, i64)>,
    /// The server-wide pair, kept for a `client_id` this store has no entry for (never expected
    /// in production -- every caller of [`Self::refresh_ttls`] already resolved the client via
    /// [`ClientStore::find_client`] first -- but a lookup miss must still resolve to a sane value
    /// rather than panic).
    default_refresh_ttls: (i64, i64),
}

impl ConfigClientStore {
    pub fn from_config(clients: &[OauthClient], global: &Oauth2TokenExchange) -> Self {
        let refresh_ttls = clients
            .iter()
            .map(|c| (c.client_id.clone(), effective_refresh_ttls(c, global)))
            .collect();
        let clients = clients
            .iter()
            .map(|c| (c.client_id.clone(), to_registration(c)))
            .collect();
        Self {
            clients,
            refresh_ttls,
            default_refresh_ttls: (
                global.refresh_ttl_seconds,
                global.refresh_absolute_ttl_seconds,
            ),
        }
    }

    /// The effective `(refresh_ttl_seconds, refresh_absolute_ttl_seconds)` pair for `client_id`,
    /// already resolved at construction time (client override, else the server-wide default).
    pub fn refresh_ttls(&self, client_id: &str) -> (i64, i64) {
        self.refresh_ttls
            .get(client_id)
            .copied()
            .unwrap_or(self.default_refresh_ttls)
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

// Behavior tests for this module live in `tests/client_store_tests.rs` (house rule: new/relocated
// tests belong in a dedicated `tests/` file, not `src/`) -- moved there to make room for the
// per-client refresh-TTL fields/lookup added above without pushing this file over the workspace's
// 200-LoC default ceiling for a file with no `.github/loc-baseline.json` entry.
