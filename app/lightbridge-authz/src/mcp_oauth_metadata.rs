//! OAuth2 authorization-server metadata the MCP listener advertises, and the resolution of the
//! upstream endpoints it is derived from.
//!
//! Split out of `mcp.rs` (which sits on its committed LoC-gate baseline, `.github/loc-baseline.json`,
//! and may be touched but not grown) when the MCP surface gained parity with the api/budget RPC
//! surfaces -- lightbridge-authz#645. Moved verbatim; `mcp.rs` re-exports every item, so its own
//! `#[cfg(test)] mod tests` (which reaches these through `use super::*`) still resolves them.

use lightbridge_authz_core::config::{ApiServer, Oauth2};
use reqwest::Client;
use serde_json::{Value, json};

use axum::http::{HeaderMap, header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Oauth2ResolvedEndpoints {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) registration_endpoint: String,
    pub(crate) jwks_uri: String,
}

#[derive(Clone)]
pub(crate) struct OauthProxyState {
    pub(crate) client: Client,
    pub(crate) endpoints: Option<Oauth2ResolvedEndpoints>,
    pub(crate) fallback_registration_endpoint: String,
}

pub(crate) fn issuer_from_jwks_url(jwks_url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(jwks_url).ok()?;
    let host = parsed.host_str()?;
    let path = parsed.path();
    let realm_path = path.strip_suffix("/protocol/openid-connect/certs")?;
    let mut issuer = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        issuer.push(':');
        issuer.push_str(&port.to_string());
    }
    issuer.push_str(realm_path);
    Some(issuer)
}

pub(crate) fn join_issuer_path(issuer: &str, path: &str) -> String {
    format!(
        "{}/{}",
        issuer.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

pub(crate) fn resolve_oauth2_endpoints(oauth2: &Oauth2) -> Option<Oauth2ResolvedEndpoints> {
    let issuer = oauth2
        .issuer_url
        .clone()
        .or_else(|| issuer_from_jwks_url(&oauth2.jwks_url))?;

    let authorization_endpoint = oauth2
        .authorization_endpoint
        .clone()
        .unwrap_or_else(|| join_issuer_path(&issuer, "protocol/openid-connect/auth"));
    let token_endpoint = oauth2
        .token_endpoint
        .clone()
        .or_else(|| oauth2.oauth2_url.clone())
        .unwrap_or_else(|| join_issuer_path(&issuer, "protocol/openid-connect/token"));
    let registration_endpoint = oauth2
        .registration_endpoint
        .clone()
        .unwrap_or_else(|| join_issuer_path(&issuer, "clients-registrations/openid-connect"));

    Some(Oauth2ResolvedEndpoints {
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        jwks_uri: oauth2.jwks_url.clone(),
    })
}

pub(crate) fn oauth_metadata_response(
    endpoints: &Oauth2ResolvedEndpoints,
    registration_endpoint: &str,
) -> Value {
    json!({
        "issuer": endpoints.issuer,
        "authorization_endpoint": endpoints.authorization_endpoint,
        "token_endpoint": endpoints.token_endpoint,
        "jwks_uri": endpoints.jwks_uri,
        "registration_endpoint": registration_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    })
}

pub(crate) fn request_origin(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("https");
    Some(format!("{proto}://{}", host.trim()))
}

pub(crate) fn registration_endpoint_for_request(headers: &HeaderMap, fallback: &str) -> String {
    request_origin(headers)
        .map(|origin| format!("{}/oauth/register", origin.trim_end_matches('/')))
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn fallback_registration_endpoint(api: &ApiServer) -> String {
    format!("https://{}:{}/oauth/register", api.address, api.port)
}
