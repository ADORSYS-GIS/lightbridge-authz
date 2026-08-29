//! The open-redirect boundary of `/oauth2/end_session`, kept in its own module.
//!
//! Split out from `end_session` deliberately. This is the only part of RP-initiated logout where
//! getting it wrong hands an attacker something: everything else about logout fails toward "the
//! user is signed out", while a loose redirect check turns the OP into a redirector trusted by a
//! user who has just authenticated. Isolating it means the check can be read, reviewed and tested
//! without the handler's session and cookie machinery around it -- see `tests/end_session_tests.rs`,
//! which exercises this module alone against every hostile URL shape.

use std::collections::HashMap;

use lightbridge_authz_core::config::OauthClient;
use serde_json::Value;

use crate::end_session::EndSessionRequest;

/// `client_id -> post_logout_redirect_uris`, built once at router-build time from config, like
/// `ConfigClientStore` (ADR-0011 Decision 5: clients are a config change plus a redeploy).
pub fn registry_from_clients(clients: &[OauthClient]) -> HashMap<String, Vec<String>> {
    clients
        .iter()
        .map(|client| {
            (
                client.client_id.clone(),
                client.post_logout_redirect_uris.clone(),
            )
        })
        .collect()
}

/// Resolves which client the request speaks for: the explicit `client_id` first (§2 makes it
/// REQUIRED when there is no hint), else the verified hint's `azp`.
///
/// `azp` and not `aud`: `aud` on an id_token may be an array, and on a token-exchange-issued token
/// it can name a downstream audience rather than the client. `azp` is unambiguously "the client
/// these tokens were issued to" (`signing::id_token_extra` stamps it from the authenticated
/// `client_id`).
pub(crate) fn resolve_client_id(
    request: &EndSessionRequest,
    hint: Option<&serde_json::Map<String, Value>>,
) -> Option<String> {
    request
        .client_id
        .clone()
        .or_else(|| hint?.get("azp").and_then(Value::as_str).map(str::to_owned))
}

/// Exact, byte-for-byte match against the resolved client's registered list -- the same discipline
/// `/authorize` applies to `redirect_uri`, and the entire open-redirect boundary for this
/// endpoint.
///
/// No normalisation, no prefix match, no "same origin is close enough". Every relaxation of an
/// exact redirect match is a way to smuggle a target past the check, and a logout landing page is
/// a uniquely attractive one: the user arrives having just proven they are who they say they are.
///
/// `pub` for the sake of `tests/end_session_tests.rs`, deliberately. This is the whole
/// open-redirect boundary, it is pure, and exercising it directly gets every hostile shape
/// (scheme swap, host suffix, path suffix, unknown client) asserted for the price of a unit test
/// -- reaching it only through the router would need a full offline IdP fixture per case and
/// would test far fewer of them.
pub fn resolve_post_logout_redirect(
    registry: &HashMap<String, Vec<String>>,
    client_id: Option<&str>,
    requested: Option<&str>,
    state: Option<&str>,
) -> Option<String> {
    let requested = requested?;
    let registered = registry.get(client_id?)?;
    if !registered.iter().any(|uri| uri == requested) {
        tracing::warn!(
            client_id = client_id.unwrap_or_default(),
            "post_logout_redirect_uri is not registered for this client; refusing to redirect"
        );
        return None;
    }
    let Some(state) = state else {
        return Some(requested.to_string());
    };
    let mut url = reqwest::Url::parse(requested).ok()?;
    url.query_pairs_mut().append_pair("state", state);
    Some(url.to_string())
}
