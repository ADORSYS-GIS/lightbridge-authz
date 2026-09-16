//! Startup validation for `oauth2.clients` -- CORS origins for the token endpoint, the
//! `authorization_code`/`client_credentials` client-shape guards, and the shared redirect-URI
//! origin parser they both need.
//!
//! Split out of `lib.rs`, not because this cluster is a natural library boundary on its own, but
//! because `lib.rs` sits exactly on its committed LoC-gate baseline (`.github/loc-baseline.json`)
//! and may be touched but not grown -- the same reason `budget_convert.rs`/
//! `reset_schedule_convert.rs` exist. `build_token_exchange_state` (`lib.rs`) is the sole caller
//! of the three `pub(crate)` entry points; `redirect_origin` stays private, used only by its two
//! siblings here.

use lightbridge_authz_core::config::{OauthClient, OauthClientType};
use lightbridge_authz_core::error::{Error, Result};

use crate::{signing, token_exchange};

pub(crate) fn token_endpoint_cors_origins(clients: &[OauthClient]) -> Result<Vec<String>> {
    clients
        .iter()
        .filter(|client| {
            client.client_type == OauthClientType::Public
                && client.require_pkce
                && client
                    .grant_types
                    .iter()
                    .any(|grant| grant == "authorization_code")
        })
        .flat_map(|client| client.redirect_uris.iter())
        .map(|redirect_uri| redirect_origin(redirect_uri))
        .collect::<Result<std::collections::BTreeSet<_>>>()
        .map(|origins| origins.into_iter().collect())
}

/// OAuth 2.1 and RFC 9700 (OAuth Security Best Current Practice) recommend PKCE for every client
/// type, not only public ones, specifically to close authorization-code-injection attacks -- a
/// confidential client's client-authentication step at the token endpoint proves who is redeeming
/// the code, not that the code being redeemed is the one THIS session actually requested. This
/// gate therefore applies to every `authorization_code` client regardless of `client_type`; do not
/// reintroduce a `client_type == Public` condition here.
///
/// Also enforces an invariant the introspection endpoint's module doc comment
/// (`token_exchange.rs`) relies on but nothing previously checked: no registered client's
/// `client_id` may equal `oauth2.signing.audience`. That equality is exactly the condition under
/// which a self-signed API-key JWT's `azp` (always the fixed `oauth2.signing.audience` value)
/// would collide with a real OAuth2 client id, making an API-key JWT pass
/// `introspect_endpoint`'s `azp == caller's client_id` gate and introspect as a live token-
/// exchange access token -- defeating the "API keys are structurally not introspectable" claim
/// that doc comment makes. Refusing to start is preferable to a config that silently invalidates
/// that claim.
pub(crate) fn validate_authorization_code_clients(
    clients: &[OauthClient],
    signing_audience: Option<&str>,
) -> Result<()> {
    for client in clients {
        for redirect_uri in &client.redirect_uris {
            redirect_origin(redirect_uri)?;
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
            && (!client.require_pkce || client.redirect_uris.is_empty())
        {
            return Err(Error::Server(
                "authorization_code clients require PKCE and at least one redirect_uri".to_string(),
            ));
        }
        if let Some(audience) = signing_audience
            && client.client_id == audience
        {
            return Err(Error::Server(format!(
                "oauth2.clients client_id {:?} equals oauth2.signing.audience -- a self-signed \
                 API-key JWT's azp would collide with this client id, making API keys \
                 introspectable as token-exchange access tokens",
                client.client_id
            )));
        }
    }
    Ok(())
}

/// Startup guard for `client_credentials`-capable and `confidential`/`service` clients (#534,
/// ADR-0030), called from [`build_token_exchange_state`] -- `start_idp_server`'s sole production
/// caller of that function, so this runs unconditionally at `authz-idp` startup exactly like
/// [`validate_authorization_code_clients`] above it. Two independent, previously-latent footguns:
///
/// 1. **A `public` client listing `client_credentials` would mint a machine token with NO
///    credential at all.** `oauth2_op::client_store::to_registration` maps `public` to `NoAuth`.
///    This check is the SOLE control against that combination, not a second line of defense behind
///    the pre-dispatch intercept: `token_exchange::client_credentials_token_endpoint`'s own
///    `authenticate_presented_client` has, as its first match arm, `(Some(NoAuth), NoCredential) =>
///    Ok(())` -- the same rule every other grant relies on for public clients -- so a `public`
///    client that somehow reached this endpoint with `client_credentials` in its `grant_types`
///    would authenticate with `Ok(())` and then pass the `allows_grant_type` check, reproducing the
///    exact footgun the intercept might otherwise be assumed to guard against. This startup check
///    is the only thing that stops that combination from ever minting a token.
/// 2. **A `confidential`/`service` client whose `jwks` does not actually parse to a usable key**
///    would previously start successfully: `find_client` would keep answering
///    `token_endpoint_auth_method: Some(PrivateKeyJwt)` for it, while
///    `signing::ClientAuthenticationMetadata::from_oauth2` silently dropped it from
///    `token_endpoint_auth_methods_supported` in discovery -- the client store and the discovery
///    document disagreeing about whether the client can ever actually authenticate. Refusing to
///    start closes that gap for `confidential` AND `service` clients alike. This check uses
///    [`signing::client_has_a_parseable_jwk`]; `from_oauth2` keeps its own inline filter chain
///    rather than calling that same function (it needs to walk every key to collect signing
///    algorithms, not just answer "is there at least one"), but both bottom out in the same
///    `parse_public_jwk` call, so a JWK either function accepts/rejects is judged identically.
///    `ConfigClientStore::has_confidential_client`/
///    `TokenExchangeOpStore::has_confidential_client` -- the aggregate "is there at least one"
///    query this per-client check replaces -- are removed as part of this fix; neither could have
///    driven a check this specific, and both were otherwise unused outside their own tests.
///
/// `client_credentials` clients additionally may not register `redirect_uris`: RFC 6749 §4.4 is a
/// non-browser, non-redirect grant by construction, so a client combining the two is either a
/// config mistake or two client roles smuggled into one registration.
pub(crate) fn validate_client_credentials_and_service_clients(
    clients: &[OauthClient],
) -> Result<()> {
    for client in clients {
        if matches!(
            client.client_type,
            OauthClientType::Confidential | OauthClientType::Service
        ) && !signing::client_has_a_parseable_jwk(client.jwks.as_ref())
        {
            return Err(Error::Server(format!(
                "oauth2.clients client_id {:?} is {:?} (bound to private_key_jwt) but its jwks \
                 does not contain at least one parseable JWK -- it could never actually \
                 authenticate",
                client.client_id, client.client_type
            )));
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant == token_exchange::CLIENT_CREDENTIALS_GRANT)
        {
            if client.client_type == OauthClientType::Public {
                return Err(Error::Server(format!(
                    "oauth2.clients client_id {:?} is type: public but lists the \
                     client_credentials grant -- a public client authenticates with no credential \
                     at all, so this would mint a machine token nobody has to prove they own; use \
                     type: service with a private_key_jwt keypair instead",
                    client.client_id
                )));
            }
            if !client.redirect_uris.is_empty() {
                return Err(Error::Server(format!(
                    "oauth2.clients client_id {:?} lists the client_credentials grant but also \
                     registers redirect_uris -- client_credentials is a non-browser, \
                     non-redirect grant (RFC 6749 §4.4)",
                    client.client_id
                )));
            }
        }
    }
    Ok(())
}

fn redirect_origin(redirect_uri: &str) -> Result<String> {
    let url = reqwest::Url::parse(redirect_uri).map_err(|_| {
        Error::Server("authorization-code redirect_uri must be an absolute URL".to_string())
    })?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none_or(|host| host.contains('*'))
    {
        return Err(Error::Server(
            "authorization-code redirect_uri must have an HTTP(S) origin without credentials"
                .to_string(),
        ));
    }
    Ok(url.origin().ascii_serialization())
}
