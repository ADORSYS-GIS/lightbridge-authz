//! Per-client refresh-token TTL resolution and startup validation.
//!
//! Repo owner request, verbatim: "the duration of a refresh token should be configurable on the
//! client entry in the .yaml config file." [`OauthClient::refresh_ttl_seconds`]/
//! [`OauthClient::refresh_absolute_ttl_seconds`] are optional per-client overrides of the
//! same-named [`Oauth2TokenExchange`] globals. [`effective_refresh_ttls`] resolves override-or-
//! global once (used by `ConfigClientStore::from_config` to build its per-client lookup, so
//! `TokenExchangeOpStore`'s per-request paths never see `Oauth2TokenExchange` itself), and
//! [`validate_client_refresh_ttls`] is the startup gate `start_idp_server`'s
//! `build_token_exchange_state` calls so a bad combination refuses to start rather than silently
//! minting a refresh token the chain's absolute cap kills before the token's own expiry ever
//! takes effect.

use lightbridge_authz_core::config::{Oauth2TokenExchange, OauthClient};
use lightbridge_authz_core::error::{Error, Result};

/// Resolves the effective `(refresh_ttl_seconds, refresh_absolute_ttl_seconds)` pair for one
/// client: its own override when present, else the server-wide `global` value.
pub fn effective_refresh_ttls(client: &OauthClient, global: &Oauth2TokenExchange) -> (i64, i64) {
    (
        client
            .refresh_ttl_seconds
            .unwrap_or(global.refresh_ttl_seconds),
        client
            .refresh_absolute_ttl_seconds
            .unwrap_or(global.refresh_absolute_ttl_seconds),
    )
}

/// Refuses (returns `Err`) when any configured client's EFFECTIVE per-token refresh TTL is not
/// positive, or exceeds its EFFECTIVE absolute chain cap -- the config trap a client set up for a
/// longer per-token TTL than the (possibly still-global) absolute cap would otherwise fall into
/// silently: every token minted for it would be invalidated by the cap before its own expiry ever
/// took effect. Also validates the bare global pair directly (label `"<global>"`), so a config
/// declaring no clients at all still gets the same check `build_token_exchange_state` ran before
/// this module existed.
pub fn validate_client_refresh_ttls(
    clients: &[OauthClient],
    global: &Oauth2TokenExchange,
) -> Result<()> {
    check_one(
        "<global>",
        global.refresh_ttl_seconds,
        global.refresh_absolute_ttl_seconds,
    )?;
    for client in clients {
        let (ttl, absolute) = effective_refresh_ttls(client, global);
        check_one(&client.client_id, ttl, absolute)?;
    }
    Ok(())
}

fn check_one(
    client_id: &str,
    refresh_ttl_seconds: i64,
    refresh_absolute_ttl_seconds: i64,
) -> Result<()> {
    if refresh_ttl_seconds <= 0 {
        return Err(Error::Server(format!(
            "oauth2 client '{client_id}': effective refresh_ttl_seconds must be positive (got \
             {refresh_ttl_seconds})"
        )));
    }
    if refresh_absolute_ttl_seconds <= 0 {
        return Err(Error::Server(format!(
            "oauth2 client '{client_id}': effective refresh_absolute_ttl_seconds must be \
             positive (got {refresh_absolute_ttl_seconds})"
        )));
    }
    if refresh_ttl_seconds > refresh_absolute_ttl_seconds {
        return Err(Error::Server(format!(
            "oauth2 client '{client_id}': effective refresh_ttl_seconds \
             ({refresh_ttl_seconds}) exceeds effective refresh_absolute_ttl_seconds \
             ({refresh_absolute_ttl_seconds}) -- every token minted for it would be invalidated \
             by the chain's absolute cap before its own expiry ever took effect"
        )));
    }
    Ok(())
}
