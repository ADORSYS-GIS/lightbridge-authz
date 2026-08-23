//! ADR-0011 phase 2: adopts `authkestra_op`'s `handle_token` dispatch (client authentication,
//! grant routing, discovery/JWKS shapes) with a real, config-defined client registry, replacing
//! the hand-rolled dispatch `token_exchange.rs` used to own end to end.
//!
//! Module layout:
//! - [`client_store`]: `ClientStore` over the config-defined client list (Decision 5).
//! - [`client_assertion_store`]: Redis-backed `ClientAssertionStore` (Decision 6) -- fail-closed
//!   `private_key_jwt` replay tracking.
//! - [`refresh_store`]: `RefreshTokenStore` over `exchange_refresh_tokens`.
//! - [`device_store`]: `DeviceCodeStore` over `device_authorizations` (ADR-0012 Decision 7, #423)
//!   -- real, CAS-consuming storage, replacing the permanent `NoDeviceCodeStore` stub ADR-0011
//!   Decision 3 originally installed for both OP-side traits.
//! - [`noop_stores`]: the one trait that IS still a permanent no-op --
//!   `AuthorizationCodeStore` (ADR-0012 Decision 3 reaffirms this half, unchanged).
//! - [`store`]: `TokenExchangeOpStore`, the `OpStore` implementation tying all of the above
//!   together, with hand-rolled `handle_token_exchange`/`handle_refresh_token` overrides (the
//!   upstream defaults are `pub(crate)` to `authkestra-op` and never stamp `extra` claims -- see
//!   that module's doc comment for exactly how much RFC 8693 logic had to be reimplemented here).

pub mod client_assertion_store;
pub mod client_store;
pub mod device_store;
pub mod noop_stores;
pub mod refresh_store;
pub mod store;

use authkestra_op::handlers::token::TokenErrorResponse;
use serde_json::Value;

/// RFC 8693 token-type identifiers this service ever mints or accepts. Only `access_token` --
/// this service issues no other token type on the wire (an `id_token` rides alongside the access
/// token in the same response, never as the primary `access_token`/`issued_token_type` value).
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub(crate) const OFFLINE_ACCESS_SCOPE: &str = "offline_access";
pub(crate) const OPENID_SCOPE: &str = "openid";
pub(crate) const REFRESH_TOKEN_PREFIX: &str = "lgbr_rt_";
const REFRESH_TOKEN_BYTES: usize = 32;

/// Builds an RFC 6749 §5.2-shaped `TokenErrorResponse`. `authkestra_op::handlers::token`'s own
/// error type carries no HTTP status; `token_exchange::status_for_oauth_error` maps `error` back
/// to one at the axum boundary, so error-string choices here are load-bearing, not cosmetic.
pub(crate) fn oauth_err(error: &str, description: &str) -> TokenErrorResponse {
    TokenErrorResponse {
        error: error.to_string(),
        error_description: description.to_string(),
    }
}

/// Intersects the client's requested scopes with the server-wide allow-list AND the requesting
/// client's own `scopes` (ADR-0011 Decision 5: clients are real, so their scope grant is real
/// too) -- neither list alone is authoritative. An empty/absent request grants the allow-list
/// *minus `offline_access`*: per OpenID Connect Core §5.4, `offline_access` MUST be explicitly
/// requested, so it never rides the default-scope grant and a scope-less exchange never silently
/// mints a refresh token.
pub(crate) fn grant_scopes(
    requested: &Option<String>,
    server_allowed: &[String],
    client_scopes: &[String],
) -> Vec<String> {
    let requested: Vec<String> = requested
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let base: Vec<String> = if requested.is_empty() {
        server_allowed
            .iter()
            .filter(|scope| *scope != OFFLINE_ACCESS_SCOPE)
            .cloned()
            .collect()
    } else {
        requested
            .into_iter()
            .filter(|scope| server_allowed.iter().any(|a| a == scope))
            .collect()
    };
    base.into_iter()
        .filter(|scope| client_scopes.iter().any(|c| c == scope))
        .collect()
}

pub(crate) fn scope_to_string(scopes: &[String]) -> Option<String> {
    if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    }
}

pub(crate) fn generate_refresh_secret() -> String {
    use base64::Engine;
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; REFRESH_TOKEN_BYTES];
    OsRng.fill_bytes(&mut buf);
    format!(
        "{REFRESH_TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    )
}

/// Best-effort, unverified decode of a JWT's payload segment into JSON. Used only to snapshot
/// specific claims off the already-`validate_bearer_token`-verified `subject_token` -- the
/// signature has already been checked by the time either caller below runs (via
/// `BearerTokenServiceTrait::validate_bearer_token`, JWKS-backed), this just re-reads the payload
/// since `TokenInfo` does not carry every upstream claim.
fn decode_payload(bearer_token: &str) -> Option<Value> {
    use base64::Engine;
    let payload = bearer_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Snapshots `email`/`email_verified` from the presented upstream token so the exchanged JWT
/// mirrors a Keycloak access token. Best-effort: a token without these claims yields `None`.
pub(crate) fn decode_email(bearer_token: &str) -> (Option<String>, Option<bool>) {
    let Some(value) = decode_payload(bearer_token) else {
        return (None, None);
    };
    let email = value
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_string);
    let email_verified = value.get("email_verified").and_then(Value::as_bool);
    (email, email_verified)
}

/// Snapshots `auth_time`/`nonce` from the presented upstream token for the derived `id_token`
/// (ADR-0011, Decision 7). Both are propagate-if-present-else-omit, never synthesized: `auth_time`
/// because this service never authenticates anyone itself (no authentication instant of its own
/// to report), `nonce` because a token exchange runs no authorization request for a nonce to bind
/// to.
pub(crate) fn decode_auth_time_and_nonce(bearer_token: &str) -> (Option<i64>, Option<String>) {
    let Some(value) = decode_payload(bearer_token) else {
        return (None, None);
    };
    let auth_time = value.get("auth_time").and_then(Value::as_i64);
    let nonce = value
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string);
    (auth_time, nonce)
}
