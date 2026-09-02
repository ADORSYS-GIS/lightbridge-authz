//! ADR-0011 phase 2: adopts `authkestra_op`'s `handle_token` dispatch (client authentication,
//! grant routing, discovery/JWKS shapes) with a real, config-defined client registry, replacing
//! the hand-rolled dispatch `token_exchange.rs` used to own end to end.
//!
//! Module layout:
//! - [`client_store`]: `ClientStore` over the config-defined client list (Decision 5).
//! - [`client_assertion_store`]: Redis-backed `ClientAssertionStore` (Decision 6) -- fail-closed
//!   `private_key_jwt` replay tracking.
//! - [`refresh_store`]: `RefreshTokenStore` over `exchange_refresh_tokens`.
//! - [`refresh_token`]: mints/verifies the refresh token itself as an RS256 JWT (was: an opaque
//!   `lgbr_rt_<random>` string) -- a presentation-format change only, `refresh_store`'s DB-backed
//!   CAS/rotation/revocation stays the single source of truth.
//! - [`device_store`]: `DeviceCodeStore` over `device_authorizations` (ADR-0012 Decision 7, #423)
//!   -- real, CAS-consuming storage, replacing the permanent `NoDeviceCodeStore` stub ADR-0011
//!   Decision 3 originally installed for both OP-side traits.
//! - [`authorization_code_store`]: persisted, TTL-bound and CAS-consuming authorization codes
//!   for ADR-0019's browser flow.
//! - [`store`]: `TokenExchangeOpStore`, the `OpStore` implementation tying all of the above
//!   together, with hand-rolled `handle_token_exchange`/`handle_refresh_token` overrides (the
//!   upstream defaults are `pub(crate)` to `authkestra-op` and never stamp `extra` claims -- see
//!   that module's doc comment for exactly how much RFC 8693 logic had to be reimplemented here).

pub mod client_assertion_store;
pub mod client_store;
pub mod device_store;
pub mod refresh_store;
pub mod refresh_token;
pub mod store;

use authkestra_op::handlers::token::TokenErrorResponse;
use serde_json::Value;

/// RFC 8693 token-type identifiers this service ever mints or accepts. Only `access_token` --
/// this service issues no other token type on the wire (an `id_token` rides alongside the access
/// token in the same response, never as the primary `access_token`/`issued_token_type` value).
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub(crate) const OFFLINE_ACCESS_SCOPE: &str = "offline_access";
pub(crate) const OPENID_SCOPE: &str = "openid";

/// Builds an RFC 6749 §5.2-shaped `TokenErrorResponse`. `authkestra_op::handlers::token`'s own
/// error type carries no HTTP status; `token_exchange::status_for_oauth_error` maps `error` back
/// to one at the axum boundary, so error-string choices here are load-bearing, not cosmetic.
pub(crate) fn oauth_err(error: &str, description: &str) -> TokenErrorResponse {
    TokenErrorResponse::new(error.to_string(), description.to_string())
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

/// Fills `bytes` random bytes from the OS CSPRNG and returns them URL-safe-base64-encoded
/// (no padding). Shared by every call site in this crate that previously duplicated this exact
/// "`OsRng` fill -> `URL_SAFE_NO_PAD` encode" sequence with its own byte count baked in --
/// [`device_store::generate_device_code`] and `relying_party`'s per-request state/nonce
/// generation.
pub(crate) fn random_urlsafe(bytes: usize) -> String {
    use base64::Engine;
    use rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
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

/// Snapshots `email`/`email_verified`/`preferred_username`/`name` from the presented upstream
/// token so the exchanged JWT mirrors a Keycloak access token. Best-effort: a token without a
/// given claim yields `None` for it, never an invented default -- same "omit, never mint a lie"
/// contract every other claim in this codebase follows.
///
/// This is the token-exchange grant's own source for these four claims, deliberately NOT a
/// database lookup: the presented `subject_token` already carries them (once
/// `BearerTokenServiceTrait::validate_bearer_token` has verified its signature -- both callers run
/// that first), so decoding it directly is both simpler and fresher than round-tripping through
/// `federated_identities` -- and a subject_token presented here need not even belong to someone
/// who ever completed a login through this service's own `KeycloakRelyingParty` (a
/// `federated_identities` row is not guaranteed to exist for it). Contrast the browser
/// `authorization_code` grant (`TokenExchangeOpStore::mint_from_authorization_code`), which has no
/// upstream token in hand at redemption time and reads
/// `StoreRepo::find_federated_identity_by_account_id` instead.
pub(crate) fn decode_profile_claims(
    bearer_token: &str,
) -> (Option<String>, Option<bool>, Option<String>, Option<String>) {
    let Some(value) = decode_payload(bearer_token) else {
        return (None, None, None, None);
    };
    let email = value
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_string);
    let email_verified = value.get("email_verified").and_then(Value::as_bool);
    let preferred_username = value
        .get("preferred_username")
        .and_then(Value::as_str)
        .map(str::to_string);
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string);
    (email, email_verified, preferred_username, name)
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
pub mod authorization_code_store;
