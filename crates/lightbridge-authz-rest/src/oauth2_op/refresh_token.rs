//! Native RFC 8693 refresh tokens as RS256 JWTs, replacing the opaque `lgbr_rt_<random>` string
//! this service minted before (hard cutover -- no compatibility branch for the old format).
//!
//! The JWT is a PRESENTATION format only. `exchange_refresh_tokens`
//! (`lightbridge_authz_api_key::repo::StoreRepo`) stays the single source of truth for
//! single-use, rotation, and revocation: `oauth2_op::store` still hashes the FULL presented
//! string with `hash_api_key` exactly as it did for the opaque format, and the existing
//! CAS/rotation/reuse-cascade logic is untouched. What changes is only what the plaintext looks
//! like, and that this module verifies it (signature/`exp`/`aud`/`typ`) before that hash/CAS step
//! ever runs -- a malformed or foreign-signed presentation never reaches the database at all.
//!
//! **A dedicated refresh signing key, not the access-token key.** Earlier revisions of this
//! module minted over the SAME `TokenManager` the access token minted alongside it used, and
//! relied on the `typ` claim below as the only guard against a refresh JWT being replayed as an
//! access token. Cross-use is now prevented BY CONSTRUCTION instead: [`mint_refresh_jwt`] builds
//! its own `TokenManager` from [`StoreRepo::get_active_refresh_signing_key`] (`purpose =
//! 'refresh'`), a key that never appears in `/.well-known/jwks.json`
//! ([`StoreRepo::list_verification_jwks`] serves `purpose = 'access'` only) -- no resource server
//! ever holds a key that can verify a refresh token, so there is no key for a forged/replayed one
//! to validate against even if the `typ` check below were somehow bypassed. See
//! `migrations/20260902000001_signing_keys_add_purpose.sql` and
//! `oauth2_op::refresh_signing::bootstrap_idp_signing_keys` for how that key is provisioned.
//!
//! **Verification** reads [`StoreRepo::list_refresh_verification_jwks`] (active + retired refresh
//! keys) rather than a single freshly-built `TokenManager`: an individual refresh token's own
//! `refresh_ttl_seconds` (default 30 days) can outlive one signing-key rotation cycle
//! (`max_key_age_days`, also default 30 days) before it is ever redeemed, so "the currently active
//! refresh key" at redemption time may not be the key that signed it.
//!
//! `aud` is fixed to [`REFRESH_TOKEN_AUDIENCE`], a value no resource server (nor this service's
//! own bearer/`subject_token` validators) is configured to accept. The `typ` claim
//! ([`lightbridge_authz_bearer::REFRESH_TOKEN_TYP_CLAIM`]) is a second, independent guard on top
//! of the dedicated key: `BearerTokenService::validate_bearer_token` refuses any token carrying it
//! outright, so a refresh JWT can never be replayed as a Bearer access token or an RFC 8693
//! `subject_token` -- see that constant's own doc comment.

use std::collections::HashMap;

use authkestra_engine::token::TokenManager;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::REFRESH_TOKEN_TYP_CLAIM;
use lightbridge_authz_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The dedicated `aud` every refresh-token JWT carries -- distinct from every access-token
/// audience this service issues or accepts. See this module's doc comment for the full replay-
/// guard picture (this is one of its two independent halves, the `typ` claim being the other).
pub const REFRESH_TOKEN_AUDIENCE: &str = "lightbridge-refresh";

const ALGORITHM: Algorithm = Algorithm::RS256;

/// The refresh-token-specific claims verification cares about, decoded off the full claim set.
/// `sub` is the acting account id (never the raw upstream subject); `jti` is the
/// `exchange_refresh_tokens` row id this token corresponds to, so the DB row and the JWT always
/// agree on identity; `sid` is the `sessions` row id the refresh chain is bound to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub jti: String,
    pub sid: String,
    pub typ: String,
}

/// Mints a refresh-token JWT for `account_id`/`session_id`, stamping `row_id` (the
/// `exchange_refresh_tokens` row this plaintext will be hashed into) as `jti`. Signed with the
/// dedicated refresh signing key (`repo.get_active_refresh_signing_key()`), never the access-token
/// key an access/id token in the same response might be signed with -- see this module's doc
/// comment for why that is what makes cross-use impossible by construction rather than by policy.
pub async fn mint_refresh_jwt(
    repo: &StoreRepo,
    account_id: &str,
    session_id: &str,
    row_id: &str,
    expires_in_secs: u64,
) -> Result<String> {
    // Self-healing rather than a hard error: see `ensure_refresh_signing_key`'s doc comment for
    // why startup bootstrap alone is not enough, and why this can create but never rotate.
    let key = match repo.get_active_refresh_signing_key().await? {
        Some(key) => key,
        None => {
            super::refresh_signing::ensure_refresh_signing_key(
                repo,
                super::refresh_signing::mint_path_cutoff(),
            )
            .await?
        }
    };
    let tokens = TokenManager::new_asymmetric(key.private_key_pem.as_bytes(), None, Some(key.kid))
        .map_err(|e| Error::Server(format!("invalid stored refresh signing key: {e}")))?;
    let mut extra: HashMap<String, Value> = HashMap::new();
    extra.insert("jti".to_string(), Value::String(row_id.to_string()));
    extra.insert("sid".to_string(), Value::String(session_id.to_string()));
    extra.insert(
        "typ".to_string(),
        Value::String(REFRESH_TOKEN_TYP_CLAIM.to_string()),
    );
    tokens
        .issue_client_token_with_extra(
            account_id,
            expires_in_secs,
            None,
            Some(REFRESH_TOKEN_AUDIENCE.to_string()),
            extra,
        )
        .map_err(|e| Error::Server(format!("refresh token signing failed: {e}")))
}

/// Verifies a presented refresh-token JWT: signature (against every REFRESH key this service has
/// ever signed with, active or retired -- see this module's doc comment for why), `exp`, `aud ==
/// `[`REFRESH_TOKEN_AUDIENCE`], and `typ == `[`REFRESH_TOKEN_TYP_CLAIM`]. Returns `None` on ANY
/// failure (malformed token, unknown `kid`, bad signature, expired, wrong audience, wrong `typ`)
/// -- `oauth2_op::store::TokenExchangeOpStore::handle_refresh_token` maps every `Ok(None)` to the
/// same `invalid_grant` it already returns for an unrecognized opaque token, so this never
/// distinguishes "malformed" from "well-formed but not ours" on the wire.
///
/// A failure to READ the key set is deliberately NOT folded into that `Ok(None)`: it is an `Err`,
/// which the caller maps to `server_error`. Both outcomes refuse the token, but only one of them
/// is the client's fault -- reporting a transient database blip as `invalid_grant` would tell
/// every CLI on the estate that its refresh token is permanently dead and stampede them all into
/// a fresh interactive login, which is precisely the failure shape `revoke_for_logout`
/// (`lightbridge_authz_api_key::session_revocation`) exists to stop causing.
pub async fn verify_refresh_jwt(
    repo: &StoreRepo,
    presented: &str,
) -> Result<Option<RefreshTokenClaims>> {
    let jwks = repo.list_refresh_verification_jwks().await?;
    Ok(verify_against_jwks(&jwks, presented))
}

fn verify_against_jwks(jwks: &[Value], presented: &str) -> Option<RefreshTokenClaims> {
    let kid = decode_header(presented).ok()?.kid?;
    let jwk = jwks
        .iter()
        .find(|jwk| jwk.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str()))?;
    let n = jwk.get("n")?.as_str()?;
    let e = jwk.get("e")?.as_str()?;
    let decoding_key = DecodingKey::from_rsa_components(n, e).ok()?;
    let mut validation = Validation::new(ALGORITHM);
    validation.set_audience(&[REFRESH_TOKEN_AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    let claims = decode::<RefreshTokenClaims>(presented, &decoding_key, &validation)
        .ok()?
        .claims;
    (claims.typ == REFRESH_TOKEN_TYP_CLAIM).then_some(claims)
}
