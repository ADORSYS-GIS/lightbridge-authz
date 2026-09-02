//! Bootstraps the dedicated refresh-token signing key for `authz-idp` -- the one service that
//! mints refresh-token JWTs ([`refresh_token::mint_refresh_jwt`](super::refresh_token::mint_refresh_jwt)).
//! `authz-api`/`lightbridge-mcp` never call this: they keep calling
//! [`crate::signing::bootstrap_signing_key`] alone, exactly as before.
//!
//! Reuses [`StoreRepo::ensure_active_signing_key`]'s existing advisory-lock rotation machinery
//! (`crates/lightbridge-authz-api-key/src/repo.rs`) rather than inventing a second one -- the only
//! difference from the access-key bootstrap is the `purpose` stamped on the candidate row, which
//! the migration-added `(status, purpose) WHERE status = 'active'` unique index is what makes it
//! legal for an access key and a refresh key to be active at the same time.
//!
//! Lives as its own file under `oauth2_op/` (registered from that module's `mod.rs`, itself well
//! under the LoC-gate default threshold) rather than inside `signing.rs`, which -- like
//! `repo.rs` -- sits exactly on its committed LoC-gate baseline and may be touched but not grown.

use chrono::{Duration, Utc};
use lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::error::Result;

use crate::signing::{bootstrap_signing_key, generate_rs256_key};

const REFRESH_KEY_PURPOSE: &str = "refresh";

/// Ensures BOTH the access and refresh signing keys exist, for `authz-idp`'s own startup only.
/// Access-key bootstrap is delegated verbatim to [`bootstrap_signing_key`] (unchanged behavior,
/// unchanged callers via that function); refresh-key bootstrap mirrors it end to end, stamping
/// [`REFRESH_KEY_PURPOSE`] on the candidate instead of the access-key default -- see this module's
/// doc comment for why that alone is enough for the two to coexist as separate active keys.
pub async fn bootstrap_idp_signing_keys(repo: &StoreRepo, cfg: &JwtSigning) -> Result<()> {
    bootstrap_signing_key(repo, cfg).await?;
    let cutoff = Utc::now() - Duration::days(cfg.max_key_age_days.max(1));
    let active = ensure_refresh_signing_key(repo, cutoff).await?;
    tracing::info!(kid = %active.kid, "active refresh-token signing key ready");
    Ok(())
}

/// A cutoff so far in the past that [`StoreRepo::ensure_active_signing_key`] can only ever CREATE
/// a missing key, never rotate a live one -- see [`ensure_refresh_signing_key`]'s callers.
const NEVER_ROTATE: i64 = 36_500;

/// Provisions the refresh signing key if it is absent, returning whichever key is active.
///
/// Called from two places, deliberately. `bootstrap_idp_signing_keys` above passes the real
/// `max_key_age_days` cutoff, so startup both creates AND rotates. `refresh_token::mint_refresh_jwt`
/// passes [`NEVER_ROTATE`], so the mint path can only ever fill in a MISSING key -- it must never
/// rotate a live one as a side effect of signing a token, which would invalidate nothing but would
/// make key rotation depend on traffic rather than on age.
///
/// The mint-path call is a production safety net, not a test crutch: the integration-test fixtures
/// do call `bootstrap_idp_signing_keys` themselves. It exists because `start_idp_server` is not the
/// only way a `TokenExchangeOpStore` can come into being, and because a pod that somehow reached
/// the refresh grant without a refresh key should self-heal rather than fail EVERY refresh with
/// `server_error` -- an estate-wide forced re-login, which is the exact failure #627 was about.
/// `ensure_active_signing_key` is advisory-lock serialized, so concurrent callers across replicas
/// still produce exactly one active key.
pub async fn ensure_refresh_signing_key(
    repo: &StoreRepo,
    cutoff: chrono::DateTime<Utc>,
) -> Result<lightbridge_authz_api_key::entities::signing_key_row::SigningKeyRow> {
    let generated = generate_rs256_key()?;
    let candidate = NewSigningKey {
        kid: generated.kid,
        algorithm: "RS256".to_string(),
        private_key_pem: generated.private_key_pem,
        public_jwk: generated.public_jwk,
        purpose: REFRESH_KEY_PURPOSE.to_string(),
        created_at: Utc::now(),
    };
    repo.ensure_active_signing_key(candidate, cutoff).await
}

/// The cutoff the mint path uses: [`NEVER_ROTATE`] days in the past.
pub fn mint_path_cutoff() -> chrono::DateTime<Utc> {
    Utc::now() - Duration::days(NEVER_ROTATE)
}
