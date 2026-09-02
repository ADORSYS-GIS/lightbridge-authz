//! Refresh-token-signing-key-specific queries.
//!
//! Lives in its own module rather than alongside [`StoreRepo`]'s other signing-key methods in
//! `repo.rs` purely because that file sits exactly on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown -- the same reason
//! `session_revocation.rs` exists as its own file.
//!
//! The refresh key itself is bootstrapped and rotated through the SAME
//! [`StoreRepo::ensure_active_signing_key`] advisory-lock machinery `repo.rs` already has for the
//! access key (see that function's own doc comment) -- `candidate.purpose` is what tells the two
//! apart, and the migration-added `(status, purpose) WHERE status = 'active'` unique index is what
//! lets one of each be active simultaneously. What this module adds are the two READ queries the
//! refresh-token path needs and the access-key equivalents (`get_active_signing_key`/
//! `list_verification_jwks`) must NOT serve: a refresh key must never appear in the public JWKS
//! (`/.well-known/jwks.json`, which is `list_verification_jwks`'s only caller) -- that is the
//! whole point of giving refresh tokens their own key, since a resource server that never holds a
//! verification key for them can never be tricked into accepting one as a Bearer/`subject_token`.

use serde_json::Value;

use lightbridge_authz_core::error::Result;

use crate::db::StoreRepo;
use crate::entities::signing_key_row::SigningKeyRow;

impl StoreRepo {
    /// The active refresh-token signing key, or `None` if it has not been bootstrapped yet.
    /// Mirrors [`StoreRepo::get_active_signing_key`] exactly, scoped to `purpose = 'refresh'`
    /// instead of `'access'`. Used by `oauth2_op::refresh_token::mint_refresh_jwt` to build the
    /// dedicated `TokenManager` refresh JWTs are signed with.
    pub async fn get_active_refresh_signing_key(&self) -> Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SigningKeyRow>(
            r#"
            SELECT kid, algorithm, private_key_pem, public_jwk, status, created_at, retired_at
            FROM signing_keys
            WHERE status = 'active' AND purpose = 'refresh'
            LIMIT 1
            "#,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Every refresh-token verification key -- active AND retired, exactly like
    /// [`StoreRepo::list_verification_jwks`] -- so a refresh token signed by a key that has since
    /// rotated (a real, expected case: `refresh_ttl_seconds` can outlive one rotation cycle) still
    /// verifies. Used ONLY by `oauth2_op::refresh_token::verify_refresh_jwt`, NEVER by the public
    /// `/.well-known/jwks.json` router -- that endpoint calls `list_verification_jwks` (scoped to
    /// `purpose = 'access'`) alone, so a refresh key is never published for a resource server to
    /// pick up.
    pub async fn list_refresh_verification_jwks(&self) -> Result<Vec<Value>> {
        let rows: Vec<(Value,)> = sqlx::query_as(
            r#"
            SELECT public_jwk
            FROM signing_keys
            WHERE purpose = 'refresh'
            ORDER BY status = 'active' DESC, created_at DESC
            "#,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|(jwk,)| jwk).collect())
    }
}
