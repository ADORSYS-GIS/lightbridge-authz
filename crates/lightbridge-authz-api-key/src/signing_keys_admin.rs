//! Operator-facing signing-key listing, backing the `lightbridge-authz idp jwk list` command
//! (kubectl-debug/init-container surface for managing keys explicitly, alongside the existing
//! 30-day age-based auto-rotation in [`crate::repo::StoreRepo::ensure_active_signing_key`]).
//!
//! Lives in its own module, like `signing_keys_refresh.rs`, rather than alongside `repo.rs`'s other
//! signing-key methods purely because that file sits exactly on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown.
//!
//! The one query here (`list_signing_keys`) is deliberately scoped to
//! [`crate::entities::signing_key_row::SigningKeyMeta`], which has no `private_key_pem`/
//! `public_jwk` fields at all -- the private key must never reach stdout or logs, so this is
//! enforced by never selecting the column in the first place, not by trusting a formatter
//! downstream to omit it.

use lightbridge_authz_core::error::Result;

use crate::db::StoreRepo;
use crate::entities::signing_key_row::SigningKeyMeta;

impl StoreRepo {
    /// Every signing key across BOTH purposes and every status (active + stale) -- unlike
    /// [`crate::repo::StoreRepo::list_verification_jwks`]/
    /// [`crate::signing_keys_refresh`]'s equivalents, which are each scoped to one purpose and
    /// return only the public JWK for the public JWKS document. This is the read the `jwk list`
    /// operator command needs: every key that exists, regardless of purpose or status, identified
    /// by metadata alone.
    pub async fn list_signing_keys(&self) -> Result<Vec<SigningKeyMeta>> {
        let rows: Vec<SigningKeyMeta> = sqlx::query_as::<_, SigningKeyMeta>(
            r#"
            SELECT kid, purpose, status, created_at, retired_at
            FROM signing_keys
            ORDER BY purpose, status = 'active' DESC, created_at DESC
            "#,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}
