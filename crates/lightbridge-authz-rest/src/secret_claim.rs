//! Single-use, subject-bound claims for handing an API key secret to a human without ever
//! putting it in a place a model can read (GHSA-9pc6-965v-2c44, #538).
//!
//! `lightbridge-mcp` returns tool results straight into the calling model's context, so it is not
//! an acceptable delivery channel for credential material. Instead the secret is sealed here and
//! only an opaque claim token is returned; the human redeems it once, in a browser, against
//! `authz-idp`.
//!
//! The property the whole design rests on: **possession of the token is not sufficient to redeem
//! it.** The token necessarily travels through the model's context -- that is the point of handing
//! it over -- so if possession were enough, this would rename the exposure rather than remove it.
//! Redemption additionally requires the redeemer's authenticated browser session to belong to the
//! same subject that created the key, which a model structurally cannot supply.
//!
//! That binding is enforced twice, deliberately. In SQL, `subject` sits in the `WHERE` clause of
//! the consuming `UPDATE` (see `StoreRepo::consume_secret_claim`), so a wrong-subject attempt
//! matches no row and therefore cannot burn the claim. Cryptographically, the subject is the
//! AES-GCM associated data ([`lightbridge_authz_core::crypto::seal`]), so a row handed over by
//! mistake still cannot be decrypted by the wrong party. The SQL predicate protects availability;
//! the AAD protects confidentiality.
//!
//! **Storage is Postgres, not Redis, and that is not an oversight.** `lightbridge-mcp` is the
//! component that issues these claims, and it is explicitly and permanently freed from the Redis
//! requirement (AGENTS.md: `-mcp` and `-opa` take no `redis` parameter at all). It already holds
//! a database handle. Putting the claim in Redis would have forced that dependency back into the
//! one component the rule exists to keep it out of. The single-statement CAS gives the same
//! exactly-once guarantee `GETDEL` would have, and is the same pattern
//! `consume_authorization_code` already uses for precisely this reason.

use std::sync::Arc;

use base64::Engine;
use chrono::{Duration, Utc};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::crypto::{open, seal};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use sha2::{Digest, Sha256};

/// What the caller gets back when a secret is stashed: the opaque token to hand to the human, and
/// how long they have. The secret itself is deliberately absent -- once issued, the only way back
/// to it is [`SecretClaimStore::redeem`].
#[derive(Debug, Clone)]
pub struct IssuedClaim {
    pub token: String,
    pub expires_in_seconds: i64,
}

/// Issues and redeems single-use secret claims.
pub struct SecretClaimStore {
    repo: Arc<StoreRepo>,
    sealing_key: [u8; 32],
    ttl_seconds: i64,
}

impl std::fmt::Debug for SecretClaimStore {
    /// Hand-written, never derived: `sealing_key` must not reach a log line. Same posture as
    /// `TokenResponse`/`KeycloakTokenSet`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretClaimStore")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("sealing_key", &"<redacted>")
            .finish()
    }
}

/// SHA-256 of the claim token, base64url-encoded. The token is never stored in the clear, for the
/// same reason `api_keys` stores only `key_hash`.
fn token_hash(token: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

impl SecretClaimStore {
    pub fn new(repo: Arc<StoreRepo>, sealing_key: [u8; 32], ttl_seconds: i64) -> Self {
        Self {
            repo,
            sealing_key,
            ttl_seconds,
        }
    }

    /// Seals `secret` against `subject` and stores it under a fresh CUID2 token (ADR-0039's one
    /// minting chokepoint).
    ///
    /// Errors are hard failures, never a silent skip: a caller that cannot stash the secret must
    /// refuse the whole operation rather than fall back to returning it inline.
    pub async fn issue(&self, secret: &str, subject: &str) -> Result<IssuedClaim> {
        let token = cuid2();
        let sealed = seal(&self.sealing_key, subject, secret.as_bytes())?;
        let expires_at = Utc::now() + Duration::seconds(self.ttl_seconds);
        self.repo
            .create_secret_claim(&cuid2(), &token_hash(&token), subject, &sealed, expires_at)
            .await?;
        Ok(IssuedClaim {
            token,
            expires_in_seconds: self.ttl_seconds,
        })
    }

    /// Redeems `token` on behalf of `subject`, returning the secret exactly once.
    ///
    /// `Ok(None)` covers every non-exceptional miss: unknown token, expired, already redeemed, or
    /// a subject that does not own the claim. The caller must not distinguish these to the
    /// redeemer -- doing so turns this into an oracle for which tokens exist.
    ///
    /// `Err` is reserved for the store itself being unusable, so the caller can answer "try again"
    /// rather than "no such claim". Both refuse; neither returns the secret.
    pub async fn redeem(&self, token: &str, subject: &str) -> Result<Option<String>> {
        let Some(sealed) = self
            .repo
            .consume_secret_claim(&token_hash(token), subject, Utc::now())
            .await?
        else {
            return Ok(None);
        };
        // Reaching here means the row matched on `subject`, so an unseal failure is a rotated
        // sealing key or a corrupted envelope -- not a wrong redeemer. The claim is spent either
        // way; there is nothing usable left to protect, and re-offering it would be worse.
        let plaintext = open(&self.sealing_key, subject, &sealed)?;
        String::from_utf8(plaintext)
            .map(Some)
            .map_err(|_| Error::Server("stored secret was not valid UTF-8".to_string()))
    }
}
