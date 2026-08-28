//! Single-use, subject-bound claims for handing an API key secret to a human without ever
//! putting it in a place a model can read (GHSA-9pc6-965v-2c44, #538).
//!
//! `lightbridge-mcp` returns tool results straight into the calling model's context, so it is not
//! an acceptable delivery channel for credential material. Instead `authz-api` seals the freshly
//! minted secret here and returns only an opaque claim token; the human redeems it once, in a
//! browser, against `authz-idp`.
//!
//! The property the whole design rests on: **possession of the token is not sufficient to redeem
//! it.** The token necessarily travels through the model's context -- that is the point of handing
//! it over -- so if possession were enough, this would rename the exposure rather than remove it.
//! Redemption additionally requires the redeemer's authenticated browser session to belong to the
//! same subject that created the key, which a model structurally cannot supply.
//!
//! That binding is cryptographic, not a string comparison: the subject is the AES-GCM associated
//! data ([`lightbridge_authz_core::crypto::seal`]), so a wrong-subject redemption cannot decrypt
//! the envelope at all. A comparison can be bypassed by any bug that reaches the unseal; an AAD
//! mismatch cannot.
//!
//! Storage is Redis rather than Postgres for two reasons: `GETDEL` gives exactly-once consumption
//! in a single atomic round trip (the same "claimed exactly once across concurrent callers"
//! property `consume_authorization_code` hand-writes as `UPDATE ... WHERE consumed_at IS NULL`),
//! and the short TTL comes free instead of needing a sweeper.

use base64::Engine;
use lightbridge_authz_core::crypto::{open, seal};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};

use crate::redis_tls::build_redis_client;

/// What the caller gets back when a secret is stashed: the opaque token to hand to the human, and
/// how long they have. The secret itself is deliberately absent -- once issued, the only way back
/// to it is [`RedisSecretClaimStore::redeem`].
#[derive(Debug, Clone)]
pub struct IssuedClaim {
    pub token: String,
    pub expires_in_seconds: u64,
}

/// Redis-backed claim store. Construction is lazy (no dial-out, matching
/// `RedisClientAssertionStore::connect`'s contract), so a component holding one still starts when
/// Redis is momentarily unreachable -- the refusal happens at first use, never as a silent pass.
pub struct RedisSecretClaimStore {
    conn: ConnectionManager,
    key_prefix: String,
    sealing_key: [u8; 32],
    ttl_seconds: u64,
}

impl std::fmt::Debug for RedisSecretClaimStore {
    /// Hand-written, never derived: `sealing_key` must not reach a log line. Same posture as
    /// `TokenResponse`/`KeycloakTokenSet`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisSecretClaimStore")
            .field("key_prefix", &self.key_prefix)
            .field("ttl_seconds", &self.ttl_seconds)
            .field("sealing_key", &"<redacted>")
            .finish()
    }
}

impl RedisSecretClaimStore {
    /// Builds the store. Lazy: this never dials Redis, so it cannot fail for an unreachable
    /// server -- only for a malformed URL or unreadable CA bundle.
    pub fn connect(
        url: &str,
        ca_bundle_path: Option<&str>,
        key_prefix: impl Into<String>,
        sealing_key: [u8; 32],
        ttl_seconds: u64,
    ) -> Result<Self> {
        let client = build_redis_client(url, ca_bundle_path)?;
        let conn = client
            .get_connection_manager_lazy(redis::aio::ConnectionManagerConfig::default())
            .map_err(|e| Error::Server(format!("failed to build redis connection manager: {e}")))?;
        Ok(Self {
            conn,
            key_prefix: key_prefix.into(),
            sealing_key,
            ttl_seconds,
        })
    }

    /// The stored key for a token. The token itself is never at rest in the clear -- same reason
    /// `api_keys` stores only `key_hash`: a dump of the claim store must not be a dump of usable
    /// claim tokens.
    fn redis_key(&self, token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        format!(
            "{}claim:{}",
            self.key_prefix,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }

    /// Seals `secret` against `subject` and stores it under a fresh CUID2 token (ADR-0039's one
    /// minting chokepoint) with the configured TTL.
    ///
    /// Errors are hard failures, never a silent skip: a caller that cannot stash the secret must
    /// refuse the whole operation rather than fall back to returning it inline.
    pub async fn issue(&self, secret: &str, subject: &str) -> Result<IssuedClaim> {
        let token = cuid2();
        let sealed = seal(&self.sealing_key, subject, secret.as_bytes())?;
        let mut conn = self.conn.clone();
        let _: () = conn
            .set_ex(self.redis_key(&token), sealed, self.ttl_seconds)
            .await
            .map_err(|e| Error::Server(format!("failed to store secret claim: {e}")))?;
        Ok(IssuedClaim {
            token,
            expires_in_seconds: self.ttl_seconds,
        })
    }

    /// Redeems `token` on behalf of `subject`, returning the secret exactly once.
    ///
    /// `Ok(None)` means "no secret for you" and covers every non-exceptional miss: unknown token,
    /// expired token, already redeemed, or a subject that does not own the claim. The caller must
    /// not distinguish these to the redeemer -- doing so turns this into an oracle for which
    /// tokens exist.
    ///
    /// A wrong-subject attempt deliberately does **not** consume the claim. Consuming on failure
    /// would let anyone holding the token -- including the model it was handed through -- destroy
    /// the legitimate user's one chance to collect their key. Rate-limit the endpoint instead.
    ///
    /// `Err` is reserved for the store itself being unusable, so the caller can answer "try again"
    /// rather than "no such claim". Both refuse; neither returns the secret.
    pub async fn redeem(&self, token: &str, subject: &str) -> Result<Option<String>> {
        let key = self.redis_key(token);
        let mut conn = self.conn.clone();
        let sealed: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| Error::Server(format!("failed to read secret claim: {e}")))?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        // Wrong subject cannot decrypt: `subject` is the AAD. Return before touching the key, so
        // the real owner's claim survives someone else's attempt.
        let Ok(plaintext) = open(&self.sealing_key, subject, &sealed) else {
            return Ok(None);
        };
        // Only now claim it. GETDEL is the exactly-once boundary: under concurrent redemption by
        // the same subject exactly one caller sees a value, and the loser falls through to `None`.
        let claimed: Option<String> = conn
            .get_del(&key)
            .await
            .map_err(|e| Error::Server(format!("failed to consume secret claim: {e}")))?;
        if claimed.is_none() {
            return Ok(None);
        }
        String::from_utf8(plaintext)
            .map(Some)
            .map_err(|_| Error::Server("stored secret was not valid UTF-8".to_string()))
    }
}
