//! Redis-backed `authkestra_op::client_assertion::ClientAssertionStore` (ADR-0011, Decision 6):
//! atomically spends a `private_key_jwt` client assertion's `jti` so a captured assertion cannot
//! be replayed for the rest of its lifetime.
//!
//! `SET <key> 1 NX PX <ttl>` is the whole implementation: `NX` makes the write conditional on the
//! key not already existing (first use), and Redis executes the check-and-set as a single atomic
//! command, so two concurrent presentations of the same `jti` can never both observe "not yet
//! seen" -- exactly the atomicity `ClientAssertionStore::record_jti`'s doc comment requires. `PX`
//! bounds the key's lifetime to the assertion's own `exp`, so the replay set self-cleans instead
//! of growing forever.
//!
//! Fail-closed by construction, not by a fallback branch: any Redis error (connection down,
//! timeout, protocol error) is mapped to `Err(OpError::Storage)`, never to `Ok(true)`. There is no
//! code path here that turns "Redis is unreachable" into "assertion accepted" -- an outage refuses
//! confidential-client authentication rather than admitting it (this repo's first review
//! priority: the unavailable branch must never become the permissive branch).

use authkestra_op::{ClientAssertionStore, OpError};
use chrono::{DateTime, Utc};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::error::{Error, Result};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;

use crate::redis_tls::build_redis_client;

/// Lower bound on the `PX` we hand Redis. `record_jti` is only ever called with an `expires_at`
/// that `client_assertion::verify_client_assertion` already checked is in the future (assertions
/// with an expired `exp` are refused before replay tracking runs at all), but clamping here keeps
/// this store correct even if that invariant is ever weakened -- Redis rejects `PX 0`/negative
/// outright, which would otherwise turn a boundary case into a hard `OpError::Storage` instead of
/// a very short-lived key.
const MIN_TTL_MS: i64 = 1_000;

#[derive(Clone)]
pub struct RedisClientAssertionStore {
    manager: ConnectionManager,
    key_prefix: String,
}

impl RedisClientAssertionStore {
    /// Builds a Redis connection manager (auto-reconnecting, shareable via `Clone`) and namespaces
    /// every `jti` key under `key_prefix` so this store's keys never collide with the rate-limit
    /// buckets `ratelimit_redis` writes into the same Redis instance.
    ///
    /// Lazy, like `ratelimit_redis::build_redis_rate_limit_store`'s `RedisRateLimitStore::open`:
    /// `get_connection_manager_lazy` does not establish a connection here, only on first use, so
    /// this never blocks or fails server startup on a not-yet-reachable Redis -- consistent with
    /// how this service already treats Redis for rate limiting. The fail-closed property this
    /// module exists for is about `record_jti`'s *return value* when Redis genuinely is
    /// unreachable at request time, not about startup ordering.
    ///
    /// `ca_bundle_path` (lightbridge-authz#363) is only consulted when `redis_url` is
    /// `rediss://` -- see [`crate::redis_tls::build_redis_client`] for the full TLS/CA
    /// contract this shares with `ratelimit_redis::build_redis_rate_limit_store`.
    pub fn connect(
        redis_url: &str,
        ca_bundle_path: Option<&str>,
        key_prefix: impl Into<String>,
    ) -> Result<Self> {
        let client = build_redis_client(redis_url, ca_bundle_path)?;
        let manager = client
            .get_connection_manager_lazy(redis::aio::ConnectionManagerConfig::default())
            .map_err(|e| {
                Error::Server(format!(
                    "failed to build redis connection manager for client-assertion replay tracking: {e}"
                ))
            })?;
        Ok(Self {
            manager,
            key_prefix: key_prefix.into(),
        })
    }

    fn key(&self, jti: &str) -> String {
        format!("{}{jti}", self.key_prefix)
    }
}

#[async_trait]
impl ClientAssertionStore for RedisClientAssertionStore {
    async fn record_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool, OpError> {
        let ttl_ms = (expires_at - Utc::now()).num_milliseconds().max(MIN_TTL_MS);
        let key = self.key(jti);
        let mut conn = self.manager.clone();
        let set: Option<String> = conn
            .set_options(
                &key,
                1,
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::PX(ttl_ms as u64)),
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    "redis error recording client assertion jti; refusing the assertion rather \
                     than risking an unenforced replay"
                );
                OpError::Storage
            })?;
        Ok(set.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lazily-connected client-assertion store must fail closed (an `Err`, never `Ok(true)`)
    /// when Redis is unreachable -- this is the polarity this whole module exists to guarantee.
    /// See `oauth2_op::store` for the end-to-end version of this test against the full token
    /// endpoint (Redis-down => confidential-client auth refused, not admitted).
    #[tokio::test]
    async fn record_jti_refuses_rather_than_admits_when_redis_is_unreachable() {
        let store = RedisClientAssertionStore::connect("redis://127.0.0.1:1/", None, "test:")
            .expect("connection manager construction is lazy and always succeeds");
        let result = store
            .record_jti("some-jti", Utc::now() + chrono::Duration::seconds(60))
            .await;
        assert!(
            matches!(result, Err(OpError::Storage)),
            "unreachable redis must refuse (Err), never silently accept: {result:?}"
        );
    }
}
