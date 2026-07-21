//! Redis-backed [`RateLimitStore`] for `authz-api`'s rate-limiting middleware
//! (see `docs/adr/0003-cratestack-crud-migration.md`, "Rate limiting (Redis-backed)").
//!
//! `cratestack-axum` ships the pluggable `RateLimitStore` trait plus
//! `InMemoryRateLimitStore` (single-replica reference implementation), but has no
//! Redis-backed implementation of its own.
//!
//! IMPORTANT — read before touching this file: a Redis-backed implementation of this
//! exact trait already exists and is published as its own crate, `cratestack-redis`
//! (crates.io, pinned to the same `0.4.9` release as `cratestack-pg`/`cratestack-axum`,
//! same author/homepage as the rest of the cratestack family). Its
//! `cratestack_redis::RedisRateLimitStore`:
//!
//! - implements `cratestack_axum::ratelimit::RateLimitStore` (the trait this crate's
//!   `RateLimitLayer` is generic over),
//! - runs the identical token-bucket algorithm as `InMemoryRateLimitStore` (same
//!   burst/refill semantics), but atomically via a single `redis::Script` (Lua) that
//!   does the HMGET-read + refill-math + HSET-write + EXPIRE under Redis's
//!   single-threaded command execution — i.e. exactly the "atomic Redis operations ...
//!   race-free under concurrent requests" requirement multi-replica correctness needs,
//!   and
//! - namespaces bucket keys with a SHA-256 hash of the caller-supplied key under a
//!   configurable prefix, and sets a TTL derived from `burst`/`refill_per_second` so
//!   idle buckets expire instead of leaking Redis memory forever.
//!
//! Hand-rolling a second implementation of the same trait against the same Redis
//! primitives here would duplicate that tested implementation (see
//! `cratestack-redis/src/ratelimit/{store,trait_impl,scripts,parse,time,util}.rs` in
//! the crate source) and risks behavioral drift from `InMemoryRateLimitStore` that the
//! upstream crate has already worked out. This module re-exports and thinly wraps the
//! upstream type instead of duplicating it.
//!
//! `RedisRateLimitStore::open`/`from_client`/`bucket_key` are cratestack-redis's own
//! public constructors; [`build_redis_rate_limit_store`] below only adapts the error
//! type to this crate's `lightbridge_authz_core::Result` and returns the
//! `Arc<dyn RateLimitStore>` shape `RateLimitLayer::new` expects.

use std::sync::Arc;

use cratestack_axum::ratelimit::RateLimitStore;
use lightbridge_authz_core::error::{Error, Result};

pub use cratestack_redis::RedisRateLimitStore;

/// Builds a Redis-backed [`RateLimitStore`] from a `redis://` connection URL and a key
/// prefix used to namespace rate-limit buckets in the shared Redis instance (see
/// `RedisRateLimitStore::bucket_key`). Suitable for direct use with
/// `cratestack_axum::ratelimit::RateLimitLayer::new`.
pub fn build_redis_rate_limit_store(
    redis_url: &str,
    key_prefix: impl Into<String>,
) -> Result<Arc<dyn RateLimitStore>> {
    let store = RedisRateLimitStore::open(redis_url, key_prefix)
        .map_err(|err| Error::Server(format!("failed to open redis rate limit store: {err}")))?;
    Ok(Arc::new(store))
}
