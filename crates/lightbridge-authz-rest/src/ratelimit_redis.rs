//! Redis-backed [`RateLimitStore`] for `authz-api`'s rate-limiting middleware
//! (see `docs/adr/0003-cratestack-crud-migration.md`, "Rate limiting (Redis-backed)").
//!
//! `cratestack-axum` ships the pluggable `RateLimitStore` trait plus
//! `InMemoryRateLimitStore` (single-replica reference implementation), but has no
//! Redis-backed implementation of its own.
//!
//! IMPORTANT — read before touching this file: a Redis-backed implementation of this
//! exact trait already exists and is published as its own crate, `cratestack-redis`
//! (crates.io, pinned to the same release as `cratestack-pg`/`cratestack-axum` — see the
//! version comment in the workspace root `Cargo.toml` for the exact pin — kept in lockstep
//! with the rest of the cratestack family whenever it's bumped). Its
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
//! public constructors; [`build_redis_rate_limit_store`] below builds the client through
//! [`crate::redis_tls::build_redis_client`] (lightbridge-authz#363 -- TLS/CA-aware, shared
//! with `oauth2_op::client_assertion_store`) and hands it to `from_client`, rather than
//! `open`'s plain-URL path, so a `rediss://` `redis.url` works here too.

use std::sync::Arc;

use cratestack_axum::ratelimit::RateLimitStore;
use lightbridge_authz_core::error::Result;

pub use cratestack_redis::RedisRateLimitStore;

use crate::redis_tls::build_redis_client;

/// Builds a Redis-backed [`RateLimitStore`] from a `redis://`/`rediss://` connection URL, an
/// optional CA bundle path (see [`crate::redis_tls::build_redis_client`]), and a key prefix
/// used to namespace rate-limit buckets in the shared Redis instance (see
/// `RedisRateLimitStore::bucket_key`). Suitable for direct use with
/// `cratestack_axum::ratelimit::RateLimitLayer::new`.
pub fn build_redis_rate_limit_store(
    redis_url: &str,
    ca_bundle_path: Option<&str>,
    key_prefix: impl Into<String>,
) -> Result<Arc<dyn RateLimitStore>> {
    let client = build_redis_client(redis_url, ca_bundle_path)?;
    let store = RedisRateLimitStore::from_client(client, key_prefix);
    Ok(Arc::new(store))
}
