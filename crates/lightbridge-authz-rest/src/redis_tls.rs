//! Shared TLS-aware `redis::Client` construction (lightbridge-authz#363): the one place this
//! crate's two Redis consumers -- `ratelimit_redis` (rate-limit buckets, `authz-api`/
//! `authz-budget`) and `oauth2_op::client_assertion_store` (client-assertion replay tracking,
//! `authz-idp`) -- build a client, so both share one fail-closed TLS/CA code path instead of
//! two independently-maintained ones.
//!
//! `redis.url`'s scheme decides everything, mirroring how the `redis` crate itself parses
//! `redis://` vs `rediss://`:
//!
//! - `redis://` (local Compose, `config/default.yaml`) -- plain `redis::Client::open`, byte-for-
//!   byte the pre-#363 behavior. `redis.ca_bundle_path` is ignored.
//! - `rediss://` (real deployments, pointed at the cluster's TLS-only `redis-ha`) -- REQUIRES
//!   `redis.ca_bundle_path`, loaded as the sole trusted root and passed to
//!   `redis::Client::build_with_tls`. `redis-ha`'s TLS listener presents a certificate signed by
//!   the cluster's internal self-signed CA (`ClusterIssuer/self-signed-ca`), which is never in
//!   the OS/public trust store -- there is deliberately no "fall back to the ambient trust
//!   store" branch for `rediss://`, because that would silently downgrade from "verified against
//!   a specific CA" to "verified against roots that don't include this CA" i.e. "never verifies,
//!   ever connects" in practice. `redis-ha` requires no client certificate
//!   (`tls-auth-clients no`), so unlike `UsageServiceSpendReader` there is no
//!   `client_tls`/mTLS wiring here.
//!
//! Fail-closed by construction, matching this repo's first review priority (does the
//! unavailable branch become the permissive branch?): a missing, unreadable, or unparseable
//! `ca_bundle_path` under `rediss://` is a hard `Err` returned eagerly from this function --
//! before any network I/O -- never a silent fallback to plaintext or to an unverified handshake.
//! The actual TLS handshake itself still happens lazily on first use (`redis::Client::open`,
//! `build_with_tls`, and every constructor built on top of them in this crate are all
//! non-blocking at construction time -- see `ratelimit_redis`'s and
//! `client_assertion_store::RedisClientAssertionStore::connect`'s own doc comments), so a
//! handshake failure at request time still surfaces as a normal Redis `Err`, which every caller
//! here already treats as "refuse the operation", never as "operation succeeded, unauthenticated
//! or without caching".

use lightbridge_authz_core::error::{Error, Result};
use std::sync::Once;

/// Installs rustls's default (`ring`) crypto provider process-wide, exactly once, idempotently
/// (a second install attempt is a harmless `Err` we discard). `build_with_tls` needs a provider
/// installed the first time it runs `rustls::ClientConfig` construction internally, and this
/// function can run *before* `lightbridge_authz_core::server::serve_tls` -- which installs the
/// same provider for the inbound TLS listener -- since redis clients are built during server
/// bootstrap, ahead of the call to `serve_tls` that finally binds and serves. Without this, the
/// very first `rediss://` connection attempt in a freshly started process would race the
/// listener's own install, or run with none installed at all.
fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Builds a `redis::Client` for `url`, upgrading to a rustls-backed TLS connection trusting only
/// `ca_bundle_path` when `url` uses the `rediss://` scheme. See the module doc comment for the
/// full contract.
pub fn build_redis_client(url: &str, ca_bundle_path: Option<&str>) -> Result<redis::Client> {
    if !url.starts_with("rediss://") {
        return redis::Client::open(url)
            .map_err(|e| Error::Server(format!("invalid redis url: {e}")));
    }
    ensure_rustls_provider();
    let path = ca_bundle_path.ok_or_else(|| {
        Error::Server(
            "redis.url uses rediss:// but redis.ca_bundle_path is not set -- a rediss:// \
             connection to the cluster's internally-signed redis-ha requires an explicit \
             trusted root; there is no OS/public trust store fallback for rediss://"
                .to_string(),
        )
    })?;
    let root_cert = std::fs::read(path)
        .map_err(|e| Error::Server(format!("failed to read redis.ca_bundle_path '{path}': {e}")))?;
    let tls_certs = redis::TlsCertificates {
        client_tls: None,
        root_cert: Some(root_cert),
    };
    redis::Client::build_with_tls(url, tls_certs)
        .map_err(|e| Error::Server(format!("failed to build TLS redis client for '{url}': {e}")))
}
