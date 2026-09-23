use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Logging {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    pub url: String,
    pub pool_size: Option<u32>,
}

/// Redis connection settings. `url` is a standard `redis://[:password@]host:port[/db]`
/// connection string, e.g. `redis://redis:6379` in Compose or `redis://localhost:6379`
/// for non-container local runs (see `config/default.yaml`, `.docker/authz/container.yaml`),
/// or `rediss://[:password@]host:port[/db]` for TLS (lightbridge-authz#363) — real
/// deployments talk to the cluster's TLS-only `redis-ha`.
#[derive(Debug, Clone, Deserialize)]
pub struct Redis {
    pub url: String,
    /// PEM file trusted as the sole root when `url` uses `rediss://`. `redis-ha`'s TLS
    /// listener presents a certificate signed by the cluster's internal self-signed CA
    /// (the same `ClusterIssuer/self-signed-ca` root as `usage_service.ca_bundle_path` and
    /// the `authz-tls` Secret's `ca.crt` already mounted at `/etc/lightbridge/tls/ca.crt`),
    /// which is never in the OS/public trust store, so this is required whenever `url` is
    /// `rediss://` — see `redis_tls::build_redis_client`. `redis-ha` requires no client
    /// certificate (`tls-auth-clients no`), so unlike `usage_service` there is no
    /// `client_cert_path`/`client_key_path` pair here. Ignored for plain `redis://` URLs
    /// (local Compose). An unreadable or unparseable path, like every other CA-bundle
    /// config in this codebase, is a hard startup failure, never a silent fallback.
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
}

/// HTTP client config for `lightbridge-authz-budget`'s `UsageServiceSpendReader` to call
/// `lightbridge-authz-usage`'s `/usage/v1/spend/query` endpoint. See `Config::usage_service`'s
/// doc comment for why this replaced a direct database connection. `client_cert_path`/
/// `client_key_path` (#347) present a client certificate for mTLS when the usage service
/// requires one; see `UsageServiceSpendReader`'s own doc comment for the full posture.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageServiceClient {
    /// Base URL of the usage service, e.g. `https://authz-usage:3002`. A trailing slash is
    /// stripped if present.
    pub base_url: String,
    /// Skip TLS certificate verification when calling the usage service. Local Compose serves
    /// every authz service over a self-signed certificate with no shared CA bundle available to
    /// mount, so a client that verifies certificates strictly can never reach it there. Defaults
    /// to `false`.
    ///
    /// This must NOT be set in production. The doc comment here previously claimed production
    /// "must never set this" on the assumption that production terminates a publicly-trusted
    /// certificate — it does not: production terminates a cert-manager-issued *self-signed*
    /// certificate (`ClusterIssuer/self-signed-ca`), the same shape as local Compose. The correct
    /// production mechanism is `ca_bundle_path` below, which verifies against that specific CA
    /// instead of either trusting nothing (`insecure_skip_verify`) or falling back to a system
    /// trust store that was never going to contain this private CA anyway.
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// Path to a PEM-encoded CA bundle used to verify the usage service's certificate, e.g.
    /// `/etc/lightbridge/tls/ca.crt` (the `ca.crt` cert-manager writes into the same `authz-tls`
    /// Secret this service already mounts for its own server certificate — see
    /// `crates/lightbridge-authz-core/src/config::server`'s `Tls` type). This is the production
    /// mechanism: it verifies the usage service's certificate is signed by the cluster's own CA,
    /// rather than skipping verification entirely. Optional — when unset, verification falls
    /// back to the platform's default trust store (or, if `insecure_skip_verify` is `true`, to no
    /// verification at all, for local Compose only). An unreadable path or a bundle that fails to
    /// parse as PEM is a hard startup failure naming the path — never a silent fallback to
    /// skip-verify or to the system trust store (an unusable trust anchor is "unknown", which per
    /// this codebase's fail-closed rule must route to the strictest branch: refuse to start,
    /// rather than start with a weaker guarantee than configured).
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
    /// Path to a PEM-encoded client certificate this reader presents to the usage service for
    /// mTLS (#347), e.g. `/etc/lightbridge/tls/tls.crt` -- the same certificate this pod already
    /// mounts for its own server listener (`Tls::cert_path`), reused as a client identity
    /// because the deployed cert already carries both `serverAuth` and `clientAuth` in its
    /// `extendedKeyUsage` (confirmed against the live cluster: `kubectl -n converse get
    /// certificate authz-tls -o yaml` shows `usages: [server auth, client auth]`). Must be set
    /// together with `client_key_path` below -- setting exactly one of the two is a hard
    /// construction error, never a silent "connect without an identity" fallback. Both unset
    /// (the default) means this reader presents no client certificate, exactly as before #347.
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Private key matching `client_cert_path` above, e.g. `/etc/lightbridge/tls/tls.key`. See
    /// that field's doc comment.
    #[serde(default)]
    pub client_key_path: Option<String>,
    /// Per-request timeout in milliseconds. Defaults to 5000 (5s).
    #[serde(default = "default_usage_service_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_usage_service_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct Otel {
    pub enabled: bool,
    pub otlp_endpoint: String,
    pub service_name: String,
}

/// Configuration for single-use, subject-bound API key secret claims (GHSA-9pc6-965v-2c44).
///
/// MCP tool results are returned into the calling model's context, so they cannot carry
/// credential material. Instead the secret is sealed under [`SecretClaim::encryption_key`] and
/// handed over as an opaque token the human redeems once, in a browser, against `authz-idp`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretClaim {
    /// base64url-encoded, exactly 32 bytes. Seals the pending secret at rest, with the creating
    /// subject as AES-GCM associated data.
    ///
    /// Rotating it makes every un-redeemed claim permanently unopenable. That is the intended
    /// posture and it is cheap here, unlike `OidcRelyingParty::token_encryption_key`: claims live
    /// for minutes, so the blast radius of a rotation is whatever was issued in the last TTL
    /// window, not every stored session.
    pub encryption_key: String,
    /// How long a human has to collect their secret. Deliberately short -- an unredeemed claim is
    /// a credential sitting at rest for no reason.
    #[serde(default = "default_secret_claim_ttl_seconds")]
    pub ttl_seconds: i64,
    /// Origin of the `authz-idp` deployment that serves redemption, e.g.
    /// `https://auth.example.com`. The issued URL is `{redeem_base_url}/api-keys/claim/{token}`.
    ///
    /// Configured rather than derived from the request: the issuer (`lightbridge-mcp`) and the
    /// redeemer (`authz-idp`) are different services on different hosts, and a URL built from an
    /// inbound request header would be attacker-influenced.
    pub redeem_base_url: String,
}

const fn default_secret_claim_ttl_seconds() -> i64 {
    300
}
