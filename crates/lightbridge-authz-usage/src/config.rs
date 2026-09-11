use lightbridge_authz_core::Result;
use lightbridge_authz_core::config::{Database, Logging, Oauth2, Otel, Tls, load_yaml_from_path};
use serde::Deserialize;
use tracing::debug;

// `RetentionConfig` lives in `retention_config` (split out by the LoC gate); re-export it here so
// every existing `use config::RetentionConfig` path still resolves.
pub use crate::retention_config::RetentionConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct UsageConfig {
    pub server: UsageServerGroup,
    pub logging: Logging,
    pub database: Database,
    pub otel: Otel,
    /// Validates the end-user bearer token `/usage/v1/usage/query` now requires (#570). Reuses
    /// core's shared `Oauth2` type (the same one `authz-api`/`authz-opa`/`authz-budget` load) even
    /// though this service only ever reads `jwks_url` (and, if set, `audience`/`rbac`) off it --
    /// see `BearerTokenService::new`. Required, not `Option`: ownership enforcement on the query
    /// listener is mandatory (this is an authentication boundary, AGENTS.md's "Failure modes"
    /// rule), so a config that omits it must fail to load rather than silently leaving the query
    /// listener unable to validate a bearer token at all.
    pub oauth2: Oauth2,
    /// The ownership authority `/usage/v1/usage/query` calls for `account`/`project` scopes
    /// (#570) -- `authz-opa`'s `POST /idp/v1/authorize-usage-scope`. Required for the same reason
    /// `oauth2` above is: this is the one thing that turns "we validated a bearer token" into "and
    /// this user actually owns what they're asking about."
    pub scope_authority: ScopeAuthorityConfig,
    /// Retention/rollup for `usage_events` (#549 AC2). Optional with safe defaults: the background
    /// job is OFF by default (see [`RetentionConfig::enabled`] for the rollback-safety reason),
    /// and when enabled keeps 90 days of raw events and rolls older rows into `usage_events_daily`
    /// hourly. See [`RetentionConfig`].
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// HTTP client config for calling `authz-opa`'s `POST /idp/v1/authorize-usage-scope` (#570).
/// Mirrors `lightbridge_authz_core::config::UsageServiceClient` field-for-field (see that type's
/// doc comments for the full `insecure_skip_verify`/`ca_bundle_path`/`client_cert_path`/
/// `client_key_path` reasoning) -- this is a distinct type, not a reuse of `UsageServiceClient`,
/// because that type lives in `core` for the budget domain's unrelated `/usage/v1/spend/query`
/// call and carries no Basic-auth credential, which this endpoint requires.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeAuthorityConfig {
    /// Base URL of `authz-opa`'s validation server, e.g. `https://authz-opa:3001`.
    pub base_url: String,
    /// Basic-auth username presented to `POST /idp/v1/authorize-usage-scope` -- the same
    /// credential `authz-opa`'s `server.opa.basic_auth` names.
    pub username: String,
    /// Basic-auth password. See `username`'s doc comment.
    pub password: String,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default = "default_scope_authority_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_scope_authority_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageServerGroup {
    /// Ingest-only listener: `/v1/otel/{traces,metrics,logs}` plus the health probes and Swagger
    /// docs. Unauthenticated, exactly as before #347 -- the caller here is an AI Envoy/OpenTelemetry
    /// exporter outside this repo's deploy surface (see `docs/usage-api.md`), so this port cannot
    /// require a client certificate without a coordinated change to that caller, which is out of
    /// this ticket's scope (see #347's "Out of Scope"). `lightbridge-authz-usage` stays
    /// `ClusterIP`-only with no ingress, same mitigation as always.
    pub usage: UsageServer,
    /// mTLS-required listener (#347): `/usage/v1/usage/query` and `/usage/v1/spend/query`, the
    /// two routes #347's acceptance criteria names, plus their own health probes. Split onto its
    /// own port (rather than gating routes on the shared `usage` listener above) because
    /// `axum-server`'s rustls integration enforces client-certificate verification at the
    /// listener level, not per-route -- gating the whole `usage` listener would also lock out the
    /// ingest caller above, which cannot present a client certificate. `Tls::client_ca_bundle_path`
    /// here is what actually turns mTLS on; this field is required (not `Option`) so a config
    /// that omits it fails to load rather than silently leaving these two routes on the old
    /// unauthenticated port -- see the deploy-sequencing note in the PR that introduced this.
    pub query: UsageServer,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
}

pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<UsageConfig> {
    debug!("loading usage config from {:?}", path.as_ref());
    let config: UsageConfig = load_yaml_from_path(path)?;
    if config.retention.raw_days < 90 {
        return Err(lightbridge_authz_core::Error::Server(format!(
            "retention.raw_days must be >= 90 (got {})",
            config.retention.raw_days
        )));
    }
    if config.retention.rollup_days < 1 {
        return Err(lightbridge_authz_core::Error::Server(format!(
            "retention.rollup_days must be >= 1 (got {})",
            config.retention.rollup_days
        )));
    }
    // The rollup must retain data LONGER than the raw window, or a rolled-up day is deleted from
    // `usage_events_daily` in the same transaction that wrote it (the rollup purge cutoff is
    // `rollup_days`, and a day older than `raw_days` is already older than `rollup_days` when
    // `rollup_days <= raw_days`). That would silently destroy every rolled-up day.
    if config.retention.rollup_days <= config.retention.raw_days {
        return Err(lightbridge_authz_core::Error::Server(format!(
            "retention.rollup_days must be > retention.raw_days (got rollup_days={}, raw_days={})",
            config.retention.rollup_days, config.retention.raw_days
        )));
    }
    debug!("loaded usage config successfully");
    Ok(config)
}
