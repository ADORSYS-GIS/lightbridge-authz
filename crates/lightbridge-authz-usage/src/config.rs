use lightbridge_authz_core::Result;
use lightbridge_authz_core::config::{Database, Logging, Oauth2, Otel, Tls, load_yaml_from_path};
use serde::Deserialize;
use tracing::debug;

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
    /// job is on by default, keeps 90 days of raw events, and rolls older rows into
    /// `usage_events_daily` hourly. See [`RetentionConfig`].
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// Retention/rollup configuration for `usage_events` (#549 AC2).
///
/// `usage_events` grows ~100 MB/day with no retention. This config drives a background job in the
/// usage service that rolls rows older than `raw_days` into the `usage_events_daily` aggregate and
/// deletes them from the raw table, in one transaction. The dashboard's max range is 90 days, so
/// `raw_days` MUST be >= 90 to keep the full dashboard window queryable from raw (which is what
/// keeps latency percentiles exact -- the rollup does not carry them). Budget spend reads the
/// current billing period, which is always within the raw window, so it is never truncated.
#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    /// Whether the retention/rollup background job runs. Default `true`.
    #[serde(default = "default_retention_enabled")]
    pub enabled: bool,
    /// Days of raw `usage_events` to keep before rolling up + deleting. Must be >= the dashboard's
    /// max range (90 days). Default `90`.
    #[serde(default = "default_retention_raw_days")]
    pub raw_days: i64,
    /// How often the retention/rollup job runs, in seconds. Default `3600` (hourly).
    #[serde(default = "default_retention_interval_seconds")]
    pub interval_seconds: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: default_retention_enabled(),
            raw_days: default_retention_raw_days(),
            interval_seconds: default_retention_interval_seconds(),
        }
    }
}

fn default_retention_enabled() -> bool {
    true
}

fn default_retention_raw_days() -> i64 {
    90
}

fn default_retention_interval_seconds() -> u64 {
    3600
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
    let config = load_yaml_from_path(path)?;
    debug!("loaded usage config successfully");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn interpolate_env_vars_should_handle_default_values() {
        unsafe {
            env::remove_var("USAGE_MISSING_VAR");
        }

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("usage-config-{unique}.yaml"));
        let content = r#"
server:
  usage:
    address: "0.0.0.0"
    port: 3002
    tls:
      cert_path: "/tls/usage.crt"
      key_path: "/tls/usage.key"
  query:
    address: "0.0.0.0"
    port: 3006
    tls:
      cert_path: "/tls/usage.crt"
      key_path: "/tls/usage.key"
      client_ca_bundle_path: "/tls/ca.crt"
logging:
  level: "info"
database:
  url: "postgres://${USAGE_MISSING_VAR:-host}:5432/db"
  pool_size: 10
otel:
  enabled: false
  otlp_endpoint: "http://localhost:4317"
  service_name: "lightbridge-authz-usage"
oauth2:
  type: external
  jwks_url: "http://keycloak:9100/realms/dev/protocol/openid-connect/certs"
scope_authority:
  base_url: "https://authz-opa:3001"
  username: "authorino"
  password: "change-me"
"#;
        fs::write(&path, content).expect("temp config should be written");

        let cfg = load_from_path(&path).expect("config should load");
        fs::remove_file(&path).expect("temp config should be removed");

        assert_eq!(cfg.database.url, "postgres://host:5432/db");
    }

    /// #347: `server.query` is required (not `Option`), a deliberate hard cutover -- a config that
    /// omits it must fail to load rather than silently leaving `/usage/v1/usage/query`/
    /// `/usage/v1/spend/query` on the old unauthenticated listener. See `UsageServerGroup::query`'s
    /// doc comment for the full reasoning and the required deploy-ordering consequence.
    #[test]
    fn config_missing_query_server_fails_to_load() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("usage-config-missing-query-{unique}.yaml"));
        let content = r#"
server:
  usage:
    address: "0.0.0.0"
    port: 3002
    tls:
      cert_path: "/tls/usage.crt"
      key_path: "/tls/usage.key"
logging:
  level: "info"
database:
  url: "postgres://host:5432/db"
  pool_size: 10
otel:
  enabled: false
  otlp_endpoint: "http://localhost:4317"
  service_name: "lightbridge-authz-usage"
oauth2:
  type: external
  jwks_url: "http://keycloak:9100/realms/dev/protocol/openid-connect/certs"
scope_authority:
  base_url: "https://authz-opa:3001"
  username: "authorino"
  password: "change-me"
"#;
        fs::write(&path, content).expect("temp config should be written");

        let result = load_from_path(&path);
        fs::remove_file(&path).expect("temp config should be removed");

        assert!(
            result.is_err(),
            "a config omitting server.query must fail to load, not silently degrade"
        );
    }

    fn valid_server_and_logging_block() -> &'static str {
        r#"
server:
  usage:
    address: "0.0.0.0"
    port: 3002
    tls:
      cert_path: "/tls/usage.crt"
      key_path: "/tls/usage.key"
  query:
    address: "0.0.0.0"
    port: 3006
    tls:
      cert_path: "/tls/usage.crt"
      key_path: "/tls/usage.key"
      client_ca_bundle_path: "/tls/ca.crt"
logging:
  level: "info"
database:
  url: "postgres://host:5432/db"
  pool_size: 10
otel:
  enabled: false
  otlp_endpoint: "http://localhost:4317"
  service_name: "lightbridge-authz-usage"
"#
    }

    /// #570: `oauth2` (used to validate the end-user bearer token `/usage/v1/usage/query` now
    /// requires) is required, not `Option` -- see [`UsageConfig::oauth2`]'s doc comment. A config
    /// omitting it must fail to load, not silently leave the query listener unable to validate a
    /// bearer token.
    #[test]
    fn config_missing_oauth2_fails_to_load() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("usage-config-missing-oauth2-{unique}.yaml"));
        let content = format!(
            "{}\nscope_authority:\n  base_url: \"https://authz-opa:3001\"\n  username: \"authorino\"\n  password: \"change-me\"\n",
            valid_server_and_logging_block()
        );
        fs::write(&path, content).expect("temp config should be written");

        let result = load_from_path(&path);
        fs::remove_file(&path).expect("temp config should be removed");

        assert!(
            result.is_err(),
            "a config omitting oauth2 must fail to load, not silently degrade"
        );
    }

    /// #570: `scope_authority` (the ownership authority `/usage/v1/usage/query` calls for
    /// `account`/`project` scopes) is required, not `Option` -- see
    /// [`UsageConfig::scope_authority`]'s doc comment. A config omitting it must fail to load, not
    /// silently leave the query listener unable to enforce ownership.
    #[test]
    fn config_missing_scope_authority_fails_to_load() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "usage-config-missing-scope-authority-{unique}.yaml"
        ));
        let content = format!(
            "{}\noauth2:\n  type: external\n  jwks_url: \"http://keycloak:9100/realms/dev/protocol/openid-connect/certs\"\n",
            valid_server_and_logging_block()
        );
        fs::write(&path, content).expect("temp config should be written");

        let result = load_from_path(&path);
        fs::remove_file(&path).expect("temp config should be removed");

        assert!(
            result.is_err(),
            "a config omitting scope_authority must fail to load, not silently degrade"
        );
    }

    /// #549 AC2: `retention` is optional with safe defaults -- a config that omits it must load
    /// with the retention job enabled, 90 raw days, and an hourly interval, so retention is on by
    /// default rather than silently absent.
    #[test]
    fn config_omitting_retention_gets_safe_defaults() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("usage-config-no-retention-{unique}.yaml"));
        let content = format!(
            "{}\noauth2:\n  type: external\n  jwks_url: \"http://keycloak:9100/realms/dev/protocol/openid-connect/certs\"\nscope_authority:\n  base_url: \"https://authz-opa:3001\"\n  username: \"authorino\"\n  password: \"change-me\"\n",
            valid_server_and_logging_block()
        );
        fs::write(&path, content).expect("temp config should be written");

        let cfg = load_from_path(&path).expect("config should load");
        fs::remove_file(&path).expect("temp config should be removed");

        assert!(cfg.retention.enabled, "retention must default to enabled");
        assert_eq!(cfg.retention.raw_days, 90, "raw_days must default to 90");
        assert_eq!(
            cfg.retention.interval_seconds, 3600,
            "interval_seconds must default to 3600"
        );
    }
}
