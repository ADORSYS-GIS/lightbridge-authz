use lightbridge_authz_core::Result;
use lightbridge_authz_core::config::{Database, Logging, Otel, Tls, load_yaml_from_path};
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Clone, Deserialize)]
pub struct UsageConfig {
    pub server: UsageServerGroup,
    pub logging: Logging,
    pub database: Database,
    pub otel: Otel,
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
"#;
        fs::write(&path, content).expect("temp config should be written");

        let result = load_from_path(&path);
        fs::remove_file(&path).expect("temp config should be removed");

        assert!(
            result.is_err(),
            "a config omitting server.query must fail to load, not silently degrade"
        );
    }
}
