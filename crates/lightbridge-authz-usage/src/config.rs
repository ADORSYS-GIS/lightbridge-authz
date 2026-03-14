use lightbridge_authz_core::config::{load_yaml_from_path, Database, Logging, Otel, Tls};
use lightbridge_authz_core::Result;
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
    pub usage: UsageServer,
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
}
