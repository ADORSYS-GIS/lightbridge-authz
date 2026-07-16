use lightbridge_authz_core::Config;
use lightbridge_authz_core::tracing::TracingConfig;

fn sample_config(otel_enabled: bool) -> Config {
    let yaml = format!(
        r#"
server:
  api:
    address: "0.0.0.0"
    port: 3000
    tls:
      cert_path: "./api.crt"
      key_path: "./api.key"
  opa:
    address: "0.0.0.0"
    port: 3001
    tls:
      cert_path: "./opa.crt"
      key_path: "./opa.key"
    basic_auth:
      username: "authorino"
      password: "change-me"
logging:
  level: "debug"
database:
  url: "postgres://postgres:postgres@localhost:5432/lightbridge_authz"
  pool_size: 10
oauth2:
  type: self
  jwks_url: "http://localhost:9100/realms/dev/protocol/openid-connect/certs"
otel:
  enabled: {otel_enabled}
  otlp_endpoint: "http://localhost:4317"
  service_name: "lightbridge-authz-test"
"#
    );
    serde_yaml::from_str(&yaml).expect("sample config should parse")
}

#[test]
fn tracing_config_exposes_logging_level() {
    let config = sample_config(false);
    assert_eq!(config.logging_level(), "debug");
}

#[test]
fn tracing_config_exposes_otel_settings_when_disabled() {
    let config = sample_config(false);
    assert!(!config.otel_enabled());
    assert_eq!(config.otlp_endpoint(), "http://localhost:4317");
    assert_eq!(config.service_name(), "lightbridge-authz-test");
}

#[test]
fn tracing_config_exposes_otel_settings_when_enabled() {
    let config = sample_config(true);
    assert!(config.otel_enabled());
}
