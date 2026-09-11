//! Config loading tests for the usage service.
//!
//! Moved out of `src/config.rs` by the LoC gate (`.github/actions/loc-gate`): the config tests are
//! a large, self-contained block that does not belong to the config module, and keeping them in a
//! `tests/` file (excluded from the gate) lets `config.rs` stay under its ceiling. The pairing is
//! unchanged -- these test the same public `load_from_path`/`UsageConfig`/`RetentionConfig` API.

use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use lightbridge_authz_usage_rest::config::load_from_path;

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
/// with the retention job DISABLED (rollback safety, see [`RetentionConfig::enabled`]), 90 raw
/// days, and an hourly interval, so the destructive job is never on without an explicit opt-in.
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

    assert!(
        !cfg.retention.enabled,
        "retention must default to disabled (rollback safety)"
    );
    assert_eq!(cfg.retention.raw_days, 90, "raw_days must default to 90");
    assert_eq!(
        cfg.retention.rollup_days, 365,
        "rollup_days must default to 365"
    );
    assert_eq!(
        cfg.retention.interval_seconds, 3600,
        "interval_seconds must default to 3600"
    );
}

/// #549: `rollup_days` must be > `raw_days`, or a rolled-up day is deleted from the rollup in
/// the same transaction that wrote it (the rollup purge cutoff is `rollup_days`, and a day
/// older than `raw_days` is already older than `rollup_days` when `rollup_days <= raw_days`).
#[test]
fn config_rejects_rollup_days_not_greater_than_raw_days() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("usage-config-bad-rollup-{unique}.yaml"));
    let content = format!(
        "{}\noauth2:\n  type: external\n  jwks_url: \"http://keycloak:9100/realms/dev/protocol/openid-connect/certs\"\nscope_authority:\n  base_url: \"https://authz-opa:3001\"\n  username: \"authorino\"\n  password: \"change-me\"\nretention:\n  enabled: true\n  raw_days: 90\n  rollup_days: 30\n",
        valid_server_and_logging_block()
    );
    fs::write(&path, content).expect("temp config should be written");

    let result = load_from_path(&path);
    fs::remove_file(&path).expect("temp config should be removed");

    assert!(
        result.is_err(),
        "rollup_days <= raw_days must fail to load, not silently destroy rolled-up days"
    );
}
