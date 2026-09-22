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

/// #587 review P2: a degenerate background-job cadence must fail at load, not be silently coerced
/// to a 1s loop by `interval_seconds.max(1)`. A sub-60s `aggregate_refresh.interval_seconds`
/// (e.g. a unit-mix typo, or a literal `0`) would otherwise run expensive
/// `REFRESH MATERIALIZED VIEW CONCURRENTLY` statements effectively continuously.
#[test]
fn config_rejects_sub_minute_aggregate_refresh_interval() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("usage-config-bad-refresh-interval-{unique}.yaml"));
    let content = format!(
        "{}\noauth2:\n  type: external\n  jwks_url: \"http://keycloak:9100/realms/dev/protocol/openid-connect/certs\"\nscope_authority:\n  base_url: \"https://authz-opa:3001\"\n  username: \"authorino\"\n  password: \"change-me\"\naggregate_refresh:\n  enabled: true\n  interval_seconds: 1\n",
        valid_server_and_logging_block()
    );
    fs::write(&path, content).expect("temp config should be written");

    let result = load_from_path(&path);
    fs::remove_file(&path).expect("temp config should be removed");

    assert!(
        result.is_err(),
        "a sub-60s aggregate_refresh.interval_seconds must fail to load, not run the refresh loop \
         continuously"
    );
}

/// #587 review: the sub-60s `aggregate_refresh.interval_seconds` check is gated on `enabled`. A
/// DISABLED job never reads `interval_seconds` (the loop returns before touching it), so a short
/// interval on a disabled job is runtime-harmless and must not refuse to boot.
#[test]
fn config_accepts_sub_minute_interval_when_aggregate_refresh_disabled() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "usage-config-disabled-refresh-interval-{unique}.yaml"
    ));
    let content = format!(
        "{}\noauth2:\n  type: external\n  jwks_url: \"http://keycloak:9100/realms/dev/protocol/openid-connect/certs\"\nscope_authority:\n  base_url: \"https://authz-opa:3001\"\n  username: \"authorino\"\n  password: \"change-me\"\naggregate_refresh:\n  enabled: false\n  interval_seconds: 1\n",
        valid_server_and_logging_block()
    );
    fs::write(&path, content).expect("temp config should be written");

    let result = load_from_path(&path);
    fs::remove_file(&path).expect("temp config should be removed");

    assert!(
        result.is_ok(),
        "a sub-60s interval on a DISABLED aggregate_refresh job must load -- the job never reads it"
    );
}

/// The `oauth2` + `scope_authority` blocks every test below needs before it can reach the
/// `ingest_auth` validation (both are mandatory, so a config omitting either fails earlier).
fn valid_auth_block() -> &'static str {
    "oauth2:\n  type: external\n  jwks_url: \"http://keycloak:9100/realms/dev/protocol/openid-connect/certs\"\n\
     scope_authority:\n  base_url: \"https://authz-opa:3001\"\n  username: \"authorino\"\n  \
     password: \"change-me\"\n"
}

/// Writes a temp config made of the valid server/logging block, the mandatory auth block, and
/// `ingest_auth` YAML, then loads it. Returns the load result.
fn load_config_with_ingest_auth(ingest_auth: &str) -> lightbridge_authz_core::Result<()> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("usage-config-ingest-{unique}.yaml"));
    let content = format!(
        "{}{}{}",
        valid_server_and_logging_block(),
        valid_auth_block(),
        ingest_auth
    );
    fs::write(&path, content).expect("temp config should be written");

    let result = load_from_path(&path).map(|_| ());
    fs::remove_file(&path).expect("temp config should be removed");
    result
}

/// `ingest_auth` is optional: absent, the config loads and the authenticated surface simply is
/// not mounted. This is the positive control without which every test below could pass by
/// rejecting all `ingest_auth` blocks.
#[test]
fn config_without_ingest_auth_loads() {
    let result = load_config_with_ingest_auth("");
    assert!(
        result.is_ok(),
        "ingest_auth is optional; omitting it must load, unmounting /auth/v1/otel/*: {result:?}"
    );
}

/// #585: `ingest_auth` present but with no principals authorizes nobody, and is far more likely
/// to be a mistake than an intention -- fail loudly at startup instead.
#[test]
fn config_with_empty_ingest_principals_fails_to_load() {
    let result = load_config_with_ingest_auth(
        "ingest_auth:\n  audience: \"lightbridge-usage-ingest\"\n  principals: {}\n",
    );
    assert!(
        result.is_err(),
        "a config with ingest_auth but empty principals must fail to load"
    );
}

/// #585: a `principals` mapping VALUE outside `normalizer::KNOWN_SOURCES` means that principal
/// can never successfully ingest -- the runtime gate requires `resolve_source` (which is itself a
/// `KNOWN_SOURCES` check) to equal this value, so every request would 400 or 403. Fail at config
/// load instead of surfacing as a mystery 400/403 when a collector deploys.
#[test]
fn config_with_ingest_principals_unknown_source_fails_to_load() {
    let result = load_config_with_ingest_auth(
        "ingest_auth:\n  audience: \"lightbridge-usage-ingest\"\n  principals:\n    \
         svc:collector-x: claudecode\n",
    );
    assert!(
        result.is_err(),
        "an ingest_auth principal mapped to an unknown source must fail to load, not silently \
         degrade to per-request 400/403s"
    );
}

/// #585: the KEYS of `principals` are matched against a `client_credentials` token's `sub`, which
/// `authz-idp` always mints as `svc:<client_id>`. A key without that prefix can therefore never
/// match -- a silently disabled principal, with nothing in the logs to say so.
///
/// Mutation this catches: dropping the `svc:` key check, which leaves this config loading cleanly.
#[test]
fn config_with_ingest_principal_not_service_prefixed_fails_to_load() {
    for bad_key in ["collector-x", "sub-1", "svc"] {
        let result = load_config_with_ingest_auth(&format!(
            "ingest_auth:\n  audience: \"lightbridge-usage-ingest\"\n  principals:\n    {bad_key}: \
             github-copilot\n"
        ));
        assert!(
            result.is_err(),
            "principal key {bad_key:?} is not `svc:`-prefixed and must fail to load"
        );
    }
}

/// #585 AC4: `audience` is the binding that makes "the credential names the collector" hold, and
/// a blank one would match no token's `aud` -- a config that can only ever refuse every request.
///
/// Mutation this catches: dropping the empty-audience check, or defaulting it to `""`.
#[test]
fn config_with_empty_ingest_audience_fails_to_load() {
    let result = load_config_with_ingest_auth(
        "ingest_auth:\n  audience: \"\"\n  principals:\n    \
         svc:collector-github-copilot: github-copilot\n",
    );
    assert!(
        result.is_err(),
        "an empty ingest_auth.audience must fail to load, not silently refuse every request"
    );
}

/// #585: a key that is `svc:`-prefixed but padded passes the prefix check and still never matches
/// a token's `sub` -- the same silently-disabled principal the prefix check exists to prevent,
/// one copy-paste away. (The key is quoted in the YAML so the space survives parsing.)
///
/// Mutation this catches: dropping the padding half of the key check.
#[test]
fn config_with_whitespace_padded_ingest_principal_key_fails_to_load() {
    let result = load_config_with_ingest_auth(
        "ingest_auth:\n  audience: \"lightbridge-usage-ingest\"\n  principals:\n    \
         \"svc:collector-github-copilot \": github-copilot\n",
    );
    assert!(
        result.is_err(),
        "a whitespace-padded principal key must fail to load, not silently disable that principal"
    );
}

/// #585 AC4: `audience` is compared VERBATIM against each token's `aud` claim, so a padded value
/// is worse than a blank one -- it passes the trim-based emptiness check above and then refuses
/// every request, with nothing in the config to suggest why.
///
/// Mutation this catches: dropping the padding check, leaving the untrimmed value to be compared.
#[test]
fn config_with_whitespace_padded_ingest_audience_fails_to_load() {
    let result = load_config_with_ingest_auth(
        "ingest_auth:\n  audience: \" lightbridge-usage-ingest \"\n  principals:\n    \
         svc:collector-github-copilot: github-copilot\n",
    );
    assert!(
        result.is_err(),
        "a whitespace-padded ingest_auth.audience must fail to load, not silently refuse every \
         request"
    );
}

/// The positive control for the tests above: a well-formed `ingest_auth` block loads.
#[test]
fn config_with_valid_ingest_auth_loads() {
    let result = load_config_with_ingest_auth(
        "ingest_auth:\n  audience: \"lightbridge-usage-ingest\"\n  principals:\n    \
         svc:collector-github-copilot: github-copilot\n",
    );
    assert!(
        result.is_ok(),
        "a well-formed ingest_auth block must load: {result:?}"
    );
}
