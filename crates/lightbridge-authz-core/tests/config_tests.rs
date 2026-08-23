use lightbridge_authz_core::Config;
use lightbridge_authz_core::config::{IdpServer, JwtSigning, Oauth2TokenExchange, load_from_path};
use std::fs;

fn unique_temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "lightbridge-authz-core-config-test-{}-{}.yaml",
        std::process::id(),
        name
    ))
}

#[test]
fn jwt_signing_defaults_ttl_and_max_key_age_when_unset() {
    let signing: JwtSigning = serde_yaml::from_str("issuer: \"https://issuer.example\"\n").unwrap();

    assert_eq!(signing.ttl_seconds, 7_776_000);
    assert_eq!(signing.max_key_age_days, 30);
}

#[test]
fn jwt_signing_honors_explicit_ttl_and_max_key_age() {
    let signing: JwtSigning = serde_yaml::from_str(
        "issuer: \"https://issuer.example\"\nttl_seconds: 60\nmax_key_age_days: 1\n",
    )
    .unwrap();

    assert_eq!(signing.ttl_seconds, 60);
    assert_eq!(signing.max_key_age_days, 1);
}

#[test]
fn oauth2_token_exchange_defaults_when_unset() {
    let exchange: Oauth2TokenExchange = serde_yaml::from_str("{}\n").unwrap();

    assert!(!exchange.enabled);
    assert_eq!(exchange.access_ttl_seconds, 900);
    assert_eq!(exchange.refresh_ttl_seconds, 2_592_000);
    assert_eq!(
        exchange.allowed_scopes,
        vec!["openid", "profile", "email", "offline_access"]
    );
}

#[test]
fn oauth2_token_exchange_honors_explicit_values() {
    let exchange: Oauth2TokenExchange = serde_yaml::from_str(
        "enabled: true\naccess_ttl_seconds: 1\nrefresh_ttl_seconds: 2\nallowed_scopes: [\"openid\"]\n",
    )
    .unwrap();

    assert!(exchange.enabled);
    assert_eq!(exchange.access_ttl_seconds, 1);
    assert_eq!(exchange.refresh_ttl_seconds, 2);
    assert_eq!(exchange.allowed_scopes, vec!["openid"]);
}

/// ADR-0021 Decisions 1 + 10 (#442): `IdpServer.static_dir` must default to `/app/static` when
/// omitted, not fail to deserialize. This is the regression test for a real prod-outage bug: the
/// separately-owned `ai-helm-values` repo's `authz-idp` config override has no `static_dir` key
/// and cannot get one until its own PR lands there, but prod tracks `main` HEAD directly (no
/// release-tag gate) -- a hard-required field here would crash-loop `authz-idp` on the very next
/// promotion after this merges, with no way to land the two changes atomically across repos.
#[test]
fn idp_server_static_dir_defaults_to_app_static_when_unset() {
    let idp: IdpServer = serde_yaml::from_str(
        "address: \"0.0.0.0\"\nport: 3004\ntls:\n  cert_path: \"./idp.crt\"\n  key_path: \"./idp.key\"\n",
    )
    .expect("an idp block omitting static_dir must still deserialize");

    assert_eq!(idp.static_dir, "/app/static");
}

#[test]
fn idp_server_static_dir_honors_an_explicit_value() {
    let idp: IdpServer = serde_yaml::from_str(
        "address: \"0.0.0.0\"\nport: 3004\ntls:\n  cert_path: \"./idp.crt\"\n  key_path: \"./idp.key\"\nstatic_dir: \"./web/hosted-login/dist\"\n",
    )
    .expect("valid idp block should deserialize");

    assert_eq!(idp.static_dir, "./web/hosted-login/dist");
}

fn minimal_config_yaml() -> String {
    r#"
server:
  api:
    address: "0.0.0.0"
    port: ${TEST_CONFIG_API_PORT:-3000}
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
  level: "info"
database:
  url: "postgres://postgres:postgres@localhost:5432/lightbridge_authz"
  pool_size: 10
oauth2:
  type: self
  jwks_url: "http://localhost:9100/realms/dev/protocol/openid-connect/certs"
otel:
  enabled: false
  otlp_endpoint: "http://localhost:4317"
  service_name: "lightbridge-authz"
"#
    .to_string()
}

#[test]
fn load_from_path_reads_and_interpolates_a_yaml_config_file() {
    let path = unique_temp_path("valid");
    fs::write(&path, minimal_config_yaml()).expect("temp config file should be writable");

    let config: Config = load_from_path(&path).expect("valid config should load");

    assert_eq!(config.server.api.port, 3000);
    assert_eq!(config.server.opa.port, 3001);
    assert!(config.oauth2.is_self_signed());

    let _ = fs::remove_file(&path);
}

#[test]
fn load_from_path_fails_when_file_is_missing() {
    let path = unique_temp_path("missing");
    let _ = fs::remove_file(&path);

    let result = load_from_path(&path);

    assert!(result.is_err(), "loading a missing config file should fail");
}

/// The exact prod scenario `idp_server_static_dir_defaults_to_app_static_when_unset` guards
/// against, reproduced through the full `load_from_path` pipeline (interpolation included) rather
/// than a bare `IdpServer` deserialize: an `idp:` block that predates `static_dir` (i.e. today's
/// `ai-helm-values` override) must still load a whole `Config`, with the new field defaulted.
#[test]
fn load_from_path_defaults_idp_static_dir_when_the_config_predates_the_field() {
    let path = unique_temp_path("idp-static-dir-default");
    // Inserted as a sibling of `api:`/`opa:` under `server:`, immediately before `logging:` --
    // matches the real shape of an `idp:` block that predates `static_dir` (address/port/tls
    // only), not a synthetic/malformed one.
    let idp_block = "  idp:\n    address: \"0.0.0.0\"\n    port: 3004\n    tls:\n      cert_path: \"./idp.crt\"\n      key_path: \"./idp.key\"\n";
    let yaml = minimal_config_yaml().replacen("logging:", &format!("{idp_block}logging:"), 1);
    fs::write(&path, yaml).expect("temp config file should be writable");

    let config: Config = load_from_path(&path).expect(
        "a config whose idp block predates static_dir must still load, not fail to deserialize",
    );

    let idp = config
        .server
        .idp
        .expect("idp block should be present per the written yaml");
    assert_eq!(idp.static_dir, "/app/static");

    let _ = fs::remove_file(&path);
}
