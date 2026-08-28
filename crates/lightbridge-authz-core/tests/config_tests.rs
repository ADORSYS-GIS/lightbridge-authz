use lightbridge_authz_core::Config;
use lightbridge_authz_core::config::{
    Federation, IdpServer, JwtSigning, Oauth2TokenExchange, load_from_path,
};
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

/// Identity-vs-location split (ADR-0025 amendment): `discovery_url` is optional and, when unset,
/// `Federation::effective_discovery_url` must fall back to `issuer` -- most deployments never set
/// `discovery_url` at all, since the same address is reachable both internally and externally.
#[test]
fn federation_discovery_url_defaults_to_issuer_when_unset() {
    let federation: Federation =
        serde_yaml::from_str("issuer: \"https://keycloak.example.test/realms/dev\"\n").unwrap();

    assert_eq!(federation.discovery_url, None);
    assert_eq!(
        federation.effective_discovery_url(),
        "https://keycloak.example.test/realms/dev"
    );
}

/// The counterpart to the defaulting test above: an explicit `discovery_url` must win over
/// `issuer` -- this is the local-Compose shape (`.docker/authz/container.yaml`), where the
/// externally-reachable issuer and the in-network discovery dial target are deliberately
/// different addresses.
#[test]
fn federation_discovery_url_honors_an_explicit_value_distinct_from_issuer() {
    let federation: Federation = serde_yaml::from_str(
        "issuer: \"http://localhost:9100/realms/dev\"\ndiscovery_url: \"http://keycloak:9100/realms/dev\"\n",
    )
    .unwrap();

    assert_eq!(
        federation.discovery_url.as_deref(),
        Some("http://keycloak:9100/realms/dev")
    );
    assert_eq!(
        federation.effective_discovery_url(),
        "http://keycloak:9100/realms/dev",
        "an explicit discovery_url must be dialed instead of the identity issuer"
    );
    assert_ne!(
        federation.effective_discovery_url(),
        federation.issuer,
        "precondition: this test is only meaningful when the two addresses actually differ"
    );
}

/// `Federation::validate` applies the same offline shape check to `discovery_url` as it already
/// does to `issuer`: non-empty, and parses as a URL. No network call.
#[test]
fn federation_validate_rejects_a_malformed_discovery_url() {
    let federation: Federation = serde_yaml::from_str(
        "issuer: \"https://keycloak.example.test/realms/dev\"\ndiscovery_url: \"not a url\"\n",
    )
    .unwrap();

    let err = federation
        .validate()
        .expect_err("a discovery_url that doesn't parse as a URL must fail validation");
    assert!(
        format!("{err}").contains("discovery_url"),
        "error should name the offending field"
    );
}

/// `Federation::validate` still passes when `discovery_url` is absent -- it is genuinely optional,
/// not "optional but validated against a hidden requirement."
#[test]
fn federation_validate_accepts_a_valid_config_without_discovery_url() {
    let federation: Federation =
        serde_yaml::from_str("issuer: \"https://keycloak.example.test/realms/dev\"\n").unwrap();

    federation
        .validate()
        .expect("issuer alone, with no discovery_url, is a valid federation config");
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

/// Regression test for the silent-misconfiguration bug found while pointing the migrate binary at
/// an isolated Postgres container during #440/#441/#437 (PR #447): `config/default.yaml`'s
/// `database.url` used to be a bare literal, so `cargo run -p lightbridge-authz -- migrate
/// --config-path config/default.yaml` silently ignored an exported `DATABASE_URL` and connected to
/// localhost regardless -- dangerously, it connected *successfully* to the wrong database rather
/// than erroring, so the migration looked like it ran when it actually ran somewhere else.
///
/// This loads the real checked-in `config/default.yaml` (not a synthetic fixture) through the same
/// `load_from_path` pipeline `main.rs` uses, so reverting that file's `database.url` back to a bare
/// literal makes this test fail for the exact right reason.
///
/// Env-var isolation: `DATABASE_URL` is process-global, so this single test drives both the
/// "set" and "unset" cases sequentially (rather than as two separate `#[test]` functions that
/// could race against each other under the default parallel test runner) and restores whatever
/// value was present beforehand before returning, including on the unset branch.
#[test]
fn checked_in_default_config_honors_database_url_env_override() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.yaml");
    assert!(
        path.exists(),
        "expected the checked-in config/default.yaml at {path:?}"
    );

    let prior_database_url = std::env::var("DATABASE_URL").ok();

    unsafe {
        std::env::set_var(
            "DATABASE_URL",
            "postgres://custom:custom@example.invalid:5555/custom_db",
        );
    }
    let config: Config =
        load_from_path(&path).expect("config/default.yaml should load with DATABASE_URL set");
    assert_eq!(
        config.database.url, "postgres://custom:custom@example.invalid:5555/custom_db",
        "config/default.yaml's database.url must honor DATABASE_URL when set -- a hardcoded \
         value here silently ignores the env var and connects to the wrong database instead of \
         erroring (see PR #447)"
    );

    unsafe {
        std::env::remove_var("DATABASE_URL");
    }
    let config: Config =
        load_from_path(&path).expect("config/default.yaml should load with DATABASE_URL unset");
    assert_eq!(
        config.database.url, "postgres://postgres:postgres@localhost:5432/lightbridge_authz",
        "config/default.yaml's database.url must still fall back to the checked-in local default \
         when DATABASE_URL is unset"
    );

    match prior_database_url {
        Some(value) => unsafe { std::env::set_var("DATABASE_URL", value) },
        None => unsafe { std::env::remove_var("DATABASE_URL") },
    }
}

/// `oauth2.signing.claim_mappers` is what lets `authz-idp` stamp the RBAC roles claim from data it
/// owns (`project_members`) instead of borrowing one from the brokered upstream IdP. Parsing is
/// asserted here because the mapping table is operator-authored YAML: a silently-dropped `map`
/// would mint tokens with the `default` (empty = no permissions) and look like a policy decision.
#[test]
fn claim_mappers_parse_source_map_and_default() {
    let yaml = r#"
issuer: "https://idp.example.test"
ttl_seconds: 3600
max_key_age_days: 30
claim_mappers:
  - claim: lightbridge_api_roles
    source: project_role
    map:
      owner: ["lightbridge-admin"]
      lead: ["lightbridge-editor"]
    default: []
"#;
    let signing: lightbridge_authz_core::config::JwtSigning =
        serde_yaml::from_str(yaml).expect("claim_mappers must parse");
    assert_eq!(signing.claim_mappers.len(), 1);
    let mapper = &signing.claim_mappers[0];
    assert_eq!(mapper.claim, "lightbridge_api_roles");
    assert_eq!(
        mapper.source,
        lightbridge_authz_core::config::ClaimSource::ProjectRole
    );
    assert_eq!(
        mapper.map.get("owner").map(Vec::as_slice),
        Some(["lightbridge-admin".to_string()].as_slice())
    );
    assert!(
        mapper.default_values.is_empty(),
        "an unmapped source value must fall through to NO roles -- the default-deny direction"
    );
}

/// Absent `claim_mappers` must parse to empty, not fail: a deployment that declares none mints
/// exactly the claims it did before this feature existed.
#[test]
fn claim_mappers_default_to_empty_when_absent() {
    let signing: lightbridge_authz_core::config::JwtSigning = serde_yaml::from_str(
        "issuer: \"https://idp.example.test\"\nttl_seconds: 3600\nmax_key_age_days: 30\n",
    )
    .expect("a signing block without claim_mappers must still parse");
    assert!(signing.claim_mappers.is_empty());
}
