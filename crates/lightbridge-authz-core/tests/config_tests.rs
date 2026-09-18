use lightbridge_authz_core::Config;
use lightbridge_authz_core::config::{
    Federation, IdpServer, JwtSigning, Oauth2, Oauth2TokenExchange, load_from_path,
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
    // #534/ADR-0030: defaults to the same 900s as access_ttl_seconds, but is its own independent
    // field -- see Oauth2TokenExchange::client_credentials_ttl_seconds's own doc comment for why.
    assert_eq!(exchange.client_credentials_ttl_seconds, 900);
}

#[test]
fn oauth2_token_exchange_honors_explicit_values() {
    let exchange: Oauth2TokenExchange = serde_yaml::from_str(
        "enabled: true\naccess_ttl_seconds: 1\nrefresh_ttl_seconds: 2\nallowed_scopes: [\"openid\"]\nclient_credentials_ttl_seconds: 3\n",
    )
    .unwrap();

    assert!(exchange.enabled);
    assert_eq!(exchange.access_ttl_seconds, 1);
    assert_eq!(exchange.refresh_ttl_seconds, 2);
    assert_eq!(exchange.allowed_scopes, vec!["openid"]);
    assert_eq!(exchange.client_credentials_ttl_seconds, 3);
}

/// lightbridge-authz#625: `jwks_ca_bundle_path` is genuinely optional -- most deployments never
/// set it, since the platform trust store already covers a publicly-reachable JWKS endpoint.
#[test]
fn oauth2_jwks_ca_bundle_path_defaults_to_none_when_unset() {
    // NOT a regression guard for `#[serde(default)]`, and deliberately labelled so: serde treats
    // an `Option<T>` field as implicitly defaulted whether or not that attribute is present, so
    // removing it does NOT make this fail (verified by mutation). The attribute is kept for
    // consistency with the sibling `ca_bundle_path` fields, not because this test pins it.
    // What this DOES pin is the observable contract -- an absent key parses, and the default is
    // `None` rather than an empty string -- which a change to the field type would break. Its
    // counterpart below IS mutation-proof (verified via a `rename`).
    let cfg: Oauth2 = serde_yaml::from_str("type: self\njwks_url: \"http://x\"\n").unwrap();
    assert_eq!(cfg.jwks_ca_bundle_path, None);
}

/// The counterpart: an explicit `jwks_ca_bundle_path` (the in-cluster, private-CA deployment
/// shape #625 exists for) must parse through untouched.
#[test]
fn oauth2_jwks_ca_bundle_path_parses_an_explicit_value() {
    let cfg: Oauth2 = serde_yaml::from_str(
        "type: self\njwks_url: \"http://x\"\njwks_ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"\n",
    )
    .unwrap();
    assert_eq!(
        cfg.jwks_ca_bundle_path.as_deref(),
        Some("/etc/lightbridge/tls/ca.crt")
    );
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
        "address: \"0.0.0.0\"\nport: 3004\ntls:\n  cert_path: \"./idp.crt\"\n  key_path: \"./idp.key\"\nstatic_dir: \"./dist/static\"\n",
    )
    .expect("valid idp block should deserialize");

    assert_eq!(idp.static_dir, "./dist/static");
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

/// ADR-0033: `source: platform_roles` parses, several mappers may name ONE claim, and a
/// `platform_roles` mapper legitimately carries no `map` at all (it resolves to role names
/// already, so an unmapped value contributes itself). Asserted because this exact two-mapper block
/// is what ai-helm-values deploys to prod -- a parse regression here is a fleet-wide mint outage,
/// since the claim source is fail-closed.
#[test]
fn several_mappers_may_target_one_claim_and_platform_roles_needs_no_map() {
    let yaml = r#"
issuer: "https://idp.example.test"
ttl_seconds: 3600
max_key_age_days: 30
claim_mappers:
  - claim: lightbridge_api_roles
    source: project_role
    map:
      owner: ["lightbridge-viewer"]
      lead: ["lightbridge-editor"]
      member: ["lightbridge-viewer"]
    default: []
  - claim: lightbridge_api_roles
    source: platform_roles
    default: []
"#;
    let signing: lightbridge_authz_core::config::JwtSigning =
        serde_yaml::from_str(yaml).expect("the prod-shaped two-mapper block must parse");
    assert_eq!(signing.claim_mappers.len(), 2);
    assert_eq!(
        signing.claim_mappers[0].source,
        lightbridge_authz_core::config::ClaimSource::ProjectRole
    );
    assert_eq!(
        signing.claim_mappers[0].map.get("owner").map(Vec::as_slice),
        Some(["lightbridge-viewer".to_string()].as_slice()),
        "post-cutover an account owner is a VIEWER -- the owner's binding ruling, and the whole          point of ADR-0033"
    );
    assert_eq!(
        signing.claim_mappers[1].source,
        lightbridge_authz_core::config::ClaimSource::PlatformRoles
    );
    assert!(
        signing.claim_mappers[1].map.is_empty(),
        "a platform_roles mapper needs no translation table"
    );
    assert_eq!(
        signing.claim_mappers[0].claim, signing.claim_mappers[1].claim,
        "both target the same claim; resolve_mapped_claims unions them"
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

#[test]
#[tracing_test::traced_test]
fn load_from_path_warns_on_unknown_and_deprecated_keys() {
    let default_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.yaml");
    let content = fs::read_to_string(&default_path).expect("default.yaml should exist");

    let yaml = content
        .replacen("server:\n", "unknown_top_level_key: foo\nserver:\n", 1)
        .replace("  signing:\n", "  signing:\n    unknown_signing_key: bar\n")
        .replace(
            "  relying_party:\n",
            "  relying_party:\n    issuer: \"https://example.com\"\n",
        );

    let path = unique_temp_path("unknown-keys");
    fs::write(&path, yaml).expect("temp file should write");

    let config = load_from_path(&path);
    assert!(
        config.is_ok(),
        "config with unknown/deprecated keys must still load successfully"
    );

    assert!(logs_contain(
        "Unknown configuration key 'unknown_top_level_key' ignored"
    ));
    assert!(logs_contain(
        "Unknown configuration key 'oauth2.signing.unknown_signing_key' ignored"
    ));
    assert!(logs_contain(
        "Configuration key 'oauth2.relying_party.issuer' is deprecated: use oauth2.federation.issuer instead"
    ));

    let _ = fs::remove_file(&path);
}

#[test]
#[tracing_test::traced_test]
fn load_from_path_clean_config_produces_no_unknown_key_warnings() {
    tracing::warn!("__capture_probe__");
    assert!(
        logs_contain("__capture_probe__"),
        "the injected tracing subscriber did not capture a warn emitted from this test \
         -- the negative assertions below would pass vacuously on an empty buffer"
    );

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.yaml");
    let container =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.docker/authz/container.yaml");
    for config_path in [path, container] {
        let config = load_from_path(&config_path);
        assert!(
            config.is_ok(),
            "checked-in config {} must load successfully",
            config_path.display()
        );
    }

    assert!(!logs_contain("Unknown configuration key"));
    assert!(!logs_contain("is deprecated"));
}

/// Every section of the `Config` schema that deserializes into a YAML mapping (as opposed to a
/// sequence such as `oauth2.clients` or a scalar such as `otel.enabled`), enumerated from the
/// serde struct definitions in `crates/lightbridge-authz-core/src/config/` -- NOT from
/// `KNOWN_KEYS`. The unknown-key walker (`unknown_keys.rs`) must descend into each of these, so
/// the sync tests below assert both directions of drift against this list.
fn config_section_paths() -> &'static [&'static str] {
    &[
        "",
        "server",
        "server.api",
        "server.api.tls",
        "server.opa",
        "server.opa.tls",
        "server.opa.basic_auth",
        "server.idp",
        "server.idp.tls",
        "server.budget",
        "server.budget.tls",
        "server.budget_internal",
        "server.budget_internal.tls",
        "logging",
        "database",
        "redis",
        "usage_service",
        "oauth2",
        "oauth2.issuance",
        "oauth2.signing",
        "oauth2.token_exchange",
        "oauth2.relying_party",
        "oauth2.rbac",
        "oauth2.federation",
        "otel",
        "billing",
        "quota_tiers",
        "models",
        "api_key_expiry",
        "secret_claim",
    ]
}

/// A `Config`-shaped YAML document that populates every field of every serde struct in
/// `crates/lightbridge-authz-core/src/config/` (including `server.budget`,
/// `server.budget_internal`, `secret_claim`, `quota_tiers`, `models`, `api_key_expiry` and every
/// `oauth2.*` subsection) and deserializes cleanly. Any field a caller can actually set that is
/// missing from `KNOWN_KEYS` would log a spurious "Unknown configuration key" warning here, so
/// this is the config the no-warnings sync test drives.
fn fully_populated_config_yaml() -> String {
    r#"
server:
  api:
    address: "0.0.0.0"
    port: 3000
    tls:
      cert_path: "./api.crt"
      key_path: "./api.key"
      client_ca_bundle_path: "./ca.crt"
    allowed_hosts: ["localhost", "127.0.0.1"]
    rpc_base_path: "/api"
  opa:
    address: "0.0.0.0"
    port: 3001
    tls:
      cert_path: "./opa.crt"
      key_path: "./opa.key"
      client_ca_bundle_path: "./ca.crt"
    basic_auth:
      username: "authorino"
      password: "change-me"
  idp:
    address: "0.0.0.0"
    port: 3004
    tls:
      cert_path: "./idp.crt"
      key_path: "./idp.key"
      client_ca_bundle_path: "./ca.crt"
    static_dir: "./dist/static"
  budget:
    address: "0.0.0.0"
    port: 3005
    tls:
      cert_path: "./budget.crt"
      key_path: "./budget.key"
      client_ca_bundle_path: "./ca.crt"
    snapshot_refresh_seconds: 60
    snapshot_active_window_minutes: 1440
    snapshot_slow_lane_minutes: 2880
    snapshot_seed_lookback_days: 7
    snapshot_batch: 100
    snapshot_concurrency: 4
  budget_internal:
    address: "0.0.0.0"
    port: 3007
    tls:
      cert_path: "./budget.crt"
      key_path: "./budget.key"
      client_ca_bundle_path: "./ca.crt"
    shared_secret: "s3cr3t"
    shared_secret_header: "X-Budget-Shared-Secret"
    remaining_grace_seconds: 30
logging:
  level: "info"
database:
  url: "postgres://postgres:postgres@localhost:5432/lightbridge_authz"
  pool_size: 10
redis:
  url: "redis://localhost:6379"
  ca_bundle_path: "./ca.crt"
usage_service:
  base_url: "https://authz-usage:3002"
  insecure_skip_verify: false
  ca_bundle_path: "./ca.crt"
  client_cert_path: "./usage.crt"
  client_key_path: "./usage.key"
  timeout_ms: 5000
oauth2:
  type: self
  jwks_url: "http://localhost:9100/realms/dev/protocol/openid-connect/certs"
  jwks_ca_bundle_path: "./ca.crt"
  oauth2_url: "http://localhost:9100"
  issuer_url: "http://localhost:9100"
  authorization_endpoint: "http://localhost:9100/authorize"
  token_endpoint: "http://localhost:9100/token"
  registration_endpoint: "http://localhost:9100/register"
  issuance:
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange"
    client_id: "authz"
    client_secret: "secret"
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
    requested_token_type: "urn:ietf:params:oauth:token-type:jwt"
    audience: "authz"
    scope: "openid"
  audience: ["authz"]
  signing:
    issuer: "https://issuer.example"
    audience: "authz"
    ttl_seconds: 3600
    max_key_age_days: 30
    claim_mappers:
      - claim: lightbridge_api_roles
        source: project_role
        map:
          owner: ["lightbridge-admin"]
        default: []
  token_exchange:
    enabled: true
    access_ttl_seconds: 900
    authorization_code_ttl_seconds: 600
    refresh_ttl_seconds: 2592000
    allowed_scopes: ["openid", "profile", "email", "offline_access"]
    refresh_absolute_ttl_seconds: 604800
    refresh_reuse_grace_seconds: 30
    device_code_ttl_seconds: 600
    device_poll_interval_seconds: 5
    device_verification_uri: "http://localhost:3004/ui/device"
    client_credentials_ttl_seconds: 900
  relying_party:
    client_id: "lightbridge-ui"
    callback_url: "http://localhost:3004/idp/callback"
    client_secret: "secret"
    state_encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    token_encryption_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    timeout_ms: 5000
    browser_session_ttl_seconds: 28800
  rbac:
    roles_claim: "lightbridge_api_roles"
    role_permissions:
      lightbridge-admin: ["*"]
    default_grants: ["lightbridge-viewer"]
  clients: []
  federation:
    issuer: "http://localhost:9100/realms/dev"
    discovery_url: "http://keycloak:9100/realms/dev"
otel:
  enabled: false
  otlp_endpoint: "http://localhost:4317"
  service_name: "lightbridge-authz"
billing:
  plans:
    - id: "basic"
      name: "Basic"
      limits:
        requests_per_second: 10
        requests_per_day: 100
        requests_per_month: 1000
        concurrent_requests: 5
quota_tiers:
  tiers:
    - id: "free"
      name: "Free"
    - id: "pro"
      name: "Pro"
models:
  models:
    - id: "gpt-4"
      name: "GPT-4"
api_key_expiry:
  max_lifetime_days: 90
secret_claim:
  encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  ttl_seconds: 300
  redeem_base_url: "https://authz-idp:3004"
"#
    .to_string()
}

fn insert_probe_at_section(value: &mut serde_yaml::Value, path: &str) {
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    let mut current = value;
    for segment in &segments {
        current = current
            .as_mapping_mut()
            .expect("section must deserialize into a mapping")
            .get_mut(serde_yaml::Value::String((*segment).to_string()))
            .expect("section must be present in the fully-populated config");
    }
    current
        .as_mapping_mut()
        .expect("section must deserialize into a mapping")
        .insert(
            serde_yaml::Value::String("__unknown_probe__".to_string()),
            serde_yaml::Value::from(1),
        );
}

/// Direction 1 of KNOWN_KEYS drift: a field a caller can actually set, but that is missing from
/// `KNOWN_KEYS`, logs a spurious "Unknown configuration key" warning. The clean-config test only
/// exercises `config/default.yaml`'s paths (no budget snapshot / `secret_claim` / `quota_tiers` /
/// `oauth2.*` subsections), so this drives every field of every struct and asserts none warns.
#[test]
#[tracing_test::traced_test]
fn known_keys_flag_no_spurious_warnings_on_fully_populated_config() {
    let yaml = fully_populated_config_yaml();
    let path = unique_temp_path("full-config");
    fs::write(&path, yaml).expect("temp file should write");

    let config = load_from_path(&path);
    assert!(
        config.is_ok(),
        "the fully-populated config must still load successfully"
    );

    assert!(
        !logs_contain("Unknown configuration key"),
        "a valid field is missing from KNOWN_KEYS and logged a spurious warning; add it to \
         crates/lightbridge-authz-core/src/config/unknown_keys_data.rs"
    );
    assert!(!logs_contain("is deprecated"));

    let _ = fs::remove_file(&path);
}

/// Direction 2 of KNOWN_KEYS drift: a section dropped/renamed in `KNOWN_KEYS` makes the walker's
/// `get_known_fields` early-return, silently skipping that whole subtree. Each of these
/// `__unknown_probe__` keys is guaranteed unknown, so a missing section (or a walk that fails to
/// descend) shows up as the probe's warning never being emitted.
#[test]
#[tracing_test::traced_test]
fn known_keys_descend_into_every_config_section() {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&fully_populated_config_yaml()).expect("base config should parse");

    for path in config_section_paths() {
        insert_probe_at_section(&mut value, path);
    }

    let probed = serde_yaml::to_string(&value).expect("probed config should re-serialize");
    let path = unique_temp_path("section-probes");
    fs::write(&path, &probed).expect("temp file should write");

    let config = load_from_path(&path);
    assert!(
        config.is_ok(),
        "a config with probes planted in every section must still load successfully"
    );

    for section in config_section_paths() {
        let probe_key = if section.is_empty() {
            "__unknown_probe__".to_string()
        } else {
            format!("{section}.__unknown_probe__")
        };
        assert!(
            logs_contain(&format!("Unknown configuration key '{probe_key}' ignored")),
            "the walker did not emit a warning for the probe under '{section}' -- either that \
             section is missing from KNOWN_KEYS (silently skipping the subtree) or the walk does \
             not descend into it"
        );
    }

    let _ = fs::remove_file(&path);
}
