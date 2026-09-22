use super::*;
use crate::error::Result;
use regex::{Captures, Regex};
use serde::de::DeserializeOwned;
use serde_yaml::from_str;
use std::env;
use std::fs::read_to_string;
use std::sync::LazyLock;

static RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$([a-zA-Z_][a-zA-Z0-9_]*)|\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?:(:-|-)([^}]*))?\}")
        .expect("env-interpolation regex is a compile-time constant and always parses")
});

pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Config> {
    let content = read_to_string(path.as_ref())?;
    let interpolated = interpolate_env_vars(&content);
    let cfg: Config = from_str(&interpolated)?;
    super::unknown_keys::warn_unknown_keys_in_config(&interpolated);
    Ok(cfg)
}

pub fn load_yaml_from_path<T, P>(path: P) -> Result<T>
where
    T: DeserializeOwned,
    P: AsRef<std::path::Path>,
{
    let content = read_to_string(path)?;
    let interpolated = interpolate_env_vars(&content);
    let cfg: T = from_str(&interpolated)?;
    Ok(cfg)
}

/// Interpolates environment variables in the given string.
/// Supports:
/// - $VAR
/// - ${VAR}
/// - ${VAR-default}
/// - ${VAR:-default}
///
/// Behavior mostly matches GNU envsubst:
/// - unresolved variables are replaced with an empty string
///
/// It additionally supports a subset of shell default expansion to make config
/// defaults ergonomic without external preprocessing.
fn interpolate_env_vars(content: &str) -> String {
    RE.replace_all(content, |caps: &Captures| {
        if let Some(var_name) = caps.get(1) {
            // $VAR
            env::var(var_name.as_str()).unwrap_or_default()
        } else if let Some(var_name) = caps.get(2) {
            // ${VAR}, ${VAR-default}, ${VAR:-default}
            let name = var_name.as_str();
            let operator = caps.get(3).map(|m| m.as_str());
            let default_value = caps.get(4).map(|m| m.as_str()).unwrap_or_default();

            match operator {
                None => env::var(name).unwrap_or_default(),
                Some("-") => env::var(name).unwrap_or_else(|_| default_value.to_string()),
                Some(":-") => match env::var(name) {
                    Ok(value) if !value.is_empty() => value,
                    _ => default_value.to_string(),
                },
                Some(_) => caps
                    .get(0)
                    .expect("capture group 0 always exists on a match")
                    .as_str()
                    .to_string(),
            }
        } else {
            caps.get(0)
                .expect("capture group 0 always exists on a match")
                .as_str()
                .to_string()
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_interpolate_env_vars() {
        unsafe {
            env::set_var("TEST_VAR", "foo");
            env::set_var("TEST_VAR_2", "bar");
            env::set_var("EMPTY_VAR", "");
        }

        // $VAR
        assert_eq!(interpolate_env_vars("$TEST_VAR"), "foo");
        assert_eq!(
            interpolate_env_vars("prefix_$TEST_VAR.suffix"),
            "prefix_foo.suffix"
        );

        // ${VAR}
        assert_eq!(interpolate_env_vars("${TEST_VAR}"), "foo");
        assert_eq!(
            interpolate_env_vars("prefix_${TEST_VAR}_suffix"),
            "prefix_foo_suffix"
        );

        // Mixed
        assert_eq!(
            interpolate_env_vars("$TEST_VAR and ${TEST_VAR_2} and $NON_EXISTENT"),
            "foo and bar and "
        );

        // Not set -> empty string
        assert_eq!(interpolate_env_vars("$NOT_SET"), "");
        assert_eq!(interpolate_env_vars("${NOT_SET}"), "");

        // ${VAR-default} and ${VAR:-default}
        assert_eq!(interpolate_env_vars("${TEST_VAR-default}"), "foo");
        assert_eq!(interpolate_env_vars("${NOT_SET-default}"), "default");
        assert_eq!(interpolate_env_vars("${EMPTY_VAR-default}"), "");
        assert_eq!(interpolate_env_vars("${TEST_VAR:-default}"), "foo");
        assert_eq!(interpolate_env_vars("${NOT_SET:-default}"), "default");
        assert_eq!(interpolate_env_vars("${EMPTY_VAR:-default}"), "default");

        // Unsupported syntax remains unchanged
        assert_eq!(
            interpolate_env_vars("${TEST_VAR:default}"),
            "${TEST_VAR:default}"
        );
        assert_eq!(
            interpolate_env_vars("${NON_EXISTENT:default_with_spaces}"),
            "${NON_EXISTENT:default_with_spaces}"
        );

        unsafe {
            env::remove_var("TEST_VAR");
            env::remove_var("TEST_VAR_2");
            env::remove_var("EMPTY_VAR");
        }
    }

    #[test]
    fn oauth2_type_self_parses() {
        let cfg: Oauth2 = from_str("type: self\njwks_url: \"http://x\"\n").unwrap();
        assert_eq!(cfg.oauth2_type, Oauth2Type::SelfSigned);
        assert!(cfg.is_self_signed());
        assert!(!cfg.is_external());
    }

    #[test]
    fn oauth2_type_external_parses() {
        let cfg: Oauth2 = from_str("type: external\njwks_url: \"http://x\"\n").unwrap();
        assert_eq!(cfg.oauth2_type, Oauth2Type::External);
        assert!(cfg.is_external());
    }

    #[test]
    fn oauth2_type_is_required_no_default() {
        let err = from_str::<Oauth2>("jwks_url: \"http://x\"\n").unwrap_err();
        assert!(
            err.to_string().contains("type"),
            "missing oauth2.type must fail config load, got: {err}"
        );
    }

    #[test]
    fn oauth2_type_rejects_unknown_value() {
        assert!(from_str::<Oauth2>("type: opaque\njwks_url: \"http://x\"\n").is_err());
    }

    #[test]
    fn billing_plans_parse_from_json_env_string() {
        let json = r#"[{"id":"free","name":"Free","limits":{"requests_per_second":5,"requests_per_month":10000}},{"id":"pro","name":"Pro"}]"#;
        let billing: Billing = from_str(&format!("plans: '{json}'\n")).unwrap();
        assert_eq!(billing.plan_ids(), vec!["free", "pro"]);
        assert!(billing.is_allowed("pro"));
        assert!(!billing.is_allowed("scale"));
        assert!(!billing.is_allowed(""));

        let free = billing.get("free").unwrap();
        assert_eq!(free.name, "Free");
        let limits = free.limits.as_ref().unwrap();
        assert_eq!(limits.requests_per_second, Some(5));
        assert_eq!(limits.requests_per_month, Some(10000));
        assert_eq!(limits.concurrent_requests, None);
        assert!(billing.get("pro").unwrap().limits.is_none());
    }

    #[test]
    fn billing_plans_parse_from_inline_sequence() {
        let yaml = "plans:\n  - id: free\n    name: Free\n  - id: pro\n    name: Pro\n    limits:\n      concurrent_requests: 20\n";
        let billing: Billing = from_str(yaml).unwrap();
        assert_eq!(billing.plan_ids(), vec!["free", "pro"]);
        assert_eq!(
            billing
                .get("pro")
                .unwrap()
                .limits
                .as_ref()
                .unwrap()
                .concurrent_requests,
            Some(20)
        );
    }

    #[test]
    fn billing_plans_empty_when_unset() {
        let billing: Billing = from_str("{}\n").unwrap();
        assert!(billing.plans.is_empty());
        assert!(!billing.is_allowed("free"));

        let blank: Billing = from_str("plans: \"\"\n").unwrap();
        assert!(blank.plans.is_empty());
    }

    #[test]
    fn billing_plans_null_is_tolerated_as_empty() {
        let via_plans_null: Billing = from_str("plans: null\n").unwrap();
        assert!(via_plans_null.plans.is_empty());

        let via_plans_bare: Billing = from_str("plans:\n").unwrap();
        assert!(via_plans_bare.plans.is_empty());

        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            billing: Billing,
        }
        let via_billing_null: Wrap = from_str("billing:\n").unwrap();
        assert!(via_billing_null.billing.plans.is_empty());
    }

    #[test]
    fn billing_validate_rejects_empty_dup_and_blank_ids() {
        assert!(Billing::default().validate().is_err());

        let dup: Billing =
            from_str("plans:\n  - id: free\n    name: Free\n  - id: free\n    name: Free2\n")
                .unwrap();
        let err = dup.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate plan id 'free'"), "got: {err}");

        let blank: Billing = from_str("plans:\n  - id: \"\"\n    name: Nameless\n").unwrap();
        assert!(
            blank
                .validate()
                .unwrap_err()
                .to_string()
                .contains("empty id")
        );

        let ok: Billing =
            from_str("plans:\n  - id: free\n    name: Free\n  - id: pro\n    name: Pro\n").unwrap();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn model_catalog_parse_from_json_env_string() {
        let json = r#"[{"id":"dev-model-a","name":"Dev Model A"},{"id":"dev-model-b","name":"Dev Model B"}]"#;
        let catalog: ModelCatalog = from_str(&format!("models: '{json}'\n")).unwrap();
        assert_eq!(catalog.model_ids(), vec!["dev-model-a", "dev-model-b"]);
        assert_eq!(catalog.models[0].name, "Dev Model A");
        assert_eq!(catalog.models[1].name, "Dev Model B");
    }

    #[test]
    fn model_catalog_parse_from_inline_sequence() {
        let yaml = "models:\n  - id: dev-model-a\n    name: Dev Model A\n  - id: dev-model-b\n    name: Dev Model B\n";
        let catalog: ModelCatalog = from_str(yaml).unwrap();
        assert_eq!(catalog.model_ids(), vec!["dev-model-a", "dev-model-b"]);
    }

    #[test]
    fn model_catalog_empty_when_unset() {
        let catalog: ModelCatalog = from_str("{}\n").unwrap();
        assert!(catalog.models.is_empty());

        let blank: ModelCatalog = from_str("models: \"\"\n").unwrap();
        assert!(blank.models.is_empty());
    }

    #[test]
    fn model_catalog_null_is_tolerated_as_empty() {
        let via_models_null: ModelCatalog = from_str("models: null\n").unwrap();
        assert!(via_models_null.models.is_empty());

        let via_models_bare: ModelCatalog = from_str("models:\n").unwrap();
        assert!(via_models_bare.models.is_empty());

        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            models: ModelCatalog,
        }
        let via_wrapper_null: Wrap = from_str("models:\n").unwrap();
        assert!(via_wrapper_null.models.models.is_empty());
    }

    // #415 (ADR-0018 Decision 5): `ModelCatalog::invalid_ids` is the validation `setProjectAllowedModels`
    // gates on. Mirrors `QuotaTiers::is_allowed`'s own test shape (configured/rejected/`None`/empty)
    // one section up, adjusted for "a list, not a scalar, so name the offending entries".
    fn configured_catalog() -> ModelCatalog {
        ModelCatalog {
            models: vec![
                ModelCatalogEntry {
                    id: "gpt-4.1-mini".to_string(),
                    name: "GPT-4.1 Mini".to_string(),
                },
                ModelCatalogEntry {
                    id: "claude-3.7".to_string(),
                    name: "Claude 3.7".to_string(),
                },
            ],
        }
    }

    #[test]
    fn model_catalog_invalid_ids_accepts_configured_entries() {
        let catalog = configured_catalog();
        let models = vec!["gpt-4.1-mini".to_string(), "claude-3.7".to_string()];
        assert!(catalog.invalid_ids(Some(&models)).is_empty());
    }

    #[test]
    fn model_catalog_invalid_ids_names_unconfigured_entries() {
        let catalog = configured_catalog();
        let models = vec![
            "gpt-4.1-mini".to_string(),
            "gtp-4.1-typo".to_string(),
            "also-unknown".to_string(),
        ];
        assert_eq!(
            catalog.invalid_ids(Some(&models)),
            vec!["gtp-4.1-typo", "also-unknown"]
        );
    }

    #[test]
    fn model_catalog_invalid_ids_deduplicates_the_same_bad_entry() {
        let catalog = configured_catalog();
        let models = vec!["typo".to_string(), "typo".to_string()];
        assert_eq!(catalog.invalid_ids(Some(&models)), vec!["typo"]);
    }

    #[test]
    fn model_catalog_invalid_ids_allows_none() {
        let catalog = configured_catalog();
        assert!(catalog.invalid_ids(None).is_empty());
    }

    #[test]
    fn model_catalog_invalid_ids_accepts_anything_when_catalogue_is_empty() {
        let catalog = ModelCatalog::default();
        let models = vec!["anything-goes".to_string()];
        assert!(
            catalog.invalid_ids(Some(&models)).is_empty(),
            "an empty/absent catalogue must accept any value, same default as QuotaTiers::is_allowed"
        );
    }

    // lightbridge-authz#395: unlike `QuotaTiers`/`ModelCatalog` above, `ApiKeyExpiry` must default
    // to a real, conservative ceiling (90 days) rather than "accept anything" when the config
    // block is entirely absent -- mirrors the null-tolerance tests above but asserts the opposite
    // failure-mode requirement (default is restrictive, not permissive).
    #[test]
    fn api_key_expiry_defaults_to_ninety_days_when_unset() {
        let cfg: ApiKeyExpiry = from_str("{}\n").unwrap();
        assert_eq!(cfg.max_lifetime_days, 90);
        assert_eq!(ApiKeyExpiry::default().max_lifetime_days, 90);
    }

    #[test]
    fn api_key_expiry_null_is_tolerated_as_the_default_not_unlimited() {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            api_key_expiry: ApiKeyExpiry,
        }
        let via_wrapper_null: Wrap = from_str("api_key_expiry:\n").unwrap();
        assert_eq!(via_wrapper_null.api_key_expiry.max_lifetime_days, 90);
    }

    #[test]
    fn api_key_expiry_parses_a_configured_ceiling() {
        let cfg: ApiKeyExpiry = from_str("max_lifetime_days: 30\n").unwrap();
        assert_eq!(cfg.max_lifetime_days, 30);
    }

    #[test]
    fn api_key_expiry_validate_rejects_zero() {
        let err = ApiKeyExpiry {
            max_lifetime_days: 0,
        }
        .validate()
        .unwrap_err();
        assert!(format!("{err}").contains("must be greater than 0"));
    }

    #[test]
    fn api_key_expiry_validate_accepts_the_default() {
        assert!(ApiKeyExpiry::default().validate().is_ok());
    }

    #[test]
    fn config_without_redis_or_usage_service_still_loads() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config omitting redis/usage_service must load");
        assert!(cfg.redis.is_none());
        assert!(cfg.usage_service.is_none());
        assert!(
            cfg.server.idp.is_none(),
            "a config file written before authz-idp existed must keep loading, with idp unset"
        );
        assert!(
            cfg.server.budget.is_none(),
            "a config file written before authz-budget existed must keep loading, with budget unset"
        );
    }

    #[test]
    fn config_with_budget_server_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
  budget:
    address: \"0.0.0.0\"
    port: 3005
    tls:
      cert_path: \"budget.crt\"
      key_path: \"budget.key\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with server.budget must load");
        let budget = cfg.server.budget.expect("server.budget must be set");
        assert_eq!(budget.address, "0.0.0.0");
        assert_eq!(budget.port, 3005);
        assert_eq!(budget.tls.cert_path, "budget.crt");
        assert_eq!(budget.tls.key_path, "budget.key");
    }

    #[test]
    fn config_with_idp_server_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
  idp:
    address: \"0.0.0.0\"
    port: 3004
    tls:
      cert_path: \"idp.crt\"
      key_path: \"idp.key\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with server.idp must load");
        let idp = cfg.server.idp.expect("server.idp must be set");
        assert_eq!(idp.address, "0.0.0.0");
        assert_eq!(idp.port, 3004);
        assert_eq!(idp.tls.cert_path, "idp.crt");
        assert_eq!(idp.tls.key_path, "idp.key");
    }

    #[test]
    fn config_with_usage_service_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://authz-usage:3002\"
  insecure_skip_verify: true
  timeout_ms: 2500
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with usage_service must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert_eq!(usage_service.base_url, "https://authz-usage:3002");
        assert!(usage_service.insecure_skip_verify);
        assert_eq!(usage_service.timeout_ms, 2500);
        assert_eq!(usage_service.ca_bundle_path, None);
    }

    #[test]
    fn config_with_usage_service_ca_bundle_path_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://lightbridge-usage.converse.svc:3000\"
  insecure_skip_verify: false
  ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config =
            from_str(yaml).expect("config with usage_service.ca_bundle_path must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert!(!usage_service.insecure_skip_verify);
        assert_eq!(
            usage_service.ca_bundle_path.as_deref(),
            Some("/etc/lightbridge/tls/ca.crt")
        );
    }

    #[test]
    fn config_with_redis_url_only_parses_ca_bundle_path_as_none() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
redis:
  url: \"redis://localhost:6379\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with a plain redis.url must load");
        let redis = cfg.redis.expect("redis must be set");
        assert_eq!(redis.url, "redis://localhost:6379");
        assert_eq!(redis.ca_bundle_path, None);
    }

    #[test]
    fn config_with_redis_ca_bundle_path_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
redis:
  url: \"rediss://:pw@redis-ha-haproxy.redis-system.svc.cluster.local:6379\"
  ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with redis.ca_bundle_path must load");
        let redis = cfg.redis.expect("redis must be set");
        assert_eq!(
            redis.url,
            "rediss://:pw@redis-ha-haproxy.redis-system.svc.cluster.local:6379"
        );
        assert_eq!(
            redis.ca_bundle_path.as_deref(),
            Some("/etc/lightbridge/tls/ca.crt")
        );
    }

    #[test]
    fn config_with_usage_service_client_identity_parses_it() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://lightbridge-usage.converse.svc:3006\"
  insecure_skip_verify: false
  ca_bundle_path: \"/etc/lightbridge/tls/ca.crt\"
  client_cert_path: \"/etc/lightbridge/tls/tls.crt\"
  client_key_path: \"/etc/lightbridge/tls/tls.key\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config =
            from_str(yaml).expect("config with usage_service client identity must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert_eq!(
            usage_service.client_cert_path.as_deref(),
            Some("/etc/lightbridge/tls/tls.crt")
        );
        assert_eq!(
            usage_service.client_key_path.as_deref(),
            Some("/etc/lightbridge/tls/tls.key")
        );
    }

    #[test]
    fn config_with_usage_service_defaults_client_identity_to_unset() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://lightbridge-usage.converse.svc:3006\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config =
            from_str(yaml).expect("config with usage_service must load without client identity");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert_eq!(usage_service.client_cert_path, None);
        assert_eq!(usage_service.client_key_path, None);
    }

    #[test]
    fn config_with_usage_service_defaults_insecure_skip_verify_and_timeout() {
        let yaml = "\
server:
  api:
    address: \"0.0.0.0\"
    port: 3000
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
  opa:
    address: \"0.0.0.0\"
    port: 3001
    tls:
      cert_path: \"a.crt\"
      key_path: \"a.key\"
    basic_auth:
      username: \"u\"
      password: \"p\"
logging:
  level: \"info\"
database:
  url: \"postgres://postgres:postgres@localhost:5432/lightbridge_authz\"
usage_service:
  base_url: \"https://authz-usage:3002\"
oauth2:
  type: self
  jwks_url: \"http://localhost/jwks\"
otel:
  enabled: true
  otlp_endpoint: \"http://localhost:4317\"
  service_name: \"svc\"
";
        let cfg: Config = from_str(yaml).expect("config with usage_service must load");
        let usage_service = cfg.usage_service.expect("usage_service must be set");
        assert!(!usage_service.insecure_skip_verify);
        assert_eq!(usage_service.timeout_ms, 5_000);
        assert_eq!(usage_service.ca_bundle_path, None);
    }

    // #177: `QuotaTiers::is_allowed` is the enforcement primitive the write paths call. These
    // cover its four cases directly; `crates/lightbridge-authz-rest/src/handlers/mod.rs` carries
    // the corresponding "is it actually wired into a write path" tests.
    fn configured_tiers() -> QuotaTiers {
        QuotaTiers {
            tiers: vec![
                QuotaTier {
                    id: "bronze".to_string(),
                    name: "Bronze".to_string(),
                },
                QuotaTier {
                    id: "gold".to_string(),
                    name: "Gold".to_string(),
                },
            ],
        }
    }

    #[test]
    fn quota_tiers_is_allowed_none_is_always_allowed() {
        assert!(configured_tiers().is_allowed(None));
        assert!(QuotaTiers::default().is_allowed(None));
    }

    #[test]
    fn quota_tiers_is_allowed_empty_catalogue_accepts_anything() {
        let empty = QuotaTiers::default();
        assert!(empty.is_allowed(Some("anything")));
        assert!(empty.is_allowed(Some("medim")));
    }

    #[test]
    fn quota_tiers_is_allowed_accepts_a_configured_id() {
        assert!(configured_tiers().is_allowed(Some("bronze")));
        assert!(configured_tiers().is_allowed(Some("gold")));
    }

    #[test]
    fn quota_tiers_is_allowed_rejects_an_unconfigured_id() {
        assert!(!configured_tiers().is_allowed(Some("medim")));
        assert!(!configured_tiers().is_allowed(Some("")));
    }
}
