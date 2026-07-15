use crate::error::Result;
use regex::{Captures, Regex};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_yaml::from_str;
use std::env;
use std::fs::read_to_string;
use std::sync::LazyLock;

static RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$([a-zA-Z_][a-zA-Z0-9_]*)|\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?:(:-|-)([^}]*))?\}")
        .unwrap()
});

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub logging: Logging,
    pub database: Database,
    pub oauth2: Oauth2,
    pub otel: Otel,
    /// Billing plans a caller may attach to an API key at creation time. The set is defined
    /// entirely by the operator (env-driven via YAML interpolation) — there is no plan table or
    /// entity. A `CreateApiKey` must name one of these plans or the request is rejected.
    #[serde(default)]
    pub billing: Billing,
}

/// The operator-configured catalogue of billing plan names. Populated from env (e.g.
/// `plans: "${BILLING_PLANS:-free,pro,enterprise}"`), so `plans` accepts either a
/// comma-separated string or a YAML sequence.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Billing {
    #[serde(default, deserialize_with = "deserialize_plan_list")]
    pub plans: Vec<String>,
}

impl Billing {
    /// Whether `plan` is one of the configured, non-empty plan names.
    pub fn is_allowed(&self, plan: &str) -> bool {
        !plan.is_empty() && self.plans.iter().any(|p| p == plan)
    }
}

/// Accepts a comma-separated string (the env-interpolation case) or a YAML sequence, trims each
/// entry, and drops empties so a blank/unset env var yields an empty list rather than `[""]`.
fn deserialize_plan_list<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Plans {
        Csv(String),
        List(Vec<String>),
    }

    let raw = match Plans::deserialize(deserializer)? {
        Plans::Csv(s) => s.split(',').map(|p| p.to_string()).collect(),
        Plans::List(list) => list,
    };
    Ok(raw
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect())
}

#[derive(Debug, Clone, Deserialize)]
pub struct Otel {
    pub enabled: bool,
    pub otlp_endpoint: String,
    pub service_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub api: ApiServer,
    pub opa: OpaServer,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
    /// Hostnames or `host:port` authorities accepted in the inbound `Host` header by the MCP
    /// streamable-HTTP transport (DNS-rebinding protection). Only consumed by the MCP server; when
    /// unset it keeps the secure default (`localhost`/`127.0.0.1`/`::1`).
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpaServer {
    pub address: String,
    pub port: u16,
    pub tls: Tls,
    pub basic_auth: BasicAuth,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tls {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Logging {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    pub url: String,
    pub pool_size: Option<u32>,
}

/// Credential-issuance mode. REQUIRED and has no default — the operator must state it explicitly,
/// because it decides how every API key is minted. `self` mints self-signed JWTs via
/// `oauth2.signing`; `external` exchanges the credential at an upstream IdP (e.g. Keycloak) via
/// `oauth2.issuance`. The two are mutually exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Oauth2Type {
    #[serde(rename = "self")]
    SelfSigned,
    External,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2 {
    /// REQUIRED credential-issuance mode (`self` or `external`). No default — a missing `type`
    /// fails config load rather than silently picking a mode.
    #[serde(rename = "type")]
    pub oauth2_type: Oauth2Type,
    pub jwks_url: String,
    #[serde(default)]
    pub oauth2_url: Option<String>,
    #[serde(default)]
    pub issuer_url: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub issuance: Option<Oauth2Issuance>,
    /// Expected audience(s) for JWT validation. If set, the JWT's `aud` claim must
    /// contain at least one of these values. Can be a single value or multiple values.
    #[serde(default)]
    pub audience: Option<Vec<String>>,
    /// Optional self-signing config: when enabled, issued API keys are RS256 JWTs signed
    /// by this service (rather than opaque secrets or Keycloak-exchanged tokens).
    #[serde(default)]
    pub signing: Option<JwtSigning>,
    /// Optional native RFC 8693 token-exchange: when enabled, this service exchanges an
    /// upstream IdP access token for a short-lived, project-scoped self-signed JWT (and an
    /// optional refresh token). Requires `type: self` (the exchanged token is signed by this
    /// service). Independent of `issuance`, which proxies exchange to an upstream IdP.
    #[serde(default)]
    pub token_exchange: Option<Oauth2TokenExchange>,
    /// Role-based access control: which JWT claim carries the caller's roles and how those roles
    /// map to permissions. When omitted, the built-in default mapping is used
    /// (`crate::authz::default_role_permissions`).
    #[serde(default)]
    pub rbac: crate::authz::Rbac,
}

impl Oauth2 {
    pub fn is_self_signed(&self) -> bool {
        matches!(self.oauth2_type, Oauth2Type::SelfSigned)
    }

    pub fn is_external(&self) -> bool {
        matches!(self.oauth2_type, Oauth2Type::External)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtSigning {
    /// `iss` claim and the OIDC issuer URL Authorino discovers the JWKS from.
    pub issuer: String,
    /// Optional `aud` claim stamped on issued tokens.
    #[serde(default)]
    pub audience: Option<String>,
    /// Default token lifetime in seconds and the hard cap on any frontend-requested expiry.
    #[serde(default = "default_signing_ttl_seconds")]
    pub ttl_seconds: i64,
    /// Auto-rotate the active signing key once it is older than this many days (checked at
    /// startup). The rotated-out key is marked stale and kept in the JWKS for verification.
    #[serde(default = "default_max_key_age_days")]
    pub max_key_age_days: i64,
}

fn default_signing_ttl_seconds() -> i64 {
    7_776_000
}

fn default_max_key_age_days() -> i64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2Issuance {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub subject_token_type: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2TokenExchange {
    #[serde(default)]
    pub enabled: bool,
    /// Lifetime of the exchanged access JWT, in seconds. Kept short (session-scoped) because
    /// these tokens are only revocable by expiry; renewal flows through the refresh token.
    #[serde(default = "default_exchange_access_ttl_seconds")]
    pub access_ttl_seconds: i64,
    /// Lifetime of an issued refresh token, in seconds. Refresh tokens are stored hashed and are
    /// revocable, so they carry the long-lived session; only minted when `offline_access` is
    /// requested and permitted.
    #[serde(default = "default_exchange_refresh_ttl_seconds")]
    pub refresh_ttl_seconds: i64,
    /// Scopes a client may request on exchange. `offline_access` gates refresh-token issuance.
    #[serde(default = "default_exchange_allowed_scopes")]
    pub allowed_scopes: Vec<String>,
}

fn default_exchange_access_ttl_seconds() -> i64 {
    900
}

fn default_exchange_refresh_ttl_seconds() -> i64 {
    2_592_000
}

fn default_exchange_allowed_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ]
}

pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Config> {
    load_yaml_from_path(path)
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
                Some(_) => caps.get(0).unwrap().as_str().to_string(),
            }
        } else {
            caps.get(0).unwrap().as_str().to_string()
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
    fn billing_plans_parse_from_csv_string() {
        let billing: Billing = from_str("plans: \"free, pro ,enterprise\"\n").unwrap();
        assert_eq!(billing.plans, vec!["free", "pro", "enterprise"]);
        assert!(billing.is_allowed("pro"));
        assert!(!billing.is_allowed("scale"));
        assert!(!billing.is_allowed(""));
    }

    #[test]
    fn billing_plans_parse_from_sequence() {
        let billing: Billing = from_str("plans:\n  - free\n  - pro\n").unwrap();
        assert_eq!(billing.plans, vec!["free", "pro"]);
    }

    #[test]
    fn billing_plans_empty_when_unset() {
        let billing: Billing = from_str("{}\n").unwrap();
        assert!(billing.plans.is_empty());
        assert!(!billing.is_allowed("free"));

        let blank: Billing = from_str("plans: \"\"\n").unwrap();
        assert!(blank.plans.is_empty());
    }
}
