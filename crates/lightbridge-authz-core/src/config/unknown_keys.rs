use serde_yaml::Value;
use tracing::warn;

const DEPRECATED_KEYS: &[(&str, &str)] = &[(
    "oauth2.relying_party.issuer",
    "use oauth2.federation.issuer instead",
)];

const KNOWN_KEYS: &[(&str, &[&str])] = &[
    (
        "",
        &[
            "server",
            "logging",
            "database",
            "redis",
            "usage_service",
            "oauth2",
            "otel",
            "billing",
            "quota_tiers",
            "models",
            "api_key_expiry",
            "secret_claim",
        ],
    ),
    (
        "server",
        &["api", "opa", "idp", "budget", "budget_internal"],
    ),
    (
        "server.api",
        &["address", "port", "tls", "allowed_hosts", "rpc_base_path"],
    ),
    (
        "server.api.tls",
        &["cert_path", "key_path", "client_ca_bundle_path"],
    ),
    ("server.opa", &["address", "port", "tls", "basic_auth"]),
    (
        "server.opa.tls",
        &["cert_path", "key_path", "client_ca_bundle_path"],
    ),
    ("server.opa.basic_auth", &["username", "password"]),
    ("server.idp", &["address", "port", "tls", "static_dir"]),
    (
        "server.idp.tls",
        &["cert_path", "key_path", "client_ca_bundle_path"],
    ),
    (
        "server.budget",
        &[
            "address",
            "port",
            "tls",
            "snapshot_refresh_seconds",
            "snapshot_active_window_minutes",
            "snapshot_slow_lane_minutes",
            "snapshot_seed_lookback_days",
            "snapshot_batch",
            "snapshot_concurrency",
        ],
    ),
    (
        "server.budget.tls",
        &["cert_path", "key_path", "client_ca_bundle_path"],
    ),
    (
        "server.budget_internal",
        &[
            "address",
            "port",
            "tls",
            "shared_secret",
            "shared_secret_header",
            "remaining_grace_seconds",
        ],
    ),
    (
        "server.budget_internal.tls",
        &["cert_path", "key_path", "client_ca_bundle_path"],
    ),
    ("logging", &["level"]),
    ("database", &["url", "pool_size"]),
    ("redis", &["url", "ca_bundle_path"]),
    (
        "usage_service",
        &[
            "base_url",
            "insecure_skip_verify",
            "ca_bundle_path",
            "client_cert_path",
            "client_key_path",
            "timeout_ms",
        ],
    ),
    (
        "oauth2",
        &[
            "type",
            "jwks_url",
            "jwks_ca_bundle_path",
            "oauth2_url",
            "issuer_url",
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "issuance",
            "audience",
            "signing",
            "token_exchange",
            "relying_party",
            "rbac",
            "clients",
            "federation",
        ],
    ),
    (
        "oauth2.issuance",
        &[
            "grant_type",
            "client_id",
            "client_secret",
            "subject_token_type",
            "requested_token_type",
            "audience",
            "scope",
        ],
    ),
    (
        "oauth2.signing",
        &[
            "issuer",
            "audience",
            "ttl_seconds",
            "max_key_age_days",
            "claim_mappers",
        ],
    ),
    (
        "oauth2.token_exchange",
        &[
            "enabled",
            "access_ttl_seconds",
            "authorization_code_ttl_seconds",
            "refresh_ttl_seconds",
            "allowed_scopes",
            "refresh_absolute_ttl_seconds",
            "refresh_reuse_grace_seconds",
            "device_code_ttl_seconds",
            "device_poll_interval_seconds",
            "device_verification_uri",
            "client_credentials_ttl_seconds",
        ],
    ),
    (
        "oauth2.relying_party",
        &[
            "client_id",
            "callback_url",
            "client_secret",
            "state_encryption_key",
            "token_encryption_key",
        ],
    ),
    (
        "oauth2.rbac",
        &["roles_claim", "role_permissions", "default_grants"],
    ),
    ("oauth2.federation", &["issuer", "discovery_url"]),
    ("otel", &["enabled", "otlp_endpoint", "service_name"]),
    ("billing", &["plans"]),
    ("quota_tiers", &["tiers"]),
    ("models", &["models"]),
    ("api_key_expiry", &["max_lifetime_days"]),
    (
        "secret_claim",
        &["encryption_key", "ttl_seconds", "redeem_base_url"],
    ),
];

pub(super) fn warn_unknown_keys_in_config(yaml: &str) {
    if let Ok(value) = serde_yaml::from_str::<Value>(yaml) {
        walk(&value, "");
    }
}

fn walk(value: &Value, path: &str) {
    let Value::Mapping(mapping) = value else {
        return;
    };

    let Some(known_fields) = get_known_fields(path) else {
        return;
    };

    for (k_val, v_val) in mapping {
        let Some(k_str) = k_val.as_str() else {
            continue;
        };

        let full_key = if path.is_empty() {
            k_str.to_string()
        } else {
            format!("{path}.{k_str}")
        };

        if let Some(hint) = get_deprecated_hint(&full_key) {
            warn!("Configuration key '{full_key}' is deprecated: {hint}");
        } else if !known_fields.contains(&k_str) {
            warn!("Unknown configuration key '{full_key}' ignored");
        } else {
            walk(v_val, &full_key);
        }
    }
}

fn get_known_fields(path: &str) -> Option<&'static [&'static str]> {
    KNOWN_KEYS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, fields)| *fields)
}

fn get_deprecated_hint(full_key: &str) -> Option<&'static str> {
    DEPRECATED_KEYS
        .iter()
        .find(|(k, _)| *k == full_key)
        .map(|(_, hint)| *hint)
}
