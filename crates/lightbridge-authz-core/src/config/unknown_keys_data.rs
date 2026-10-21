/// Deprecated configuration keys, mapped to the hint to print when one is seen.
///
/// Keep this in sync with the serde structs in this `config` module (`mod.rs`, plus
/// `budget_server.rs`, `budget_internal.rs`, `claim_mapper.rs`): when a config key is renamed or
/// removed, record its old path here so an operator still shipping the old key is told how to fix
/// it instead of silently dropping it.
pub(super) const DEPRECATED_KEYS: &[(&str, &str)] = &[(
    "oauth2.relying_party.issuer",
    "use oauth2.federation.issuer instead",
)];

/// Every configuration key the serde structs in this `config` module accept, by dotted path.
///
/// A hand-maintained mirror of the struct fields in `mod.rs`, `budget_server.rs`,
/// `budget_internal.rs` and `claim_mapper.rs`, updated whenever a key changes; the sync tests in
/// `tests/config_tests.rs` (`known_keys_flag_no_spurious_warnings_on_fully_populated_config` and
/// `known_keys_descend_into_every_config_section`) fail loudly when it drifts.
///
/// A path absent here makes `walk` early-return for that whole subtree (how free-form maps such as
/// `funding.principals` opt out). No struct has `deny_unknown_fields`: this table is the warning.
pub(super) const KNOWN_KEYS: &[(&str, &[&str])] = &[
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
            "settlement_seconds",
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
            "funding",
        ],
    ),
    (
        "server.budget_internal.funding",
        &["audience", "principals"],
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
            "timeout_ms",
            "browser_session_ttl_seconds",
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
