use axum::{Router, routing::get};
use lightbridge_authz_core::db::DbPoolTrait;

pub mod actor_api_key_labels;
pub mod auth_provider;
pub mod authorize;
pub mod authorize_session_state;
pub mod budget_convert;
pub mod budget_remaining;
pub mod budget_remaining_auth;
pub mod budget_remaining_router;
pub mod budget_remaining_wire;
pub mod budget_services;
pub mod budget_snapshot_refresher;
pub mod claim_redeem;
pub mod codec;
pub mod convert;
pub mod end_session;
pub mod error_convert;
pub mod handlers;
mod health_handlers;
pub mod html_page;
pub mod identity_directory;
pub mod introspect_budget;
pub mod loopback;
pub mod middleware;
pub mod models;
pub mod my_access;
pub mod oauth2_client_validation;
pub mod oauth2_op;
mod opa_doc;
pub mod opa_repo;
pub mod platform_roles_directory;
pub mod post_logout;
pub mod procedures;
pub mod ratelimit_redis;
pub mod redis_tls;
pub mod relying_party;
pub mod reset_schedule_convert;
pub mod routers;
pub mod rpc_authorize;
pub mod rpc_permission_map;
pub mod secret_claim;
pub mod server_api;
pub mod server_budget;
pub mod server_idp;
pub mod server_opa;
pub mod session_cookie;
pub mod session_directory;
pub mod session_management;
pub mod session_query;
pub mod signing;
pub mod static_assets;
pub mod token_exchange;
pub mod userinfo;

use health_handlers::{
    health_handler, readiness_handler, root_handler, startup_handler, version_handler,
};
use std::sync::Arc;
use std::time::Duration;

use cratestack::ratelimit::StoreErrorPolicy;

pub use opa_repo::{OpaRepoTrait, OpaState, SessionStatusRow};
pub use procedures::Procedures;
pub use server_api::{build_api_router, start_api_server};
pub use server_budget::{build_budget_router, start_budget_server};
pub use server_idp::{build_idp_router, start_idp_server};
pub use server_opa::{build_opa_router, start_opa_server};

pub(crate) use crate::error_convert::to_cratestack_error;
pub(crate) use convert::{has_permission, subject_from_ctx};

/// Idempotency replay window for the CRUD RPC surface (ADR-0003, "Idempotency").
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(24 * 3600);
/// Per-principal token-bucket rate-limit defaults for the CRUD RPC surface (ADR-0003, "Rate
/// limiting (Redis-backed)"). Generous burst with steady refill; tune via deployment as needed.
const RATE_LIMIT_BURST: u32 = 120;
const RATE_LIMIT_REFILL_PER_SECOND: f64 = 60.0;
/// Store-failure policy for every `RateLimitLayer` this crate builds.
const RATE_LIMIT_STORE_ERROR_POLICY: StoreErrorPolicy = StoreErrorPolicy::Deny;

/// How often `authz-budget` wakes to claim due budget reset schedules (ADR-0032). 60 seconds is
/// comfortably fine-grained for a domain whose finest cadence is daily, and coarse enough that an
/// idle deployment's scheduler costs one indexed `SELECT` a minute.
const RESET_SCHEDULER_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Service names reported by `GET /version` and the `service.build` startup log line (#573).
pub const SERVICE_API: &str = "authz-api";
/// See [`SERVICE_API`].
pub const SERVICE_OPA: &str = "authz-opa";
/// See [`SERVICE_API`].
pub const SERVICE_IDP: &str = "authz-idp";
/// See [`SERVICE_API`].
pub const SERVICE_BUDGET: &str = "authz-budget";
/// See [`SERVICE_API`]. `authz-budget`'s second, mTLS-only listener (ADR-0034) reports as its own
/// service for the same reason `lightbridge-authz-usage` splits `authz-usage`/`authz-usage-query`
/// (#347): the two ports have different auth postures, and "which one am I hitting?" must have an
/// answer.
pub const SERVICE_BUDGET_INTERNAL: &str = "authz-budget-internal";

/// Shared `/`, `/healthz`, `/healthz/startup`, `/healthz/ready`, `/version` mount, reused by every
/// server router (`build_api_router`/`build_opa_router`/`build_idp_router`/`build_budget_router`)
/// so the probe surface — and its DB-readiness semantics (`readiness_handler`/`is_database_ready`)
/// — can never drift between them. Generic over `S` the same way
/// `well_known_router`/`token_exchange_router` are, so it merges into any router regardless of that
/// router's own state type.
pub(crate) fn probe_router<S>(
    readiness_pool: Arc<dyn DbPoolTrait>,
    service: &'static str,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(health_handler))
        .route("/healthz/startup", get(startup_handler))
        .route("/version", get(move || version_handler(service)))
        .route(
            "/healthz/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::{
        DEFAULT_EXPIRING_SOON_WINDOW_DAYS, MAX_EXPIRING_SOON_WINDOW_DAYS,
        clamp_expiring_soon_window_days,
    };
    use crate::opa_doc::OpaDoc;
    use crate::server_api::normalize_rpc_base_path;
    use crate::server_idp::build_token_exchange_state;
    use axum::http::StatusCode;
    use lightbridge_authz_api_key::repo::StoreRepo;
    use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
    use lightbridge_authz_core::async_trait;
    use lightbridge_authz_core::config::{
        Oauth2, Oauth2TokenExchange, Oauth2Type, OauthClient, OauthClientType,
    };
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use utoipa::OpenApi;

    struct NoopBearer;

    #[async_trait]
    impl BearerTokenServiceTrait for NoopBearer {
        async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
            unreachable!("build_token_exchange_state never calls the bearer service")
        }
    }

    fn lazy_signing_repo() -> Arc<StoreRepo> {
        let pool = PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool: Arc<dyn DbPoolTrait> =
            Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool));
        Arc::new(StoreRepo::new(pool))
    }

    /// Same lazy/dead-pool trick as [`lazy_signing_repo`], for the config-validation tests below
    /// -- none of them reach a real `current_tier` query, only `build_token_exchange_state`'s own
    /// synchronous validation branches, so a live budget ledger is never needed here.
    fn lazy_budget_repo() -> Arc<lightbridge_authz_budget::repo::BudgetRepo> {
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool: Arc<dyn DbPoolTrait> =
            Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool));
        Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(pool))
    }

    fn noop_bearer() -> Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> {
        Arc::new(NoopBearer)
    }

    /// A `PolicyEngine` double that panics if `evaluate` is ever called.
    /// `build_token_exchange_state` only needs a `PolicyEngine` to satisfy
    /// `TokenExchangeOpStore::new`'s constructor (ADR-0015 Decision 6); none of the
    /// config-validation tests below ever mint a token, so `resolve_budget_tier` -- the only
    /// caller of any `PolicyEngine` method reachable from this store -- is never exercised here
    /// either.
    #[derive(Debug)]
    struct UnusedPolicyEngine;

    #[async_trait]
    impl lightbridge_authz_budget::PolicyEngine for UnusedPolicyEngine {
        async fn evaluate(
            &self,
            _facts: &lightbridge_authz_budget::Facts,
            _requested_amount_micros: i64,
        ) -> Result<lightbridge_authz_budget::Decision, lightbridge_authz_budget::BudgetError>
        {
            unreachable!("build_token_exchange_state never calls the policy engine")
        }

        fn allowed_amounts_micros(&self) -> Vec<i64> {
            vec![6_000_000, 15_000_000, 30_000_000]
        }

        fn starting_amount_micros(&self) -> i64 {
            15_000_000
        }

        fn fail_closed_floor_micros(&self) -> i64 {
            6_000_000
        }
    }

    fn lazy_policy_engine() -> Arc<dyn lightbridge_authz_budget::PolicyEngine> {
        Arc::new(UnusedPolicyEngine)
    }

    #[test]
    fn normalize_rpc_base_path_handles_unset_and_root() {
        // Unset / empty / bare-slash all mean "root mount" (caller uses `merge`).
        assert_eq!(normalize_rpc_base_path(None), None);
        assert_eq!(normalize_rpc_base_path(Some("")), None);
        assert_eq!(normalize_rpc_base_path(Some("   ")), None);
        assert_eq!(normalize_rpc_base_path(Some("/")), None);
    }

    #[test]
    fn normalize_rpc_base_path_normalizes_slashes() {
        // Leading slash added if missing; trailing slash stripped (axum `nest` rejects both edges).
        assert_eq!(
            normalize_rpc_base_path(Some("/api")).as_deref(),
            Some("/api")
        );
        assert_eq!(
            normalize_rpc_base_path(Some("api")).as_deref(),
            Some("/api")
        );
        assert_eq!(
            normalize_rpc_base_path(Some("/api/")).as_deref(),
            Some("/api")
        );
        assert_eq!(
            normalize_rpc_base_path(Some(" /gateway/v1/ ")).as_deref(),
            Some("/gateway/v1")
        );
    }

    fn base_oauth2(oauth2_type: Oauth2Type) -> Oauth2 {
        Oauth2 {
            oauth2_type,
            jwks_url: "http://jwks".to_string(),
            jwks_ca_bundle_path: None,
            oauth2_url: None,
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            issuance: None,
            audience: None,
            signing: None,
            token_exchange: None,
            relying_party: None,
            rbac: Default::default(),
            clients: Vec::new(),
            federation: Some(lightbridge_authz_core::config::Federation {
                issuer: "https://keycloak.example.test/realms/dev".to_string(),
                discovery_url: None,
            }),
        }
    }

    /// Unreachable but syntactically valid -- `RedisClientAssertionStore::connect` is lazy (see
    /// its own doc comment), so building `TokenExchangeState` never actually dials this.
    const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";

    fn exchange_cfg() -> Oauth2TokenExchange {
        Oauth2TokenExchange {
            enabled: true,
            access_ttl_seconds: 900,
            authorization_code_ttl_seconds: 300,
            refresh_ttl_seconds: 2_592_000,
            allowed_scopes: vec!["openid".to_string()],
            refresh_absolute_ttl_seconds: 7_776_000,
            refresh_reuse_grace_seconds: 30,
            device_code_ttl_seconds: 600,
            device_poll_interval_seconds: 5,
            device_verification_uri: "https://authz.example.test/device/verify".to_string(),
            client_credentials_ttl_seconds: 900,
        }
    }

    fn signing_cfg() -> lightbridge_authz_core::config::JwtSigning {
        lightbridge_authz_core::config::JwtSigning {
            issuer: "https://authz.example.test".to_string(),
            audience: None,
            ttl_seconds: 7_776_000,
            max_key_age_days: 30,
            claim_mappers: Vec::new(),
        }
    }

    /// Shared fixture for this module's `build_token_exchange_state` tests: every field this
    /// crate's own validation cares about, defaulted to the shape every test below needs unless
    /// it overrides one -- none of these tests exercise `refresh_ttl_seconds`/
    /// `refresh_absolute_ttl_seconds` overrides, so both stay `None` (falls back to
    /// `exchange_cfg()`'s global values).
    fn oauth_client_fixture(
        client_id: &str,
        client_type: OauthClientType,
        scopes: Vec<String>,
        grant_types: Vec<String>,
        jwks: Option<serde_json::Value>,
    ) -> OauthClient {
        OauthClient {
            client_id: client_id.to_string(),
            client_type,
            scopes,
            grant_types,
            allowed_audiences: vec![client_id.to_string()],
            jwks,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            require_pkce: false,
            refresh_ttl_seconds: None,
            refresh_absolute_ttl_seconds: None,
        }
    }

    // This function's own `Result<Option<...>>` contract is unchanged by ADR-0023 -- only its
    // sole production caller, `start_idp_server`, now treats this `None` result as fatal (see
    // `build_token_exchange_state`'s doc comment).
    #[tokio::test]
    async fn build_token_exchange_state_is_none_when_disabled() {
        let oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        let result = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_external_oauth2() {
        let mut oauth2 = base_oauth2(Oauth2Type::External);
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for external oauth2 with token_exchange enabled");
        };
        assert!(format!("{err}").contains("requires oauth2.type: self"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_missing_signing_block() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a missing signing block");
        };
        assert!(format!("{err}").contains("requires oauth2.signing"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_non_positive_ttls() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut cfg = exchange_cfg();
        cfg.access_ttl_seconds = 0;
        oauth2.token_exchange = Some(cfg);
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a non-positive ttl");
        };
        assert!(format!("{err}").contains("must be positive"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_unsafe_device_verification_uri() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut cfg = exchange_cfg();
        cfg.device_verification_uri =
            "https://user:password@authz.example.test/device/verify?unexpected=1#fragment"
                .to_string();
        oauth2.token_exchange = Some(cfg);
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for an unsafe device verification URI");
        };
        assert!(format!("{err}").contains("credential-free"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_zero_refresh_absolute_ttl() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut cfg = exchange_cfg();
        cfg.refresh_absolute_ttl_seconds = 0;
        oauth2.token_exchange = Some(cfg);
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a zero refresh_absolute_ttl_seconds");
        };
        let message = format!("{err}");
        assert!(message.contains("refresh_absolute_ttl_seconds"));
        assert!(message.contains("must be positive"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_negative_refresh_absolute_ttl() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut cfg = exchange_cfg();
        cfg.refresh_absolute_ttl_seconds = -1;
        oauth2.token_exchange = Some(cfg);
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a negative refresh_absolute_ttl_seconds");
        };
        let message = format!("{err}");
        assert!(message.contains("refresh_absolute_ttl_seconds"));
        assert!(message.contains("must be positive"));
    }

    /// Per `oauth2_op::refresh_ttl::validate_client_refresh_ttls` (the per-client-aware
    /// replacement for this function's own former inline global-only check): the boundary is
    /// `refresh_ttl_seconds <= refresh_absolute_ttl_seconds`, not strict `<` -- an EQUAL pair is
    /// accepted (see that module's own `an_effective_ttl_equal_to_the_absolute_cap_is_accepted`),
    /// only a `refresh_ttl_seconds` that genuinely EXCEEDS the cap is refused.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_refresh_ttl_exceeding_refresh_absolute_ttl() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut cfg = exchange_cfg();
        cfg.refresh_absolute_ttl_seconds = 2_592_000;
        cfg.refresh_ttl_seconds = 2_592_001;
        oauth2.token_exchange = Some(cfg);
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!(
                "expected an error when refresh_ttl_seconds exceeds refresh_absolute_ttl_seconds"
            );
        };
        let message = format!("{err}");
        assert!(message.contains("refresh_absolute_ttl_seconds"));
        assert!(message.contains("refresh_ttl_seconds"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_builds_state_for_valid_config() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        oauth2.token_exchange = Some(exchange_cfg());
        let result = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        )
        .unwrap();
        assert!(result.is_some());
    }

    /// F4 (adversarial-review follow-up): nothing previously stopped a registered client's
    /// `client_id` from equaling `oauth2.signing.audience` -- the value a self-signed API-key
    /// JWT's `azp` always carries. That equality is exactly the condition under which
    /// `token_exchange::introspect_endpoint`'s `azp == caller's client_id` gate would admit an
    /// API-key JWT as a live token-exchange access token, defeating the "API keys are
    /// structurally not introspectable" invariant that module documents.
    /// `validate_authorization_code_clients` must refuse to start in this configuration.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_a_client_id_colliding_with_the_signing_audience() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        let mut signing = signing_cfg();
        signing.audience = Some("shared-audience".to_string());
        oauth2.signing = Some(signing);
        oauth2.clients = vec![oauth_client_fixture(
            "shared-audience",
            OauthClientType::Public,
            vec!["openid".to_string()],
            vec!["refresh_token".to_string()],
            None,
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error when a client_id equals oauth2.signing.audience");
        };
        assert!(format!("{err}").contains("equals oauth2.signing.audience"));
    }

    /// Control: distinct client ids and a distinct signing audience must still start cleanly --
    /// the new check above must not be a blanket refusal of every configured client.
    #[tokio::test]
    async fn build_token_exchange_state_allows_a_client_id_distinct_from_the_signing_audience() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        let mut signing = signing_cfg();
        signing.audience = Some("api-key-audience".to_string());
        oauth2.signing = Some(signing);
        oauth2.clients = vec![oauth_client_fixture(
            "a-real-oauth-client",
            OauthClientType::Public,
            vec!["openid".to_string()],
            vec!["refresh_token".to_string()],
            None,
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let result = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        )
        .unwrap();
        assert!(result.is_some());
    }

    fn service_client_with_grant_types(client_id: &str, grant_types: Vec<String>) -> OauthClient {
        let key = signing::generate_rs256_key().expect("rsa keypair generation");
        oauth_client_fixture(
            client_id,
            OauthClientType::Service,
            vec!["read:usage".to_string()],
            grant_types,
            Some(serde_json::json!({ "keys": [key.public_jwk] })),
        )
    }

    /// Test 8 (DECISIVE, #534/ADR-0030): a `public` client (`NoAuth` at the token endpoint) listing
    /// the `client_credentials` grant must be refused at startup -- a public client mints a machine
    /// token with NO credential proving who asked for it. Prove-fail-first (recorded verbatim in
    /// the PR body): deleting the `client_type == OauthClientType::Public` branch inside
    /// `validate_client_credentials_and_service_clients` turns this test green-to-red -- restored
    /// immediately after.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_a_public_client_credentials_client() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        oauth2.clients = vec![oauth_client_fixture(
            "public-machine",
            OauthClientType::Public,
            vec!["read:usage".to_string()],
            vec!["client_credentials".to_string()],
            None,
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!(
                "expected an error for a public client listing the client_credentials grant -- \
                 it would mint a machine token with no credential at all"
            );
        };
        let message = format!("{err}");
        assert!(message.contains("public-machine"));
        assert!(message.contains("client_credentials"));
    }

    /// Test 9: a `Service`/`Confidential` client whose `jwks` does not contain at least one
    /// parseable JWK must be refused at startup -- before this fix, `find_client` would keep
    /// answering `token_endpoint_auth_method: Some(PrivateKeyJwt)` for it while discovery silently
    /// dropped it from `token_endpoint_auth_methods_supported`, and nothing ever caught the
    /// disagreement.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_a_service_client_with_unparseable_jwks() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        oauth2.clients = vec![oauth_client_fixture(
            "no-jwks-machine",
            OauthClientType::Service,
            vec!["read:usage".to_string()],
            vec!["client_credentials".to_string()],
            None,
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a service client with no jwks at all");
        };
        let message = format!("{err}");
        assert!(message.contains("no-jwks-machine"));
        assert!(message.contains("parseable"));
    }

    /// The same check (9), but for a `jwks` present yet genuinely unparseable (an empty `keys`
    /// array) rather than absent entirely -- both must be refused identically.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_a_confidential_client_with_an_empty_jwks_array() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        oauth2.clients = vec![oauth_client_fixture(
            "empty-jwks-client",
            OauthClientType::Confidential,
            vec!["openid".to_string()],
            vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
            Some(serde_json::json!({ "keys": [] })),
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a confidential client with an empty jwks key set");
        };
        assert!(format!("{err}").contains("empty-jwks-client"));
    }

    /// Fail-first-proven RSA-strength floor: a well-formed, parseable, but only 1024-bit RSA JWK
    /// must be refused at startup exactly like an unparseable one -- `parse_public_jwk` validates
    /// shape, not strength, so without `signing::jwk_meets_minimum_strength` this JWK would pass
    /// the same gate a genuinely unusable key fails, defeating the "could never actually
    /// authenticate" promise that gate's own error text makes. `n` here is a fabricated,
    /// mathematically-meaningless 128-byte (1024-bit) value -- `parse_public_jwk` never checks that
    /// `n`/`e` form an invertible keypair, only that they parse, so this is sufficient to exercise
    /// the size check without a real weak keypair. Prove-fail-first, actually run: reverted
    /// `client_has_a_parseable_jwk` to its pre-floor body (`parse_public_jwk(jwk).is_ok()` alone,
    /// no `jwk_meets_minimum_strength` call), reran just this test, and it went red for the
    /// predicted reason (no error at all -- the weak key was accepted). Restored immediately after.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_a_1024_bit_rsa_service_client() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let weak_modulus_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xAAu8; 128])
        };
        oauth2.clients = vec![oauth_client_fixture(
            "weak-key-machine",
            OauthClientType::Service,
            vec!["read:usage".to_string()],
            vec!["client_credentials".to_string()],
            Some(serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "weak-key-2026",
                    "n": weak_modulus_b64,
                    "e": "AQAB",
                }]
            })),
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!(
                "expected an error for a service client whose only RSA key is 1024 bits -- \
                 parseable is not the same bar as usable"
            );
        };
        let message = format!("{err}");
        assert!(message.contains("weak-key-machine"));
        assert!(message.contains("parseable"));
    }

    /// A `client_credentials` client may not also register `redirect_uris` -- RFC 6749 §4.4 is a
    /// non-browser, non-redirect grant by construction.
    #[tokio::test]
    async fn build_token_exchange_state_rejects_a_client_credentials_client_with_redirect_uris() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut client = service_client_with_grant_types(
            "machine-with-redirect",
            vec!["client_credentials".to_string()],
        );
        client.redirect_uris = vec!["https://cb.example.test/callback".to_string()];
        oauth2.clients = vec![client];
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a client_credentials client registering redirect_uris");
        };
        let message = format!("{err}");
        assert!(message.contains("machine-with-redirect"));
        assert!(message.contains("redirect_uris"));
    }

    /// Control: a well-formed `Service` client with a real, parseable `jwks`, the
    /// `client_credentials` grant, and no `redirect_uris` starts cleanly -- the checks above must
    /// not be a blanket refusal of every service client.
    #[tokio::test]
    async fn build_token_exchange_state_allows_a_well_formed_service_client() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        oauth2.clients = vec![service_client_with_grant_types(
            "it-machine",
            vec!["client_credentials".to_string()],
        )];
        oauth2.token_exchange = Some(exchange_cfg());
        let result = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
            lazy_budget_repo(),
            lazy_policy_engine(),
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        )
        .unwrap();
        assert!(result.is_some());
    }

    fn opa_openapi() -> Value {
        serde_json::to_value(OpaDoc::openapi()).expect("openapi should serialize")
    }

    #[test]
    fn introspect_endpoint_should_exist_in_opa_openapi() {
        let doc = opa_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/v1/authorino/validate/introspect"),
            "expected the OPA server to expose the RFC 7662 introspection endpoint"
        );
        assert!(
            !paths.contains_key("/v1/authorino/validate"),
            "the legacy authorino validate endpoint should no longer be exposed"
        );
        assert!(
            !paths.contains_key("/v1/opa/validate"),
            "the legacy opa validate endpoint should no longer be exposed"
        );
    }

    #[test]
    fn resolve_context_endpoint_should_exist_in_opa_openapi() {
        let doc = opa_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/idp/v1/resolve-context"),
            "expected the OPA server to expose the identity resolve-context endpoint"
        );
    }

    /// #570: pins `POST /idp/v1/authorize-usage-scope` (the ownership authority
    /// `lightbridge-authz-usage`'s query listener calls) in the published OPA OpenAPI contract,
    /// mirroring `resolve_context_endpoint_should_exist_in_opa_openapi` above.
    #[test]
    fn authorize_usage_scope_endpoint_should_exist_in_opa_openapi() {
        let doc = opa_openapi();
        let paths = doc["paths"]
            .as_object()
            .expect("openapi paths should be an object");

        assert!(
            paths.contains_key("/idp/v1/authorize-usage-scope"),
            "expected the OPA server to expose the usage-scope ownership authority endpoint"
        );
    }

    #[test]
    fn introspect_response_should_expose_active_flag() {
        let doc = opa_openapi();
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas should be an object");
        let resp = schemas
            .get("IntrospectResponse")
            .expect("missing IntrospectResponse schema");

        assert!(
            resp["properties"].get("active").is_some(),
            "IntrospectResponse should expose the RFC 7662 `active` flag"
        );

        assert!(
            resp["properties"].get("billing_plan_name").is_some()
                && resp["properties"].get("billing_plan_limits").is_some(),
            "IntrospectResponse should expose the resolved billing plan name and limits"
        );
        assert!(
            schemas.contains_key("BillingLimits"),
            "the BillingLimits schema referenced by IntrospectResponse must be a defined \
             component (no dangling $ref)"
        );
    }

    #[tokio::test]
    async fn health_and_startup_endpoints_report_ok() {
        assert_eq!(health_handler().await, StatusCode::OK);
        assert_eq!(startup_handler().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn root_handler_reports_welcome() {
        let (status, body) = root_handler().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
        assert!(!body.message.is_empty());
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_when_database_is_down() {
        let pool = PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy pool should be constructible");
        let pool: Arc<dyn DbPoolTrait> =
            Arc::new(lightbridge_authz_core::db::DbPool::from_pool(pool));

        assert_eq!(
            readiness_handler(pool).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    // -----------------------------------------------------------------------------------------
    // `clamp_expiring_soon_window_days` (lightbridge-authz#436, `listMyExpiringApiKeys`'s
    // `withinDays` resolution) -- boundary cases only; the query's own "which keys actually come
    // back" boundary (exactly-at-threshold expiry timestamps, already-expired exclusion,
    // cross-tenant isolation) is covered by the live-database `rpc_it_tests.rs` suite, which can
    // exercise the real generated `db.api_key()` policy-scoped query this function's result feeds
    // into -- this unit test only proves the pure clamp arithmetic in isolation.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn expiring_soon_window_defaults_to_fourteen_days_when_omitted() {
        assert_eq!(
            clamp_expiring_soon_window_days(None),
            DEFAULT_EXPIRING_SOON_WINDOW_DAYS
        );
        assert_eq!(DEFAULT_EXPIRING_SOON_WINDOW_DAYS, 14);
    }

    #[test]
    fn expiring_soon_window_passes_through_an_in_range_value_unchanged() {
        assert_eq!(clamp_expiring_soon_window_days(Some(1)), 1);
        assert_eq!(clamp_expiring_soon_window_days(Some(7)), 7);
        assert_eq!(clamp_expiring_soon_window_days(Some(90)), 90);
    }

    #[test]
    fn expiring_soon_window_clamps_a_non_positive_request_up_to_one() {
        assert_eq!(clamp_expiring_soon_window_days(Some(0)), 1);
        assert_eq!(clamp_expiring_soon_window_days(Some(-30)), 1);
    }

    #[test]
    fn expiring_soon_window_clamps_an_oversized_request_down_to_the_ceiling() {
        assert_eq!(
            clamp_expiring_soon_window_days(Some(91)),
            MAX_EXPIRING_SOON_WINDOW_DAYS
        );
        assert_eq!(
            clamp_expiring_soon_window_days(Some(36_500)),
            MAX_EXPIRING_SOON_WINDOW_DAYS
        );
        assert_eq!(MAX_EXPIRING_SOON_WINDOW_DAYS, 90);
    }
}
