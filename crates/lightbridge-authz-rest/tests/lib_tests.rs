use std::sync::Arc;

use lightbridge_authz_core::config::{
    ApiKeyExpiry, ApiServer, BasicAuth, Billing, BillingPlan, ModelCatalog, Oauth2, Oauth2Type,
    OpaServer, QuotaTiers, Redis, Tls,
};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::postgres::PgPoolOptions;

fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    Arc::new(DbPool::from_pool(pool))
}

/// A trust-everything [`lightbridge_authz_rest::auth_provider::SubjectResolver`] test double
/// (ADR-0025): resolves any `(iss, sub)` to `AccountId::assert_already_resolved(sub)` unconditionally,
/// never touching a database.
struct TrustEverythingResolver;

#[lightbridge_authz_core::async_trait]
impl lightbridge_authz_rest::auth_provider::SubjectResolver for TrustEverythingResolver {
    async fn resolve(
        &self,
        _iss: &str,
        sub: &str,
    ) -> lightbridge_authz_core::error::Result<lightbridge_authz_core::identity::AccountId> {
        Ok(lightbridge_authz_core::identity::AccountId::assert_already_resolved(sub))
    }
}

fn test_resolver() -> Arc<dyn lightbridge_authz_rest::auth_provider::SubjectResolver> {
    Arc::new(TrustEverythingResolver)
}

fn sample_redis() -> Option<Redis> {
    Some(Redis {
        url: "redis://127.0.0.1:6379".to_string(),
        ca_bundle_path: None,
    })
}

fn sample_billing() -> Billing {
    Billing {
        plans: vec![BillingPlan {
            id: "free".to_string(),
            name: "Free".to_string(),
            limits: None,
        }],
    }
}

/// Empty catalogue -- none of these tests exercise quota-tier validation itself (that lives in
/// `crates/lightbridge-authz-rest/src/handlers/mod.rs`'s own tests), so the deliberate
/// accept-anything default (see `QuotaTiers`'s doc comment) is exactly what every server-startup
/// test here wants: unrelated to what's under test either way.
fn sample_quota_tiers() -> QuotaTiers {
    QuotaTiers::default()
}

/// Empty catalogue -- none of these tests exercise `listModelCatalog` itself (that lives in
/// `rpc_router_tests.rs`), so the deliberate accept-anything empty default (see `ModelCatalog`'s
/// doc comment) is exactly what every server-startup test here wants -- mirrors
/// `sample_quota_tiers` above.
fn sample_models() -> ModelCatalog {
    ModelCatalog::default()
}

/// The built-in default (90 days) -- none of these tests exercise `expires_at` validation itself
/// (that lives in `crates/lightbridge-authz-rest/src/handlers/mod.rs`'s own tests and
/// `api_key_expiry_tests.rs`), so the real default is exactly what every server-startup test here
/// wants -- mirrors `sample_quota_tiers`/`sample_models` above.
fn sample_api_key_expiry() -> ApiKeyExpiry {
    ApiKeyExpiry::default()
}

fn bad_tls() -> Tls {
    Tls {
        cert_path: "/nonexistent/lightbridge-authz-rest-test/cert.pem".to_string(),
        key_path: "/nonexistent/lightbridge-authz-rest-test/key.pem".to_string(),
        client_ca_bundle_path: None,
    }
}

fn external_oauth2() -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
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

/// `serve_tls` loads the TLS cert/key from disk before ever binding a socket (see
/// `lightbridge_authz_core::server::serve_tls`), so pointing it at nonexistent paths makes it
/// fail fast during cert loading without opening any real listener. This exercises the entire
/// setup path of `start_api_server`/`start_opa_server` (config branches, router assembly,
/// tracing) while staying fully offline.
#[tokio::test]
async fn start_api_server_fails_fast_when_tls_certs_are_missing() {
    let api = ApiServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        allowed_hosts: None,
        rpc_base_path: None,
    };
    let result = lightbridge_authz_rest::start_api_server(
        &api,
        lazy_pool(),
        &external_oauth2(),
        &sample_billing(),
        &sample_quota_tiers(),
        &sample_models(),
        &sample_api_key_expiry(),
        &sample_redis(),
        &None,
    )
    .await;
    assert!(
        result.is_err(),
        "missing TLS cert paths must surface as an error"
    );
}

#[tokio::test]
async fn start_opa_server_fails_fast_when_tls_certs_are_missing() {
    let opa = OpaServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
    };
    let result = lightbridge_authz_rest::start_opa_server(
        &opa,
        lazy_pool(),
        &sample_billing(),
        &external_oauth2(),
    )
    .await;
    assert!(
        result.is_err(),
        "missing TLS cert paths must surface as an error"
    );
}

/// Regression guard for the "authz-opa is freed from the mandatory-Redis requirement" half of
/// AGENTS.md's "Redis is a mandatory dependency" house rule: `start_opa_server` doesn't even take
/// a `redis` parameter (unlike `start_api_server`/`start_idp_server`/`start_budget_server`, which
/// all now hard-require `Config.redis`), so it must run its whole startup sequence to completion
/// with no Redis configured anywhere, failing only for the TLS reason this test deliberately
/// induces -- never anything Redis-shaped.
#[tokio::test]
async fn start_opa_server_starts_fine_with_no_redis_configured() {
    let opa = OpaServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        basic_auth: BasicAuth {
            username: "authorino".to_string(),
            password: "change-me".to_string(),
        },
    };
    let result = lightbridge_authz_rest::start_opa_server(
        &opa,
        lazy_pool(),
        &sample_billing(),
        &external_oauth2(),
    )
    .await;
    let err = result.expect_err("missing TLS cert paths must surface as an error");
    assert!(
        !format!("{err}").to_lowercase().contains("redis"),
        "authz-opa must never fail for a redis-shaped reason: got {err}"
    );
}

/// `oauth2.type: self` with a missing `signing` block must fail before ever touching the
/// database (the `ok_or_else` short-circuits ahead of `bootstrap_signing_key`), so this stays
/// fully offline like the tests above.
#[tokio::test]
async fn start_api_server_rejects_self_signed_oauth2_without_signing_block() {
    let mut oauth2 = external_oauth2();
    oauth2.oauth2_type = Oauth2Type::SelfSigned;
    let api = ApiServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        allowed_hosts: None,
        rpc_base_path: None,
    };
    let result = lightbridge_authz_rest::start_api_server(
        &api,
        lazy_pool(),
        &oauth2,
        &sample_billing(),
        &sample_quota_tiers(),
        &sample_models(),
        &sample_api_key_expiry(),
        &sample_redis(),
        &None,
    )
    .await;
    assert!(
        result.is_err(),
        "self-signed oauth2 without a signing block must be rejected"
    );
}

/// Exercises the `AUTHZ_DEV_CORS` branch of `start_api_server`. The env var is process-global, so
/// this test owns it for its short, synchronous-looking critical section and restores it
/// afterwards; no other test in this crate reads `AUTHZ_DEV_CORS`, mirroring the pattern already
/// used for it in `lightbridge-authz-core`'s `server_tests.rs`.
#[tokio::test]
async fn start_api_server_warns_when_dev_cors_is_enabled() {
    unsafe {
        std::env::set_var("AUTHZ_DEV_CORS", "true");
    }
    let api = ApiServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        allowed_hosts: None,
        rpc_base_path: None,
    };
    let result = lightbridge_authz_rest::start_api_server(
        &api,
        lazy_pool(),
        &external_oauth2(),
        &sample_billing(),
        &sample_quota_tiers(),
        &sample_models(),
        &sample_api_key_expiry(),
        &sample_redis(),
        &None,
    )
    .await;
    unsafe {
        std::env::remove_var("AUTHZ_DEV_CORS");
    }
    assert!(
        result.is_err(),
        "missing TLS cert paths must surface as an error"
    );
}

#[cfg(feature = "it-tests")]
mod db {
    use super::*;
    use cratestack::SqlxIdempotencyStore;
    use cratestack::ratelimit::RateLimitStore;
    use lightbridge_authz_api::schema;
    use lightbridge_authz_api_key::repo::StoreRepo;
    use lightbridge_authz_bearer::BearerTokenServiceTrait;
    use lightbridge_authz_core::config::{
        BudgetInternalServer, BudgetServer, JwtSigning, Oauth2Issuance,
    };
    use lightbridge_authz_core::cuid::cuid2;
    use lightbridge_authz_core::{CreateAccount, CreateApiKey, CreateProject};
    use lightbridge_authz_rest::OpaRepoTrait;
    use lightbridge_authz_rest::handlers::AuthzStoreImpl;
    use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
    use sqlx::PgPool;

    /// Unreachable but syntactically valid -- AGENTS.md's "Redis is a mandatory dependency" house
    /// rule enforces presence, not startup-time reachability (no `PING`): every constructor a
    /// well-formed `redis.url` reaches here (`RedisRateLimitStore::open`) is lazy and never dials
    /// out at construction time, so this never actually connects.
    fn unreachable_redis() -> Option<Redis> {
        Some(Redis {
            url: "redis://127.0.0.1:1".to_string(),
            ca_bundle_path: None,
        })
    }

    /// `external_oauth2()` (top-level, shared by every offline test in this file) deliberately
    /// leaves `issuance`/`oauth2_url` unset -- fine for tests that only assert `result.is_err()`,
    /// but `AuthzStoreImpl::with_pool_and_oauth2` validates both eagerly, ahead of the
    /// mandatory-redis check this module's redis-specific tests need to actually reach. This adds
    /// the minimum valid `external` config to get past that validation.
    fn external_oauth2_with_issuance() -> Oauth2 {
        let mut oauth2 = external_oauth2();
        oauth2.oauth2_url = Some("http://keycloak.example.test/token".to_string());
        oauth2.issuance = Some(Oauth2Issuance {
            grant_type: None,
            client_id: "lightbridge-token-issuer".to_string(),
            client_secret: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            scope: None,
        });
        oauth2
    }

    fn repo(pool: PgPool) -> Arc<StoreRepo> {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        Arc::new(StoreRepo::new(pool))
    }

    /// The cratestack CRUD client / idempotency store / rate-limit store are built on their own
    /// (cratestack sqlx) pools pointed at an unreachable address. `build_api_router` only *stores*
    /// them behind the RPC router's idempotency/rate-limit layers — the `/healthz/*` probes this
    /// module drives live on the un-wrapped public router, so these lazily-connected handles are
    /// never actually queried. This keeps the readiness test hermetic to the real `sqlx::test`
    /// database (the readiness pool) without needing a second live DB for the cratestack surface.
    fn lazy_cratestack_db() -> schema::Cratestack {
        let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy cratestack pool should be constructible");
        schema::Cratestack::builder(pool).build()
    }

    fn lazy_idempotency_store() -> Arc<SqlxIdempotencyStore> {
        let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
            // Bounded so a deliberately-dead pool fails fast: sqlx's default
            // `acquire_timeout` is 30s, and every test that touches one paid it in full.
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy cratestack pool should be constructible");
        Arc::new(SqlxIdempotencyStore::new(pool))
    }

    fn lazy_rate_limit_store() -> Arc<dyn RateLimitStore> {
        build_redis_rate_limit_store("redis://127.0.0.1:6379", None, "authz-api-test")
            .expect("well-formed redis url constructs a store without connecting")
    }

    fn signing_cfg() -> JwtSigning {
        JwtSigning {
            issuer: "https://authz.example.test".to_string(),
            audience: None,
            ttl_seconds: 7_776_000,
            max_key_age_days: 30,
            claim_mappers: Vec::new(),
        }
    }

    fn self_signed_oauth2() -> Oauth2 {
        let mut oauth2 = external_oauth2();
        oauth2.oauth2_type = Oauth2Type::SelfSigned;
        oauth2.signing = Some(signing_cfg());
        oauth2
    }

    /// Covers the `oauth2.is_self_signed()` branch inside `start_api_server`, which bootstraps
    /// the signing key against the real database before router assembly. The TLS cert paths are
    /// still bogus, so `serve_tls` fails fast right after bootstrap without binding a socket.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_api_server_bootstraps_signing_key_for_self_signed_oauth2(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
        let api = ApiServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            allowed_hosts: None,
            rpc_base_path: None,
        };
        let result = lightbridge_authz_rest::start_api_server(
            &api,
            db_pool,
            &self_signed_oauth2(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &sample_redis(),
            &None,
        )
        .await;
        assert!(
            result.is_err(),
            "missing TLS cert paths must surface as an error"
        );

        let repo = repo(pool);
        assert!(
            repo.get_active_signing_key().await.unwrap().is_some(),
            "start_api_server must bootstrap a signing key before failing on TLS load"
        );
    }

    /// AGENTS.md's "Redis is a mandatory dependency" house rule: `authz-api` must refuse to start
    /// with no `redis.url` configured. `external_oauth2_with_issuance()` skips the self-signed
    /// signing-key bootstrap branch, so the real database is only touched by `policy_store`'s
    /// active-revision load (which the `sqlx::test` migrations seed) before the redis check is
    /// reached.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_api_server_requires_redis(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let api = ApiServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            allowed_hosts: None,
            rpc_base_path: None,
        };
        let err = lightbridge_authz_rest::start_api_server(
            &api,
            db_pool,
            &external_oauth2_with_issuance(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &None,
            &None,
        )
        .await
        .expect_err("authz-api must refuse to start with no redis config");
        let message = format!("{err}");
        assert!(message.contains("authz-api"), "got: {message}");
        assert!(message.to_lowercase().contains("redis"), "got: {message}");
    }

    /// Presence-only enforcement (AGENTS.md's "Redis is a mandatory dependency" house rule): a
    /// syntactically valid but unreachable `redis.url` must NOT be rejected by the mandatory-redis
    /// check -- it must proceed and fail only for the deliberately-bogus TLS cert path.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_api_server_does_not_require_redis_to_be_reachable(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let api = ApiServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            allowed_hosts: None,
            rpc_base_path: None,
        };
        let result = lightbridge_authz_rest::start_api_server(
            &api,
            db_pool,
            &external_oauth2_with_issuance(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &unreachable_redis(),
            &None,
        )
        .await;
        let err = result.expect_err("missing TLS cert paths must surface as an error");
        assert!(
            !format!("{err}").to_lowercase().contains("redis"),
            "an unreachable-but-well-formed redis.url must not fail the mandatory-redis check: \
             got {err}"
        );
    }

    fn budget_server() -> BudgetServer {
        BudgetServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            snapshot_refresh_seconds: 15,
            snapshot_active_window_minutes: 1440,
            snapshot_slow_lane_minutes: 10,
            snapshot_seed_lookback_days: 30,
            snapshot_batch: 500,
            snapshot_concurrency: 8,
        }
    }

    /// AGENTS.md's "Redis is a mandatory dependency" house rule: `authz-budget` must refuse to
    /// start with no `redis.url` configured -- mirrors `start_api_server_requires_redis` above.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_budget_server_requires_redis(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let err = lightbridge_authz_rest::start_budget_server(
            &budget_server(),
            None,
            db_pool,
            &external_oauth2_with_issuance(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &None,
            &None,
        )
        .await
        .expect_err("authz-budget must refuse to start with no redis config");
        let message = format!("{err}");
        assert!(message.contains("authz-budget"), "got: {message}");
        assert!(message.to_lowercase().contains("redis"), "got: {message}");
    }

    /// Presence-only enforcement, mirroring
    /// `start_api_server_does_not_require_redis_to_be_reachable` above.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_budget_server_does_not_require_redis_to_be_reachable(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let result = lightbridge_authz_rest::start_budget_server(
            &budget_server(),
            None,
            db_pool,
            &external_oauth2_with_issuance(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &unreachable_redis(),
            &None,
        )
        .await;
        let err = result.expect_err("missing TLS cert paths must surface as an error");
        assert!(
            !format!("{err}").to_lowercase().contains("redis"),
            "an unreachable-but-well-formed redis.url must not fail the mandatory-redis check: \
             got {err}"
        );
    }

    /// ADR-0034 + its 2026-09-03 amendment: `server.budget_internal` is optional, but a configured
    /// internal listener with an EMPTY `shared_secret` is a hard startup failure, never a listener
    /// served with no credential at all. `GET /budget/v1/remaining` answers a cross-account
    /// balance question with no per-caller ownership check of any kind; the shared secret is the
    /// only thing in front of it, and forgetting it must be loud rather than silently permissive.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_budget_server_refuses_an_internal_listener_without_a_shared_secret(
        pool: PgPool,
    ) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let internal = BudgetInternalServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            shared_secret: "   ".to_string(),
            shared_secret_header: "x-lightbridge-budget-token".to_string(),
            remaining_grace_seconds: 120,
        };

        let err = lightbridge_authz_rest::start_budget_server(
            &budget_server(),
            Some(&internal),
            db_pool,
            &external_oauth2_with_issuance(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &unreachable_redis(),
            &None,
        )
        .await
        .expect_err("a budget_internal listener without a shared secret must not start");

        let message = format!("{err}");
        assert!(
            message.contains("shared_secret"),
            "the error must name the missing credential: got {message}"
        );
        assert!(
            message.contains("/budget/v1/remaining"),
            "the error must name the route it protects: got {message}"
        );
    }

    /// The other half of the amendment, and the one that would otherwise be discovered in
    /// production: a client-CA bundle here is not a *stricter* configuration, it is a broken one.
    /// Authorino v0.24.0's `metadata.http` cannot present a client certificate, so requiring one
    /// makes the route unreachable by its only caller — every metadata fetch fails the handshake
    /// and the gateway reads `budget_unavailable` on every request. Refuse at startup instead.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_budget_server_refuses_an_internal_listener_that_demands_a_client_certificate(
        pool: PgPool,
    ) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut tls = bad_tls();
        tls.client_ca_bundle_path = Some("/etc/lightbridge/tls/ca.crt".to_string());
        let internal = BudgetInternalServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls,
            shared_secret: "a-real-secret".to_string(),
            shared_secret_header: "x-lightbridge-budget-token".to_string(),
            remaining_grace_seconds: 120,
        };

        let err = lightbridge_authz_rest::start_budget_server(
            &budget_server(),
            Some(&internal),
            db_pool,
            &external_oauth2_with_issuance(),
            &sample_billing(),
            &sample_quota_tiers(),
            &sample_models(),
            &sample_api_key_expiry(),
            &unreachable_redis(),
            &None,
        )
        .await
        .expect_err("a budget_internal listener demanding mTLS must not start");

        let message = format!("{err}");
        assert!(
            message.contains("client_ca_bundle_path"),
            "the error must name the offending key: got {message}"
        );
        assert!(
            message.contains("Authorino"),
            "the error must say WHY it is refused: got {message}"
        );
    }

    /// Drives the settled `build_api_router` (the RPC surface replaced the old REST mount).
    /// The cratestack CRUD client / idempotency store / rate-limit store are lazily-connected to an
    /// unreachable address and never touched — the `/healthz/ready` probe sits on the un-wrapped
    /// public router and only consults `readiness_pool`, the real `sqlx::test` database.
    #[sqlx::test(migrations = "../../migrations")]
    async fn readiness_route_reports_ok_with_a_reachable_database(pool: PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use lightbridge_authz_bearer::TokenInfo;
        use lightbridge_authz_core::async_trait;
        use tower::ServiceExt;

        struct NoopBearer;
        #[async_trait]
        impl BearerTokenServiceTrait for NoopBearer {
            async fn validate_bearer_token(&self, _token: &str) -> anyhow::Result<TokenInfo> {
                unreachable!("readiness probe never validates a bearer token")
            }
        }

        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(NoopBearer);
        let issuer = Arc::new(AuthzStoreImpl::with_pool(db_pool.clone()));
        // The migration this test's `sqlx::test` runs seeds an active `budget-refill` revision,
        // so a real `load_active_from_db` (not the offline `from_engine` helper) works here.
        let policy_store = Arc::new(
            lightbridge_authz_budget::PolicyStore::load_active_from_db(
                db_pool.clone(),
                "budget-refill",
                10_000,
            )
            .await
            .expect("migration seeds an active budget-refill revision"),
        );
        // This test never reaches a budget-refill procedure (only `/healthz/ready`), so a real
        // `budget_repo`/`augmentation_repo` against the same live `db_pool` plus the offline
        // `UnavailableSpendReader` is enough to construct `Procedures` -- mirroring how
        // `policy_store` above is real but never evaluated by this test either.
        let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
            db_pool.clone(),
        ));
        let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
            db_pool.clone(),
        ));
        let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
            budget_repo.clone(),
            augmentation_repo.clone(),
            policy_store.engine(),
            Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
        ));
        let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
            budget_repo.clone(),
            augmentation_repo,
        ));
        let reset_scheduler = Arc::new(lightbridge_authz_budget::ResetScheduler::new(
            db_pool.clone(),
            budget_repo.clone(),
            Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
        ));
        let router = lightbridge_authz_rest::build_api_router(
            bearer,
            test_resolver(),
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
            reset_scheduler,
            std::sync::Arc::new(lightbridge_authz_core::platform_role::known_platform_roles(
                &lightbridge_authz_core::authz::Rbac::default(),
            )),
            lazy_cratestack_db(),
            db_pool.clone(),
            lazy_idempotency_store(),
            lazy_rate_limit_store(),
            false,
            None,
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// `OpaRepoTrait for StoreRepo` is a thin one-line delegation per method, only reachable
    /// through `start_opa_server`'s production wiring (the test suite otherwise talks to a
    /// `MockOpaRepo`). Exercise the real delegation against the database directly, seeding the
    /// account + api-key through the surviving `AuthzStoreImpl` procedures and the project directly
    /// through the hand-written `StoreRepo::create_project` (project CRUD left `AuthzStoreImpl` in
    /// the cratestack migration), then re-reading it all through the `OpaRepoTrait` object built on
    /// the same pool.
    #[sqlx::test(migrations = "../../migrations")]
    async fn opa_repo_trait_impl_delegates_to_store_repo(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
        let store = AuthzStoreImpl::with_pool(db_pool).with_billing(sample_billing());
        let seed = repo(pool.clone());
        let subject = "owner-opa-trait";

        let account = store
            .create_account(
                subject,
                CreateAccount {
                    default_quota: None,
                    name: None,
                },
            )
            .await
            .unwrap();
        let project = seed
            .create_project(
                &lightbridge_authz_core::identity::AccountId::assert_already_resolved(subject),
                &account.id,
                CreateProject {
                    name: "opa-trait-project".to_string(),
                    allowed_models: None,
                    default_limits: None,
                    billing_plan: "free".to_string(),
                    billing_identity: format!("bill-{}", cuid2()),
                    project_quota: None,
                },
                cuid2(),
            )
            .await
            .unwrap();
        let created = store
            .create_api_key(
                subject,
                None,
                &project.id,
                CreateApiKey {
                    name: "opa-trait-key".to_string(),
                    // `expires_at` is mandatory as of lightbridge-authz#395 --
                    // `AuthzStoreImpl::create_api_key` now rejects `None` outright.
                    expires_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
                    billing_plan: "free".to_string(),
                },
            )
            .await
            .unwrap();
        let api_key = created.api_key;

        let trait_object: Arc<dyn OpaRepoTrait> = repo(pool);

        let updated = trait_object
            .record_api_key_usage(&api_key.id, Some("127.0.0.1".to_string()))
            .await
            .unwrap();
        assert_eq!(updated.id, api_key.id);
        assert_eq!(updated.last_ip.as_deref(), Some("127.0.0.1"));

        let validation = trait_object
            .find_api_key_validation_by_hash(&api_key.key_hash)
            .await
            .unwrap()
            .expect("validation row should exist");
        assert_eq!(validation.api_key_id, api_key.id);

        let fetched_project = trait_object
            .get_project(subject, &project.id)
            .await
            .unwrap()
            .expect("project should exist for owning subject");
        assert_eq!(fetched_project.id, project.id);

        let fetched_account = trait_object
            .get_account(subject, &account.id)
            .await
            .unwrap()
            .expect("account should exist for owning subject");
        assert_eq!(fetched_account.id, account.id);

        let project_by_id = trait_object
            .get_project_by_id(&project.id)
            .await
            .unwrap()
            .expect("project should be found by id");
        assert_eq!(project_by_id.id, project.id);

        let account_by_id = trait_object
            .get_account_by_id(&account.id)
            .await
            .unwrap()
            .expect("account should be found by id");
        assert_eq!(account_by_id.id, account.id);

        let resolved = trait_object
            .resolve_context(subject, &project.id)
            .await
            .unwrap();
        assert_eq!(resolved.account_id, account.id);
        assert_eq!(resolved.project_id, project.id);
    }
}
