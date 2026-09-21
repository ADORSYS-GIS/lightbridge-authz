//! LoC rationale: `build_api_router` and `start_api_server` form the single API server routing & startup entrypoint.

use std::sync::Arc;

use axum::Router;
use cratestack::{
    DEFAULT_BODY_LIMIT_BYTES, SqlxIdempotencyStore,
    idempotency::IdempotencyLayer,
    ratelimit::{RateLimitConfig, RateLimitLayer, RateLimitStore},
};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::{
    config::{
        ApiKeyExpiry, ApiServer, Billing, ModelCatalog, Oauth2, QuotaTiers, Redis,
        UsageServiceClient,
    },
    db::DbPoolTrait,
    error::{Error, Result},
    platform_role::known_platform_roles,
    server::{dev_cors_enabled, serve_tls},
};
use tower_http::cors::CorsLayer;

use crate::{
    IDEMPOTENCY_TTL, RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SECOND, RATE_LIMIT_STORE_ERROR_POLICY,
    SERVICE_API,
    auth_provider::{CratestackAuthProvider, FederatedSubjectResolver, SubjectResolver},
    budget_services,
    codec::LenientCborCodec,
    handlers::AuthzStoreImpl,
    probe_router,
    procedures::Procedures,
    ratelimit_redis::build_redis_rate_limit_store,
    rpc_authorize::{RpcAuthorizeState, RpcScope, rpc_authorize},
    server_idp::{build_bearer_service, require_federation},
    signing,
};

/// Assembles the API server router: public probes plus the generated cratestack RPC CRUD surface
/// (`POST /rpc/{op_id}`, `POST /rpc/batch`) wrapped in idempotency + rate-limit middleware.
/// Separated from `start_api_server` so the composition can be built without binding a TLS socket.
/// `dev_cors` (driven by `AUTHZ_DEV_CORS`) layers a wide-open CORS policy over the whole router —
/// never enable it in production. `cratestack_db` and `idempotency_store` are built on cratestack's
/// own sqlx pool (see `start_api_server`); the RPC surface replaces the old REST `/api/v1` CRUD
/// mount entirely (ADR-0003, "RPC transport, not REST"), and its OpenAPI/Swagger UI is
/// intentionally gone (ADR-0003, "Loss of Swagger UI").
///
/// **No longer serves OIDC discovery/JWKS or native token-exchange.** Those routes moved
/// exclusively to `authz-idp` (`build_idp_router`) once the `auth.ai.camer.digital` ingress was
/// repointed there — see that function's doc comment. A request to `/.well-known/*` or
/// `/oauth2/{token,revoke}` here now falls through to the RPC router's own fallback, which
/// `rpc_authorize` fail-closes to `403` for an unmatched path (this router never served a literal
/// axum `404` for any path, mounted or not).
#[allow(clippy::too_many_arguments)]
pub fn build_api_router(
    bearer: Arc<dyn BearerTokenServiceTrait>,
    resolver: Arc<dyn SubjectResolver>,
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    refill_service: Arc<lightbridge_authz_budget::RefillService>,
    review_service: Arc<lightbridge_authz_budget::ReviewService>,
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    reset_scheduler: Arc<lightbridge_authz_budget::ResetScheduler>,
    // ADR-0033: the configured platform-role catalogue `grantPlatformRole` validates against.
    // Build it with `lightbridge_authz_core::platform_role::known_platform_roles`.
    rbac_roles: Arc<Vec<String>>,
    cratestack_db: schema::Cratestack,
    readiness_pool: Arc<dyn DbPoolTrait>,
    idempotency_store: Arc<SqlxIdempotencyStore>,
    rate_limit_store: Arc<dyn RateLimitStore>,
    dev_cors: bool,
    rpc_base_path: Option<&str>,
) -> Router {
    let public = probe_router(readiness_pool, SERVICE_API);

    // Generated RPC CRUD surface. Codec: CBOR is the ONLY wire format this router serves — no JSON
    // fallback (ADR-0013, "CBOR is the only transport codec", reversing ADR-0003's "CBOR in
    // production, JSON in dev/CI" split; a config-selected/environment-split codec is exactly the
    // "tested path != shipped path" gap that produced two prod-only bugs invisible to a green CI).
    // `LenientCborCodec`, not the raw `cratestack_codec_cbor::CborCodec` — see `codec.rs` for why
    // (CBOR clients that encode JS `undefined` as wire-level `undefined` instead of omitting the
    // key, e.g. `cborg`). A single `CratestackCodec` implementor satisfies `rpc_router`'s transport bound
    // directly via cratestack-axum's blanket `impl<C: CratestackCodec> HttpTransport for C` — no
    // `CodecSet` wrapper needed once there is only one codec to serve.
    // The coarse RBAC gate (docs/rbac.md) that cratestack's membership `@@allow` policies do not
    // express. Applied as the OUTERMOST layer so an unauthorized caller is rejected with 403 before
    // consuming idempotency/rate-limit budget or reaching cratestack's dispatch; the membership
    // policy then runs as the second gate inside dispatch. The bearer service is validated here and
    // again by the RPC `AuthProvider` — cheap given the shared JWKS cache — keeping this a pure,
    // additive gate that shares no state with the provider.
    let rpc = schema::axum::rpc_router(
        cratestack_db,
        Procedures::new(
            SERVICE_API,
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
            reset_scheduler,
            rbac_roles,
        ),
        // cratestack 0.8.11 (@computed) added this parameter to every generated router fn.
        // `authz.cstack` declares no `@computed` field, so `()` (the generated
        // `impl ComputedFieldResolver for ()`) is the correct, zero-behavior-change value here.
        (),
        LenientCborCodec::default(),
        CratestackAuthProvider::new(bearer.clone(), RpcScope::Crud, resolver),
        // cratestack 0.7.12 (#413) made this request-body-size bound an explicit parameter instead
        // of an axum implementation detail. `DEFAULT_BODY_LIMIT_BYTES` (2 MiB) is the value the
        // changelog documents as reproducing the pre-0.7.12 runtime behavior exactly — this call
        // site accepted no larger body before this bump either, since axum's own `Bytes` extractor
        // already refused anything over 2 MiB with no layer required.
        DEFAULT_BODY_LIMIT_BYTES,
    )
    .layer(IdempotencyLayer::new(idempotency_store, IDEMPOTENCY_TTL))
    .layer(
        RateLimitLayer::new(
            rate_limit_store,
            RateLimitConfig::new(RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SECOND),
        )
        // Opt out of cratestack 0.11.0's fail-open default -- see `RATE_LIMIT_STORE_ERROR_POLICY`.
        .with_store_error_policy(RATE_LIMIT_STORE_ERROR_POLICY),
    )
    .layer(axum::middleware::from_fn_with_state(
        RpcAuthorizeState {
            bearer,
            scope: RpcScope::Crud,
        },
        rpc_authorize,
    ));

    // Mount the RPC surface at the configured base path (default: root, i.e. `/rpc/<op_id>`). axum's
    // `nest` strips the prefix before the inner router runs, so the gate, idempotency/rate-limit
    // layers, and cratestack's dispatch all still see the canonical `/rpc/<op_id>` the client signs
    // byte-for-byte — only the externally-visible path gains the prefix. `op_id_from_path` is also
    // prefix-agnostic as a second line of defense.
    let router = match normalize_rpc_base_path(rpc_base_path) {
        Some(base) => public.nest(&base, rpc),
        None => public.merge(rpc),
    };
    if dev_cors {
        router.layer(CorsLayer::permissive())
    } else {
        router
    }
}

/// Normalize a configured RPC base path into an axum-`nest`-safe prefix, or `None` for the historical
/// root mount. Ensures a single leading slash and strips a trailing slash; treats `None`, empty, or
/// `/` as unset. axum's `nest` panics on an empty path or a trailing slash, so this guards both.
pub(crate) fn normalize_rpc_base_path(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "startup wiring for authz-api -- each parameter is a distinct, independently-loaded \
              config section (billing/quota_tiers/models catalogues, redis, usage_service); \
              bundling them into a struct would just move the same count into a constructor call \
              at the one caller (main.rs) without reducing anything"
)]
pub async fn start_api_server(
    api: &ApiServer,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
    billing: &Billing,
    quota_tiers: &QuotaTiers,
    models: &ModelCatalog,
    api_key_expiry: &ApiKeyExpiry,
    redis: &Option<Redis>,
    usage_service: &Option<UsageServiceClient>,
) -> Result<()> {
    billing.validate()?;
    api_key_expiry.validate()?;
    oauth2.rbac.validate()?;
    let federation = require_federation(oauth2, "authz-api")?;

    // ADR-0007 / ADR-0032, one shared builder (`budget_services`) rather than a copy per server:
    // `authz-api`, `authz-budget` and `lightbridge-mcp` all need the identical graph, including
    // the fail-closed spend-reader degrade. `authz-api` holds an inert `reset_scheduler` -- only
    // `start_budget_server` spawns the interval task that drives it, and `RpcScope::Crud` refuses
    // every `budget:*` op-id here before dispatch.
    let budget_services::BudgetServices {
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        reset_scheduler,
        // ADR-0034's remaining reader is assembled and mounted only by `start_budget_server`, on
        // its own internal listener; §15's snapshot refresher runs only there too. `authz-api`
        // shares the graph and drops both handles.
        spend_reader: _,
        snapshots: _,
    } = budget_services::build_budget_services(pool.clone(), usage_service).await?;

    let readiness_pool = pool.clone();
    // Bootstraps (or observes) the active self-signed-JWT signing key so `AuthzStoreImpl`'s own
    // `ApiKeyJwtSigner` (constructed just below, via `with_pool_and_oauth2`) can mint API-key JWTs
    // immediately -- unrelated to OIDC discovery/JWKS, which `authz-api` no longer serves at all
    // (that surface lives exclusively on `authz-idp` now; see `build_api_router`'s doc comment).
    if oauth2.is_self_signed() {
        let signing = oauth2.signing.as_ref().ok_or_else(|| {
            Error::Server("oauth2.type is 'self' but oauth2.signing is missing".to_string())
        })?;
        let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
        signing::bootstrap_signing_key(&signing_repo, signing).await?;
    }
    // Secret-issuance + membership operations reused by the RPC procedures (hand-written sqlx on the
    // core `DbPool`, sqlx 0.9).
    let issuer = Arc::new(AuthzStoreImpl::with_pool_and_oauth2(
        pool.clone(),
        oauth2,
        billing,
        quota_tiers,
        models,
        api_key_expiry,
    )?);
    let bearer_service = build_bearer_service(oauth2)?;
    // ADR-0025 Stage 2: `federation` above is already `require_federation`'s validated value.
    let resolver: Arc<dyn SubjectResolver> = Arc::new(FederatedSubjectResolver::new(
        Arc::new(StoreRepo::new(pool.clone())),
        oauth2.signing.as_ref().map(|s| s.issuer.clone()),
        federation.issuer.clone(),
    ));

    // Redis is required unconditionally for authz-api rate limiting.
    let redis = redis.as_ref().ok_or_else(|| {
        Error::Server(
            "redis config is required for authz-api rate limiting (set `redis.url`)".to_string(),
        )
    })?;

    // cratestack runs on its own sqlx major (0.8, vs this workspace's 0.9), so its CRUD client and
    // Postgres-backed idempotency store need a separate pool built with cratestack's sqlx. Both talk
    // to the same database as the core `DbPool`; the URL comes from `DATABASE_URL` (the same env the
    // schema's `datasource ... env("DATABASE_URL")` reads).
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        Error::Server(
            "DATABASE_URL must be set for the cratestack CRUD pool (authz-api RPC surface)"
                .to_string(),
        )
    })?;
    let cratestack_pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .connect(&database_url)
        .await
        .map_err(|e| Error::Server(format!("failed to open cratestack Postgres pool: {e}")))?;
    let cratestack_db = schema::Cratestack::builder(cratestack_pool.clone()).build();

    // Idempotency store (Postgres-backed, cratestack sqlx). Its table is created by
    // `migrations/20260904000002_cratestack_bootstrap_tables.sql`, NOT by `ensure_schema()` here:
    // that call issued `CREATE TABLE IF NOT EXISTS`, which is not atomic across sessions, so two
    // replicas starting together against a fresh database could fail to start on a `23505` against
    // `pg_type_typname_nsp_index` (#684). One owner, and it is the migration.
    let idempotency_store = Arc::new(SqlxIdempotencyStore::new(cratestack_pool.clone()));

    // Redis-backed rate-limit store for multi-replica correctness (ADR-0003, "Rate limiting
    // (Redis-backed)"). `redis::Client::open` is lazy, so this does not block on a live Redis here.
    // The URL comes from the already-loaded `Config.redis.url` (YAML `redis: url:`, itself
    // populated from `REDIS_URL` via env interpolation — see `config/default.yaml`), not a
    // separately-read raw env var, mirroring how every other config value reaches this function.
    let rate_limit_store =
        build_redis_rate_limit_store(&redis.url, redis.ca_bundle_path.as_deref(), "authz-api")?;

    let dev_cors = dev_cors_enabled();
    let app = build_api_router(
        bearer_service,
        resolver,
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        reset_scheduler,
        Arc::new(known_platform_roles(&oauth2.rbac)),
        cratestack_db,
        readiness_pool,
        idempotency_store,
        rate_limit_store,
        dev_cors,
        api.rpc_base_path.as_deref(),
    );

    if dev_cors {
        tracing::warn!("AUTHZ_DEV_CORS is set — API server allows any CORS origin (dev only)");
    }
    let signing_enabled = oauth2.is_self_signed();
    let issuance_enabled = oauth2.is_external();
    lightbridge_authz_core::log_build_info(SERVICE_API);
    tracing::info!(
        server = SERVICE_API,
        address = %api.address,
        port = api.port,
        oauth2_type = ?oauth2.oauth2_type,
        signing_enabled,
        issuance_enabled,
        "starting api server"
    );

    serve_tls("API", &api.address, api.port, &api.tls, app).await
}
