//! LoC rationale: `build_budget_router` and `start_budget_server` form the budget-domain server router & startup entrypoint (including the internal listener and reset scheduler loop).

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
        ApiKeyExpiry, Billing, BudgetInternalServer, BudgetServer, ModelCatalog, Oauth2,
        QuotaTiers, Redis, UsageServiceClient,
    },
    db::DbPoolTrait,
    error::{Error, Result},
    platform_role::known_platform_roles,
    server::{dev_cors_enabled, serve_tls},
};
use tower_http::cors::CorsLayer;

use crate::{
    IDEMPOTENCY_TTL, RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SECOND, RATE_LIMIT_STORE_ERROR_POLICY,
    RESET_SCHEDULER_TICK_INTERVAL, SERVICE_BUDGET, SERVICE_BUDGET_INTERNAL,
    auth_provider::{CratestackAuthProvider, FederatedSubjectResolver, SubjectResolver},
    budget_remaining::{self, BUDGET_REMAINING_PATH},
    budget_remaining_auth, budget_services, budget_snapshot_refresher,
    codec::LenientCborCodec,
    handlers::AuthzStoreImpl,
    probe_router,
    procedures::Procedures,
    ratelimit_redis::build_redis_rate_limit_store,
    rpc_authorize::{RpcAuthorizeState, RpcScope, rpc_authorize},
    server_idp::{build_bearer_service, require_federation},
};

/// The fixed base path `authz-budget`'s RPC surface is nested under. Not configurable, unlike
/// `ApiServer.rpc_base_path` — the prefix is what makes this service reachable behind a shared
/// gateway origin alongside `authz-api` (see [`config::BudgetServer`]'s doc comment and
/// `docs/architecture/budget.md`), not an operator preference.
const BUDGET_RPC_BASE_PATH: &str = "/budget";

/// Assembles the `authz-budget` server router: public probes plus the exact `budget:*`-gated RPC
/// procedures `build_api_router` used to serve, now mounted under [`BUDGET_RPC_BASE_PATH`] and
/// reachable ONLY here — a hard cutover, same shape as `authz-api`'s own OIDC surface removal
/// (`build_api_router`'s doc comment): the old location stops serving the moved routes entirely,
/// no transitional dual-serving window. Both the outer `rpc_authorize` gate and the per-op
/// `CratestackAuthProvider` are constructed with
/// `RpcScope::Budget`, so every non-budget op-id — the whole CRUD surface included — 404s here,
/// exactly as every budget op-id now 404s on `build_api_router` (`RpcScope::Crud`). Separated from
/// `start_budget_server` for testability, mirroring `build_api_router`/`build_idp_router`.
///
/// Reuses the SAME `Procedures` type `build_api_router` does (ADR-0010: budget procedures are
/// hand-written, not cratestack-generated, but they still live inside the one
/// `schema::procedures::ProcedureRegistry` impl cratestack's single-schema-module-per-crate
/// constraint requires — see `docs/architecture/budget.md`, "Why one `Procedures` impl, not a
/// second schema/crate"). `issuer` is still required to construct it even though this router never
/// dispatches a CRUD op-id (`RpcScope::Budget` refuses them before dispatch) — `Procedures::new`
/// takes it unconditionally, and constructing an `AuthzStoreImpl` is cheap (no I/O; see its own
/// doc comment), so this is a type-level obligation, not a real dependency on the CRUD domain.
#[allow(clippy::too_many_arguments)]
pub fn build_budget_router(
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    refill_service: Arc<lightbridge_authz_budget::RefillService>,
    review_service: Arc<lightbridge_authz_budget::ReviewService>,
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    reset_scheduler: Arc<lightbridge_authz_budget::ResetScheduler>,
    // See `build_api_router`'s parameter of the same name. `authz-budget` serves none of the
    // `rbac:manage` op-ids (they are `crud`-scoped), but it builds the same `Procedures`.
    rbac_roles: Arc<Vec<String>>,
    cratestack_db: schema::Cratestack,
    readiness_pool: Arc<dyn DbPoolTrait>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    resolver: Arc<dyn SubjectResolver>,
    idempotency_store: Arc<SqlxIdempotencyStore>,
    rate_limit_store: Arc<dyn RateLimitStore>,
    dev_cors: bool,
) -> Router {
    let public = probe_router(readiness_pool, SERVICE_BUDGET);

    let rpc = schema::axum::rpc_router(
        cratestack_db,
        Procedures::new(
            SERVICE_BUDGET,
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
        CratestackAuthProvider::new(bearer.clone(), RpcScope::Budget, resolver),
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
            scope: RpcScope::Budget,
        },
        rpc_authorize,
    ));

    let router = public.nest(BUDGET_RPC_BASE_PATH, rpc);
    if dev_cors {
        router.layer(CorsLayer::permissive())
    } else {
        router
    }
}

/// Starts `authz-budget`: the budget-domain microservice carrying every `budget:*`-gated RPC
/// procedure off `authz-api` (hard cutover — see `build_budget_router`'s own doc comment,
/// `docs/architecture/budget.md`). Mirrors `start_api_server`'s budget-domain wiring
/// (`policy_store`/`budget_repo`/`refill_service`/`review_service`/spend-reader selection)
/// line-for-line intentionally — this server owns exactly that half of what `start_api_server`
/// used to build, nothing added, nothing dropped. What it deliberately does NOT carry:
/// `well_known_router`/token-exchange (an `authz-idp` concern, unrelated to budget), and signing-
/// key bootstrap (this server only ever validates bearer tokens via `oauth2.jwks_url`, never
/// issues or rotates one — `rotateApiKey`/`createApiKey` are CRUD op-ids, refused here by
/// `RpcScope::Budget` before they could reach `AuthzStoreImpl`'s signer).
#[expect(
    clippy::too_many_arguments,
    reason = "startup wiring for authz-budget, mirroring start_api_server's identical rationale \
              -- each parameter is a distinct, independently-loaded config section"
)]
pub async fn start_budget_server(
    budget: &BudgetServer,
    budget_internal: Option<&BudgetInternalServer>,
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
    let federation = require_federation(oauth2, "authz-budget")?;

    // The same shared `budget_services` graph `start_api_server` builds -- this server owns the
    // half of it that is actually reachable (`RpcScope::Budget`) and is the only one that spawns
    // the reset scheduler's interval task, below.
    let services = budget_services::build_budget_services(pool.clone(), usage_service).await?;
    // ADR-0034 §15, started HERE and only here: the loop that precomputes every active account's
    // remaining balance, so `authz-opa`'s introspection can answer the gateway's budget question
    // from one indexed read instead of a second metadata call.
    budget_snapshot_refresher::spawn_snapshot_refresher(&services, budget)?;
    let budget_services::BudgetServices {
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        reset_scheduler,
        spend_reader,
        snapshots,
    } = services;

    let readiness_pool = pool.clone();
    // Hand-written sqlx on the core `DbPool` (sqlx 0.9), same as `start_api_server` -- required to
    // construct `Procedures` (see `build_budget_router`'s doc comment for why this is a type-level
    // obligation, not a real CRUD dependency for this server).
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

    // Redis is required unconditionally for authz-budget rate limiting, mirroring authz-api's own
    // hard requirement (see `start_api_server`'s identical check).
    let redis = redis.as_ref().ok_or_else(|| {
        Error::Server(
            "redis config is required for authz-budget rate limiting (set `redis.url`)".to_string(),
        )
    })?;

    // cratestack runs on its own sqlx major (0.8, vs this workspace's 0.9), so its CRUD client and
    // Postgres-backed idempotency store need a separate pool built with cratestack's sqlx, exactly
    // like `start_api_server`'s identical pool.
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        Error::Server(
            "DATABASE_URL must be set for the cratestack CRUD pool (authz-budget RPC surface)"
                .to_string(),
        )
    })?;
    let cratestack_pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .connect(&database_url)
        .await
        .map_err(|e| Error::Server(format!("failed to open cratestack Postgres pool: {e}")))?;
    let cratestack_db = schema::Cratestack::builder(cratestack_pool.clone()).build();

    // Same as `start_api_server`: the table is migration-owned (#684), never bootstrapped here.
    let idempotency_store = Arc::new(SqlxIdempotencyStore::new(cratestack_pool.clone()));

    // Own key prefix ("authz-budget", not "authz-api") so the two services' token buckets never
    // share state, even though they may point at the same Redis instance.
    let rate_limit_store =
        build_redis_rate_limit_store(&redis.url, redis.ca_bundle_path.as_deref(), "authz-budget")?;

    // ADR-0032: the budget reset scheduler's own tick loop, started HERE and only here -- one
    // `tokio::interval` alongside the three existing listener tasks, on the process that owns the
    // budget domain. Running several `authz-budget` replicas is safe by construction: each tick
    // claims due rows with `FOR UPDATE SKIP LOCKED`, so a schedule another replica already holds
    // is skipped rather than fired twice.
    //
    // `spawn`ed, not awaited: a scheduler failure must never stop the RPC surface from serving. A
    // failing tick is logged and the next one retries 60 seconds later -- and because the tick's
    // claim transaction only commits the `next_run_at` advance on success, a failed window stays
    // due rather than being silently skipped.
    let scheduler_task = reset_scheduler.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RESET_SCHEDULER_TICK_INTERVAL);
        // `Delay`, not the default `Burst`: a tick that overruns 60 seconds (a global schedule
        // over a large estate) must not queue up a backlog of immediate catch-up ticks behind it.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match scheduler_task.tick(chrono::Utc::now()).await {
                Ok(report) if report.claimed_schedule_ids.is_empty() => {}
                Ok(report) => tracing::info!(
                    claimed = report.claimed_schedule_ids.len(),
                    grants_written = report.grants_written,
                    "budget reset scheduler tick"
                ),
                Err(err) => tracing::error!(
                    error = %err,
                    "budget reset scheduler tick failed; retrying on the next interval"
                ),
            }
        }
    });

    let dev_cors = dev_cors_enabled();
    // Cloned before `build_budget_router` consumes them: ADR-0034's reader must be the SAME repo
    // and the SAME scheduler the RPC surface serves from, not a second graph over the same pool.
    let budget_repo_for_remaining = budget_repo.clone();
    let reset_scheduler_for_remaining = reset_scheduler.clone();
    let app = build_budget_router(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        reset_scheduler,
        Arc::new(known_platform_roles(&oauth2.rbac)),
        cratestack_db,
        readiness_pool,
        bearer_service,
        resolver,
        idempotency_store,
        rate_limit_store,
        dev_cors,
    );

    if dev_cors {
        tracing::warn!("AUTHZ_DEV_CORS is set — budget server allows any CORS origin (dev only)");
    }
    lightbridge_authz_core::log_build_info(SERVICE_BUDGET);
    tracing::info!(
        server = SERVICE_BUDGET,
        address = %budget.address,
        port = budget.port,
        rpc_base_path = BUDGET_RPC_BASE_PATH,
        "starting budget server"
    );

    let rpc_listener = serve_tls("BUDGET", &budget.address, budget.port, &budget.tls, app);

    // ADR-0034: the mTLS-only internal listener, when configured. `tokio::try_join!` runs the two
    // concurrently rather than sequentially (the same shape `start_usage_server` uses for its own
    // two listeners) so neither listener's lifetime blocks the other's, and either one failing
    // fails this function.
    let Some(internal) = budget_internal else {
        tracing::info!(
            server = SERVICE_BUDGET_INTERNAL,
            "server.budget_internal is not configured; the gateway's budget-remaining read \
             ({BUDGET_REMAINING_PATH}) is not served by this process"
        );
        return rpc_listener.await;
    };

    // Fail-closed, and loudly (ADR-0034 §3.2) -- see `budget_remaining_auth`.
    let shared_secret_header =
        budget_remaining_auth::validate_budget_internal(internal, BUDGET_REMAINING_PATH)
            .map_err(Error::Server)?;

    // The grace window is this listener's own config, which is why `build_budget_services` hands
    // back the shared `spend_reader` rather than a pre-assembled reader: `authz-api` and
    // `lightbridge-mcp` share the graph but have no `budget_internal` block to read a grace from.
    let grace = chrono::Duration::seconds(
        i64::try_from(internal.remaining_grace_seconds).map_err(|_| {
            Error::Server(format!(
                "server.budget_internal.remaining_grace_seconds is out of range: {}",
                internal.remaining_grace_seconds
            ))
        })?,
    );
    let live_remaining = Arc::new(lightbridge_authz_budget::RemainingService::with_grace(
        budget_repo_for_remaining,
        spend_reader,
        reset_scheduler_for_remaining,
        grace,
    ));
    // ADR-0034 §15: snapshot first, live read as the fallback. The endpoint's 404/503 semantics
    // are unchanged — they still live in the inner reader, which this layer delegates to whenever
    // there is no usable stored reading (and whenever `?fresh=true` asks it to).
    let remaining_service = Arc::new(lightbridge_authz_budget::SnapshotRemainingService::new(
        snapshots,
        live_remaining,
    ));

    let internal_state = Arc::new(budget_remaining::BudgetInternalState {
        remaining: remaining_service,
        shared_secret: internal.shared_secret.clone(),
        shared_secret_header,
    });
    let internal_app = budget_remaining::budget_remaining_router(internal_state.clone())
        .with_state(internal_state);

    lightbridge_authz_core::log_build_info(SERVICE_BUDGET_INTERNAL);
    tracing::info!(
        server = SERVICE_BUDGET_INTERNAL,
        address = %internal.address,
        port = internal.port,
        path = BUDGET_REMAINING_PATH,
        grace_seconds = internal.remaining_grace_seconds,
        auth_header = %internal.shared_secret_header,
        "starting budget internal (shared-secret) server"
    );

    let internal_listener = serve_tls(
        "BUDGET_INTERNAL",
        &internal.address,
        internal.port,
        &internal.tls,
        internal_app,
    );

    tokio::try_join!(rpc_listener, internal_listener)?;
    Ok(())
}
