//! LoC rationale: `build_token_exchange_state`, `build_idp_router`, `start_idp_server`, and mandatory IdP configuration helpers form one unified OIDC server setup module.

use std::sync::Arc;

use axum::Router;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait};
use lightbridge_authz_core::{
    config::{Federation, IdpServer, JwtSigning, Oauth2, Redis},
    db::DbPoolTrait,
    error::{Error, Result},
    server::serve_tls,
};

use crate::{
    SERVICE_IDP, authorize,
    budget_services::{BUDGET_POLICY_EVALUATION_BUDGET, BUDGET_POLICY_SET_ID},
    claim_redeem, end_session, handlers, oauth2_client_validation, oauth2_op, probe_router,
    ratelimit_redis::build_redis_rate_limit_store,
    relying_party, secret_claim, session_management, signing, static_assets, token_exchange,
    userinfo,
};

/// Derives the token-surface `well_known_router` parameters from the successfully assembled
/// state, rather than configuration intent. Used by `build_idp_router` — `authz-idp` is now the
/// only server that mounts `well_known_router` at all; `authz-api` stopped serving OIDC
/// discovery/JWKS once the `auth.ai.camer.digital` ingress was repointed at `authz-idp` (see
/// `build_api_router`'s doc comment). `token_exchange` is unconditionally assembled by
/// `start_idp_server` (ADR-0023: `oauth2.token_exchange` is mandatory for `authz-idp`, no longer
/// optional), so this always reports the real scope/client-authentication metadata — there is no
/// "token exchange absent" case left to fall back from.
fn well_known_mount_params(
    oauth2: &Oauth2,
    token_exchange: &token_exchange::TokenExchangeState,
) -> (Option<Vec<String>>, signing::ClientAuthenticationMetadata) {
    (
        Some(token_exchange.op_config().scopes_supported.clone()),
        signing::ClientAuthenticationMetadata::from_oauth2(oauth2),
    )
}

/// Redis key prefix for the `private_key_jwt` replay-tracking store (ADR-0011, Decision 6).
/// Namespaced separately from `ratelimit_redis`'s bucket keys in the same Redis instance.
const CLIENT_ASSERTION_JTI_KEY_PREFIX: &str = "authz-api:client-assertion-jti:";

/// Builds the native token-exchange state. Enabled only when `token_exchange.enabled` is set, and
/// it REQUIRES `oauth2.type: self` (the exchanged access token is a self-signed JWT). Returns
/// `Ok(None)` when the feature is off; errors on invalid config so startup fails fast. This
/// function's `Result<Option<...>>` contract is unchanged by ADR-0023, and its own unit tests
/// still exercise the `None`/disabled path directly -- but its sole production caller,
/// `start_idp_server`, now treats a `None` result as fatal (`oauth2.token_exchange` is mandatory
/// for authz-idp), so `build_token_exchange_state` itself has exactly ONE production caller.
///
/// ADR-0011 phase 2: builds the config-defined `ClientStore` (Decision 5) and the Redis-backed
/// `ClientAssertionStore` (Decision 6) that together let `oauth2_op::store::TokenExchangeOpStore`
/// implement `authkestra_op::store::OpStore`.
///
/// `budget_repo` (ADR-0014) is a new dependency edge, not a new outbound service call: it reads
/// `budget_grants`/`budget_balances` off the SAME Postgres `pool` every other repository on this
/// server already uses (see the call site's own `budget_repo` construction), so this stays an
/// intra-database read, never a network hop to the separate `authz-budget` microservice.
///
/// `policy_engine` (ADR-0015 Decision 6) is the same kind of edge: the call site loads its own
/// `PolicyStore` off the shared `budget_policy_sets`/`budget_policy_revisions` tables, so
/// `TokenExchangeOpStore::resolve_budget_tier`'s fail-closed fallback reads the live, admin-
/// configured `fail_closed_floor_micros` instead of a hard-coded rung.
///
/// `TokenExchangeOpStore::new` also takes `repo` twice more, as its own `quota_repo` (ADR-0017)
/// and `platform_repo` (ADR-0033) parameters: production always passes the same `Arc<StoreRepo>`
/// clone for all three, since `project_members` and `platform_role_grants` live on this exact
/// pool with no operational separation from tenant-context resolution -- the duplicate parameters
/// exist purely as independent test-injection seams, see `TokenExchangeOpStore`'s own field doc
/// comments for why.
pub fn build_token_exchange_state(
    oauth2: &Oauth2,
    repo: Arc<StoreRepo>,
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine>,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
    redis_url: &str,
    redis_ca_bundle_path: Option<&str>,
) -> Result<Option<token_exchange::TokenExchangeState>> {
    let Some(cfg) = oauth2.token_exchange.as_ref().filter(|t| t.enabled) else {
        return Ok(None);
    };
    if !oauth2.is_self_signed() {
        return Err(Error::Server(
            "oauth2.token_exchange is enabled but requires oauth2.type: self".to_string(),
        ));
    }
    let signing = oauth2.signing.as_ref().ok_or_else(|| {
        Error::Server("oauth2.token_exchange requires oauth2.signing (type: self)".to_string())
    })?;
    if cfg.access_ttl_seconds <= 0
        || cfg.authorization_code_ttl_seconds <= 0
        || cfg.refresh_ttl_seconds <= 0
    {
        return Err(Error::Server(
            "token_exchange access_ttl_seconds, authorization_code_ttl_seconds, and \
             refresh_ttl_seconds must be positive"
                .to_string(),
        ));
    }
    // Per-client refresh-TTL overrides (`OauthClient::refresh_ttl_seconds`/
    // `refresh_absolute_ttl_seconds`): refuses to start when any client's EFFECTIVE per-token TTL
    // is non-positive or exceeds its EFFECTIVE absolute chain cap -- see that module's doc
    // comment. Subsumes this function's own former inline global-only check.
    oauth2_op::refresh_ttl::validate_client_refresh_ttls(&oauth2.clients, cfg)?;
    if cfg.device_code_ttl_seconds <= 0 || cfg.device_poll_interval_seconds <= 0 {
        return Err(Error::Server(
            "token_exchange device_code_ttl_seconds and device_poll_interval_seconds must be positive"
                .to_string(),
        ));
    }
    if cfg.client_credentials_ttl_seconds <= 0 {
        return Err(Error::Server(
            "token_exchange client_credentials_ttl_seconds must be positive".to_string(),
        ));
    }
    let device_verification_uri =
        reqwest::Url::parse(&cfg.device_verification_uri).map_err(|_| {
            Error::Server(
                "token_exchange device_verification_uri must be an absolute URL".to_string(),
            )
        })?;
    if device_verification_uri.scheme() != "https"
        || device_verification_uri.path() != "/device/verify"
        || !device_verification_uri.username().is_empty()
        || device_verification_uri.password().is_some()
        || device_verification_uri.query().is_some()
        || device_verification_uri.fragment().is_some()
    {
        return Err(Error::Server(
            "token_exchange device_verification_uri must be a credential-free, query-free HTTPS /device/verify URL"
                .to_string(),
        ));
    }
    oauth2_client_validation::validate_authorization_code_clients(
        &oauth2.clients,
        signing.audience.as_deref(),
    )?;
    oauth2_client_validation::validate_client_credentials_and_service_clients(&oauth2.clients)?;
    let signer = signing::ApiKeyJwtSigner::from_config(signing, repo.clone())?;

    // ADR-0025 Stage 1/2: `start_idp_server` (this function's sole production caller) already
    // enforces `oauth2.federation` via `require_federation` before this function ever runs; this
    // check exists so a *test* fixture that forgets `federation` fails loudly here rather than
    // the store silently grandfathering against an empty issuer string.
    let grandfather_issuer = oauth2
        .federation
        .as_ref()
        .ok_or_else(|| {
            Error::Server(
                "oauth2.federation.issuer is required to build the token-exchange store \
                 (ADR-0025)"
                    .to_string(),
            )
        })?
        .issuer
        .clone();

    let client_store =
        oauth2_op::client_store::ConfigClientStore::from_config(&oauth2.clients, cfg);
    let assertions = oauth2_op::client_assertion_store::RedisClientAssertionStore::connect(
        redis_url,
        redis_ca_bundle_path,
        CLIENT_ASSERTION_JTI_KEY_PREFIX,
    )?;
    let op_store = Arc::new(oauth2_op::store::TokenExchangeOpStore::new(
        client_store,
        assertions,
        repo.clone(),
        repo.clone(),
        repo,
        budget_repo,
        policy_engine,
        bearer,
        // Declared in `oauth2.signing.claim_mappers`, evaluated at mint time against data this
        // deployment owns -- see `TokenExchangeOpStore::resolve_mapped_claims`.
        Arc::new(signing.claim_mappers.clone()),
        cfg.clone(),
        grandfather_issuer,
    ));
    let op_config = authkestra_op::config::OpConfig {
        issuer: signing.issuer.clone(),
        scopes_supported: cfg.allowed_scopes.clone(),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            token_exchange::TOKEN_EXCHANGE_GRANT.to_string(),
            token_exchange::REFRESH_TOKEN_GRANT.to_string(),
            token_exchange::DEVICE_CODE_GRANT.to_string(),
            token_exchange::CLIENT_CREDENTIALS_GRANT.to_string(),
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: cfg.authorization_code_ttl_seconds,
        access_token_ttl_secs: cfg.access_ttl_seconds.max(0) as u64,
        device_code_ttl_secs: cfg.device_code_ttl_seconds as u64,
        token_exchange_enabled: cfg.enabled,
    };
    let cors_origins = oauth2_client_validation::token_endpoint_cors_origins(&oauth2.clients)?;
    Ok(Some(
        token_exchange::TokenExchangeState::new(
            signer,
            op_config,
            op_store,
            cfg.device_verification_uri.clone(),
            cfg.device_code_ttl_seconds as u64,
            cfg.device_poll_interval_seconds as u64,
        )
        .with_cors_origins(cors_origins)
        .with_client_credentials_ttl_seconds(cfg.client_credentials_ttl_seconds),
    ))
}

/// ADR-0025 Stage 1: every serving component -- `authz-api`, `authz-idp`, `authz-opa`,
/// `authz-budget`, `lightbridge-mcp` -- refuses to start without `oauth2.federation.issuer`,
/// loudly, naming both the missing field and the component (the same shape AGENTS.md's "Redis is
/// a mandatory dependency" house rule documents for a different dependency). Presence PLUS
/// [`Federation::validate`]'s offline shape check -- never a live reachability probe against the
/// issuer, matching `oauth2.relying_party`'s own startup-validation posture.
pub fn require_federation<'a>(oauth2: &'a Oauth2, component: &str) -> Result<&'a Federation> {
    let federation = oauth2.federation.as_ref().ok_or_else(|| {
        Error::Server(format!(
            "oauth2.federation.issuer is required for {component} (ADR-0025) -- set the \
             oauth2.federation block naming the one issuer this deployment trusts for \
             remote-subject-to-account-id translation"
        ))
    })?;
    federation.validate()?;
    Ok(federation)
}

/// Shared by `start_api_server`/`start_idp_server`/`start_budget_server`. Fails when
/// `oauth2.jwks_ca_bundle_path` is unreadable/malformed (lightbridge-authz#625).
pub fn build_bearer_service(oauth2: &Oauth2) -> Result<Arc<dyn BearerTokenServiceTrait>> {
    let service = BearerTokenService::new(oauth2.clone())
        .map_err(|e| Error::Server(format!("failed to build bearer JWKS client: {e}")))?;
    Ok(Arc::new(service))
}

/// Assembles the `authz-idp` server router (ADR-0012): public probes plus the OIDC
/// discovery/JWKS/token-exchange surface, the only place this codebase still mounts it (see
/// "The only server that serves this surface" below). Separated from `start_idp_server` for
/// testability, mirroring `build_api_router`/`build_opa_router`.
///
/// **The only server that serves this surface.** ADR-0012 Phase 1 ran `authz-idp` alongside
/// `authz-api`'s own (now-removed) `well_known_router`/`token_exchange_router` merges as a
/// transitional duplication while the `auth.ai.camer.digital` ingress still routed
/// `/.well-known`, `/oauth2/token`, and `/oauth2/revoke` to `authz-api`. That ingress has since
/// been repointed at `authz-idp` and `authz-api`'s copy of this surface removed (see
/// `build_api_router`'s doc comment) — `authz-idp` is now the sole owner.
///
/// ## Static asset serving under `/ui` (ADR-0021 Decisions 1 + 10, #442, and the follow-up that
/// moved this from a root-level fallback to a path-scoped mount)
///
/// `static_dir` is mounted at `/ui`, via `.nest_service("/ui", ..)`, not as a root-level
/// `.fallback_service(..)`. Mounting it as a root fallback made `GET /` split-brained in
/// production: a real route always wins over a fallback, so `GET /` kept answering this server's
/// own API-welcome-JSON `root_handler` (from `probe_router`, merged above) while `GET /index.html`
/// or `GET /login` served the SPA — same build, two different personalities depending on the
/// exact path. Scoping the static build under `/ui` removes the ambiguity outright: `GET /` is
/// unconditionally the API route, `GET /ui` and `GET /ui/` are the SPA's `index.html`, and a path
/// outside `/ui` that matches no protocol route is a normal `404` — the SPA is no longer a
/// catch-all for the whole server. **Since lightbridge-authz#598, `/ui` is not a catch-all for its
/// own subtree either** — `GET /ui/<anything>` only serves `index.html` when `<anything>` is one
/// of the artifact's own `dist/routes.json` entries; every other `/ui/<anything>` is a plain `404`
/// too (`static_assets::load_route_manifest`'s own doc comment has the fail-closed reasoning).
/// This also makes the safety property strictly path-scoping rather than mount-order: static
/// assets and protocol routes now occupy disjoint path spaces, so they cannot collide regardless
/// of merge order, whereas the old fallback-based mount was safe only because a real route always
/// beats a fallback. See `static_assets::static_assets_fallback`'s own doc comment for the
/// caching/CSP posture applied to everything served from `static_dir`.
///
/// ## Every parameter here is a pre-validated product of `start_idp_server`'s checks
///
/// ADR-0023 reverses PR #473 (468084a) on purpose: `oauth2.relying_party` and
/// `oauth2.token_exchange` are no longer optional inputs this function branches on -- they are
/// mandatory for `authz-idp`, enforced once, up front, in `start_idp_server`, exactly the same
/// shape as the "Redis is a mandatory dependency" house rule in `AGENTS.md`. By the time this
/// function runs, `signing`, `token_exchange`, and `relying_party` are all known-good: `signing`
/// and `relying_party` come from `start_idp_server`'s own construction (`KeycloakRelyingParty::new`
/// validates its config offline -- no Keycloak discovery fetch at startup, the same
/// presence-PLUS-offline-validation posture, not presence-only, that AGENTS.md documents for this
/// exact field), and `token_exchange` is the `Some` arm of `build_token_exchange_state`'s result
/// (`start_idp_server` now treats `None` as fatal). So every flow route below -- well-known/JWKS,
/// `/authorize`, `/oauth2/token` + `/oauth2/revoke` + `/oauth2/device_authorization`,
/// `/device/verify`, `/idp/callback` -- is mounted unconditionally, and `DiscoveryCapabilities::
/// full_idp()` describes that unconditionally too. #473's OTHER half is kept and strengthened
/// here: `relying_party` was already threaded through as a pre-validated `Arc` instead of being
/// rebuilt inside this function; only the `Option` wrapper (and the mount-conditional branching it
/// enabled) is removed.
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is a distinct mandatory dependency of the IdP surface (ADR-0023 \
              mounts all routes unconditionally, so none can be folded away as optional); \
              bundling them into a struct would only move the same arity behind a constructor"
)]
pub fn build_idp_router(
    oauth2: &Oauth2,
    signing: &JwtSigning,
    signing_repo: Arc<StoreRepo>,
    token_exchange: token_exchange::TokenExchangeState,
    readiness_pool: Arc<dyn DbPoolTrait>,
    static_dir: impl AsRef<std::path::Path>,
    relying_party: Arc<relying_party::KeycloakRelyingParty>,
    claim_redeem: claim_redeem::ClaimRedeemState,
) -> Router {
    let mut router = probe_router(readiness_pool, SERVICE_IDP);
    let claim_redeem_repo = Arc::clone(&claim_redeem.repo);
    // GHSA-9pc6-965v-2c44: mounted unconditionally, like every other authz-idp route (ADR-0023).
    // A deployment where this 404s while lightbridge-mcp still issues claim URLs would hand users
    // links they cannot use -- the exact advertised-but-unmounted failure ADR-0023 exists to stop.
    router = router.merge(claim_redeem::router(claim_redeem));
    let (token_exchange_scopes, client_authentication) =
        well_known_mount_params(oauth2, &token_exchange);
    router = router.merge(signing::well_known_router(
        &signing.issuer,
        signing_repo,
        token_exchange_scopes,
        client_authentication,
        signing::DiscoveryCapabilities::full_idp(),
    ));
    router = router.merge(authorize::router(authorize::AuthorizeState::new(
        Arc::clone(&relying_party),
        token_exchange.clone(),
    )));
    router = router.merge(userinfo::router(token_exchange.clone()));
    // OIDC RP-Initiated Logout. Mounted unconditionally beside every other authz-idp route
    // (ADR-0023): discovery advertises it whenever `/authorize` is mounted, and the two must not
    // be able to disagree.
    router = router.merge(end_session::router(end_session::EndSessionState::new(
        Arc::clone(&claim_redeem_repo),
        token_exchange.clone(),
        &oauth2.clients,
        Arc::clone(&relying_party),
    )));
    router = router.merge(token_exchange::token_exchange_router(token_exchange));
    router = router.merge(session_management::router());
    router = router.merge(relying_party::router(relying_party));
    router.nest_service("/ui", static_assets::static_assets_fallback(static_dir))
}

/// Starts `authz-idp` (ADR-0012, ADR-0023): the OIDC broker service carrying `/oauth2/token`,
/// `/oauth2/revoke`, `/oauth2/device_authorization`, `.well-known/*`, `/authorize`,
/// `/device/verify`, and `/idp/callback`. Since ADR-0023 the full surface is unconditional — every
/// authz-idp deployment must supply `oauth2.relying_party` and an enabled
/// `oauth2.token_exchange`, or this function refuses to start. Deliberately thin next to
/// `start_api_server` — no RPC CRUD surface, no budget domain, no per-route
/// idempotency/rate-limit tower layers — because
/// `well_known_router`/`token_exchange_router` need none of that; every route this server mounts
/// is public (see [`config::IdpServer`]'s doc comment). The one exception: the Keycloak RP-leg's
/// public, unauthenticated `user_code` lookups (`relying_party::verify_submit`/`verify_continue`)
/// go through the SAME Redis-backed [`RateLimitStore`] `start_api_server`/`start_budget_server`
/// build for their tower `RateLimitLayer`, just consulted directly by
/// `device_store::get_by_user_code_rate_limited` rather than via a layer.
///
/// **The sole owner of this surface, not a duplicate.** ADR-0012 Phase 1 ran this alongside
/// `authz-api`'s own copy of the same routes while `auth.ai.camer.digital` still routed here via
/// `authz-api`. The ingress has since been repointed at `authz-idp` directly and `authz-api`'s
/// copy removed (`build_api_router` no longer mounts `well_known_router`/`token_exchange_router`
/// at all — see its doc comment), so `authz-idp` resolving `https://auth.ai.camer.digital` — a
/// live, trusted issuer in `security-policies.yaml` (every in-circulation API-key JWT carries it
/// as `iss`) — is now load-bearing on its own, not backed by a same-surface fallback on
/// `authz-api`.
///
/// ## Signing-key ownership decision (ADR-0012, "signing-key bootstrap")
///
/// `authz-idp` calls [`oauth2_op::refresh_signing::bootstrap_idp_signing_keys`] on startup: the
/// access key via [`signing::bootstrap_signing_key`], exactly as `authz-api` (`start_api_server`)
/// and `lightbridge-mcp` already do (the *third* concurrent bootstrapper of that key, not a new
/// kind of participant) -- AND, only here, the dedicated refresh-token signing key. See both
/// functions' own doc comments for the concurrent-bootstrap and `max_key_age_days` analysis.
pub async fn start_idp_server(
    idp: &IdpServer,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
    redis: &Option<Redis>,
    secret_claim: &Option<lightbridge_authz_core::config::SecretClaim>,
) -> Result<()> {
    if !oauth2.is_self_signed() {
        return Err(Error::Server(
            "authz-idp requires oauth2.type: self -- it only ever serves the self-signed-JWT \
             discovery/JWKS/token-exchange surface, never the external-issuance path"
                .to_string(),
        ));
    }
    let signing = oauth2.signing.as_ref().ok_or_else(|| {
        Error::Server("oauth2.type is 'self' but oauth2.signing is missing".to_string())
    })?;
    let federation = require_federation(oauth2, "authz-idp")?;

    // Redis is required unconditionally for authz-idp -- every lightbridge-authz serving role
    // that isn't explicitly freed from it (authz-opa, lightbridge-mcp) needs Redis-backed caching,
    // not only when `oauth2.token_exchange` happens to be enabled today (that used to be the only
    // gate; it no longer is -- see AGENTS.md's "Redis is a mandatory dependency" house rule).
    // Mirrors start_api_server's/start_budget_server's identical unconditional check. Resolved
    // here (rather than just before `build_token_exchange_state`, its original spot) so the
    // Redis-backed rate limit store built from it is available to the `KeycloakRelyingParty::new`
    // validation below. `build_token_exchange_state` itself still no-ops to `Ok(None)` when
    // token_exchange is disabled (see its own doc comment), so this changes only whether a
    // *missing* redis config is tolerated, never whether token exchange itself is attempted.
    let redis = redis.as_ref().ok_or_else(|| {
        Error::Server(
            "redis config is required for authz-idp (set `redis.url`) -- mandatory for every \
             authz-idp deployment, not only when oauth2.token_exchange is enabled"
                .to_string(),
        )
    })?;
    let device_verify_rate_limit_store =
        build_redis_rate_limit_store(&redis.url, redis.ca_bundle_path.as_deref(), "authz-idp")?;

    // `oauth2.relying_party` is now MANDATORY for authz-idp -- the same house-rule shape as the
    // "Redis is a mandatory dependency" rule above: `Config.oauth2.relying_party` stays an
    // `Option` at the type level (other components -- authz-api/authz-opa/authz-budget/
    // lightbridge-mcp -- load the same `Config` type and never set this block at all), but
    // enforcement is unconditional here, inside `start_idp_server`, not a config-driven mount
    // decision. This is a DELIBERATE REVERSAL of PR #473 (468084a), which made `relying_party`
    // optional to fix PR #463 (9e0ef4d)'s over-eager unconditional requirement. #463 was reverted
    // for the wrong reason, not a wrong one: the repo owner's own words, verbatim: "Let's not make
    // something from the IdP optional anymore. It's a full IDP now." Do not reintroduce #473's
    // mount-conditional gate -- the defect it left behind was live in production: discovery
    // advertised `device_code` (the device-authorization routes are gated on `token_exchange`,
    // not on `relying_party`) while `/device/verify` 404'd, because the RP-leg silently wasn't
    // mounted. "Optional" and "half-broken" were the same state for this field. Unlike the Redis
    // rule, enforcement here is presence PLUS the existing offline validation, not presence-only:
    // `KeycloakRelyingParty::new` is fully synchronous and offline (it validates the config
    // shape, e.g. `state_encryption_key`, it does not dial Keycloak), so validating it at startup
    // costs no startup-ordering dependency on a third party -- this deliberately does NOT fetch
    // Keycloak discovery at startup, which would be the same mistake the Redis rule's own
    // "presence-only, not a PING" reasoning warns against, aimed at an external IdP instead of an
    // in-cluster Redis. Constructed once here (not re-derived inside `build_idp_router`) and
    // threaded through as an already-validated `Arc`, so there is exactly one
    // `KeycloakRelyingParty::new` call site -- #473's OTHER half (pre-validated `Arc` threading,
    // not config re-derivation inside `build_idp_router`) is kept and strengthened, not reversed.
    let rp_config = oauth2.relying_party.clone().ok_or_else(|| {
        Error::Server(
            "oauth2.relying_party is required for authz-idp -- it is a full IdP: /authorize, \
             /device/verify and /idp/callback are always mounted and discovery always advertises \
             authorization_endpoint. Set the oauth2.relying_party block (client_id, callback_url, \
             state_encryption_key)."
                .to_string(),
        )
    })?;
    // ADR-0025 Stage 1: `authz-idp` seals `federated_identities` rows under, and validates ID
    // tokens against, `oauth2.federation.issuer` -- the ONE issuer field this deployment trusts
    // (there is no longer a separate `oauth2.relying_party.issuer` for it to drift from; that
    // field was deleted, closing the config trap where the two had to be kept byte-equal by
    // hand). `oauth2.federation.discovery_url` is a distinct, optional LOCATION override for
    // where `authz-idp` dials OIDC discovery from inside this deployment's own network -- see
    // `KeycloakRelyingParty::discover`'s doc comment for why that dial target and the identity
    // issuer are kept separate. `oauth2.jwks_url` is deliberately NOT passed -- on authz-idp it
    // is the OPPOSITE trust root; see `KeycloakRelyingParty::jwks` (conflating them broke prod).
    //
    // #697/#701, via the SAME `handlers::build_starting_grant_service` constructor
    // `AuthzStoreImpl::with_pool` uses, so the policy set id / evaluation budget can never drift
    // between the RPC surface's starting grants and browser-SSO self-service provisioning's: a
    // login that provisions a brand new account (restored self-service provisioning, see
    // `relying_party::KeycloakRelyingParty::persist_federated_identity`) books its starting grant
    // the same way `createAccount` does, so it does not read `remaining = 0` at the gateway.
    let starting_grant = Arc::new(handlers::build_starting_grant_service(pool.clone()));
    let relying_party = Arc::new(relying_party::KeycloakRelyingParty::new(
        rp_config,
        federation.issuer.clone(),
        federation.effective_discovery_url().to_string(),
        Arc::new(StoreRepo::new(pool.clone())),
        device_verify_rate_limit_store,
        starting_grant,
        oauth2.jwks_ca_bundle_path.clone(),
    )?);

    let readiness_pool = pool.clone();
    // ADR-0014: the budget ledger is read here (not called over the network) because
    // `authz-idp`/`authz-budget` share the same Postgres -- see `build_token_exchange_state`'s
    // own doc comment.
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        pool.clone(),
    ));
    // ADR-0015 Decision 6: `TokenExchangeOpStore::resolve_budget_tier`'s fail-closed fallback
    // needs a live `PolicyEngine`, exactly like `start_api_server`'s/`start_budget_server`'s
    // identical load -- loading whatever is genuinely active in the DB right now, off the SAME
    // shared Postgres `budget_policy_sets`/`budget_policy_revisions` tables, so `authz-idp` never
    // drifts from what `activateBudgetPolicy` most recently activated.
    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            pool.clone(),
            BUDGET_POLICY_SET_ID,
            BUDGET_POLICY_EVALUATION_BUDGET,
        )
        .await
        .map_err(|e| Error::Server(format!("failed to load active budget policy: {e}")))?,
    );
    let policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine> = policy_store.engine();
    let signing_repo = Arc::new(StoreRepo::new(pool));
    oauth2_op::refresh_signing::bootstrap_idp_signing_keys(&signing_repo, signing).await?;

    let bearer_service = build_bearer_service(oauth2)?;

    // `oauth2.token_exchange` is now MANDATORY for authz-idp, the same reversal as
    // `relying_party` above: without it there is no `/oauth2/token`, no
    // `/oauth2/device_authorization`, and the `authorization_code` grant `authorize::router`
    // mounts unconditionally cannot issue a redeemable token (`build_token_exchange_state`'s sole
    // production caller is this function -- see its own doc comment). `build_token_exchange_state`
    // keeps its `Result<Option<...>>` contract (its unit tests still exercise the `None`/disabled
    // path directly), so the "disabled is fatal for authz-idp" decision lives here, at the one
    // production call site, not inside that function.
    let token_exchange_state = build_token_exchange_state(
        oauth2,
        signing_repo.clone(),
        budget_repo,
        policy_engine,
        bearer_service,
        &redis.url,
        redis.ca_bundle_path.as_deref(),
    )?
    .ok_or_else(|| {
        Error::Server(
            "oauth2.token_exchange is required and must be enabled for authz-idp (set \
             oauth2.token_exchange.enabled: true) -- /oauth2/token, /oauth2/revoke and \
             /oauth2/device_authorization are always mounted, and the authorization_code grant \
             cannot issue a redeemable token without them"
                .to_string(),
        )
    })?;

    // OIDC Discovery 1.0 §3: an OpenID Provider's `scopes_supported` MUST include `openid` --
    // absent it, this is a bare OAuth2 authorization server, not the OIDC provider the mounted
    // `/authorize` browser-SSO flow and discovery document both advertise being. Checked here
    // (Q2), not inside `build_token_exchange_state`, for the same reason the `None` check above
    // lives here: this is an authz-idp-specific requirement, not a general token-exchange
    // constraint on every caller of that function.
    if !token_exchange_state
        .op_config()
        .scopes_supported
        .iter()
        .any(|scope| scope == "openid")
    {
        return Err(Error::Server(
            "oauth2.token_exchange.allowed_scopes must include \"openid\" for authz-idp -- it is \
             an OpenID Provider, and OIDC Discovery 1.0 §3 requires scopes_supported to advertise \
             openid"
                .to_string(),
        ));
    }

    // GHSA-9pc6-965v-2c44. Deliberately NOT a startup mandate, unlike the redis/relying_party/
    // token_exchange checks above: authz-idp is the sole server of this deployment's issuer, and
    // every in-circulation API-key JWT names it in `iss`. Refusing to boot over a missing
    // claim-redemption key would take the whole issuer down to disable one page. An absent block
    // instead makes /api-keys/claim answer an explicit 503.
    //
    // A PRESENT but malformed block is still a hard startup failure -- `from_config` validates
    // offline. The tolerated case is "absent", never "wrong".
    //
    // Same repo the signing bootstrap already built over this pool -- one StoreRepo per pool, not
    // a second connection path for the same database.
    let claim_repo = signing_repo.clone();
    let claim_redeem = claim_redeem::ClaimRedeemState {
        claims: secret_claim
            .as_ref()
            .map(|cfg| secret_claim::SecretClaimStore::from_config(claim_repo.clone(), cfg))
            .transpose()?
            .map(Arc::new),
        repo: claim_repo,
    };

    let app = build_idp_router(
        oauth2,
        signing,
        signing_repo,
        token_exchange_state,
        readiness_pool,
        &idp.static_dir,
        relying_party,
        claim_redeem,
    );

    lightbridge_authz_core::log_build_info(SERVICE_IDP);
    tracing::info!(
        server = SERVICE_IDP,
        address = %idp.address,
        port = idp.port,
        "starting idp server"
    );

    serve_tls("IDP", &idp.address, idp.port, &idp.tls, app).await
}
