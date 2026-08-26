use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_core::{
    Account, AccountId, ApiKey, ApiKeySecret, CreateAccount, CreateApiKey, Project, ProjectMember,
    RotateApiKey, async_trait,
    config::{
        ApiKeyExpiry, ApiServer, BasicAuth, Billing, BudgetServer, Federation, IdpServer,
        JwtSigning, ModelCatalog, Oauth2, OauthClient, OauthClientType, OpaServer, QuotaTiers,
        Redis, UsageServiceClient,
    },
    db::{DbPoolTrait, is_database_ready},
    error::{Error, Result},
    server::{dev_cors_enabled, serve_tls},
};

pub mod auth_provider;
pub mod authorize;
pub mod codec;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod oauth2_op;
pub mod ratelimit_redis;
pub mod redis_tls;
pub mod relying_party;
pub mod routers;
pub mod rpc_authorize;
pub mod session_cookie;
pub mod session_management;
pub mod signing;
pub mod static_assets;
pub mod token_exchange;

use auth_provider::{ACCESS_TOKEN_CONTEXT_KEY, CratestackAuthProvider};
use codec::LenientCborCodec;
use handlers::AuthzStoreImpl;
use ratelimit_redis::build_redis_rate_limit_store;
use routers::opa_router;
use rpc_authorize::{RpcAuthorizeState, RpcScope};

use cratestack::idempotency::IdempotencyLayer;
use cratestack::ratelimit::{RateLimitConfig, RateLimitLayer, RateLimitStore};
use cratestack::{
    CratestackContext, CratestackError, DEFAULT_BODY_LIMIT_BYTES, SqlxIdempotencyStore, Value,
};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::{BearerTokenService, BearerTokenServiceTrait};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Idempotency replay window for the CRUD RPC surface (ADR-0003, "Idempotency").
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(24 * 3600);
/// Per-principal token-bucket rate-limit defaults for the CRUD RPC surface (ADR-0003, "Rate
/// limiting (Redis-backed)"). Generous burst with steady refill; tune via deployment as needed.
const RATE_LIMIT_BURST: u32 = 120;
const RATE_LIMIT_REFILL_PER_SECOND: f64 = 60.0;
/// The node-count evaluation budget passed to the [`lightbridge_authz_budget::RuleDataEngine`]
/// this server's [`lightbridge_authz_budget::PolicyStore`] wraps. See
/// [`lightbridge_authz_budget::RuleDataEngine`]'s own doc comment for why this is a deterministic
/// node-count budget rather than a wall-clock request timeout.
const BUDGET_POLICY_EVALUATION_BUDGET: usize = 10_000;
/// The one budget policy set this epic needs (ADR-0007; `PolicyStore` is bound to it once at
/// server startup). See `migrations/20260804000001_budget_policy_sets_and_revisions.sql`.
const BUDGET_POLICY_SET_ID: &str = "budget-refill";

#[derive(Serialize, Deserialize)]
struct RootResponse {
    status: String,
    message: String,
}

/// Shared state for the OPA server.
pub struct OpaState {
    pub repo: Arc<dyn OpaRepoTrait>,
    pub basic_auth: BasicAuth,
    /// Configured billing-plan catalogue, used to resolve a key's plan id into its display name
    /// and limits at introspection time.
    pub billing: Arc<Billing>,
    /// `oauth2.signing.audience` -- the FIXED `azp` value a self-signed API-key JWT always
    /// carries (`ApiKeyJwtSigner::sign`). `handlers::exchange_token::verify_self_issued_token`
    /// uses this to refuse any self-issued token shaped like an API-key JWT before ever treating
    /// it as an exchange session, independent of whether an `api_keys` row still exists for it --
    /// see that function's doc comment. `None` when `oauth2.type` is `external` (no self-signing
    /// at all) or when `oauth2.signing.audience` is left unconfigured under `type: self`.
    pub api_key_audience: Option<String>,
    /// ADR-0025 Stage 2: translates `handlers::idp::resolve_context`'s presented
    /// `(issuer, subject)` into the acting account id -- the real translation seam for that
    /// endpoint, distinct from [`OpaRepoTrait`]'s own `subject: &str` methods (whose callers
    /// already hold an ADR-0025-resolved value -- see the `OpaRepoTrait for StoreRepo` impl's own
    /// doc comment).
    pub resolver: Arc<dyn auth_provider::SubjectResolver>,
    /// `oauth2.federation.issuer` -- the default `handlers::idp::resolve_context` uses when the
    /// request body omits `issuer` (the legacy `lightbridge-keycloak-spi` adapter's shape).
    pub federation_issuer: String,
}

#[async_trait]
pub trait OpaRepoTrait: Send + Sync {
    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey>;
    async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>>;
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>>;
    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>>;
    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>>;
    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>>;
    async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext>;
    /// `subject`'s per-member `quota_tier` on `project_id` (ADR-0017), or `None` for "no
    /// per-member ceiling" -- see `StoreRepo::project_member_quota_tier`'s doc comment for the
    /// full `Ok(None)` vs `Err` distinction. Used by introspection to resolve the `quota_tier`
    /// field for a native RFC 8693 exchange session the same way `owner_quota_tier` already does
    /// for the API-key plane.
    async fn project_member_quota_tier(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>>;
    /// `subject`'s roster `role` on `project_id`, or `None` if they hold no `project_members` row.
    /// Used by introspection to resolve the `role` field for a native RFC 8693 exchange session,
    /// the human/OIDC-plane mirror of `owner_role` on the API-key plane.
    async fn project_member_role(&self, project_id: &str, subject: &str) -> Result<Option<String>>;
    /// Every signing key (active + retired-but-not-yet-expired) this service has minted, as raw
    /// JWK JSON -- the same rows `signing::well_known_router`'s `/.well-known/jwks.json` handler
    /// serves. Introspection uses this to verify a presented token was signed by one of THIS
    /// service's own keys (a *different* trust root than `oauth2.jwks_url`, the external IdP)
    /// before trusting any tenant claim on it -- see
    /// `handlers::exchange_token::verify_self_issued_token`.
    async fn list_verification_jwks(&self) -> Result<Vec<serde_json::Value>>;
    /// ADR-0020 Decision 4 / #437: the current `status`/`expires_at` of the `sessions` row named
    /// by a token-exchange access token's `sid` claim -- `Ok(None)` when no such row exists (a
    /// pre-ADR-0020 token, or an unrecognized `sid`), `Err` when the lookup itself fails (DB
    /// unreachable). See `handlers::exchange_token::resolve_exchange_token_context`'s own doc
    /// comment for why the `Err` case must never be read as "session is fine" -- it is the one
    /// fail-closed branch this whole ADR exists to add.
    async fn find_session_status(&self, session_id: &str) -> Result<Option<SessionStatusRow>>;
}

/// The two session-row fields introspection needs to decide `active`/`revoked`/`expired`
/// (ADR-0020 Decision 6) -- deliberately narrower than the full `sessions` row (no `account_id`/
/// `project_id`/`client_id`/`kind`/etc, none of which `resolve_exchange_token_context` needs).
#[derive(Debug, Clone)]
pub struct SessionStatusRow {
    /// `"active"` / `"revoked"` -- plain `String`, parsed fail-closed on the read side (an
    /// unrecognized value is never treated as `"active"`), matching this schema's established
    /// convention for closed-set string columns (`Project.modelPolicy`, `AugmentationRequest.status`).
    pub status: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
impl OpaRepoTrait for StoreRepo {
    async fn record_api_key_usage(
        &self,
        key_id: &str,
        ip: Option<String>,
    ) -> Result<lightbridge_authz_core::ApiKey> {
        StoreRepo::record_api_key_usage(self, key_id, ip).await
    }

    async fn find_api_key_validation_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<lightbridge_authz_core::ApiKeyValidation>> {
        StoreRepo::find_api_key_validation_by_hash(self, key_hash).await
    }

    // ADR-0025: `OpaRepoTrait`'s own `subject: &str` contract is UNCHANGED here on purpose --
    // every caller of this trait (OPA/Authorino introspection, `handlers::opa`/
    // `handlers::exchange_token`) already holds a value read straight off an `accounts.id`-anchored
    // column (`owner_account_id`, a resolved exchange session's `account_id`, ...), never a raw
    // bearer claim that has not passed through `StoreRepo::resolve_account_for_federated_subject`.
    // Wrapping via `AccountId::assert_already_resolved` here is exactly the "already-legitimate account id,
    // just not yet typed" case that constructor's own doc comment describes -- this trait is
    // deliberately outside the ingress list ADR-0025 Stage 2 translates (auth_provider.rs,
    // bearer, mcp.rs, handlers/idp.rs, relying_party.rs, oauth2_op/store.rs).
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project(
            self,
            &AccountId::assert_already_resolved(subject),
            project_id,
        )
        .await
    }

    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account(
            self,
            &AccountId::assert_already_resolved(subject),
            account_id,
        )
        .await
    }

    async fn get_project_by_id(&self, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project_by_id(self, project_id).await
    }

    async fn get_account_by_id(&self, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account_by_id(self, account_id).await
    }

    async fn resolve_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::ResolvedContext> {
        StoreRepo::resolve_context(
            self,
            &AccountId::assert_already_resolved(subject),
            project_id,
        )
        .await
    }

    async fn project_member_quota_tier(
        &self,
        project_id: &str,
        subject: &str,
    ) -> Result<Option<String>> {
        StoreRepo::project_member_quota_tier(
            self,
            project_id,
            &AccountId::assert_already_resolved(subject),
        )
        .await
    }

    async fn project_member_role(&self, project_id: &str, subject: &str) -> Result<Option<String>> {
        StoreRepo::project_member_role(
            self,
            project_id,
            &AccountId::assert_already_resolved(subject),
        )
        .await
    }

    async fn list_verification_jwks(&self) -> Result<Vec<serde_json::Value>> {
        StoreRepo::list_verification_jwks(self).await
    }

    async fn find_session_status(&self, session_id: &str) -> Result<Option<SessionStatusRow>> {
        StoreRepo::find_session_status(self, session_id)
            .await
            .map(|opt| {
                opt.map(|row| SessionStatusRow {
                    status: row.status,
                    expires_at: row.expires_at,
                })
            })
    }
}

/// Maps a core repository `Error` (reused hand-written sqlx) into cratestack's `CratestackError` so an RPC
/// procedure failure surfaces with the right HTTP status through the RPC error envelope.
fn to_cratestack_error(err: Error) -> CratestackError {
    match err {
        Error::NotFound => CratestackError::NotFound("not found".to_owned()),
        Error::Forbidden(m) => CratestackError::Forbidden(m),
        Error::Conflict(m) => CratestackError::Conflict(m),
        Error::BadRequest(m) => CratestackError::BadRequest(m),
        other => CratestackError::Internal(other.to_string()),
    }
}

/// Maps a [`lightbridge_authz_budget::BudgetError`] into cratestack's `CratestackError`, mirroring
/// [`to_cratestack_error`] above for the (unrelated) core `Error` type. Exhaustive match, no wildcard
/// arm, so a new `BudgetError` variant fails this crate's build until it is triaged here rather
/// than silently falling into some default status.
fn budget_error_to_cratestack_error(err: lightbridge_authz_budget::BudgetError) -> CratestackError {
    use lightbridge_authz_budget::BudgetError;
    match err {
        BudgetError::InvalidRuleData(m) => CratestackError::BadRequest(m),
        BudgetError::InvalidAmount(_)
        | BudgetError::InvalidPeriod(_)
        | BudgetError::UnknownSource(_)
        | BudgetError::UnknownTier(_)
        | BudgetError::UnknownStatus(_)
        | BudgetError::InvalidReviewOutcome(_)
        | BudgetError::MissingRejectionReason
        | BudgetError::AmountNotOffered(_) => CratestackError::BadRequest(err.to_string()),
        BudgetError::AlreadyGranted | BudgetError::AlreadyReviewed(_) => {
            CratestackError::Conflict(err.to_string())
        }
        BudgetError::PolicyDenied(_) => CratestackError::Forbidden(err.to_string()),
        BudgetError::NotFound(m) => CratestackError::NotFound(m),
        BudgetError::StorageFailed(m) => CratestackError::Internal(m),
    }
}

/// Renders a [`lightbridge_authz_budget::Effect`] as the exact snake_case wire value its own
/// `Serialize` impl (`#[serde(rename_all = "snake_case")]`) produces, e.g. `"auto_approve"` /
/// `"manual_review"`. Used to fill the schema `Decision.effect` `String` field (see the schema's
/// doc comment on `type Decision` for why that field is a `String` rather than a schema-level
/// enum) without a second, hand-maintained mapping that could drift from `Effect`'s own derive.
fn effect_to_wire_string(effect: lightbridge_authz_budget::Effect) -> String {
    serde_json::to_string(&effect)
        .expect("Effect always serializes to a JSON string")
        .trim_matches('"')
        .to_owned()
}

/// Maps a domain [`lightbridge_authz_budget::Decision`] into the schema's wire `Decision` shape
/// (ADR-0007's decision contract, mirrored field-for-field in `authz.cstack`'s `type Decision`).
/// The two `i64` micro-USD amounts are stringified per that type's documented 64-bit-safety
/// rationale (matching `ruleDataJson`'s existing string-encoding precedent).
fn to_schema_decision(
    decision: lightbridge_authz_budget::Decision,
) -> schema::procedures::simulate_budget_policy::Output {
    schema::procedures::simulate_budget_policy::Output {
        effect: effect_to_wire_string(decision.effect),
        approvedAmountMicros: decision.approved_amount_micros.to_string(),
        maximumAmountMicros: decision.maximum_amount_micros.to_string(),
        reasonCodes: decision.reason_codes,
        matchedRuleIds: decision.matched_rule_ids,
        policyRevision: decision.policy_revision,
        obligations: schema::Obligations {
            requiredApproverRole: decision.obligations.required_approver_role,
        },
    }
}

/// Maps a domain [`lightbridge_authz_budget::AugmentationRequest`] into the schema's wire
/// `AugmentationRequest` shape (see `authz.cstack`'s `type AugmentationRequest` doc comment for
/// the field-by-field reasoning, in particular why `policyReasonCodes`/`matchedRuleIds` are
/// required `String[]` rather than the `Option<Vec<String>>` the domain type carries -- both
/// `unwrap_or_default()` calls below are the "never actually `None` by the time a procedure
/// returns a value" case that comment documents, not a silent-loss compromise).
fn to_schema_augmentation_request(
    request: lightbridge_authz_budget::AugmentationRequest,
) -> schema::AugmentationRequest {
    schema::AugmentationRequest {
        id: request.id,
        budgetAccountId: request.budget_account_id,
        accountId: request.account_id,
        projectId: request.project_id,
        period: request.period.to_string(),
        requestedTier: request.requested_tier.to_string(),
        requestedAmountMicros: request.requested_amount_micros.to_string(),
        status: request.status.to_string(),
        policyEffect: request.policy_effect.map(effect_to_wire_string),
        policyReasonCodes: request.policy_reason_codes.unwrap_or_default(),
        matchedRuleIds: request.matched_rule_ids.unwrap_or_default(),
        policyRevision: request.policy_revision,
        approvedAmountMicros: request.approved_amount_micros.map(|a| a.to_string()),
        grantId: request.grant_id,
        idempotencyKey: request.idempotency_key,
        reviewedBy: request.reviewed_by,
        rejectionReason: request.rejection_reason,
        createdAt: request.created_at,
        reviewedAt: request.reviewed_at,
    }
}

/// Default/max page size for `listPendingAugmentationRequests`/`listMyAugmentationRequests`
/// (#296/#295). Mirrors [`DEFAULT_BUDGET_GRANTS_PAGE_SIZE`]/[`MAX_BUDGET_GRANTS_PAGE_SIZE`]
/// exactly -- same reasoning: this procedure layer's own default when a caller omits `limit`,
/// and its own tighter ceiling when a caller supplies one, independent of whatever
/// `AugmentationRepo` additionally clamps to.
const DEFAULT_AUGMENTATION_REQUESTS_PAGE_SIZE: i64 = 20;
const MAX_AUGMENTATION_REQUESTS_PAGE_SIZE: i64 = 50;

/// Resolves a caller-supplied, optional `limit` into a page size clamped to
/// `[1, MAX_AUGMENTATION_REQUESTS_PAGE_SIZE]`, defaulting to
/// [`DEFAULT_AUGMENTATION_REQUESTS_PAGE_SIZE`] when omitted. Shared by
/// `listPendingAugmentationRequests` and `listMyAugmentationRequests` -- both page the same
/// `AugmentationRequest` entity, just in opposite directions (see each procedure's own doc
/// comment).
fn resolve_augmentation_requests_page_size(limit: Option<i64>) -> i64 {
    match limit {
        Some(requested) => requested.clamp(1, MAX_AUGMENTATION_REQUESTS_PAGE_SIZE),
        None => DEFAULT_AUGMENTATION_REQUESTS_PAGE_SIZE,
    }
}

/// Maps one page of domain [`lightbridge_authz_budget::AugmentationRequest`] rows into the
/// schema's `AugmentationRequestPage` (#296/#295), mirroring `list_budget_grants_page`'s own
/// `nextCursor` rule: the last entry's `createdAt` when the page came back exactly `page_size`
/// long (there may be more), `None` when it came back short (nothing further). This works
/// identically regardless of which direction the underlying query walked (ASC for
/// `listPendingAugmentationRequests`, DESC for `listMyAugmentationRequests`) -- "the last entry
/// in this page" is always the correct cursor to continue that same walk, whichever way it goes.
fn to_schema_augmentation_request_page(
    requests: Vec<lightbridge_authz_budget::AugmentationRequest>,
    page_size: i64,
) -> schema::AugmentationRequestPage {
    let next_cursor = if requests.len() == usize::try_from(page_size).unwrap_or(usize::MAX) {
        requests.last().map(|r| r.created_at)
    } else {
        None
    };

    schema::AugmentationRequestPage {
        entries: requests
            .into_iter()
            .map(to_schema_augmentation_request)
            .collect(),
        nextCursor: next_cursor,
    }
}

/// Maps a domain [`lightbridge_authz_budget::repo::BalanceSnapshot`] into the schema's wire
/// `BudgetBalance` shape (see `authz.cstack`'s `type BudgetBalance` doc comment for the
/// string-vs-`Int` field reasoning).
fn to_schema_budget_balance(
    snapshot: lightbridge_authz_budget::repo::BalanceSnapshot,
) -> schema::BudgetBalance {
    schema::BudgetBalance {
        budgetAccountId: snapshot.budget_account_id,
        period: snapshot.period.to_string(),
        baseTotalMicros: snapshot.base_total_micros.to_string(),
        selfServiceTotalMicros: snapshot.self_service_total_micros.to_string(),
        adminTotalMicros: snapshot.admin_total_micros.to_string(),
        automaticTotalMicros: snapshot.automatic_total_micros.to_string(),
        refundTotalMicros: snapshot.refund_total_micros.to_string(),
        effectiveBudgetMicros: snapshot.effective_budget_micros.to_string(),
        selfServiceGrantCount: i64::from(snapshot.self_service_grant_count),
        automaticGrantCount: i64::from(snapshot.automatic_grant_count),
        version: snapshot.version,
        updatedAt: snapshot.updated_at,
    }
}

/// Maps a domain [`lightbridge_authz_budget::RefillStatus`] into the schema's wire
/// `MyBudgetRefillLadder` shape (see `authz.cstack`'s `type MyBudgetRefillLadder` doc comment).
/// `budget_account_id`/`period` are threaded through from the call site rather than carried on
/// `RefillStatus` itself -- the domain type only needs to answer "what amounts are offered", not
/// echo back the request that produced it.
fn to_schema_my_budget_refill_ladder(
    budget_account_id: String,
    period: String,
    status: lightbridge_authz_budget::RefillStatus,
) -> schema::MyBudgetRefillLadder {
    schema::MyBudgetRefillLadder {
        budgetAccountId: budget_account_id,
        period,
        allowedAmountsMicros: status
            .allowed_amounts_micros
            .into_iter()
            .map(|amount| amount.to_string())
            .collect(),
    }
}

/// Maps a domain [`lightbridge_authz_budget::repo::BudgetGrant`] into the schema's wire
/// `BudgetGrantEntry` shape (see `authz.cstack`'s `type BudgetGrantEntry` doc comment).
fn to_schema_budget_grant_entry(
    grant: lightbridge_authz_budget::repo::BudgetGrant,
) -> schema::BudgetGrantEntry {
    schema::BudgetGrantEntry {
        id: grant.id,
        budgetAccountId: grant.budget_account_id,
        accountId: grant.account_id,
        projectId: grant.project_id,
        period: grant.period.to_string(),
        amountMicros: grant.amount_micros.to_string(),
        source: grant.source.to_string(),
        actorId: grant.actor_id,
        reason: grant.reason,
        policyRevision: grant.policy_revision,
        matchedRuleIds: grant.matched_rule_ids.unwrap_or_default(),
        idempotencyKey: grant.idempotency_key,
        triggerKey: grant.trigger_key,
        createdAt: grant.created_at,
        expiresAt: grant.expires_at,
        revokedAt: grant.revoked_at,
    }
}

/// Default/max page size for `listMyBudgetGrants`/`listBudgetGrants`. `BudgetRepo::list_grants`
/// independently clamps to its own `MAX_LIST_GRANTS_LIMIT` (200) regardless of what this layer
/// passes -- this constant is this procedure layer's own default when a caller omits `limit`, and
/// its own tighter ceiling (50) when a caller supplies one, so a single caller-supplied `limit`
/// cannot force a 200-row page by accident.
const DEFAULT_BUDGET_GRANTS_PAGE_SIZE: i64 = 20;
const MAX_BUDGET_GRANTS_PAGE_SIZE: i64 = 50;

/// Resolves a caller-supplied, optional `limit` into a page size clamped to
/// `[1, MAX_BUDGET_GRANTS_PAGE_SIZE]`, defaulting to [`DEFAULT_BUDGET_GRANTS_PAGE_SIZE`] when
/// omitted.
fn resolve_budget_grants_page_size(limit: Option<i64>) -> i64 {
    match limit {
        Some(requested) => requested.clamp(1, MAX_BUDGET_GRANTS_PAGE_SIZE),
        None => DEFAULT_BUDGET_GRANTS_PAGE_SIZE,
    }
}

/// `listMyExpiringApiKeys`'s default "soon" window when a caller omits `withinDays`
/// (lightbridge-authz#436). Matches `apps/self-service/src/lib/api-key-expiry.ts`'s
/// `EXPIRING_SOON_WINDOW_DAYS` in converse-frontends so the two surfaces agree on what "soon"
/// means rather than silently diverging -- see `docs/api-key-expiry-visibility.md`.
const DEFAULT_EXPIRING_SOON_WINDOW_DAYS: i64 = 14;
/// Ceiling a caller-supplied `withinDays` clamps to. Mirrors the documented default of the
/// operator-configured `ApiKeyExpiry` ceiling (`api_key_expiry`,
/// `lightbridge_authz_core::config::ApiKeyExpiry::max_lifetime_days`) -- a window wider than the
/// maximum possible key lifetime cannot surface anything a plain `model.ApiKey.list` call could
/// not already return, so there is no security reason to allow (or need to reject) more.
const MAX_EXPIRING_SOON_WINDOW_DAYS: i64 = 90;
/// Hard cap on rows `listMyExpiringApiKeys` returns (soonest-expiring first). Comfortably above
/// the estate-wide count of keys expiring within 30 days at the time of lightbridge-authz#436's
/// own investigation (11) -- this bounds the query rather than expecting that count to hold
/// forever.
const MAX_EXPIRING_API_KEYS_RESULTS: i64 = 500;

/// Resolves a caller-supplied, optional `withinDays` into a window clamped to
/// `[1, MAX_EXPIRING_SOON_WINDOW_DAYS]`, defaulting to [`DEFAULT_EXPIRING_SOON_WINDOW_DAYS`] when
/// omitted -- the same "clamp, don't reject" convention [`resolve_budget_grants_page_size`] above
/// already uses for a read-side convenience parameter, not the fail-closed "reject, never clamp"
/// rule `validate_expires_at` (`handlers/mod.rs`) uses for the write-time expiry gate.
fn clamp_expiring_soon_window_days(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_EXPIRING_SOON_WINDOW_DAYS)
        .clamp(1, MAX_EXPIRING_SOON_WINDOW_DAYS)
}

/// The validated caller's subject, projected as `auth().id` by [`CratestackAuthProvider`].
fn subject_from_ctx(ctx: &CratestackContext) -> Option<String> {
    match ctx.auth_field("id") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// The caller's raw access token, stashed into the context by [`CratestackAuthProvider`] so the
/// rotate procedure's downstream secret issuance can reuse it (email profile / token exchange).
fn access_token_from_ctx(ctx: &CratestackContext) -> Option<String> {
    match ctx.extensions.get(ACCESS_TOKEN_CONTEXT_KEY) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn to_schema_api_key(k: ApiKey) -> schema::ApiKey {
    schema::ApiKey {
        createdAt: k.created_at,
        updatedAt: k.updated_at,
        id: k.id,
        projectId: k.project_id,
        name: k.name,
        keyPrefix: k.key_prefix,
        keyHash: k.key_hash,
        status: k.status.to_string(),
        expiresAt: k.expires_at,
        lastUsedAt: k.last_used_at,
        lastIp: k.last_ip,
        revokedAt: k.revoked_at,
        deletedAt: None,
        billingPlan: k.billing_plan,
    }
}

fn to_schema_account(a: Account) -> schema::Account {
    schema::Account {
        createdAt: a.created_at,
        updatedAt: a.updated_at,
        id: a.id,
        defaultQuota: a.default_quota,
        status: a.status.to_string(),
    }
}

/// Recursively lower a `serde_json::Value` (the shape the core repo speaks) into cratestack's own
/// `Value` enum, which is what the generated model structs carry for `Json` columns. Needed because
/// the two crates use different JSON value types and there is no cross-conversion in either.
fn json_to_cratestack_value(value: serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(Value::Int)
            .unwrap_or_else(|| Value::Float(n.as_f64().unwrap_or(0.0))),
        serde_json::Value::String(s) => Value::String(s),
        serde_json::Value::Array(items) => {
            Value::List(items.into_iter().map(json_to_cratestack_value).collect())
        }
        serde_json::Value::Object(map) => Value::Map(
            map.into_iter()
                .map(|(k, v)| (k, json_to_cratestack_value(v)))
                .collect(),
        ),
    }
}

/// The inverse of `json_to_cratestack_value` above: lowers cratestack's own `Value` enum back into
/// the `serde_json::Value` shape the core repo speaks. Needed by `set_project_allowed_models`
/// (#415) to read a `Json?` procedure argument (`Option<cratestack::Json<Value>>`) back into
/// `Option<Vec<String>>` before handing it to `AuthzStoreImpl`.
fn cratestack_value_to_json(value: Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(b),
        Value::Int(i) => serde_json::Value::Number(i.into()),
        Value::Float(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::String(s) => serde_json::Value::String(s),
        Value::List(items) => {
            serde_json::Value::Array(items.into_iter().map(cratestack_value_to_json).collect())
        }
        Value::Map(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, cratestack_value_to_json(v)))
                .collect(),
        ),
        // `Bytes` has no `serde_json::Value` counterpart and no forward `json_to_cratestack_value`
        // arm ever produces it (the core repo never stores binary blobs in `Json` columns) -- not
        // reachable from `Project.allowedModels`'s own DB round-trip, so `Null` here just means
        // "not a shape this converter's only caller understands", same tolerance
        // `allowed_models_from_json_arg` already applies to any other unexpected whole-argument
        // shape.
        Value::Bytes(_) => serde_json::Value::Null,
    }
}

/// Reads a `Project.allowedModels`-shaped `Json?` procedure argument
/// (`Option<cratestack::Json<Value>>`) into the core domain's `Option<Vec<String>>`: an absent
/// argument or an explicit `null` both mean "leave/set to all models allowed" (`None`); a JSON
/// array is read element-by-element, silently dropping any non-string entry (mirrors
/// `StoreRepo::json_to_vec`'s existing tolerance for the same shape read back from the DB); any
/// other JSON shape (a bare string/number/object) is not a valid `allowedModels` value and is
/// treated the same as `null` rather than panicking -- the catalogue check downstream only ever
/// rejects known-bad *entries*, so a malformed whole-argument shape fails the same permissive way
/// `Project.allowedModels`'s own DB decode already does for legacy rows (see that field's schema
/// doc comment).
fn allowed_models_from_json_arg(value: Option<cratestack::Json<Value>>) -> Option<Vec<String>> {
    let json = cratestack_value_to_json(value?.0);
    match json {
        serde_json::Value::Null => None,
        serde_json::Value::Array(items) => Some(
            items
                .into_iter()
                .filter_map(|item| match item {
                    serde_json::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

fn to_schema_project(p: Project) -> schema::Project {
    let allowed_models = p
        .allowed_models
        .map(|models| cratestack::Json(json_to_cratestack_value(serde_json::json!(models))));
    let default_limits = cratestack::Json(json_to_cratestack_value(
        serde_json::to_value(&p.default_limits).unwrap_or(serde_json::Value::Null),
    ));
    schema::Project {
        createdAt: p.created_at,
        updatedAt: p.updated_at,
        id: p.id,
        accountId: p.account_id,
        name: p.name,
        allowedModels: allowed_models,
        defaultLimits: default_limits,
        billingPlan: p.billing_plan,
        billingIdentity: p.billing_identity,
        projectQuota: p.project_quota,
        status: p.status.to_string(),
        isDefault: p.is_default,
        modelPolicy: p.model_policy.to_string(),
    }
}

/// Maps a roster row onto the generated `ProjectMember`, synthesising the `id`.
///
/// `project_members` is keyed `(project_id, account_id)` and has no `id` column -- the schema
/// field exists only because cratestack requires exactly one scalar `@id`. `"<project>:<account>"`
/// is derived from the real composite key, so it is stable for a given row across calls, which is
/// what clients need from a list key. Nothing parses it back; the mutating procedures all take
/// `projectId` + `accountId` explicitly.
fn to_schema_project_member(m: ProjectMember) -> schema::ProjectMember {
    schema::ProjectMember {
        id: format!("{}:{}", m.project_id, m.account_id),
        projectId: m.project_id,
        accountId: m.account_id,
        role: m.role,
        quotaTier: m.quota_tier,
        createdAt: m.created_at,
    }
}

fn to_schema_api_key_secret(s: ApiKeySecret) -> schema::ApiKeySecret {
    schema::ApiKeySecret {
        apiKey: to_schema_api_key(s.api_key),
        secret: s.secret,
        oauth2Url: s.oauth2_url,
    }
}

/// Maps the operator-configured `config::Billing` catalogue onto the wire `BillingPlanInfo[]`
/// shape `listBillingPlans` returns. `Int` fields are `i64` on the generated schema type
/// (`authz.cstack`'s `Int` mapping) while `BillingLimits`' per-second/per-day/concurrent fields are
/// `i32` in config -- the `i64::from` widenings below are exact, never lossy, in either direction.
fn to_schema_billing_plans(billing: &Billing) -> Vec<schema::BillingPlanInfo> {
    billing
        .plans
        .iter()
        .map(|plan| schema::BillingPlanInfo {
            id: plan.id.clone(),
            name: plan.name.clone(),
            limits: plan
                .limits
                .as_ref()
                .map(|limits| schema::BillingPlanLimits {
                    requestsPerSecond: limits.requests_per_second.map(i64::from),
                    requestsPerDay: limits.requests_per_day.map(i64::from),
                    requestsPerMonth: limits.requests_per_month,
                    concurrentRequests: limits.concurrent_requests.map(i64::from),
                }),
        })
        .collect()
}

/// Maps the operator-configured `config::ModelCatalog` catalogue onto the wire
/// `ModelCatalogEntry[]` shape `listModelCatalog` returns. No numeric fields, so unlike
/// `to_schema_billing_plans` above there is no widening to account for.
fn to_schema_model_catalog(models: &ModelCatalog) -> Vec<schema::ModelCatalogEntry> {
    models
        .models
        .iter()
        .map(|entry| schema::ModelCatalogEntry {
            id: entry.id.clone(),
            name: entry.name.clone(),
        })
        .collect()
}

fn to_schema_session_revocation_result(revoked_count: u64) -> schema::SessionRevocationResult {
    // `revokedCount` is a schema `Int` (Rust `i64`, see `authz.cstack`'s `Int` mapping note on
    // `SimulateBudgetPolicyInput`) -- `rows_affected()` is `u64`, so this is a lossy cast only in
    // the astronomically unreachable case of revoking over i64::MAX rows in one call.
    schema::SessionRevocationResult {
        revokedCount: revoked_count as i64,
    }
}

/// RPC procedure registry (ADR-0003 item 4). Every procedure delegates to the hand-written sqlx in
/// `AuthzStoreImpl`/`StoreRepo` (tenant-scoped by account ownership or a `project_members` row,
/// ADR-0006), never cratestack's `run_in_tx`, so the chained-write deadlock in cratestack-pg 0.4.9
/// (ADR-0003, "Known cratestack-pg 0.4.9 bugs", item 1) cannot occur. `db` is intentionally unused:
/// the generated CRUD client speaks over cratestack's own sqlx pool (a different sqlx major than
/// this workspace's), so the procedures use the pre-migration repository pool for their writes.
///
/// `policy_store` (ADR-0007) is the one exception to "delegates to `AuthzStoreImpl`/`StoreRepo`" --
/// the budget policy activation/status procedures below delegate to
/// [`lightbridge_authz_budget::PolicyStore`] instead, which owns its own persistence against the
/// same underlying database.
///
/// `refill_service`/`review_service` (#191, PR 3.4) are the same shape of exception: the
/// self-service refill and admin review-queue procedures delegate to
/// [`lightbridge_authz_budget::RefillService`]/[`lightbridge_authz_budget::ReviewService`], which
/// each own their own persistence (`BudgetRepo`/`AugmentationRepo`) against the same underlying
/// database, constructed once at server startup alongside `policy_store` -- see
/// `start_api_server`.
#[derive(Clone)]
pub struct Procedures {
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    refill_service: Arc<lightbridge_authz_budget::RefillService>,
    review_service: Arc<lightbridge_authz_budget::ReviewService>,
    /// The direct-read/grant/revoke surface (`getMyBudgetBalance`/`getBudgetBalance`/
    /// `listMyBudgetGrants`/`listBudgetGrants`/`grantBudget`/`revokeBudgetGrant`) shares this
    /// `BudgetRepo` handle rather than going through `refill_service`/`review_service` -- those
    /// two own their own private `BudgetRepo` internally for the self-service/review flows, but
    /// neither exposes a read-only balance/ledger query surface, so this field is a second,
    /// independent handle against the SAME underlying database (constructed once at server
    /// startup, see `start_api_server`).
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
}

impl Procedures {
    pub fn new(
        issuer: Arc<AuthzStoreImpl>,
        policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
        refill_service: Arc<lightbridge_authz_budget::RefillService>,
        review_service: Arc<lightbridge_authz_budget::ReviewService>,
        budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    ) -> Self {
        Self {
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
        }
    }
}

impl schema::procedures::ProcedureRegistry for Procedures {
    fn create_account(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::create_account::Args,
        _authorized: schema::procedures::create_account::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::create_account::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let default_quota = args.args.defaultQuota;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .create_account(&subject, CreateAccount { default_quota })
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn update_account_default_quota(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::update_account_default_quota::Args,
        _authorized: schema::procedures::update_account_default_quota::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::update_account_default_quota::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        let default_quota = args.args.defaultQuota;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .update_account_default_quota(&subject, &account_id, default_quota.as_deref())
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn rotate_api_key(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::rotate_api_key::Args,
        _authorized: schema::procedures::rotate_api_key::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::rotate_api_key::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let access_token = access_token_from_ctx(ctx);
        let key_id = args.args.keyId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let secret = issuer
                .rotate_api_key(
                    &subject,
                    access_token.as_deref(),
                    &key_id,
                    RotateApiKey {
                        name: None,
                        expires_at: None,
                        grace_period_seconds: None,
                    },
                )
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_api_key_secret(secret))
        }
    }

    fn create_api_key(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::create_api_key::Args,
        _authorized: schema::procedures::create_api_key::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::create_api_key::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let access_token = access_token_from_ctx(ctx);
        let input = args.args;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let secret = issuer
                .create_api_key(
                    &subject,
                    access_token.as_deref(),
                    &input.projectId,
                    CreateApiKey {
                        name: input.name,
                        expires_at: Some(input.expiresAt),
                        billing_plan: input.billingPlan,
                    },
                )
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_api_key_secret(secret))
        }
    }

    /// Read-only: the operator-configured billing-plan catalogue `createApiKey` validates
    /// `billingPlan` against (see that procedure's doc comment in `authz.cstack`). No DB access --
    /// `AuthzStoreImpl::billing_plans` returns the in-memory `Billing` config loaded at startup.
    fn list_billing_plans(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        _args: schema::procedures::list_billing_plans::Args,
        _authorized: schema::procedures::list_billing_plans::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_billing_plans::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            Ok(to_schema_billing_plans(issuer.billing_plans()))
        }
    }

    /// Read-only: the operator-configured AI-model catalogue a `Project.allowedModels` editor
    /// renders (see that procedure's doc comment in `authz.cstack`). No DB access --
    /// `AuthzStoreImpl::model_catalog` returns the in-memory `ModelCatalog` config loaded at
    /// startup. Mirrors `list_billing_plans` above.
    fn list_model_catalog(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        _args: schema::procedures::list_model_catalog::Args,
        _authorized: schema::procedures::list_model_catalog::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_model_catalog::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            Ok(to_schema_model_catalog(issuer.model_catalog()))
        }
    }

    fn disable_account(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::disable_account::Args,
        _authorized: schema::procedures::disable_account::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::disable_account::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .disable_account(&subject, &account_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn enable_account(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::enable_account::Args,
        _authorized: schema::procedures::enable_account::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::enable_account::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .enable_account(&subject, &account_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn disable_project(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::disable_project::Args,
        _authorized: schema::procedures::disable_project::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::disable_project::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .disable_project(&subject, &project_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn enable_project(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::enable_project::Args,
        _authorized: schema::procedures::enable_project::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::enable_project::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .enable_project(&subject, &project_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_default_project(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::set_default_project::Args,
        _authorized: schema::procedures::set_default_project::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_default_project::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_default_project(&subject, &project_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_quota(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::set_project_quota::Args,
        _authorized: schema::procedures::set_project_quota::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_quota::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let project_quota = args.args.projectQuota;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_quota(&subject, &project_id, project_quota.as_deref())
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_allowed_models(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::set_project_allowed_models::Args,
        _authorized: schema::procedures::set_project_allowed_models::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_allowed_models::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let allowed_models = allowed_models_from_json_arg(args.args.allowedModels);
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_allowed_models(&subject, &project_id, allowed_models)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_model_policy(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::set_project_model_policy::Args,
        _authorized: schema::procedures::set_project_model_policy::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_model_policy::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let model_policy = args.args.modelPolicy;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_model_policy(&subject, &project_id, &model_policy)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn revoke_api_key(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::revoke_api_key::Args,
        _authorized: schema::procedures::revoke_api_key::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::revoke_api_key::Output, CratestackError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let key_id = args.args.keyId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let key = issuer
                .revoke_api_key(&subject, &key_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_api_key(key))
        }
    }

    /// Self-scoped, cross-project "expiring soon" aggregate (lightbridge-authz#436). Unlike every
    /// other procedure in this impl, this one DOES use `db` -- see the schema doc comment on
    /// `listMyExpiringApiKeys` for why: calling the generated `db.api_key()` delegate means this
    /// procedure's tenant isolation is enforced by the exact same compiled `@@allow("read", ...)`
    /// clause `model.ApiKey.list`/`get` already go through (`push_scoped_conditions` in
    /// cratestack-pg folds it into the query unconditionally, with no bypass), rather than a
    /// second, hand-written ownership join that could drift from the model's own policy.
    /// Soft-deleted rows are excluded the same way (the model's `@@soft_delete` filter, also
    /// applied unconditionally by the generated delegate) -- no explicit `deletedAt` check needed
    /// here.
    fn list_my_expiring_api_keys(
        &self,
        db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::list_my_expiring_api_keys::Args,
        _authorized: schema::procedures::list_my_expiring_api_keys::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_my_expiring_api_keys::Output,
            CratestackError,
        >,
    > + Send {
        let within_days = args.args.withinDays;
        async move {
            let within_days = clamp_expiring_soon_window_days(within_days);
            let now = chrono::Utc::now();
            let cutoff = now + chrono::Duration::days(within_days);
            // Three separate `.where_(...)` calls, not one `.and()`-chained expression:
            // `FindMany`/`ScopedFindMany` combine every entry in its `filters: Vec<FilterExpr>`
            // with `AND` when building the query (`push_filter_query`,
            // cratestack-sqlx/src/query/support/filter.rs), so this is equivalent to (and simpler
            // than) chaining `.and()` on the `Filter` values `eq`/`gt`/`lte` return.
            let keys = db
                .api_key()
                .find_many()
                .where_(schema::api_key::status().eq("active".to_string()))
                .where_(schema::api_key::expiresAt().gt(now))
                .where_(schema::api_key::expiresAt().lte(cutoff))
                .order_by(schema::api_key::expiresAt().asc())
                .limit(MAX_EXPIRING_API_KEYS_RESULTS)
                .run(ctx)
                .await?;
            Ok(keys)
        }
    }

    fn add_project_member(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::add_project_member::Args,
        _authorized: schema::procedures::add_project_member::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::add_project_member::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        let role = args.args.role;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .add_project_member(&subject, &project_id, &target_account_id, role.as_deref())
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn remove_project_member(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::remove_project_member::Args,
        _authorized: schema::procedures::remove_project_member::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::remove_project_member::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .remove_project_member(&subject, &project_id, &target_account_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_member_role(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::set_project_member_role::Args,
        _authorized: schema::procedures::set_project_member_role::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_member_role::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        let role = args.args.role;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_member_role(&subject, &project_id, &target_account_id, &role)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_member_quota_tier(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::set_project_member_quota_tier::Args,
        _authorized: schema::procedures::set_project_member_quota_tier::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_member_quota_tier::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        let quota_tier = args.args.quotaTier;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_member_quota_tier(
                    &subject,
                    &project_id,
                    &target_account_id,
                    quota_tier.as_deref(),
                )
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_project(project))
        }
    }

    /// The roster's only read path. Authorization is wider than the four mutations above -- any
    /// member may read, not just leads -- and lives in the repository's SQL; see
    /// `StoreRepo::list_project_roster`.
    fn list_project_roster(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::list_project_roster::Args,
        _authorized: schema::procedures::list_project_roster::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_project_roster::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let members = issuer
                .list_project_roster(&subject, &project_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(members.into_iter().map(to_schema_project_member).collect())
        }
    }

    fn delete_account_permanently(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::delete_account_permanently::Args,
        _authorized: schema::procedures::delete_account_permanently::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::delete_account_permanently::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .delete_account(&subject, &account_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_account(account))
        }
    }

    /// Activates a budget policy (ADR-0007): either brand-new rule data (`ruleDataJson`) or a
    /// rollback to an already-existing revision (`revisionId`) --
    /// `docs/runbooks/roll-back-a-budget-policy.md`'s rollback flow needs the latter, since
    /// resubmitting the same rule data through the "new revision" path would collide with
    /// `budget_policy_revisions`' `UNIQUE (policy_set_id, policy_revision)` constraint. Exactly
    /// one of the two must be supplied.
    ///
    /// `policy_store` is bound once at server startup to [`BUDGET_POLICY_SET_ID`] -- there is
    /// genuinely only one policy set today. Rather than silently ignoring a caller-supplied
    /// `policySetId` that doesn't match it, this rejects the mismatch with a clear `BadRequest`:
    /// a caller who typos the policy set id should be told, not silently redirected to the one
    /// real set.
    fn activate_budget_policy(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::activate_budget_policy::Args,
        _authorized: schema::procedures::activate_budget_policy::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::activate_budget_policy::Output,
            CratestackError,
        >,
    > + Send {
        let policy_store = self.policy_store.clone();
        let subject = subject_from_ctx(ctx);
        let policy_set_id = args.args.policySetId;
        let rule_data_json = args.args.ruleDataJson;
        let revision_id = args.args.revisionId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            if policy_set_id != BUDGET_POLICY_SET_ID {
                return Err(CratestackError::BadRequest(format!(
                    "unknown policySetId '{policy_set_id}' -- only '{BUDGET_POLICY_SET_ID}' \
                     exists today"
                )));
            }

            let active_revision = match (rule_data_json, revision_id) {
                (Some(json), None) => policy_store
                    .activate(&json, Some(&subject))
                    .await
                    .map_err(budget_error_to_cratestack_error)?,
                (None, Some(revision_id)) => policy_store
                    .activate_by_revision_id(&revision_id)
                    .await
                    .map_err(budget_error_to_cratestack_error)?,
                (Some(_), Some(_)) => {
                    return Err(CratestackError::BadRequest(
                        "exactly one of ruleDataJson or revisionId must be provided, not both"
                            .to_owned(),
                    ));
                }
                (None, None) => {
                    return Err(CratestackError::BadRequest(
                        "exactly one of ruleDataJson or revisionId must be provided".to_owned(),
                    ));
                }
            };

            Ok(schema::procedures::activate_budget_policy::Output {
                policySetId: policy_set_id,
                activePolicyRevision: active_revision,
            })
        }
    }

    /// Reports the revision genuinely serving `evaluate()` calls right now -- reads the live
    /// in-memory engine state directly (`PolicyStore::active_policy_revision`), no database
    /// round-trip needed. See the schema's `getBudgetPolicyStatus` doc comment for why this
    /// distinction (serving vs. most-recently-attempted) matters for the rollback runbook.
    fn get_budget_policy_status(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::get_budget_policy_status::Args,
        _authorized: schema::procedures::get_budget_policy_status::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::get_budget_policy_status::Output,
            CratestackError,
        >,
    > + Send {
        let policy_store = self.policy_store.clone();
        let subject = subject_from_ctx(ctx);
        let policy_set_id = args.args.policySetId;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            if policy_set_id != BUDGET_POLICY_SET_ID {
                return Err(CratestackError::BadRequest(format!(
                    "unknown policySetId '{policy_set_id}' -- only '{BUDGET_POLICY_SET_ID}' \
                     exists today"
                )));
            }

            Ok(schema::procedures::get_budget_policy_status::Output {
                policySetId: policy_set_id,
                activePolicyRevision: policy_store.active_policy_revision(),
            })
        }
    }

    /// Evaluates a proposed rule-data policy against a caller-supplied scenario, entirely in
    /// memory (#190, ADR-0007). Deliberately does NOT touch `self.policy_store` -- unlike every
    /// other method on this `impl`, this one constructs its own short-lived
    /// [`lightbridge_authz_budget::RuleDataEngine`] directly from the caller's `ruleDataJson`,
    /// calls `evaluate()` on it once, and discards it. There is no code path here capable of
    /// writing to `budget_policy_sets`/`budget_policy_revisions` (no `PolicyStore` reference to
    /// do so through) or to `budget_grants`/`budget_balances` (no repository reference to do so
    /// through either) -- "no side effects" holds by construction, not by discipline. See
    /// `crates/lightbridge-authz-rest/tests/budget_policy_simulate_tests.rs` for the row-count
    /// proof.
    fn simulate_budget_policy(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::simulate_budget_policy::Args,
        _authorized: schema::procedures::simulate_budget_policy::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::simulate_budget_policy::Output,
            CratestackError,
        >,
    > + Send {
        let subject = subject_from_ctx(ctx);
        let rule_data_json = args.args.ruleDataJson;
        let scenario_json = args.args.scenarioJson;
        let requested_amount_str = args.args.requestedAmountMicros;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let requested_amount_micros: i64 = requested_amount_str.trim().parse().map_err(|_| {
                CratestackError::BadRequest(format!(
                    "requestedAmountMicros must be a valid integer, got '{requested_amount_str}'"
                ))
            })?;

            let facts: lightbridge_authz_budget::Facts = serde_json::from_str(&scenario_json)
                .map_err(|e| CratestackError::BadRequest(format!("invalid scenarioJson: {e}")))?;

            // A short-lived engine, constructed and discarded within this one call -- never
            // wired into `self.policy_store`, never persisted, never touches
            // budget_policy_sets/budget_policy_revisions.
            let engine = lightbridge_authz_budget::RuleDataEngine::new(
                &rule_data_json,
                BUDGET_POLICY_EVALUATION_BUDGET,
            )
            .map_err(budget_error_to_cratestack_error)?;

            let decision = lightbridge_authz_budget::PolicyEngine::evaluate(
                &engine,
                &facts,
                requested_amount_micros,
            )
            .await
            .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_decision(decision))
        }
    }

    /// Self-service refill (#191, PR 3.4): a caller asks for more budget for
    /// `budgetAccountId`/`period`, and [`lightbridge_authz_budget::RefillService::request_refill`]
    /// decides -- immediately, or by queuing for a human -- without anyone hand-editing config.
    /// `as_of` is read from the real wall clock here, deliberately: this is the one place in the
    /// whole refill call chain a live `chrono::Utc::now()` read belongs, because this is live
    /// request handling (not a pure, unit-testable domain function -- `RefillRequest.as_of` is a
    /// caller-supplied parameter for exactly this reason, per that struct's own doc comment).
    ///
    /// ## Authorization is `budget:self-refill` alone (#419)
    ///
    /// This procedure used to *additionally* refuse any caller whose validated token carried
    /// [`lightbridge_authz_bearer::CALLER_KIND_CLAIM`] equal to
    /// [`lightbridge_authz_bearer::API_KEY_CALLER_KIND`] (#191/#216) -- intended to keep a service
    /// account from self-refilling ("refills are OIDC users only"). #419 deleted that check: it
    /// fired on humans, not service accounts. `signing.rs`'s `access_token_extra` -- shared by
    /// both `ApiKeyJwtSigner::sign` (API keys) *and* `oauth2_op::store::TokenExchangeOpStore`'s
    /// `handle_token_exchange`/`handle_refresh_token` (the human-plane RFC 8693 exchange) --
    /// stamps this claim on every access token it mints, unconditionally, with no parameter to
    /// vary it by caller. So every human-plane token carried it too, and got refused by a message
    /// asserting the opposite of what was happening. It was also never load-bearing: under
    /// `oauth2.type: self` (this repo's shipped default) an API-key JWT carries no roles claim at
    /// all, so `rpc_authorize`/`CratestackAuthProvider` already refuses it for lacking
    /// `budget:self-refill` before this procedure ever runs; under `external`, tokens from the
    /// upstream IdP's own API-key exchange never carried the claim to begin with (`docs/rbac.md`).
    /// The service-account exclusion this was written for is already correctly expressed by the
    /// permission gate alone: a service account never performs an OIDC dashboard login, so it
    /// never holds a role granting `budget:self-refill` in the first place. See
    /// `crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`'s
    /// `request_refill_accepts_a_real_human_plane_token_that_still_carries_the_stale_api_key_signal`
    /// for the regression coverage minted through the real signing path (not a hand-built
    /// context) that would have caught this before it shipped.
    fn request_budget_refill(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::request_budget_refill::Args,
        _authorized: schema::procedures::request_budget_refill::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::request_budget_refill::Output,
            CratestackError,
        >,
    > + Send {
        let refill_service = self.refill_service.clone();
        let subject = subject_from_ctx(ctx);
        let input = args.args;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let period = lightbridge_authz_budget::Period::parse(&input.period)
                .map_err(budget_error_to_cratestack_error)?;

            // ADR-0015: required -- checked against the active policy's offered set
            // (`allowed_amounts_micros`) inside `RefillService::request_refill` itself.
            let requested_amount_raw = input.requestedAmountMicros.trim();
            let requested_amount_micros: i64 = requested_amount_raw.parse().map_err(|_| {
                CratestackError::BadRequest(format!(
                    "requestedAmountMicros must be a valid integer, got '{requested_amount_raw}'"
                ))
            })?;

            let request = lightbridge_authz_budget::RefillRequest {
                budget_account_id: input.budgetAccountId,
                account_id: input.accountId,
                project_id: input.projectId,
                period,
                idempotency_key: input.idempotencyKey,
                as_of: chrono::Utc::now(),
                requested_amount_micros,
            };

            let created = refill_service
                .request_refill(request)
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_augmentation_request(created))
        }
    }

    /// Read-only companion to [`Self::request_budget_refill`]: the self-service refill amounts
    /// currently offered by the active policy for `period` -- delegating to
    /// [`lightbridge_authz_budget::RefillService::refill_status`], which calls no policy engine
    /// and mutates nothing. `budgetAccountId` is derived from the authenticated subject exactly
    /// like [`Self::get_my_budget_balance`] (never a caller-supplied field, the same structural
    /// self-scoping guarantee), which is why `GetMyBudgetRefillLadderInput` has no target field
    /// either. No caller-kind refusal here -- unlike the mutation above, this is a pure read with
    /// no OIDC-human-only business rule of its own; the shared `budget:self-refill` RBAC gate is
    /// the entire authorization story for this op-id.
    fn get_my_budget_refill_ladder(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::get_my_budget_refill_ladder::Args,
        _authorized: schema::procedures::get_my_budget_refill_ladder::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::get_my_budget_refill_ladder::Output,
            CratestackError,
        >,
    > + Send {
        let refill_service = self.refill_service.clone();
        let subject = subject_from_ctx(ctx);
        let period_str = args.args.period;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            lightbridge_authz_budget::Period::parse(&period_str)
                .map_err(budget_error_to_cratestack_error)?;

            let status = refill_service
                .refill_status()
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_my_budget_refill_ladder(
                subject, period_str, status,
            ))
        }
    }

    /// The admin review queue's read path (#191, PR 3.4; pagination added by #296), delegating
    /// to [`lightbridge_authz_budget::ReviewService::list_pending`]. `budgetAccountId: None`
    /// lists the whole cross-account queue; `Some` scopes to one account -- see that method's own
    /// doc comment.
    ///
    /// Paginated by `createdAt`, oldest-first, cursored via `after` -- see
    /// `authz.cstack`'s `ListPendingAugmentationRequestsInput` doc comment for why this queue
    /// keeps its pre-existing ASC order and uses `after` rather than `listMyBudgetGrants`'s
    /// `before`.
    fn list_pending_augmentation_requests(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::list_pending_augmentation_requests::Args,
        _authorized: schema::procedures::list_pending_augmentation_requests::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_pending_augmentation_requests::Output,
            CratestackError,
        >,
    > + Send {
        let review_service = self.review_service.clone();
        let subject = subject_from_ctx(ctx);
        let input = args.args;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let page_size = resolve_augmentation_requests_page_size(input.limit);
            let requests = review_service
                .list_pending(input.budgetAccountId.as_deref(), input.after, page_size)
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_augmentation_request_page(requests, page_size))
        }
    }

    /// The caller's own request history (#295's remaining half), delegating to
    /// [`lightbridge_authz_budget::RefillService::list_own_history`]. No target field on this
    /// input at all -- the target is always the caller's own budget account (`auth().id`), the
    /// same structural IDOR guard `getMyBudgetBalance`/`listMyBudgetGrants` already give. Returns
    /// every status, not filtered to `pending_review` the way
    /// `listPendingAugmentationRequests` is. Gated at `budget:read-own`.
    ///
    /// Paginated by `createdAt`, newest-first, cursored via `before` -- matching
    /// `listMyBudgetGrants`/`listBudgetGrants`'s own convention exactly (see
    /// `authz.cstack`'s `ListMyAugmentationRequestsInput` doc comment for why this, unlike the
    /// admin queue above, follows that precedent rather than the ASC/`after` shape).
    fn list_my_augmentation_requests(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::list_my_augmentation_requests::Args,
        _authorized: schema::procedures::list_my_augmentation_requests::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_my_augmentation_requests::Output,
            CratestackError,
        >,
    > + Send {
        let refill_service = self.refill_service.clone();
        let subject = subject_from_ctx(ctx);
        let input = args.args;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let page_size = resolve_augmentation_requests_page_size(input.limit);
            let requests = refill_service
                .list_own_history(&subject, input.before, page_size)
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_augmentation_request_page(requests, page_size))
        }
    }

    /// Approves a `pending_review` request (#191, PR 3.4), delegating to
    /// [`lightbridge_authz_budget::ReviewService::approve`]. The reviewing identity is the
    /// authenticated caller's own subject -- there is no separate "act on behalf of" input here,
    /// matching every other procedure in this file.
    fn approve_augmentation_request(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::approve_augmentation_request::Args,
        _authorized: schema::procedures::approve_augmentation_request::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::approve_augmentation_request::Output,
            CratestackError,
        >,
    > + Send {
        let review_service = self.review_service.clone();
        let subject = subject_from_ctx(ctx);
        let request_id = args.args.requestId;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let reviewed = review_service
                .approve(&request_id, &subject)
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_augmentation_request(reviewed))
        }
    }

    /// Rejects a `pending_review` request (#191, PR 3.4), delegating to
    /// [`lightbridge_authz_budget::ReviewService::reject`]. `reason` is non-optional in the
    /// schema (see `authz.cstack`'s `RejectAugmentationRequestInput` doc comment) as well as
    /// validated at runtime by `ReviewService::reject` itself -- this procedure adds no
    /// additional validation of its own, deliberately: one place owns the mandatory-reason rule.
    fn reject_augmentation_request(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::reject_augmentation_request::Args,
        _authorized: schema::procedures::reject_augmentation_request::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::reject_augmentation_request::Output,
            CratestackError,
        >,
    > + Send {
        let review_service = self.review_service.clone();
        let subject = subject_from_ctx(ctx);
        let request_id = args.args.requestId;
        let reason = args.args.reason;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let reviewed = review_service
                .reject(&request_id, &subject, &reason)
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_augmentation_request(reviewed))
        }
    }

    /// "Log out everywhere": revokes every active refresh-token session belonging to the
    /// authenticated caller. `input.reason` is accepted for audit-trail purposes only (not
    /// persisted anywhere today -- there is no session-revocation audit table, unlike the budget
    /// ledger) and never changes which subject is targeted. There is deliberately no subject
    /// field on this procedure's input at all: the target is always `auth().id`, never a
    /// caller-supplied value, which is what makes this procedure structurally incapable of being
    /// aimed at anyone but the caller -- see `revokeSubjectSessions` for the admin equivalent.
    /// Gated at `session:revoke-own` (`rpc_authorize.rs`).
    fn revoke_own_sessions(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        _args: schema::procedures::revoke_own_sessions::Args,
        _authorized: schema::procedures::revoke_own_sessions::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::revoke_own_sessions::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let revoked_count = issuer
                .revoke_sessions(&subject)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_session_revocation_result(revoked_count))
        }
    }

    /// The offboarding kill switch: revokes every active refresh-token session for
    /// `input.accountId`, an operator-supplied target subject (`accounts.id` holds the JWT `sub`
    /// verbatim, ADR-0006). Previously the only way to do this was a manual SQL `UPDATE` against
    /// prod. `@allow(auth() != null)` only in the schema, same as the budget-policy/review
    /// procedures above -- there is no per-tenant ownership relation between an admin and an
    /// arbitrary target subject for a schema `@@allow` to check, so the entire authorization
    /// story is the RBAC gate: `session:revoke`, held only via `lightbridge-admin`'s `*` in the
    /// default role mapping (`docs/rbac.md`).
    fn revoke_subject_sessions(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::revoke_subject_sessions::Args,
        _authorized: schema::procedures::revoke_subject_sessions::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::revoke_subject_sessions::Output,
            CratestackError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let target_account_id = args.args.accountId;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let revoked_count = issuer
                .revoke_sessions(&target_account_id)
                .await
                .map_err(to_cratestack_error)?;
            Ok(to_schema_session_revocation_result(revoked_count))
        }
    }

    /// Reads the caller's own current budget balance for `input.period`. There is no target
    /// field on this input at all -- the target is always `auth().id`, the same structural
    /// guarantee `revokeOwnSessions` gives for session revocation. Gated at `budget:read-own`.
    /// See `BalanceSnapshot::zero`'s doc comment for why "no balance row yet" synthesizes a
    /// zero-valued response rather than an error.
    fn get_my_budget_balance(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::get_my_budget_balance::Args,
        _authorized: schema::procedures::get_my_budget_balance::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::get_my_budget_balance::Output,
            CratestackError,
        >,
    > + Send {
        let budget_repo = self.budget_repo.clone();
        let subject = subject_from_ctx(ctx);
        let period_str = args.args.period;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let period = lightbridge_authz_budget::Period::parse(&period_str)
                .map_err(budget_error_to_cratestack_error)?;

            let snapshot = budget_repo
                .get_balance(&subject, &period)
                .await
                .map_err(budget_error_to_cratestack_error)?
                .unwrap_or_else(|| {
                    lightbridge_authz_budget::repo::BalanceSnapshot::zero(&subject, &period)
                });

            Ok(to_schema_budget_balance(snapshot))
        }
    }

    /// The admin equivalent of `getMyBudgetBalance`: reads any account's balance. Gated at
    /// `budget:read`.
    fn get_budget_balance(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::get_budget_balance::Args,
        _authorized: schema::procedures::get_budget_balance::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::get_budget_balance::Output,
            CratestackError,
        >,
    > + Send {
        let budget_repo = self.budget_repo.clone();
        let subject = subject_from_ctx(ctx);
        let budget_account_id = args.args.budgetAccountId;
        let period_str = args.args.period;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let period = lightbridge_authz_budget::Period::parse(&period_str)
                .map_err(budget_error_to_cratestack_error)?;

            let snapshot = budget_repo
                .get_balance(&budget_account_id, &period)
                .await
                .map_err(budget_error_to_cratestack_error)?
                .unwrap_or_else(|| {
                    lightbridge_authz_budget::repo::BalanceSnapshot::zero(
                        &budget_account_id,
                        &period,
                    )
                });

            Ok(to_schema_budget_balance(snapshot))
        }
    }

    /// The caller's own ledger history, paginated by `createdAt` (ADR-0039 -- never by id). No
    /// target field on this input, same structural guarantee as `getMyBudgetBalance`. Gated at
    /// `budget:read-own`.
    fn list_my_budget_grants(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::list_my_budget_grants::Args,
        _authorized: schema::procedures::list_my_budget_grants::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_my_budget_grants::Output,
            CratestackError,
        >,
    > + Send {
        let budget_repo = self.budget_repo.clone();
        let subject = subject_from_ctx(ctx);
        let input = args.args;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let page = list_budget_grants_page(
                &budget_repo,
                &subject,
                input.period,
                input.before,
                input.limit,
            )
            .await?;
            Ok(page)
        }
    }

    /// The admin equivalent of `listMyBudgetGrants`: any account's ledger history. Gated at
    /// `budget:audit-read`.
    fn list_budget_grants(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::list_budget_grants::Args,
        _authorized: schema::procedures::list_budget_grants::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::list_budget_grants::Output,
            CratestackError,
        >,
    > + Send {
        let budget_repo = self.budget_repo.clone();
        let subject = subject_from_ctx(ctx);
        let input = args.args;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            let page = list_budget_grants_page(
                &budget_repo,
                &input.budgetAccountId,
                input.period,
                input.before,
                input.limit,
            )
            .await?;
            Ok(page)
        }
    }

    /// A direct admin grant, bypassing self-service policy evaluation. Delegates to the same
    /// `BudgetRepo::grant` transactional write path every other grant source uses, with
    /// `source = admin`. Gated at `budget:grant`.
    fn grant_budget(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::grant_budget::Args,
        _authorized: schema::procedures::grant_budget::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::grant_budget::Output, CratestackError>,
    > + Send {
        let budget_repo = self.budget_repo.clone();
        let subject = subject_from_ctx(ctx);
        let input = args.args;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let period = lightbridge_authz_budget::Period::parse(&input.period)
                .map_err(budget_error_to_cratestack_error)?;
            let amount_micros: i64 = input.amountMicros.trim().parse().map_err(|_| {
                CratestackError::BadRequest(format!(
                    "amountMicros must be a valid integer, got '{}'",
                    input.amountMicros
                ))
            })?;

            let grant = budget_repo
                .grant(lightbridge_authz_budget::repo::GrantRequest {
                    budget_account_id: input.budgetAccountId,
                    account_id: input.accountId,
                    project_id: input.projectId,
                    period,
                    amount_micros,
                    source: lightbridge_authz_budget::GrantSource::Admin,
                    actor_id: Some(subject),
                    reason: input.reason,
                    policy_revision: None,
                    matched_rule_ids: None,
                    idempotency_key: input.idempotencyKey,
                    trigger_key: None,
                    expires_at: None,
                })
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_budget_grant_entry(grant))
        }
    }

    /// The compensating-correction counterpart to `grantBudget` (ADR-0009: the ledger is
    /// append-only, so this never mutates `input.grantId`'s row -- it looks it up and writes a
    /// NEW `source = correction` row negating its amount). The correction's idempotency key is
    /// derived from `grantId` (`"revoke:{grantId}"`), so a repeated call for the same grant is
    /// idempotent rather than double-negating. Gated at `budget:revoke`.
    fn revoke_budget_grant(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::revoke_budget_grant::Args,
        _authorized: schema::procedures::revoke_budget_grant::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::revoke_budget_grant::Output,
            CratestackError,
        >,
    > + Send {
        let budget_repo = self.budget_repo.clone();
        let subject = subject_from_ctx(ctx);
        let grant_id = args.args.grantId;
        let reason = args.args.reason;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            let original = budget_repo
                .get_grant_by_id(&grant_id)
                .await
                .map_err(budget_error_to_cratestack_error)?;

            let correction = budget_repo
                .grant(lightbridge_authz_budget::repo::GrantRequest {
                    budget_account_id: original.budget_account_id,
                    account_id: original.account_id,
                    project_id: original.project_id,
                    period: original.period,
                    amount_micros: -original.amount_micros,
                    source: lightbridge_authz_budget::GrantSource::Correction,
                    actor_id: Some(subject),
                    reason: Some(reason),
                    policy_revision: None,
                    matched_rule_ids: None,
                    idempotency_key: Some(format!("revoke:{grant_id}")),
                    trigger_key: None,
                    expires_at: None,
                })
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(to_schema_budget_grant_entry(correction))
        }
    }

    /// Authors a new budget-policy revision WITHOUT activating it (ADR-0007). Delegates to
    /// `PolicyStore::create_revision`, which validates before writing, exactly mirroring
    /// `activateBudgetPolicy`'s "a bad revision never displaces a good one" property for the
    /// write path. Gated at `budget:policy-write`, kept distinct from `budget:policy-activate`.
    fn create_budget_policy_revision(
        &self,
        _db: &schema::Cratestack,
        ctx: &CratestackContext,
        args: schema::procedures::create_budget_policy_revision::Args,
        _authorized: schema::procedures::create_budget_policy_revision::Authorized,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::create_budget_policy_revision::Output,
            CratestackError,
        >,
    > + Send {
        let policy_store = self.policy_store.clone();
        let subject = subject_from_ctx(ctx);
        let policy_set_id = args.args.policySetId;
        let rule_data_json = args.args.ruleDataJson;
        async move {
            let subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;

            if policy_set_id != BUDGET_POLICY_SET_ID {
                return Err(CratestackError::BadRequest(format!(
                    "unknown policySetId '{policy_set_id}' -- only '{BUDGET_POLICY_SET_ID}' \
                     exists today"
                )));
            }

            let new_revision = policy_store
                .create_revision(&rule_data_json, Some(&subject))
                .await
                .map_err(budget_error_to_cratestack_error)?;

            Ok(schema::procedures::create_budget_policy_revision::Output {
                policySetId: policy_set_id,
                revisionId: new_revision.id,
                policyRevision: new_revision.policy_revision,
            })
        }
    }
}

/// Shared page-fetch for `listMyBudgetGrants`/`listBudgetGrants`: parses the optional `period`,
/// resolves the page size, reads one page from `BudgetRepo::list_grants`, and maps it to the
/// schema's `BudgetGrantPage` (`nextCursor` = the last entry's `createdAt`, or `None` when the
/// page came back short of a full page -- i.e. there is nothing further to page to).
async fn list_budget_grants_page(
    budget_repo: &lightbridge_authz_budget::repo::BudgetRepo,
    budget_account_id: &str,
    period_str: Option<String>,
    before: Option<chrono::DateTime<chrono::Utc>>,
    limit: Option<i64>,
) -> std::result::Result<schema::BudgetGrantPage, CratestackError> {
    let period = period_str
        .as_deref()
        .map(lightbridge_authz_budget::Period::parse)
        .transpose()
        .map_err(budget_error_to_cratestack_error)?;
    let page_size = resolve_budget_grants_page_size(limit);

    let grants = budget_repo
        .list_grants(budget_account_id, period.as_ref(), before, page_size)
        .await
        .map_err(budget_error_to_cratestack_error)?;

    let next_cursor = if grants.len() == usize::try_from(page_size).unwrap_or(usize::MAX) {
        grants.last().map(|g| g.created_at)
    } else {
        None
    };

    Ok(schema::BudgetGrantPage {
        entries: grants
            .into_iter()
            .map(to_schema_budget_grant_entry)
            .collect(),
        nextCursor: next_cursor,
    })
}

/// Shared `/`, `/healthz`, `/healthz/startup`, `/healthz/ready` mount, reused by every server
/// router (`build_api_router`/`build_opa_router`/`build_idp_router`) so the probe surface — and
/// its DB-readiness semantics (`readiness_handler`/`is_database_ready`) — can never drift between
/// them. Generic over `S` the same way `well_known_router`/`token_exchange_router` are, so it
/// merges into any router regardless of that router's own state type.
fn probe_router<S>(readiness_pool: Arc<dyn DbPoolTrait>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(health_handler))
        .route("/healthz/startup", get(startup_handler))
        .route(
            "/healthz/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        )
}

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
    resolver: Arc<dyn auth_provider::SubjectResolver>,
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    refill_service: Arc<lightbridge_authz_budget::RefillService>,
    review_service: Arc<lightbridge_authz_budget::ReviewService>,
    budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    cratestack_db: schema::Cratestack,
    readiness_pool: Arc<dyn DbPoolTrait>,
    idempotency_store: Arc<SqlxIdempotencyStore>,
    rate_limit_store: Arc<dyn RateLimitStore>,
    dev_cors: bool,
    rpc_base_path: Option<&str>,
) -> Router {
    let public = probe_router(readiness_pool);

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
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
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
    .layer(RateLimitLayer::new(
        rate_limit_store,
        RateLimitConfig::new(RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SECOND),
    ))
    .layer(axum::middleware::from_fn_with_state(
        RpcAuthorizeState {
            bearer,
            scope: RpcScope::Crud,
        },
        rpc_authorize::rpc_authorize,
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
fn normalize_rpc_base_path(raw: Option<&str>) -> Option<String> {
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
/// `TokenExchangeOpStore::new` also takes `repo` a second time as its own `quota_repo` parameter
/// (ADR-0017): production always passes the same `Arc<StoreRepo>` clone for both, since
/// `project_members` lives on this exact pool with no operational separation from tenant-context
/// resolution -- the duplicate parameter exists purely as an independent test-injection seam, see
/// `TokenExchangeOpStore`'s own `quota_repo` field doc comment for why.
fn build_token_exchange_state(
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
    if cfg.refresh_absolute_ttl_seconds <= 0 {
        return Err(Error::Server(
            "token_exchange refresh_absolute_ttl_seconds must be positive".to_string(),
        ));
    }
    if cfg.refresh_absolute_ttl_seconds <= cfg.refresh_ttl_seconds {
        return Err(Error::Server(
            "token_exchange refresh_absolute_ttl_seconds must be greater than \
             refresh_ttl_seconds, otherwise the chain's absolute cap is reached no later than \
             every individual token's own expiry and refresh_ttl_seconds never takes effect"
                .to_string(),
        ));
    }
    if cfg.device_code_ttl_seconds <= 0 || cfg.device_poll_interval_seconds <= 0 {
        return Err(Error::Server(
            "token_exchange device_code_ttl_seconds and device_poll_interval_seconds must be positive"
                .to_string(),
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
    validate_authorization_code_clients(&oauth2.clients, signing.audience.as_deref())?;
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

    let client_store = oauth2_op::client_store::ConfigClientStore::from_config(&oauth2.clients);
    let assertions = oauth2_op::client_assertion_store::RedisClientAssertionStore::connect(
        redis_url,
        redis_ca_bundle_path,
        CLIENT_ASSERTION_JTI_KEY_PREFIX,
    )?;
    let op_store = Arc::new(oauth2_op::store::TokenExchangeOpStore::new(
        client_store,
        assertions,
        repo.clone(),
        repo,
        budget_repo,
        policy_engine,
        bearer,
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
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: cfg.authorization_code_ttl_seconds,
        access_token_ttl_secs: cfg.access_ttl_seconds.max(0) as u64,
        device_code_ttl_secs: cfg.device_code_ttl_seconds as u64,
        token_exchange_enabled: cfg.enabled,
    };
    let cors_origins = token_endpoint_cors_origins(&oauth2.clients)?;
    Ok(Some(
        token_exchange::TokenExchangeState::new(
            signer,
            op_config,
            op_store,
            cfg.device_verification_uri.clone(),
            cfg.device_code_ttl_seconds as u64,
            cfg.device_poll_interval_seconds as u64,
        )
        .with_cors_origins(cors_origins),
    ))
}

fn token_endpoint_cors_origins(clients: &[OauthClient]) -> Result<Vec<String>> {
    clients
        .iter()
        .filter(|client| {
            client.client_type == OauthClientType::Public
                && client.require_pkce
                && client
                    .grant_types
                    .iter()
                    .any(|grant| grant == "authorization_code")
        })
        .flat_map(|client| client.redirect_uris.iter())
        .map(|redirect_uri| redirect_origin(redirect_uri))
        .collect::<Result<std::collections::BTreeSet<_>>>()
        .map(|origins| origins.into_iter().collect())
}

/// OAuth 2.1 and RFC 9700 (OAuth Security Best Current Practice) recommend PKCE for every client
/// type, not only public ones, specifically to close authorization-code-injection attacks -- a
/// confidential client's client-authentication step at the token endpoint proves who is redeeming
/// the code, not that the code being redeemed is the one THIS session actually requested. This
/// gate therefore applies to every `authorization_code` client regardless of `client_type`; do not
/// reintroduce a `client_type == Public` condition here.
///
/// Also enforces an invariant the introspection endpoint's module doc comment
/// (`token_exchange.rs`) relies on but nothing previously checked: no registered client's
/// `client_id` may equal `oauth2.signing.audience`. That equality is exactly the condition under
/// which a self-signed API-key JWT's `azp` (always the fixed `oauth2.signing.audience` value)
/// would collide with a real OAuth2 client id, making an API-key JWT pass
/// `introspect_endpoint`'s `azp == caller's client_id` gate and introspect as a live token-
/// exchange access token -- defeating the "API keys are structurally not introspectable" claim
/// that doc comment makes. Refusing to start is preferable to a config that silently invalidates
/// that claim.
fn validate_authorization_code_clients(
    clients: &[OauthClient],
    signing_audience: Option<&str>,
) -> Result<()> {
    for client in clients {
        for redirect_uri in &client.redirect_uris {
            redirect_origin(redirect_uri)?;
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
            && (!client.require_pkce || client.redirect_uris.is_empty())
        {
            return Err(Error::Server(
                "authorization_code clients require PKCE and at least one redirect_uri".to_string(),
            ));
        }
        if let Some(audience) = signing_audience
            && client.client_id == audience
        {
            return Err(Error::Server(format!(
                "oauth2.clients client_id {:?} equals oauth2.signing.audience -- a self-signed \
                 API-key JWT's azp would collide with this client id, making API keys \
                 introspectable as token-exchange access tokens",
                client.client_id
            )));
        }
    }
    Ok(())
}

fn redirect_origin(redirect_uri: &str) -> Result<String> {
    let url = reqwest::Url::parse(redirect_uri).map_err(|_| {
        Error::Server("authorization-code redirect_uri must be an absolute URL".to_string())
    })?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none_or(|host| host.contains('*'))
    {
        return Err(Error::Server(
            "authorization-code redirect_uri must have an HTTP(S) origin without credentials"
                .to_string(),
        ));
    }
    Ok(url.origin().ascii_serialization())
}

/// ADR-0025 Stage 1: every serving component -- `authz-api`, `authz-idp`, `authz-opa`,
/// `authz-budget`, `lightbridge-mcp` -- refuses to start without `oauth2.federation.issuer`,
/// loudly, naming both the missing field and the component (the same shape AGENTS.md's "Redis is
/// a mandatory dependency" house rule documents for a different dependency). Presence PLUS
/// [`Federation::validate`]'s offline shape check -- never a live reachability probe against the
/// issuer, matching `oauth2.relying_party`'s own startup-validation posture.
fn require_federation<'a>(oauth2: &'a Oauth2, component: &str) -> Result<&'a Federation> {
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

    // ADR-0007: load whatever is genuinely active in the DB right now, so a fresh startup always
    // agrees with the last successful activation -- this is what proves "no restart needed to see
    // a policy change AND still correct if you do restart" holds for the real running server, not
    // just at the `PolicyStore` unit level.
    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            pool.clone(),
            BUDGET_POLICY_SET_ID,
            BUDGET_POLICY_EVALUATION_BUDGET,
        )
        .await
        .map_err(|e| Error::Server(format!("failed to load active budget policy: {e}")))?,
    );

    // Self-service refill and the admin review queue (#191, PR 3.4). `budget_repo`/
    // `augmentation_repo` are fresh handles against the same `pool` every other hand-written
    // repository on this server uses; `policy_store.engine()` is the SAME live, hot-swappable
    // engine `activateBudgetPolicy`/`getBudgetPolicyStatus` above read/write, so a policy
    // activated at runtime takes effect for refills immediately, with no restart, exactly as it
    // already does for `simulateBudgetPolicy`'s sibling procedures.
    //
    // `usage_service` (`Config.usage_service`) is optional -- see that field's own doc comment.
    // When it is not configured, this degrades to `UnavailableSpendReader` rather than failing
    // server startup: every spend-dependent policy fact then reads `Spend::Unavailable`, which
    // the rule-data evaluator already treats as a fail-closed signal (routes to `manual_review`,
    // never `auto_approve` -- see `UnavailableSpendReader`'s own doc comment for the full
    // reasoning). Choosing to degrade rather than hard-fail (unlike `policy_store` above, which
    // DOES fail startup loudly on a bad load) is deliberate: a missing `usage_service` narrows
    // what self-service refill can decide automatically, it does not make the RPC surface
    // unsafe to serve -- so a deployment that has not wired up the usage service yet can still
    // start, just with every refill routing to manual review until it does. When it IS
    // configured, `UsageServiceSpendReader` calls the usage service's `/usage/v1/spend/query`
    // over HTTP instead of opening a second database connection (see
    // `crates/lightbridge-authz-budget/src/spend.rs`'s module doc comment for why); every way
    // that HTTP call can fail -- unreachable, timeout, non-2xx, unparseable body -- also resolves
    // to `Spend::Unavailable`, never a hard error, so a flaky or down usage service degrades
    // refill decisions the same way a missing config does, rather than failing this server's own
    // requests.
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        pool.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
        pool.clone(),
    ));
    let policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine> = policy_store.engine();
    let spend_reader: Arc<dyn lightbridge_authz_budget::SpendReader> = match usage_service {
        Some(usage_service) => Arc::new(
            lightbridge_authz_budget::UsageServiceSpendReader::new(
                usage_service.base_url.clone(),
                usage_service.insecure_skip_verify,
                usage_service.ca_bundle_path.as_deref(),
                usage_service.client_cert_path.as_deref(),
                usage_service.client_key_path.as_deref(),
                std::time::Duration::from_millis(usage_service.timeout_ms),
            )
            .map_err(|e| {
                Error::Server(format!("failed to build usage-service spend reader: {e}"))
            })?,
        ),
        None => {
            tracing::warn!(
                "usage_service is not configured -- budget refill spend facts will report \
                 Unavailable, and self-service refill decisions that depend on them will fail \
                 closed to manual review"
            );
            Arc::new(lightbridge_authz_budget::UnavailableSpendReader)
        }
    };
    let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_engine,
        spend_reader,
    ));
    let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
        budget_repo.clone(),
        augmentation_repo,
    ));

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
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));
    // ADR-0025 Stage 2: `federation` above is already `require_federation`'s validated value.
    let resolver: Arc<dyn auth_provider::SubjectResolver> =
        Arc::new(auth_provider::FederatedSubjectResolver::new(
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

    // Idempotency store (Postgres-backed, cratestack sqlx); create its table before serving
    // (ADR-0003, "Idempotency").
    let idempotency_store = Arc::new(SqlxIdempotencyStore::new(cratestack_pool.clone()));
    idempotency_store
        .ensure_schema()
        .await
        .map_err(|e| Error::Server(format!("failed to ensure idempotency schema: {e}")))?;

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
    tracing::info!(
        server = "authz-api",
        address = %api.address,
        port = api.port,
        oauth2_type = ?oauth2.oauth2_type,
        signing_enabled,
        issuance_enabled,
        "starting api server"
    );

    serve_tls("API", &api.address, api.port, &api.tls, app).await
}

/// Assembles the OPA server router (public probes + Basic-auth introspection/resolve routes).
/// Separated from `start_opa_server` for testability.
pub fn build_opa_router(state: Arc<OpaState>, readiness_pool: Arc<dyn DbPoolTrait>) -> Router {
    let public = probe_router(readiness_pool)
        .merge(SwaggerUi::new("/v1/opa/docs").url("/v1/opa/openapi.json", OpaDoc::openapi()));

    let protected = opa_router(state.clone()).with_state(state.clone());

    public.merge(protected).with_state(state)
}

pub async fn start_opa_server(
    opa: &OpaServer,
    pool: Arc<dyn DbPoolTrait>,
    billing: &Billing,
    oauth2: &Oauth2,
) -> Result<()> {
    let federation = require_federation(oauth2, "authz-opa")?;
    let readiness_pool = pool.clone();
    // ADR-0025 Stage 2: `federation` above is already `require_federation`'s validated value.
    let resolver: Arc<dyn auth_provider::SubjectResolver> =
        Arc::new(auth_provider::FederatedSubjectResolver::new(
            Arc::new(StoreRepo::new(pool.clone())),
            oauth2.signing.as_ref().map(|s| s.issuer.clone()),
            federation.issuer.clone(),
        ));
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let api_key_audience = oauth2
        .signing
        .as_ref()
        .and_then(|signing| signing.audience.clone());
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
        billing: Arc::new(billing.clone()),
        api_key_audience,
        resolver,
        federation_issuer: federation.issuer.clone(),
    });

    let app = build_opa_router(state, readiness_pool);

    tracing::info!(
        server = "authz-opa",
        address = %opa.address,
        port = opa.port,
        "starting opa server"
    );

    serve_tls("OPA", &opa.address, opa.port, &opa.tls, app).await
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
/// unconditionally the API route, `GET /ui`, `GET /ui/`, and every `GET /ui/<anything>` are
/// unconditionally the SPA (client-side routing falls back to `index.html`), and a path outside
/// `/ui` that matches no protocol route is a normal `404` — the SPA is no longer a catch-all for
/// the whole server. This also makes the safety property strictly path-scoping rather than
/// mount-order: static assets and protocol routes now occupy disjoint path spaces, so they cannot
/// collide regardless of merge order, whereas the old fallback-based mount was safe only because
/// a real route always beats a fallback. See `static_assets::static_assets_fallback`'s own doc
/// comment for the caching/CSP posture applied to everything served from `static_dir`.
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
pub fn build_idp_router(
    oauth2: &Oauth2,
    signing: &JwtSigning,
    signing_repo: Arc<StoreRepo>,
    token_exchange: token_exchange::TokenExchangeState,
    readiness_pool: Arc<dyn DbPoolTrait>,
    static_dir: impl AsRef<std::path::Path>,
    relying_party: Arc<relying_party::KeycloakRelyingParty>,
) -> Router {
    let mut router = probe_router(readiness_pool);
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
/// `authz-idp` calls [`signing::bootstrap_signing_key`] on startup, exactly as `authz-api`
/// (`start_api_server`) and `lightbridge-mcp` already do — making this the *third* concurrent
/// bootstrapper against the shared `signing_keys` table, not a new kind of participant. See
/// [`signing::bootstrap_signing_key`]'s own doc comment for why a third caller is exactly as safe
/// as the two that already exist, and for the `max_key_age_days`-disagreement analysis.
pub async fn start_idp_server(
    idp: &IdpServer,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
    redis: &Option<Redis>,
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
    // issuer are kept separate.
    let relying_party = Arc::new(relying_party::KeycloakRelyingParty::new(
        rp_config,
        federation.issuer.clone(),
        federation.effective_discovery_url().to_string(),
        oauth2.jwks_url.clone(),
        Arc::new(StoreRepo::new(pool.clone())),
        device_verify_rate_limit_store,
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
    signing::bootstrap_signing_key(&signing_repo, signing).await?;

    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

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

    let app = build_idp_router(
        oauth2,
        signing,
        signing_repo,
        token_exchange_state,
        readiness_pool,
        &idp.static_dir,
        relying_party,
    );

    tracing::info!(
        server = "authz-idp",
        address = %idp.address,
        port = idp.port,
        "starting idp server"
    );

    serve_tls("IDP", &idp.address, idp.port, &idp.tls, app).await
}

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
    cratestack_db: schema::Cratestack,
    readiness_pool: Arc<dyn DbPoolTrait>,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    resolver: Arc<dyn auth_provider::SubjectResolver>,
    idempotency_store: Arc<SqlxIdempotencyStore>,
    rate_limit_store: Arc<dyn RateLimitStore>,
    dev_cors: bool,
) -> Router {
    let public = probe_router(readiness_pool);

    let rpc = schema::axum::rpc_router(
        cratestack_db,
        Procedures::new(
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
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
    .layer(RateLimitLayer::new(
        rate_limit_store,
        RateLimitConfig::new(RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SECOND),
    ))
    .layer(axum::middleware::from_fn_with_state(
        RpcAuthorizeState {
            bearer,
            scope: RpcScope::Budget,
        },
        rpc_authorize::rpc_authorize,
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

    // ADR-0007: load whatever is genuinely active in the DB right now, so a fresh startup always
    // agrees with the last successful activation, exactly like `start_api_server`'s identical load
    // did before the cutover.
    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            pool.clone(),
            BUDGET_POLICY_SET_ID,
            BUDGET_POLICY_EVALUATION_BUDGET,
        )
        .await
        .map_err(|e| Error::Server(format!("failed to load active budget policy: {e}")))?,
    );

    // Self-service refill and the admin review queue (#191, PR 3.4) -- see `start_api_server`'s
    // identical construction for the full spend-reader degrade-not-fail reasoning
    // (`UnavailableSpendReader` on a missing/unreachable `usage_service`, never a hard startup
    // failure or an auto-approve).
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        pool.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
        pool.clone(),
    ));
    let policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine> = policy_store.engine();
    let spend_reader: Arc<dyn lightbridge_authz_budget::SpendReader> = match usage_service {
        Some(usage_service) => Arc::new(
            lightbridge_authz_budget::UsageServiceSpendReader::new(
                usage_service.base_url.clone(),
                usage_service.insecure_skip_verify,
                usage_service.ca_bundle_path.as_deref(),
                usage_service.client_cert_path.as_deref(),
                usage_service.client_key_path.as_deref(),
                std::time::Duration::from_millis(usage_service.timeout_ms),
            )
            .map_err(|e| {
                Error::Server(format!("failed to build usage-service spend reader: {e}"))
            })?,
        ),
        None => {
            tracing::warn!(
                "usage_service is not configured -- budget refill spend facts will report \
                 Unavailable, and self-service refill decisions that depend on them will fail \
                 closed to manual review"
            );
            Arc::new(lightbridge_authz_budget::UnavailableSpendReader)
        }
    };
    let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_engine,
        spend_reader,
    ));
    let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
        budget_repo.clone(),
        augmentation_repo,
    ));

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
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));
    // ADR-0025 Stage 2: `federation` above is already `require_federation`'s validated value.
    let resolver: Arc<dyn auth_provider::SubjectResolver> =
        Arc::new(auth_provider::FederatedSubjectResolver::new(
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

    let idempotency_store = Arc::new(SqlxIdempotencyStore::new(cratestack_pool.clone()));
    idempotency_store
        .ensure_schema()
        .await
        .map_err(|e| Error::Server(format!("failed to ensure idempotency schema: {e}")))?;

    // Own key prefix ("authz-budget", not "authz-api") so the two services' token buckets never
    // share state, even though they may point at the same Redis instance.
    let rate_limit_store =
        build_redis_rate_limit_store(&redis.url, redis.ca_bundle_path.as_deref(), "authz-budget")?;

    let dev_cors = dev_cors_enabled();
    let app = build_budget_router(
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
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
    tracing::info!(
        server = "authz-budget",
        address = %budget.address,
        port = budget.port,
        rpc_base_path = BUDGET_RPC_BASE_PATH,
        "starting budget server"
    );

    serve_tls("BUDGET", &budget.address, budget.port, &budget.tls, app).await
}

async fn root_handler() -> (StatusCode, Json<RootResponse>) {
    let response = RootResponse {
        status: "ok".to_string(),
        message: "Welcome to Lightbridge Authz API".to_string(),
    };
    (StatusCode::OK, Json(response))
}

async fn health_handler() -> StatusCode {
    StatusCode::OK
}

async fn startup_handler() -> StatusCode {
    StatusCode::OK
}

async fn readiness_handler(pool: Arc<dyn DbPoolTrait>) -> StatusCode {
    if is_database_ready(pool.as_ref()).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::introspect::introspect_api_key,
        crate::handlers::idp::resolve_context
    ),
    components(
        schemas(
            crate::models::IntrospectRequest,
            crate::models::IntrospectResponse,
            lightbridge_authz_core::ApiKey,
            lightbridge_authz_core::Project,
            lightbridge_authz_core::Account,
            lightbridge_authz_core::ResolveContextRequest,
            lightbridge_authz_core::ResolvedContext
        )
    ),
    tags(
        (name = "authorino", description = "Authorino integration"),
        (name = "idp", description = "Identity request resolution")
    )
)]
struct OpaDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use lightbridge_authz_bearer::{BearerTokenServiceTrait, TokenInfo};
    use lightbridge_authz_core::config::{Oauth2TokenExchange, Oauth2Type};
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;

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
            device_code_ttl_seconds: 600,
            device_poll_interval_seconds: 5,
            device_verification_uri: "https://authz.example.test/device/verify".to_string(),
        }
    }

    fn signing_cfg() -> lightbridge_authz_core::config::JwtSigning {
        lightbridge_authz_core::config::JwtSigning {
            issuer: "https://authz.example.test".to_string(),
            audience: None,
            ttl_seconds: 7_776_000,
            max_key_age_days: 30,
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

    #[tokio::test]
    async fn build_token_exchange_state_rejects_refresh_absolute_ttl_not_longer_than_refresh_ttl() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        let mut cfg = exchange_cfg();
        cfg.refresh_ttl_seconds = 2_592_000;
        cfg.refresh_absolute_ttl_seconds = 2_592_000;
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
                "expected an error when refresh_absolute_ttl_seconds does not exceed refresh_ttl_seconds"
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
        oauth2.clients = vec![OauthClient {
            client_id: "shared-audience".to_string(),
            client_type: OauthClientType::Public,
            scopes: vec!["openid".to_string()],
            grant_types: vec!["refresh_token".to_string()],
            allowed_audiences: vec!["shared-audience".to_string()],
            jwks: None,
            redirect_uris: Vec::new(),
            require_pkce: false,
        }];
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
        oauth2.clients = vec![OauthClient {
            client_id: "a-real-oauth-client".to_string(),
            client_type: OauthClientType::Public,
            scopes: vec!["openid".to_string()],
            grant_types: vec!["refresh_token".to_string()],
            allowed_audiences: vec!["a-real-oauth-client".to_string()],
            jwks: None,
            redirect_uris: Vec::new(),
            require_pkce: false,
        }];
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
