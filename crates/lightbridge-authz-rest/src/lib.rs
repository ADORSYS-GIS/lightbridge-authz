use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, CreateAccount, CreateApiKey, Project, ProjectMember,
    RotateApiKey, async_trait,
    config::{
        ApiServer, BasicAuth, Billing, BudgetServer, IdpServer, ModelCatalog, Oauth2,
        OauthClientType, OpaServer, QuotaTiers, Redis, UsageServiceClient,
    },
    db::{DbPoolTrait, is_database_ready},
    error::{Error, Result},
    server::{dev_cors_enabled, serve_tls},
};

pub mod auth_provider;
pub mod codec;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod oauth2_op;
pub mod ratelimit_redis;
pub mod redis_tls;
pub mod routers;
pub mod rpc_authorize;
pub mod signing;
pub mod token_exchange;

use auth_provider::{ACCESS_TOKEN_CONTEXT_KEY, CALLER_KIND_CONTEXT_KEY, CratestackAuthProvider};
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

    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Option<Project>> {
        StoreRepo::get_project(self, subject, project_id).await
    }

    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Option<Account>> {
        StoreRepo::get_account(self, subject, account_id).await
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
        StoreRepo::resolve_context(self, subject, project_id).await
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
/// `RefillStatus` itself -- the domain type only needs to answer "which tier, what ladder", not
/// echo back the request that produced it.
fn to_schema_my_budget_refill_ladder(
    budget_account_id: String,
    period: String,
    status: lightbridge_authz_budget::RefillStatus,
) -> schema::MyBudgetRefillLadder {
    schema::MyBudgetRefillLadder {
        budgetAccountId: budget_account_id,
        period,
        currentTier: status.current_tier.to_string(),
        currentTierAmountMicros: status.current_tier.amount().get().to_string(),
        nextTier: status.next_tier.map(|tier| tier.to_string()),
        nextTierAmountMicros: status.next_tier.map(|tier| tier.amount().get().to_string()),
        ladder: status
            .ladder
            .into_iter()
            .map(|rung| schema::BudgetLadderRung {
                tier: rung.tier.to_string(),
                amountMicros: rung.amount_micros.to_string(),
            })
            .collect(),
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

/// The caller-kind signal stashed into the context by [`CratestackAuthProvider`], when the
/// validated token carried [`lightbridge_authz_bearer::CALLER_KIND_CLAIM`]. `None` means the claim
/// was absent, which must be treated as "unknown" -- see that constant's docs.
fn caller_kind_from_ctx(ctx: &CratestackContext) -> Option<String> {
    match ctx.extensions.get(CALLER_KIND_CONTEXT_KEY) {
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
                        expires_at: input.expiresAt,
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
    /// ## Internal/API-key-client refusal (#191/#216)
    ///
    /// #191's own acceptance criteria require this operation to be refused for an internal or
    /// API-key-derived caller -- "refills are OIDC users only". This is enforced by refusing
    /// whenever the validated token carries [`lightbridge_authz_bearer::CALLER_KIND_CLAIM`] equal
    /// to [`lightbridge_authz_bearer::API_KEY_CALLER_KIND`] (projected into the context by
    /// [`CratestackAuthProvider`] as [`auth_provider::CALLER_KIND_CONTEXT_KEY`]).
    ///
    /// **Coverage differs by `oauth2.type`** (see #216's investigation for the full analysis of
    /// why no existing claim -- `aud` included -- reliably distinguished the two caller kinds):
    /// - `oauth2.type: self`: fully closed. `lightbridge_authz_rest::signing::ApiKeyJwtSigner`
    ///   stamps this claim on every self-signed API-key JWT it mints, unconditionally, so it is
    ///   present precisely when the caller is API-key-derived. This is the mode this repo ships by
    ///   default (`config/default.yaml`, `.docker/authz/container.yaml`).
    /// - `oauth2.type: external`: **not yet closed**. Tokens minted by the upstream IdP's own
    ///   API-key token-exchange flow do not carry this claim until that flow (outside this repo --
    ///   see `docs/rbac.md`) is updated to stamp it. Until then, an API-key-derived caller
    ///   authenticated under `external` is indistinguishable from a human one at this layer, and
    ///   is not refused. Tracked as the remaining scope of #216.
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
        let caller_kind = caller_kind_from_ctx(ctx);
        let input = args.args;
        async move {
            let _subject = subject
                .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
            if caller_kind.as_deref() == Some(lightbridge_authz_bearer::API_KEY_CALLER_KIND) {
                return Err(CratestackError::Forbidden(
                    "self-service budget refills are for OIDC human callers only".to_owned(),
                ));
            }

            let period = lightbridge_authz_budget::Period::parse(&input.period)
                .map_err(budget_error_to_cratestack_error)?;

            // ADR-0015: optional and additive -- `None` when the caller omits the field
            // preserves the pre-ADR-0015 wire shape exactly (`RefillRequest::
            // requested_amount_micros`'s own doc comment covers why).
            let requested_amount_micros = input
                .requestedAmountMicros
                .map(|raw| {
                    raw.trim().parse::<i64>().map_err(|_| {
                        CratestackError::BadRequest(format!(
                            "requestedAmountMicros must be a valid integer, got '{raw}'"
                        ))
                    })
                })
                .transpose()?;

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

    /// Read-only companion to [`Self::request_budget_refill`]: where the caller currently sits on
    /// the ADR-0008 ladder for `period`, and what the next refill would grant if approved --
    /// delegating to [`lightbridge_authz_budget::RefillService::refill_status`], which calls no
    /// policy engine and mutates nothing. `budgetAccountId` is derived from the authenticated
    /// subject exactly like [`Self::get_my_budget_balance`] (never a caller-supplied field, the
    /// same structural self-scoping guarantee), which is why `GetMyBudgetRefillLadderInput` has no
    /// target field either. No caller-kind refusal here -- unlike the mutation above, this is a
    /// pure read with no OIDC-human-only business rule of its own; the shared
    /// `budget:self-refill` RBAC gate is the entire authorization story for this op-id.
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
            let period = lightbridge_authz_budget::Period::parse(&period_str)
                .map_err(budget_error_to_cratestack_error)?;

            let status = refill_service
                .refill_status(&subject, &period)
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

/// Derives the two `well_known_router` mount parameters (`token_exchange_scopes`,
/// `private_key_jwt_supported`) from `oauth2`. Used by `build_idp_router` — `authz-idp` is now the
/// only server that mounts `well_known_router` at all; `authz-api` stopped serving OIDC
/// discovery/JWKS once the `auth.ai.camer.digital` ingress was repointed at `authz-idp` (see
/// `build_api_router`'s doc comment). Kept as its own function rather than inlined into
/// `build_idp_router` so a future second self-signed-JWKS server can reuse it the same way
/// `build_api_router` used to.
fn well_known_mount_params(oauth2: &Oauth2) -> (Option<Vec<String>>, bool) {
    let token_exchange_scopes = oauth2
        .token_exchange
        .as_ref()
        .filter(|t| t.enabled)
        .map(|t| t.allowed_scopes.clone());
    let private_key_jwt_supported = oauth2
        .clients
        .iter()
        .any(|c| c.client_type == OauthClientType::Confidential);
    (token_exchange_scopes, private_key_jwt_supported)
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
        LenientCborCodec::default(),
        CratestackAuthProvider::new(bearer.clone(), RpcScope::Crud),
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
/// `Ok(None)` when the feature is off; errors on invalid config so startup fails fast.
///
/// ADR-0011 phase 2: builds the config-defined `ClientStore` (Decision 5) and the Redis-backed
/// `ClientAssertionStore` (Decision 6) that together let `oauth2_op::store::TokenExchangeOpStore`
/// implement `authkestra_op::store::OpStore`.
fn build_token_exchange_state(
    oauth2: &Oauth2,
    repo: Arc<StoreRepo>,
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
    if cfg.access_ttl_seconds <= 0 || cfg.refresh_ttl_seconds <= 0 {
        return Err(Error::Server(
            "token_exchange access_ttl_seconds and refresh_ttl_seconds must be positive"
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
    let signer = signing::ApiKeyJwtSigner::from_config(signing, repo.clone())?;

    let client_store = oauth2_op::client_store::ConfigClientStore::from_config(&oauth2.clients);
    let assertions = oauth2_op::client_assertion_store::RedisClientAssertionStore::connect(
        redis_url,
        redis_ca_bundle_path,
        CLIENT_ASSERTION_JTI_KEY_PREFIX,
    )?;
    let op_store = Arc::new(oauth2_op::store::TokenExchangeOpStore::new(
        client_store,
        assertions,
        repo,
        bearer,
        cfg.clone(),
    ));
    let op_config = authkestra_op::config::OpConfig {
        issuer: signing.issuer.clone(),
        scopes_supported: cfg.allowed_scopes.clone(),
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            token_exchange::TOKEN_EXCHANGE_GRANT.to_string(),
            token_exchange::REFRESH_TOKEN_GRANT.to_string(),
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: 0,
        access_token_ttl_secs: cfg.access_ttl_seconds.max(0) as u64,
        device_code_ttl_secs: 0,
        token_exchange_enabled: cfg.enabled,
    };
    Ok(Some(token_exchange::TokenExchangeState::new(
        signer, op_config, op_store,
    )))
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
    redis: &Option<Redis>,
    usage_service: &Option<UsageServiceClient>,
) -> Result<()> {
    billing.validate()?;
    oauth2.rbac.validate()?;

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
    )?);
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

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
) -> Result<()> {
    let readiness_pool = pool.clone();
    let repo: Arc<dyn OpaRepoTrait> = Arc::new(StoreRepo::new(pool));
    let state = Arc::new(OpaState {
        repo,
        basic_auth: opa.basic_auth.clone(),
        billing: Arc::new(billing.clone()),
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
pub fn build_idp_router(
    oauth2: &Oauth2,
    signing_repo: Arc<StoreRepo>,
    token_exchange: Option<token_exchange::TokenExchangeState>,
    readiness_pool: Arc<dyn DbPoolTrait>,
) -> Router {
    let mut router = probe_router(readiness_pool);

    let (token_exchange_scopes, private_key_jwt_supported) = well_known_mount_params(oauth2);
    if oauth2.is_self_signed()
        && let Some(signing) = oauth2.signing.as_ref()
    {
        router = router.merge(signing::well_known_router(
            &signing.issuer,
            signing_repo,
            token_exchange_scopes,
            private_key_jwt_supported,
        ));
    }

    if let Some(te_state) = token_exchange {
        router = router.merge(token_exchange::token_exchange_router(te_state));
    }

    router
}

/// Starts `authz-idp` (ADR-0012): the OIDC broker service carrying `/oauth2/token`,
/// `/oauth2/revoke`, and `.well-known/*`. Deliberately thin next to `start_api_server` — no RPC
/// CRUD surface, no budget domain, no idempotency/rate-limit layers — because
/// `well_known_router`/`token_exchange_router` need none of that; every route this server mounts
/// is public (see [`config::IdpServer`]'s doc comment).
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

    let readiness_pool = pool.clone();
    let signing_repo = Arc::new(StoreRepo::new(pool));
    signing::bootstrap_signing_key(&signing_repo, signing).await?;

    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

    // Redis is required unconditionally for authz-idp -- every lightbridge-authz serving role
    // that isn't explicitly freed from it (authz-opa, lightbridge-mcp) needs Redis-backed caching,
    // not only when `oauth2.token_exchange` happens to be enabled today (that used to be the only
    // gate; it no longer is -- see AGENTS.md's "Redis is a mandatory dependency" house rule).
    // Mirrors start_api_server's/start_budget_server's identical unconditional check.
    // `build_token_exchange_state` itself still no-ops to `Ok(None)` when token_exchange is
    // disabled (see its own doc comment), so this changes only whether a *missing* redis config
    // is tolerated, never whether token exchange itself is attempted.
    let redis = redis.as_ref().ok_or_else(|| {
        Error::Server(
            "redis config is required for authz-idp (set `redis.url`) -- mandatory for every \
             authz-idp deployment, not only when oauth2.token_exchange is enabled"
                .to_string(),
        )
    })?;

    let token_exchange_state = build_token_exchange_state(
        oauth2,
        signing_repo.clone(),
        bearer_service,
        &redis.url,
        redis.ca_bundle_path.as_deref(),
    )?;
    let token_exchange_enabled = token_exchange_state.is_some();

    let app = build_idp_router(oauth2, signing_repo, token_exchange_state, readiness_pool);

    tracing::info!(
        server = "authz-idp",
        address = %idp.address,
        port = idp.port,
        token_exchange_enabled,
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
        LenientCborCodec::default(),
        CratestackAuthProvider::new(bearer.clone(), RpcScope::Budget),
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
    redis: &Option<Redis>,
    usage_service: &Option<UsageServiceClient>,
) -> Result<()> {
    billing.validate()?;
    oauth2.rbac.validate()?;

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
    )?);
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

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

    fn noop_bearer() -> Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> {
        Arc::new(NoopBearer)
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
            rbac: Default::default(),
            clients: Vec::new(),
        }
    }

    /// Unreachable but syntactically valid -- `RedisClientAssertionStore::connect` is lazy (see
    /// its own doc comment), so building `TokenExchangeState` never actually dials this.
    const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";

    fn exchange_cfg() -> Oauth2TokenExchange {
        Oauth2TokenExchange {
            enabled: true,
            access_ttl_seconds: 900,
            refresh_ttl_seconds: 2_592_000,
            allowed_scopes: vec!["openid".to_string()],
            refresh_absolute_ttl_seconds: 7_776_000,
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

    #[tokio::test]
    async fn build_token_exchange_state_is_none_when_disabled() {
        let oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        let result = build_token_exchange_state(
            &oauth2,
            lazy_signing_repo(),
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
            noop_bearer(),
            UNREACHABLE_REDIS_URL,
            None,
        ) else {
            panic!("expected an error for a non-positive ttl");
        };
        assert!(format!("{err}").contains("must be positive"));
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
}
