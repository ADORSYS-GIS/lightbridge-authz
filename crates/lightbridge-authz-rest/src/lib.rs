use axum::{Json, Router, http::StatusCode, routing::get};
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, CreateAccount, CreateApiKey, Project, ProjectMember,
    RotateApiKey, async_trait,
    config::{ApiServer, BasicAuth, Billing, Oauth2, OpaServer, Redis},
    db::{DbPoolTrait, is_database_ready},
    error::{Error, Result},
    server::{dev_cors_enabled, serve_tls},
};

pub mod auth_provider;
pub mod codec;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod ratelimit_redis;
pub mod routers;
pub mod rpc_authorize;
pub mod signing;
pub mod token_exchange;

use auth_provider::{ACCESS_TOKEN_CONTEXT_KEY, CratestackAuthProvider};
use codec::LenientCborCodec;
use handlers::AuthzStoreImpl;
use ratelimit_redis::build_redis_rate_limit_store;
use routers::opa_router;

use cratestack::idempotency::IdempotencyLayer;
use cratestack::ratelimit::{RateLimitConfig, RateLimitLayer, RateLimitStore};
use cratestack::{CodecSet, CoolContext, CoolError, SqlxIdempotencyStore, Value};
use cratestack_codec_json::JsonCodec;
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

/// Maps a core repository `Error` (reused hand-written sqlx) into cratestack's `CoolError` so an RPC
/// procedure failure surfaces with the right HTTP status through the RPC error envelope.
fn to_cool_error(err: Error) -> CoolError {
    match err {
        Error::NotFound => CoolError::NotFound("not found".to_owned()),
        Error::Forbidden(m) => CoolError::Forbidden(m),
        Error::Conflict(m) => CoolError::Conflict(m),
        Error::BadRequest(m) => CoolError::BadRequest(m),
        other => CoolError::Internal(other.to_string()),
    }
}

/// Maps a [`lightbridge_authz_budget::BudgetError`] into cratestack's `CoolError`, mirroring
/// [`to_cool_error`] above for the (unrelated) core `Error` type. Exhaustive match, no wildcard
/// arm, so a new `BudgetError` variant fails this crate's build until it is triaged here rather
/// than silently falling into some default status.
fn budget_error_to_cool_error(err: lightbridge_authz_budget::BudgetError) -> CoolError {
    use lightbridge_authz_budget::BudgetError;
    match err {
        BudgetError::InvalidRuleData(m) => CoolError::BadRequest(m),
        BudgetError::InvalidAmount(_)
        | BudgetError::InvalidPeriod(_)
        | BudgetError::UnknownSource(_)
        | BudgetError::UnknownTier(_)
        | BudgetError::UnknownStatus(_)
        | BudgetError::InvalidReviewOutcome(_)
        | BudgetError::MissingRejectionReason => CoolError::BadRequest(err.to_string()),
        BudgetError::AlreadyGranted | BudgetError::AlreadyReviewed(_) => {
            CoolError::Conflict(err.to_string())
        }
        BudgetError::PolicyDenied(_) => CoolError::Forbidden(err.to_string()),
        BudgetError::NotFound(m) => CoolError::NotFound(m),
        BudgetError::StorageFailed(m) => CoolError::Internal(m),
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

/// The validated caller's subject, projected as `auth().id` by [`CratestackAuthProvider`].
fn subject_from_ctx(ctx: &CoolContext) -> Option<String> {
    match ctx.auth_field("id") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// The caller's raw access token, stashed into the context by [`CratestackAuthProvider`] so the
/// rotate procedure's downstream secret issuance can reuse it (email profile / token exchange).
fn access_token_from_ctx(ctx: &CoolContext) -> Option<String> {
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
#[derive(Clone)]
pub struct Procedures {
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
}

impl Procedures {
    pub fn new(
        issuer: Arc<AuthzStoreImpl>,
        policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    ) -> Self {
        Self {
            issuer,
            policy_store,
        }
    }
}

impl schema::procedures::ProcedureRegistry for Procedures {
    fn create_account(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::create_account::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::create_account::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let default_quota = args.args.defaultQuota;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .create_account(&subject, CreateAccount { default_quota })
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn rotate_api_key(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::rotate_api_key::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::rotate_api_key::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let access_token = access_token_from_ctx(ctx);
        let key_id = args.args.keyId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
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
                .map_err(to_cool_error)?;
            Ok(to_schema_api_key_secret(secret))
        }
    }

    fn create_api_key(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::create_api_key::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::create_api_key::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let access_token = access_token_from_ctx(ctx);
        let input = args.args;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
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
                .map_err(to_cool_error)?;
            Ok(to_schema_api_key_secret(secret))
        }
    }

    fn disable_account(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::disable_account::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::disable_account::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .disable_account(&subject, &account_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn enable_account(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::enable_account::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::enable_account::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .enable_account(&subject, &account_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_account(account))
        }
    }

    fn disable_project(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::disable_project::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::disable_project::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .disable_project(&subject, &project_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn enable_project(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::enable_project::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::enable_project::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .enable_project(&subject, &project_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_default_project(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::set_default_project::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::set_default_project::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_default_project(&subject, &project_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn revoke_api_key(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::revoke_api_key::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::revoke_api_key::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let key_id = args.args.keyId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let key = issuer
                .revoke_api_key(&subject, &key_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_api_key(key))
        }
    }

    fn add_project_member(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::add_project_member::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::add_project_member::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        let role = args.args.role;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .add_project_member(&subject, &project_id, &target_account_id, role.as_deref())
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn remove_project_member(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::remove_project_member::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::remove_project_member::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .remove_project_member(&subject, &project_id, &target_account_id)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_member_role(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::set_project_member_role::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_member_role::Output,
            CoolError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        let role = args.args.role;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_member_role(&subject, &project_id, &target_account_id, &role)
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    fn set_project_member_quota_tier(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::set_project_member_quota_tier::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::set_project_member_quota_tier::Output,
            CoolError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        let target_account_id = args.args.accountId;
        let quota_tier = args.args.quotaTier;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let project = issuer
                .set_project_member_quota_tier(
                    &subject,
                    &project_id,
                    &target_account_id,
                    quota_tier.as_deref(),
                )
                .await
                .map_err(to_cool_error)?;
            Ok(to_schema_project(project))
        }
    }

    /// The roster's only read path. Authorization is wider than the four mutations above -- any
    /// member may read, not just leads -- and lives in the repository's SQL; see
    /// `StoreRepo::list_project_roster`.
    fn list_project_roster(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::list_project_roster::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::list_project_roster::Output, CoolError>,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let project_id = args.args.projectId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let members = issuer
                .list_project_roster(&subject, &project_id)
                .await
                .map_err(to_cool_error)?;
            Ok(members.into_iter().map(to_schema_project_member).collect())
        }
    }

    fn delete_account_permanently(
        &self,
        _db: &schema::Cratestack,
        ctx: &CoolContext,
        args: schema::procedures::delete_account_permanently::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::delete_account_permanently::Output,
            CoolError,
        >,
    > + Send {
        let issuer = self.issuer.clone();
        let subject = subject_from_ctx(ctx);
        let account_id = args.args.accountId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;
            let account = issuer
                .delete_account(&subject, &account_id)
                .await
                .map_err(to_cool_error)?;
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
        ctx: &CoolContext,
        args: schema::procedures::activate_budget_policy::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::activate_budget_policy::Output, CoolError>,
    > + Send {
        let policy_store = self.policy_store.clone();
        let subject = subject_from_ctx(ctx);
        let policy_set_id = args.args.policySetId;
        let rule_data_json = args.args.ruleDataJson;
        let revision_id = args.args.revisionId;
        async move {
            let subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;

            if policy_set_id != BUDGET_POLICY_SET_ID {
                return Err(CoolError::BadRequest(format!(
                    "unknown policySetId '{policy_set_id}' -- only '{BUDGET_POLICY_SET_ID}' \
                     exists today"
                )));
            }

            let active_revision = match (rule_data_json, revision_id) {
                (Some(json), None) => policy_store
                    .activate(&json, Some(&subject))
                    .await
                    .map_err(budget_error_to_cool_error)?,
                (None, Some(revision_id)) => policy_store
                    .activate_by_revision_id(&revision_id)
                    .await
                    .map_err(budget_error_to_cool_error)?,
                (Some(_), Some(_)) => {
                    return Err(CoolError::BadRequest(
                        "exactly one of ruleDataJson or revisionId must be provided, not both"
                            .to_owned(),
                    ));
                }
                (None, None) => {
                    return Err(CoolError::BadRequest(
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
        ctx: &CoolContext,
        args: schema::procedures::get_budget_policy_status::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<
            schema::procedures::get_budget_policy_status::Output,
            CoolError,
        >,
    > + Send {
        let policy_store = self.policy_store.clone();
        let subject = subject_from_ctx(ctx);
        let policy_set_id = args.args.policySetId;
        async move {
            let _subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;

            if policy_set_id != BUDGET_POLICY_SET_ID {
                return Err(CoolError::BadRequest(format!(
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
        ctx: &CoolContext,
        args: schema::procedures::simulate_budget_policy::Args,
    ) -> impl core::future::Future<
        Output = std::result::Result<schema::procedures::simulate_budget_policy::Output, CoolError>,
    > + Send {
        let subject = subject_from_ctx(ctx);
        let rule_data_json = args.args.ruleDataJson;
        let scenario_json = args.args.scenarioJson;
        let requested_amount_str = args.args.requestedAmountMicros;
        async move {
            let _subject =
                subject.ok_or_else(|| CoolError::Unauthorized("missing subject".to_owned()))?;

            let requested_amount_micros: i64 = requested_amount_str.trim().parse().map_err(|_| {
                CoolError::BadRequest(format!(
                    "requestedAmountMicros must be a valid integer, got '{requested_amount_str}'"
                ))
            })?;

            let facts: lightbridge_authz_budget::Facts = serde_json::from_str(&scenario_json)
                .map_err(|e| CoolError::BadRequest(format!("invalid scenarioJson: {e}")))?;

            // A short-lived engine, constructed and discarded within this one call -- never
            // wired into `self.policy_store`, never persisted, never touches
            // budget_policy_sets/budget_policy_revisions.
            let engine = lightbridge_authz_budget::RuleDataEngine::new(
                &rule_data_json,
                BUDGET_POLICY_EVALUATION_BUDGET,
            )
            .map_err(budget_error_to_cool_error)?;

            let decision = lightbridge_authz_budget::PolicyEngine::evaluate(
                &engine,
                &facts,
                requested_amount_micros,
            )
            .await
            .map_err(budget_error_to_cool_error)?;

            Ok(to_schema_decision(decision))
        }
    }
}

/// Assembles the API server router: public probes, OIDC discovery/JWKS (when signing is enabled),
/// native token-exchange, and the generated cratestack RPC CRUD surface (`POST /rpc/{op_id}`,
/// `POST /rpc/batch`) wrapped in idempotency + rate-limit middleware. Separated from
/// `start_api_server` so the composition can be built without binding a TLS socket. `dev_cors`
/// (driven by `AUTHZ_DEV_CORS`) layers a wide-open CORS policy over the whole router — never enable
/// it in production. `cratestack_db` and `idempotency_store` are built on cratestack's own sqlx pool
/// (see `start_api_server`); the RPC surface replaces the old REST `/api/v1` CRUD mount entirely
/// (ADR-0003, "RPC transport, not REST"), and its OpenAPI/Swagger UI is intentionally gone
/// (ADR-0003, "Loss of Swagger UI").
#[allow(clippy::too_many_arguments)]
pub fn build_api_router(
    oauth2: &Oauth2,
    bearer: Arc<dyn BearerTokenServiceTrait>,
    issuer: Arc<AuthzStoreImpl>,
    policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    cratestack_db: schema::Cratestack,
    readiness_pool: Arc<dyn DbPoolTrait>,
    signing_repo: Arc<StoreRepo>,
    token_exchange: Option<token_exchange::TokenExchangeState>,
    idempotency_store: Arc<SqlxIdempotencyStore>,
    rate_limit_store: Arc<dyn RateLimitStore>,
    dev_cors: bool,
    rpc_base_path: Option<&str>,
) -> Router {
    let mut public = Router::new()
        .route("/", get(root_handler))
        .route("/healthz", get(health_handler))
        .route("/healthz/startup", get(startup_handler))
        .route(
            "/healthz/ready",
            get(move || {
                let readiness_pool = readiness_pool.clone();
                async move { readiness_handler(readiness_pool).await }
            }),
        );

    let token_exchange_enabled = token_exchange.is_some();
    if oauth2.is_self_signed()
        && let Some(signing) = oauth2.signing.as_ref()
    {
        public = public.merge(signing::well_known_router(
            &signing.issuer,
            signing_repo,
            token_exchange_enabled,
        ));
    }

    if let Some(te_state) = token_exchange {
        public = public.merge(token_exchange::token_exchange_router(te_state));
    }

    // Generated RPC CRUD surface. Codec: a single `CodecSet` accepting both wire formats, dispatched
    // on request `Content-Type` — CBOR primary (production default) with JSON secondary so
    // `curl`/dev/CI stay usable on the same router instance (ADR-0003, "CBOR in production, JSON in
    // dev/CI"; the ADR explicitly blesses the single-CodecSet form). Primary is `LenientCborCodec`,
    // not the raw `cratestack_codec_cbor::CborCodec` — see `codec.rs` for why (CBOR clients that
    // encode JS `undefined` as wire-level `undefined` instead of omitting the key, e.g. `cborg`).
    // The coarse RBAC gate (docs/rbac.md) that cratestack's membership `@@allow` policies do not
    // express. Applied as the OUTERMOST layer so an unauthorized caller is rejected with 403 before
    // consuming idempotency/rate-limit budget or reaching cratestack's dispatch; the membership
    // policy then runs as the second gate inside dispatch. The bearer service is validated here and
    // again by the RPC `AuthProvider` — cheap given the shared JWKS cache — keeping this a pure,
    // additive gate that shares no state with the provider.
    let rpc = schema::axum::rpc_router(
        cratestack_db,
        Procedures::new(issuer, policy_store),
        CodecSet::new(LenientCborCodec::default(), JsonCodec),
        CratestackAuthProvider::new(bearer.clone()),
    )
    .layer(IdempotencyLayer::new(idempotency_store, IDEMPOTENCY_TTL))
    .layer(RateLimitLayer::new(
        rate_limit_store,
        RateLimitConfig::new(RATE_LIMIT_BURST, RATE_LIMIT_REFILL_PER_SECOND),
    ))
    .layer(axum::middleware::from_fn_with_state(
        bearer,
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

/// Builds the native token-exchange state. Enabled only when `token_exchange.enabled` is set, and
/// it REQUIRES `oauth2.type: self` (the exchanged access token is a self-signed JWT). Returns
/// `Ok(None)` when the feature is off; errors on invalid config so startup fails fast.
fn build_token_exchange_state(
    oauth2: &Oauth2,
    repo: Arc<StoreRepo>,
    bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait>,
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
    let signer = signing::ApiKeyJwtSigner::from_config(signing, repo.clone())?;
    Ok(Some(token_exchange::TokenExchangeState {
        repo,
        signer,
        bearer,
        cfg: cfg.clone(),
    }))
}

pub async fn start_api_server(
    api: &ApiServer,
    pool: Arc<dyn DbPoolTrait>,
    oauth2: &Oauth2,
    billing: &Billing,
    redis: &Option<Redis>,
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

    let readiness_pool = pool.clone();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    if oauth2.is_self_signed() {
        let signing = oauth2.signing.as_ref().ok_or_else(|| {
            Error::Server("oauth2.type is 'self' but oauth2.signing is missing".to_string())
        })?;
        signing::bootstrap_signing_key(&signing_repo, signing).await?;
    }
    // Secret-issuance + membership operations reused by the RPC procedures (hand-written sqlx on the
    // core `DbPool`, sqlx 0.9).
    let issuer = Arc::new(AuthzStoreImpl::with_pool_and_oauth2(
        pool.clone(),
        oauth2,
        billing,
    )?);
    let bearer_service: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(BearerTokenService::new(oauth2.clone()));

    let token_exchange_state =
        build_token_exchange_state(oauth2, signing_repo.clone(), bearer_service.clone())?;
    let token_exchange_enabled = token_exchange_state.is_some();

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
    let redis = redis.as_ref().ok_or_else(|| {
        Error::Server(
            "redis config is required for authz-api rate limiting (set `redis.url`)".to_string(),
        )
    })?;
    let rate_limit_store = build_redis_rate_limit_store(&redis.url, "authz-api")?;

    let dev_cors = dev_cors_enabled();
    let app = build_api_router(
        oauth2,
        bearer_service,
        issuer,
        policy_store,
        cratestack_db,
        readiness_pool,
        signing_repo,
        token_exchange_state,
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
        token_exchange_enabled,
        "starting api server"
    );

    serve_tls("API", &api.address, api.port, &api.tls, app).await
}

/// Assembles the OPA server router (public probes + Basic-auth introspection/resolve routes).
/// Separated from `start_opa_server` for testability.
pub fn build_opa_router(state: Arc<OpaState>, readiness_pool: Arc<dyn DbPoolTrait>) -> Router {
    let public = Router::new()
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
        }
    }

    fn exchange_cfg() -> Oauth2TokenExchange {
        Oauth2TokenExchange {
            enabled: true,
            access_ttl_seconds: 900,
            refresh_ttl_seconds: 2_592_000,
            allowed_scopes: vec!["openid".to_string()],
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
        let result =
            build_token_exchange_state(&oauth2, lazy_signing_repo(), noop_bearer()).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_external_oauth2() {
        let mut oauth2 = base_oauth2(Oauth2Type::External);
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(&oauth2, lazy_signing_repo(), noop_bearer())
        else {
            panic!("expected an error for external oauth2 with token_exchange enabled");
        };
        assert!(format!("{err}").contains("requires oauth2.type: self"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_rejects_missing_signing_block() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.token_exchange = Some(exchange_cfg());
        let Err(err) = build_token_exchange_state(&oauth2, lazy_signing_repo(), noop_bearer())
        else {
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
        let Err(err) = build_token_exchange_state(&oauth2, lazy_signing_repo(), noop_bearer())
        else {
            panic!("expected an error for a non-positive ttl");
        };
        assert!(format!("{err}").contains("must be positive"));
    }

    #[tokio::test]
    async fn build_token_exchange_state_builds_state_for_valid_config() {
        let mut oauth2 = base_oauth2(Oauth2Type::SelfSigned);
        oauth2.signing = Some(signing_cfg());
        oauth2.token_exchange = Some(exchange_cfg());
        let result =
            build_token_exchange_state(&oauth2, lazy_signing_repo(), noop_bearer()).unwrap();
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
