//! LoC rationale: Wire and schema conversion helper functions mapping domain types to schema types for procedure outputs.

use cratestack::{CratestackContext, CratestackError, Value};
use lightbridge_authz_api::schema;
use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, Project, ProjectMember,
    config::{Billing, ModelCatalog},
};

use crate::{
    auth_provider::ACCESS_TOKEN_CONTEXT_KEY, error_convert::budget_error_to_cratestack_error,
};

/// Maps a domain [`lightbridge_authz_budget::repo::BalanceSnapshot`] into the schema's wire
/// `BudgetBalance` shape (see `authz.cstack`'s `type BudgetBalance` doc comment for the
/// string-vs-`Int` field reasoning).
pub(crate) fn to_schema_budget_balance(
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
pub(crate) fn to_schema_my_budget_refill_ladder(
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
pub(crate) fn to_schema_budget_grant_entry(
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
pub(crate) const DEFAULT_BUDGET_GRANTS_PAGE_SIZE: i64 = 20;
pub(crate) const MAX_BUDGET_GRANTS_PAGE_SIZE: i64 = 50;

/// Resolves a caller-supplied, optional `limit` into a page size clamped to
/// `[1, MAX_BUDGET_GRANTS_PAGE_SIZE]`, defaulting to [`DEFAULT_BUDGET_GRANTS_PAGE_SIZE`] when
/// omitted.
pub(crate) fn resolve_budget_grants_page_size(limit: Option<i64>) -> i64 {
    match limit {
        Some(requested) => requested.clamp(1, MAX_BUDGET_GRANTS_PAGE_SIZE),
        None => DEFAULT_BUDGET_GRANTS_PAGE_SIZE,
    }
}

/// `listMyExpiringApiKeys`'s default "soon" window when a caller omits `withinDays`
/// (lightbridge-authz#436). Matches `apps/self-service/src/lib/api-key-expiry.ts`'s
/// `EXPIRING_SOON_WINDOW_DAYS` in converse-frontends so the two surfaces agree on what "soon"
/// means rather than silently diverging -- see `docs/api-key-expiry-visibility.md`.
pub(crate) const DEFAULT_EXPIRING_SOON_WINDOW_DAYS: i64 = 14;
/// Ceiling a caller-supplied `withinDays` clamps to. Mirrors the documented default of the
/// operator-configured `ApiKeyExpiry` ceiling (`api_key_expiry`,
/// `lightbridge_authz_core::config::ApiKeyExpiry::max_lifetime_days`) -- a window wider than the
/// maximum possible key lifetime cannot surface anything a plain `model.ApiKey.list` call could
/// not already return, so there is no security reason to allow (or need to reject) more.
pub(crate) const MAX_EXPIRING_SOON_WINDOW_DAYS: i64 = 90;
/// Hard cap on rows `listMyExpiringApiKeys` returns (soonest-expiring first). Comfortably above
/// the estate-wide count of keys expiring within 30 days at the time of lightbridge-authz#436's
/// own investigation (11) -- this bounds the query rather than expecting that count to hold
/// forever.
pub(crate) const MAX_EXPIRING_API_KEYS_RESULTS: i64 = 500;

/// Resolves a caller-supplied, optional `withinDays` into a window clamped to
/// `[1, MAX_EXPIRING_SOON_WINDOW_DAYS]`, defaulting to [`DEFAULT_EXPIRING_SOON_WINDOW_DAYS`] when
/// omitted -- the same "clamp, don't reject" convention [`resolve_budget_grants_page_size`] above
/// already uses for a read-side convenience parameter, not the fail-closed "reject, never clamp"
/// rule `validate_expires_at` (`handlers/mod.rs`) uses for the write-time expiry gate.
pub(crate) fn clamp_expiring_soon_window_days(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_EXPIRING_SOON_WINDOW_DAYS)
        .clamp(1, MAX_EXPIRING_SOON_WINDOW_DAYS)
}

/// The validated caller's subject, projected as `auth().id` by [`CratestackAuthProvider`].
pub(crate) fn subject_from_ctx(ctx: &CratestackContext) -> Option<String> {
    match ctx.auth_field("id") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Whether the caller holds a given permission, read back out of the auth context
/// `CratestackAuthProvider` populated once at authentication time (one boolean per
/// `Permission::ALL` variant -- see `auth_provider.rs`). Absent or non-boolean reads as `false`:
/// unknown is not a default, it routes to the strictest branch.
///
/// One copy, not one per module: it is a security predicate, and a second hand-written copy that
/// forgot the `Bool(true)` match (or matched `Some(_)`) would fail OPEN. `field` is the
/// `auth().perm*` name, which callers derive from [`rpc_permission_map::permission_field_name`]
/// rather than typing.
pub(crate) fn has_permission(ctx: &CratestackContext, field: &str) -> bool {
    matches!(ctx.auth_field(field), Some(Value::Bool(true)))
}

/// The caller's raw access token, stashed into the context by [`CratestackAuthProvider`] so the
/// rotate procedure's downstream secret issuance can reuse it (email profile / token exchange).
pub(crate) fn access_token_from_ctx(ctx: &CratestackContext) -> Option<String> {
    match ctx.extensions.get(ACCESS_TOKEN_CONTEXT_KEY) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

pub(crate) fn to_schema_api_key(k: ApiKey) -> schema::ApiKey {
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

pub(crate) fn to_schema_account(a: Account) -> schema::Account {
    schema::Account {
        createdAt: a.created_at,
        updatedAt: a.updated_at,
        id: a.id,
        defaultQuota: a.default_quota,
        status: a.status.to_string(),
        name: a.name,
        userId: a.user_id,
    }
}

/// Recursively lower a `serde_json::Value` (the shape the core repo speaks) into cratestack's own
/// `Value` enum, which is what the generated model structs carry for `Json` columns. Needed because
/// the two crates use different JSON value types and there is no cross-conversion in either.
pub(crate) fn json_to_cratestack_value(value: serde_json::Value) -> Value {
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
pub(crate) fn cratestack_value_to_json(value: Value) -> serde_json::Value {
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
pub(crate) fn allowed_models_from_json_arg(
    value: Option<cratestack::Json<Value>>,
) -> Option<Vec<String>> {
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

pub(crate) fn to_schema_project(p: Project) -> schema::Project {
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
pub(crate) fn to_schema_project_member(m: ProjectMember) -> schema::ProjectMember {
    schema::ProjectMember {
        id: format!("{}:{}", m.project_id, m.account_id),
        projectId: m.project_id,
        accountId: m.account_id,
        role: m.role,
        quotaTier: m.quota_tier,
        createdAt: m.created_at,
    }
}

pub(crate) fn to_schema_api_key_secret(s: ApiKeySecret) -> schema::ApiKeySecret {
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
pub(crate) fn to_schema_billing_plans(billing: &Billing) -> Vec<schema::BillingPlanInfo> {
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
pub(crate) fn to_schema_model_catalog(models: &ModelCatalog) -> Vec<schema::ModelCatalogEntry> {
    models
        .models
        .iter()
        .map(|entry| schema::ModelCatalogEntry {
            id: entry.id.clone(),
            name: entry.name.clone(),
        })
        .collect()
}

pub(crate) fn to_schema_session_revocation_result(
    revoked_count: u64,
) -> schema::SessionRevocationResult {
    // `revokedCount` is a schema `Int` (Rust `i64`, see `authz.cstack`'s `Int` mapping note on
    // `SimulateBudgetPolicyInput`) -- `rows_affected()` is `u64`, so this is a lossy cast only in
    // the astronomically unreachable case of revoking over i64::MAX rows in one call.
    schema::SessionRevocationResult {
        revokedCount: revoked_count as i64,
    }
}

/// Shared page-fetch for `listMyBudgetGrants`/`listBudgetGrants`: parses the optional `period`,
/// resolves the page size, reads one page from `BudgetRepo::list_grants`, and maps it to the
/// schema's `BudgetGrantPage` (`nextCursor` = the last entry's `createdAt`, or `None` when the
/// page came back short of a full page -- i.e. there is nothing further to page to).
pub(crate) async fn list_budget_grants_page(
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
