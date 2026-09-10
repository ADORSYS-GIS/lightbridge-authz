//! Wire conversions for the budget domain's *decision* and *augmentation-request* shapes.
//!
//! Split out of `lib.rs` (which holds the procedure bodies that call them) purely because that
//! file sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be touched
//! but not grown — and `lib.rs` is entry 1 in `docs/code-size-baseline.md`'s split order anyway.
//! Moved verbatim: same functions, same doc comments, same visibility to the rest of the crate.

use lightbridge_authz_api::schema;

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
pub(crate) fn to_schema_decision(
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
pub(crate) fn to_schema_augmentation_request(
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
        requestedByUserId: request.requested_by_user_id,
        createdAt: request.created_at,
        reviewedAt: request.reviewed_at,
    }
}

/// Default/max page size for `listPendingAugmentationRequests`/`listMyAugmentationRequests`
/// (#296/#295). Mirrors [`DEFAULT_BUDGET_GRANTS_PAGE_SIZE`]/[`MAX_BUDGET_GRANTS_PAGE_SIZE`]
/// exactly -- same reasoning: this procedure layer's own default when a caller omits `limit`,
/// and its own tighter ceiling when a caller supplies one, independent of whatever
/// `AugmentationRepo` additionally clamps to.
pub(crate) const DEFAULT_AUGMENTATION_REQUESTS_PAGE_SIZE: i64 = 20;
pub(crate) const MAX_AUGMENTATION_REQUESTS_PAGE_SIZE: i64 = 50;

/// Resolves a caller-supplied, optional `limit` into a page size clamped to
/// `[1, MAX_AUGMENTATION_REQUESTS_PAGE_SIZE]`, defaulting to
/// [`DEFAULT_AUGMENTATION_REQUESTS_PAGE_SIZE`] when omitted. Shared by
/// `listPendingAugmentationRequests` and `listMyAugmentationRequests` -- both page the same
/// `AugmentationRequest` entity, just in opposite directions (see each procedure's own doc
/// comment).
pub(crate) fn resolve_augmentation_requests_page_size(limit: Option<i64>) -> i64 {
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
pub(crate) fn to_schema_augmentation_request_page(
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
