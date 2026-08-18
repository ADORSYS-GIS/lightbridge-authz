//! The self-service refill orchestration (#191, PR 3.2): the function the whole #188 epic exists
//! for. A user asks for more budget; [`RefillService::request_refill`] decides -- immediately, or
//! by queuing for a human -- without anyone hand-editing configuration.
//!
//! ## Scope boundary
//!
//! This module does NOT determine whether a caller is an eligible OIDC user versus an
//! internal/API-key client. That is an authentication-layer concern this crate has no visibility
//! into by design (ADR-0007: "OPA decides; this service mutates" -- and, by extension here, "the
//! RPC layer decides who may ask; this service decides what happens once asked"). The refusal for
//! internal/API-key clients happens in a later PR, in the RPC procedure that calls into this one,
//! before this code is ever reached.
//!
//! ## The starting-tier gap (ADR-0008, flagged, not solved here)
//!
//! ADR-0008 says "the billing plan determines the starting rung". That `billing_plan` ->
//! `BudgetTier` mapping does not exist anywhere in this codebase yet. [`RefillService`] defaults
//! every account with no qualifying grant history this period to [`BudgetTier::B15`], the lowest
//! rung. That default is *safe* (it never grants more than the cheapest plan would justify) but it
//! is NOT the real, intended behavior for e.g. an enterprise-plan account that should start at
//! `B1000` -- such an account would have to refill repeatedly, one rung at a time, to reach the
//! tier it should have started at. This is a deliberate, flagged simplification for follow-up, not
//! something this PR is claiming is fully solved.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::augmentation::{
    ApprovedDecision, AugmentationRepo, AugmentationRequest, NewAugmentationRequest,
    RecordedDecision, UnapprovedDecision,
};
use crate::decision::{Effect, PolicyEngine};
use crate::error::BudgetError;
use crate::facts::Facts;
use crate::period::Period;
use crate::repo::{BudgetRepo, GrantRequest};
use crate::source::GrantSource;
use crate::spend::SpendReader;
use crate::tier::BudgetTier;

/// The grants whose most recent `amount_micros` for `(budget_account_id, period)` represents "the
/// tier this account is currently on". Deliberately excludes `correction`/`refund`: neither
/// represents a tier an account is on -- a `correction` can shift the raw ledger total in a way
/// that no longer matches any known rung, and a `refund` is a compensating adjustment, not a
/// statement about the account's current tier.
const LATEST_TIER_GRANT_AMOUNT_SQL: &str = "SELECT amount_micros FROM budget_grants \
     WHERE budget_account_id = $1 AND period = $2 \
       AND source IN ('base','self_service','automatic','admin','manual_approval','promotion') \
     ORDER BY created_at DESC LIMIT 1";

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

/// One refill request. Deliberately caller-supplied `as_of`, not read from the clock internally --
/// the same discipline the rest of this crate already applies (`Period` is clock-free;
/// `PolicyStore`/`RuleDataEngine`/[`BudgetRepo::effective_balance`] all take `as_of`/`now` as a
/// parameter).
#[derive(Debug, Clone, PartialEq)]
pub struct RefillRequest {
    pub budget_account_id: String,
    pub account_id: String,
    pub project_id: Option<String>,
    pub period: Period,
    pub idempotency_key: Option<String>,
    pub as_of: DateTime<Utc>,
}

/// Orchestrates one refill request end to end: idempotency short-circuit, tier resolution, policy
/// evaluation, and (when approved) the grant write -- all recorded on the
/// `budget_augmentation_requests` ledger via [`AugmentationRepo`]. See the module doc for the
/// scope boundary (auth eligibility) this service deliberately does not enforce.
#[derive(Debug, Clone)]
pub struct RefillService {
    budget_repo: Arc<BudgetRepo>,
    augmentation_repo: Arc<AugmentationRepo>,
    policy_engine: Arc<dyn PolicyEngine>,
    spend_reader: Arc<dyn SpendReader>,
}

impl RefillService {
    pub fn new(
        budget_repo: Arc<BudgetRepo>,
        augmentation_repo: Arc<AugmentationRepo>,
        policy_engine: Arc<dyn PolicyEngine>,
        spend_reader: Arc<dyn SpendReader>,
    ) -> Self {
        Self {
            budget_repo,
            augmentation_repo,
            policy_engine,
            spend_reader,
        }
    }

    /// The caller's own request history (#295's remaining half -- `getMyBudgetBalance`/
    /// `listMyBudgetGrants` shipped the balance/ledger half in PR #325). Thin delegation to
    /// [`AugmentationRepo::list_by_budget_account`], placed on `RefillService` rather than
    /// [`crate::review::ReviewService`] -- this is a read over requests a caller made through
    /// *this* service's [`Self::request_refill`], not the reviewer-facing queue `ReviewService`
    /// wraps. Every status is returned, not filtered to `pending_review` the way
    /// [`crate::review::ReviewService::list_pending`] is.
    pub async fn list_own_history(
        &self,
        budget_account_id: &str,
        before: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<AugmentationRequest>, BudgetError> {
        self.augmentation_repo
            .list_by_budget_account(budget_account_id, before, limit)
            .await
    }

    /// Resolves the tier an account is currently on for `period`, from the most recent
    /// tier-representing grant (see [`LATEST_TIER_GRANT_AMOUNT_SQL`]'s doc comment for exactly
    /// which sources count). A plain read against `budget_grants`, not routed through
    /// [`BudgetRepo`] -- reads don't need to go through `BudgetRepo`, only writes do.
    ///
    /// Falls back to [`BudgetTier::B15`] in two cases, and both are deliberate, defensive
    /// fallbacks rather than a trusted derivation:
    ///
    /// - No qualifying grant exists yet this period (a genuinely new account/period).
    /// - A qualifying grant exists, but its `amount_micros` doesn't match any known rung (e.g. a
    ///   `correction` shifted the raw ledger total in a way that makes the *most recent
    ///   tier-grant* no longer reflect current reality -- or just data this service doesn't
    ///   expect in practice).
    async fn current_tier(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<BudgetTier, BudgetError> {
        let period_str = period.to_string();

        let row: Option<(i64,)> = sqlx::query_as(LATEST_TIER_GRANT_AMOUNT_SQL)
            .bind(budget_account_id)
            .bind(&period_str)
            .fetch_optional(self.budget_repo.pool())
            .await
            .map_err(storage_failed)?;

        Ok(match row {
            Some((amount_micros,)) => {
                BudgetTier::from_amount_micros(amount_micros).unwrap_or(BudgetTier::B15)
            }
            None => BudgetTier::B15,
        })
    }

    /// Handles one refill request end to end. Returns the resulting [`AugmentationRequest`] in
    /// whatever terminal state it reached -- the caller (a later PR's RPC procedure) inspects
    /// `.status`/`.policy_reason_codes` to decide what to tell the user.
    ///
    /// Sequence:
    ///
    /// 1. Idempotency short-circuit (before any other work) -- see [`Self::find_existing`].
    /// 2. Resolve the current tier, then `.next()`. If there is no next tier (already on
    ///    [`BudgetTier::B1000`]), record a `denied` outcome with reason code
    ///    `"already_at_top_rung"` WITHOUT ever calling the policy engine -- there is nothing to
    ///    evaluate.
    /// 3. Create the `budget_augmentation_requests` row.
    /// 4. Load [`Facts`].
    /// 5. Evaluate. Per [`PolicyEngine`]'s own doc comment, an evaluator that can run to
    ///    completion should prefer `Ok(Decision { Deny | ManualReview, .. })` over `Err`; `Err` is
    ///    reserved for "the engine could not be invoked at all". This is treated as its own,
    ///    distinct outcome: refused AND queued (`pending_review`, reason code
    ///    `"policy_engine_unavailable"`) -- never propagated as a caller-facing error, and never
    ///    silently granted.
    /// 6. Interpret a successful [`crate::decision::Decision`]: `AutoApprove`/`AutoApproveCapped`
    ///    write a grant then record `AutoApproved`/`PartiallyApproved`; `ManualReview` records
    ///    `PendingReview`; `Deny`/`NoAction` record `Denied` (`NoAction` has no defined meaning for
    ///    an actively-submitted, awaiting-outcome request -- mapped to `Denied` per
    ///    [`RecordedDecision`]'s own doc comment).
    pub async fn request_refill(
        &self,
        request: RefillRequest,
    ) -> Result<AugmentationRequest, BudgetError> {
        if let Some(existing) = self
            .find_existing(request.idempotency_key.as_deref())
            .await?
        {
            return Ok(existing);
        }

        let current_tier = self
            .current_tier(&request.budget_account_id, &request.period)
            .await?;

        let Some(requested_tier) = current_tier.next() else {
            return self.deny_already_at_top_rung(&request, current_tier).await;
        };

        let created = self
            .augmentation_repo
            .create(NewAugmentationRequest {
                budget_account_id: request.budget_account_id.clone(),
                account_id: request.account_id.clone(),
                project_id: request.project_id.clone(),
                period: request.period.clone(),
                requested_tier,
                requested_amount_micros: requested_tier.amount().get(),
                idempotency_key: request.idempotency_key.clone(),
            })
            .await?;

        let facts = self.load_facts(&request).await?;

        let decision = match self
            .policy_engine
            .evaluate(&facts, requested_tier.amount().get())
            .await
        {
            Ok(decision) => decision,
            Err(_engine_err) => {
                return self
                    .augmentation_repo
                    .record_decision(
                        &created.id,
                        RecordedDecision::PendingReview(UnapprovedDecision {
                            policy_effect: Effect::ManualReview,
                            policy_reason_codes: vec!["policy_engine_unavailable".to_string()],
                            matched_rule_ids: vec![],
                            policy_revision: "n/a".to_string(),
                        }),
                    )
                    .await;
            }
        };

        match decision.effect {
            Effect::AutoApprove | Effect::AutoApproveCapped => {
                let grant = self
                    .budget_repo
                    .grant(GrantRequest {
                        budget_account_id: request.budget_account_id.clone(),
                        account_id: request.account_id.clone(),
                        project_id: request.project_id.clone(),
                        period: request.period.clone(),
                        amount_micros: decision.approved_amount_micros,
                        source: GrantSource::SelfService,
                        actor_id: Some(request.account_id.clone()),
                        reason: None,
                        policy_revision: Some(decision.policy_revision.clone()),
                        matched_rule_ids: Some(decision.matched_rule_ids.clone()),
                        idempotency_key: request.idempotency_key.clone(),
                        trigger_key: None,
                        expires_at: None,
                    })
                    .await?;

                let approved = ApprovedDecision {
                    policy_effect: decision.effect,
                    policy_reason_codes: decision.reason_codes,
                    matched_rule_ids: decision.matched_rule_ids,
                    policy_revision: decision.policy_revision,
                    approved_amount_micros: decision.approved_amount_micros,
                    grant_id: grant.id,
                };

                let recorded = if decision.effect == Effect::AutoApprove {
                    RecordedDecision::AutoApproved(approved)
                } else {
                    RecordedDecision::PartiallyApproved(approved)
                };

                self.augmentation_repo
                    .record_decision(&created.id, recorded)
                    .await
            }
            Effect::ManualReview => {
                self.augmentation_repo
                    .record_decision(
                        &created.id,
                        RecordedDecision::PendingReview(UnapprovedDecision {
                            policy_effect: decision.effect,
                            policy_reason_codes: decision.reason_codes,
                            matched_rule_ids: decision.matched_rule_ids,
                            policy_revision: decision.policy_revision,
                        }),
                    )
                    .await
            }
            Effect::Deny | Effect::NoAction => {
                self.augmentation_repo
                    .record_decision(
                        &created.id,
                        RecordedDecision::Denied(UnapprovedDecision {
                            policy_effect: decision.effect,
                            policy_reason_codes: decision.reason_codes,
                            matched_rule_ids: decision.matched_rule_ids,
                            policy_revision: decision.policy_revision,
                        }),
                    )
                    .await
            }
        }
    }

    /// Step 1 of [`Self::request_refill`]: if `idempotency_key` is `Some` and a request with that
    /// key already exists, return it. Called before any other work -- no `BudgetRepo` read, no
    /// request-row creation, no policy evaluation -- so a genuine retry (double-click, client
    /// retry) never triggers a second, redundant evaluation of what should be a single logical
    /// request.
    async fn find_existing(
        &self,
        idempotency_key: Option<&str>,
    ) -> Result<Option<AugmentationRequest>, BudgetError> {
        match idempotency_key {
            Some(key) => self.augmentation_repo.find_by_idempotency_key(key).await,
            None => Ok(None),
        }
    }

    /// Step 2's "already at the top rung" branch: creates the request row (using `current_tier`
    /// as both the requested tier and amount, since there is nothing higher to request), then
    /// records a `denied` outcome with reason code `"already_at_top_rung"` directly -- no policy
    /// engine call, since there is nothing to evaluate. This is #191's own acceptance criterion:
    /// "a clear message rather than a failed grant", not a policy decision.
    async fn deny_already_at_top_rung(
        &self,
        request: &RefillRequest,
        current_tier: BudgetTier,
    ) -> Result<AugmentationRequest, BudgetError> {
        let created = self
            .augmentation_repo
            .create(NewAugmentationRequest {
                budget_account_id: request.budget_account_id.clone(),
                account_id: request.account_id.clone(),
                project_id: request.project_id.clone(),
                period: request.period.clone(),
                requested_tier: current_tier,
                requested_amount_micros: current_tier.amount().get(),
                idempotency_key: request.idempotency_key.clone(),
            })
            .await?;

        self.augmentation_repo
            .record_decision(
                &created.id,
                RecordedDecision::Denied(UnapprovedDecision {
                    policy_effect: Effect::Deny,
                    policy_reason_codes: vec!["already_at_top_rung".to_string()],
                    matched_rule_ids: vec![],
                    policy_revision: "n/a".to_string(),
                }),
            )
            .await
    }

    /// Step 4: gathers the [`Facts`] a [`PolicyEngine`] evaluates against, per ADR-0007's "the
    /// host loads every fact" discipline.
    async fn load_facts(&self, request: &RefillRequest) -> Result<Facts, BudgetError> {
        let effective_balance_micros = self
            .budget_repo
            .effective_balance(&request.budget_account_id, &request.period, request.as_of)
            .await?;
        let self_service_grant_count = self
            .budget_repo
            .get_balance(&request.budget_account_id, &request.period)
            .await?
            .map(|balance| balance.self_service_grant_count)
            .unwrap_or(0);
        let spend_this_period = self
            .spend_reader
            .spend_for_account(&request.account_id, &request.period)
            .await?;
        let spend_last_period = self
            .spend_reader
            .spend_for_account(&request.account_id, &request.period.previous())
            .await?;

        Ok(Facts {
            effective_balance_micros,
            self_service_grant_count,
            spend_this_period,
            spend_last_period,
        })
    }
}
