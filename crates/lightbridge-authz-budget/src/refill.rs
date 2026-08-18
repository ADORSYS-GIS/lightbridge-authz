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
//! `BudgetTier` mapping does not exist anywhere in this codebase yet. [`BudgetRepo::current_tier`]
//! (which [`RefillService`] resolves through, and which ADR-0014's token-mint claim also now
//! reads) defaults every account with no qualifying grant history this period to
//! [`BudgetTier::B15`], the lowest rung. That default is *safe* (it never grants -- or claims --
//! more than the cheapest plan would justify) but it is NOT the real, intended behavior for e.g.
//! an enterprise-plan account that should start at `B1000` -- such an account would have to
//! refill repeatedly, one rung at a time, to reach the tier it should have started at. This is a
//! deliberate, flagged simplification for follow-up, not something this PR is claiming is fully
//! solved.

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
    /// ADR-0015: the caller-chosen amount, validated against the active policy's
    /// `allowed_amounts_micros` before evaluation. `None` is the pre-ADR-0015 wire shape --
    /// preserved deliberately so a live caller that has not yet been redeployed to send this
    /// field keeps getting exactly today's behavior (`current_tier.next()`), rather than the
    /// backend deploy breaking it out from under it. Transitional: tracked for removal once
    /// every caller sends `Some`, in the same follow-up as [`RefillStatus::ladder`].
    pub requested_amount_micros: Option<i64>,
}

/// One rung on the ADR-0008 ladder, paired with the dollar amount (in micros) it represents. Part
/// of [`RefillStatus::ladder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LadderRung {
    pub tier: BudgetTier,
    pub amount_micros: i64,
}

/// The result of [`RefillService::refill_status`] -- see that method's doc comment for what this
/// does and does not guarantee.
#[derive(Debug, Clone, PartialEq)]
pub struct RefillStatus {
    /// ADR-0008-era fields, kept byte-for-byte as today. Transitional -- `converse-frontends`
    /// still reads them in production (#185); do not remove until a frontend PR has switched to
    /// `allowed_amounts_micros` and deployed. Tracked for removal in the same follow-up issue as
    /// [`RefillRequest::requested_amount_micros`]'s optionality.
    pub current_tier: BudgetTier,
    pub next_tier: Option<BudgetTier>,
    pub ladder: Vec<LadderRung>,
    /// ADR-0015: the self-service refill amounts currently offered by the active policy,
    /// strictly ascending. This is the source of truth going forward; `ladder` above is a
    /// frozen, pre-ADR-0015 snapshot shape kept only for the live frontend's current contract.
    pub allowed_amounts_micros: Vec<i64>,
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

    /// Read-only companion to [`Self::request_refill`]: where an account currently sits on the
    /// ADR-0008 ladder for `period`, and what the next refill would grant *if* a submitted
    /// request is later approved. Deliberately does not call the policy engine and makes no claim
    /// about the outcome of an actual submission -- see [`Self::request_refill`]'s own doc comment
    /// for the evaluation, capping, and denial paths this status intentionally does not preview.
    /// `next_tier` is `None` exactly when [`Self::request_refill`] would deny with
    /// `"already_at_top_rung"` (already on [`BudgetTier::B1000`]).
    ///
    /// This exists so a UI can show "you are here, this is next" instead of asking the caller to
    /// choose an amount -- ADR-0008's ladder stays the server's decision space; this is visibility
    /// into it, not a selector (see converse-frontends#148 for the prior attempt at a
    /// caller-chosen tier and why it was rejected).
    pub async fn refill_status(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<RefillStatus, BudgetError> {
        let current_tier = self.current_tier(budget_account_id, period).await?;
        Ok(RefillStatus {
            current_tier,
            next_tier: current_tier.next(),
            ladder: BudgetTier::ALL
                .iter()
                .map(|&tier| LadderRung {
                    tier,
                    amount_micros: tier.amount().get(),
                })
                .collect(),
            allowed_amounts_micros: self.policy_engine.allowed_amounts_micros(),
        })
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
    ///
    /// ⚠️ ADR-0015: this method, and the `BudgetTier` enum it returns, are now used **only** by
    /// the transitional [`RefillStatus`] fields (`current_tier`/`next_tier`/`ladder`) and the
    /// transitional `requested_amount_micros: None` branch of [`Self::request_refill`] -- both
    /// scheduled for removal once the frontend switches to `allowed_amounts_micros`. The
    /// `BudgetTier` enum has no representation for amounts introduced by policy after ADR-0015
    /// (e.g. a $6 floor below `B15`), so this fallback deliberately still resolves to `B15`
    /// exactly as before ADR-0015 rather than to the policy-configured floor -- fixing that would
    /// require either extending this enum (rejected; ADR-0015 moved amounts out of it on purpose)
    /// or deleting this transitional path early (breaks the live frontend, see ADR-0015 and the
    /// `MyBudgetRefillLadder`/`RequestBudgetRefillInput` doc comments in `authz.cstack`). The
    /// real, policy-sourced floor (`fail_closed_floor_micros`) is what every new/current caller
    /// actually observes, since it is not read through this method at all -- including ADR-0014's
    /// own token-mint fail-closed fallback, which reads
    /// [`PolicyEngine::fail_closed_floor_micros`] directly rather than going through this
    /// transitional, `BudgetTier`-shaped path. (ADR-0014 moved this query onto [`BudgetRepo`]
    /// itself, as [`BudgetRepo::current_tier`], so both this transitional caller and the
    /// token-exchange minting path could share it without constructing a full `RefillService` --
    /// see that method's doc comment for the exact fallback semantics.)
    async fn current_tier(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<BudgetTier, BudgetError> {
        self.budget_repo
            .current_tier(budget_account_id, period)
            .await
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

        // ADR-0015: `Some` is the current, policy-driven path -- the caller names an amount and
        // it is checked against the active policy's offered set. `None` is the pre-ADR-0015 wire
        // shape, preserved so a live caller that has not yet redeployed to send this field keeps
        // getting exactly today's behavior. See `RefillRequest::requested_amount_micros`'s own
        // doc comment for why this branch exists and when it may be removed.
        let (requested_tier, requested_amount_micros): (BudgetTier, i64) =
            match request.requested_amount_micros {
                Some(amount) => {
                    let allowed = self.policy_engine.allowed_amounts_micros();
                    if !allowed.contains(&amount) {
                        return Err(BudgetError::AmountNotOffered(amount));
                    }
                    // Best-effort display label only -- see `Self::current_tier`'s doc comment on
                    // why an amount outside the legacy `BudgetTier` enum (e.g. the $6 floor) has
                    // no exact label and falls back to `B15` here. `requested_amount_micros`
                    // below is the authoritative value; this label is not.
                    let label = BudgetTier::from_amount_micros(amount).unwrap_or(BudgetTier::B15);
                    (label, amount)
                }
                None => {
                    let current_tier = self
                        .current_tier(&request.budget_account_id, &request.period)
                        .await?;
                    let Some(next_tier) = current_tier.next() else {
                        return self.deny_already_at_top_rung(&request, current_tier).await;
                    };
                    (next_tier, next_tier.amount().get())
                }
            };

        let created = self
            .augmentation_repo
            .create(NewAugmentationRequest {
                budget_account_id: request.budget_account_id.clone(),
                account_id: request.account_id.clone(),
                project_id: request.project_id.clone(),
                period: request.period.clone(),
                requested_tier,
                requested_amount_micros,
                idempotency_key: request.idempotency_key.clone(),
            })
            .await?;

        let facts = self.load_facts(&request).await?;

        let decision = match self
            .policy_engine
            .evaluate(&facts, requested_amount_micros)
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
