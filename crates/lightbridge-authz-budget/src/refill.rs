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
//! (which ADR-0014's token-mint claim reads) defaults every account with no qualifying grant
//! history this period to [`BudgetTier::B15`], the lowest rung. That default is *safe* (it never
//! grants -- or claims -- more than the cheapest plan would justify) but it is NOT the real,
//! intended behavior for e.g. an enterprise-plan account that should start at `B1000` -- such an
//! account would have to refill repeatedly, one rung at a time, to reach the tier it should have
//! started at. This is a deliberate, flagged simplification for follow-up, not something this PR
//! is claiming is fully solved.

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
    /// `allowed_amounts_micros` before evaluation. Required -- the pre-ADR-0015 optional wire
    /// shape (an absent value deriving `current_tier.next()`) was a deliberately temporary bridge
    /// for a live frontend still reading the legacy ladder fields; #387 removed both once that
    /// frontend switched to `allowed_amounts_micros` and deployed.
    pub requested_amount_micros: i64,
}

/// The result of [`RefillService::refill_status`] -- see that method's doc comment for what this
/// does and does not guarantee.
#[derive(Debug, Clone, PartialEq)]
pub struct RefillStatus {
    /// ADR-0015: the self-service refill amounts currently offered by the active policy, strictly
    /// ascending. This is the source of truth for what [`RefillRequest::requested_amount_micros`]
    /// may legally be.
    pub allowed_amounts_micros: Vec<i64>,
}

/// Orchestrates one refill request end to end: idempotency short-circuit, offered-amount
/// validation, policy evaluation, and (when approved) the grant write -- all recorded on the
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

    /// Read-only companion to [`Self::request_refill`]: the self-service refill amounts currently
    /// offered by the active policy. Deliberately never calls [`PolicyEngine::evaluate`] and makes
    /// no claim about the outcome of an actual submission -- see [`Self::request_refill`]'s own
    /// doc comment for the evaluation, capping, and denial paths this status intentionally does
    /// not preview. Takes no arguments: [`PolicyEngine::allowed_amounts_micros`] is a flat,
    /// admin-configured set (ADR-0015), not scoped to any particular account or period.
    ///
    /// This exists so a UI can render an amount picker without hand-maintaining its own copy of
    /// the offered set (see converse-frontends#148 for the prior, pre-ADR-0015 attempt at a
    /// caller-chosen tier and why it was rejected, and ADR-0015 for why that objection no longer
    /// applies).
    pub async fn refill_status(&self) -> Result<RefillStatus, BudgetError> {
        Ok(RefillStatus {
            allowed_amounts_micros: self.policy_engine.allowed_amounts_micros(),
        })
    }

    /// Handles one refill request end to end. Returns the resulting [`AugmentationRequest`] in
    /// whatever terminal state it reached -- the caller (a later PR's RPC procedure) inspects
    /// `.status`/`.policy_reason_codes` to decide what to tell the user.
    ///
    /// Sequence:
    ///
    /// 1. Idempotency short-circuit (before any other work) -- see [`Self::find_existing`].
    /// 2. Validate `requested_amount_micros` against the active policy's offered set
    ///    (`allowed_amounts_micros`, ADR-0015) -- an amount outside that set is refused with
    ///    [`BudgetError::AmountNotOffered`] before a `budget_augmentation_requests` row is ever
    ///    created or the policy engine is ever consulted.
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

        let requested_amount_micros = request.requested_amount_micros;
        let allowed = self.policy_engine.allowed_amounts_micros();
        if !allowed.contains(&requested_amount_micros) {
            return Err(BudgetError::AmountNotOffered(requested_amount_micros));
        }
        // Best-effort display label only -- an amount outside the `BudgetTier` enum (e.g.
        // ADR-0015's $6 floor, which predates any tier variant for it) has no exact label and
        // falls back to `B15` here. `requested_amount_micros` above is the authoritative value;
        // this label is not.
        let requested_tier =
            BudgetTier::from_amount_micros(requested_amount_micros).unwrap_or(BudgetTier::B15);

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
