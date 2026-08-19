//! The plain-Rust, JSON-rule-data policy evaluator (ADR-0007): "the path ordinary
//! administrators use", shipped before any OPA-Wasm engine exists. This module defines the
//! rule-data schema (`RuleSet`/`Rule`/`Condition`/`Field`/`Operator`) and [`RuleDataEngine`], an
//! in-memory, hot-swappable [`crate::decision::PolicyEngine`] implementation driven entirely by
//! that JSON. No OPA/Wasm/Rego and no database persistence live here -- `load()` is the bare
//! mechanism a later PR (the policy lifecycle: storage, an activation RPC, `/health` wiring)
//! wraps in persistence.
//!
//! See `docs/adr/0007-refill-decisions-rule-data-then-opa-wasm.md` and
//! `docs/adr/0008-refills-are-discrete-budget-tiers.md` for the policy this schema exists to
//! express, and `docs/budget-decision-contract.md` for the `Decision`/`Facts` contract this
//! engine sits behind.
//!
//! ## Schema note: `Condition::All`/`Condition::Any` are struct variants, not tuple variants
//!
//! An internally tagged enum (`#[serde(tag = "type")]`) cannot serialize a newtype variant whose
//! payload is a sequence -- serde only supports internal tagging for variants that themselves
//! serialize as a map (struct variants, or a newtype wrapping a struct). A `Vec<Condition>`
//! serializes as a JSON array, so `All(Vec<Condition>)`/`Any(Vec<Condition>)` as bare tuple
//! variants fail at serialization time (`cannot serialize tagged newtype variant ... containing a
//! sequence`), verified directly against this serde version before writing the rest of this
//! module. `All { conditions: Vec<Condition> }`/`Any { conditions: Vec<Condition> }` are the
//! smallest change that keeps `Threshold`'s flat `{ "type": "threshold", "field": ..., ... }`
//! shape untouched while making the combinators representable at all.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::decision::{Decision, Effect, Obligations, PolicyEngine};
use crate::error::BudgetError;
use crate::facts::Facts;
use crate::spend::Spend;

/// A fact `Condition::Threshold` can compare against. Mirrors [`Facts`] plus the one value that
/// isn't a fact at all -- the amount being requested -- so rules like "auto-approve requests
/// under $5" are expressible without inventing a separate mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    SelfServiceGrantCount,
    EffectiveBalanceMicros,
    SpendThisPeriodMicros,
    SpendLastPeriodMicros,
    RequestedAmountMicros,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
}

/// A boolean expression over [`Facts`]/the requested amount. See the module doc for why `All`/
/// `Any` are struct variants (`{ conditions: [...] }`) rather than bare tuple variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    Threshold {
        field: Field,
        operator: Operator,
        value: i64,
    },
    All {
        conditions: Vec<Condition>,
    },
    Any {
        conditions: Vec<Condition>,
    },
}

/// One entry in a [`RuleSet`]. Rules are evaluated in order; the first whose `condition` matches
/// wins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub condition: Condition,
    pub effect: Effect,
    pub reason_code: String,
    /// Only meaningful when `effect` is `AutoApproveCapped` -- the ceiling this rule imposes.
    /// The actual approved amount becomes `min(requested_amount_micros, cap_micros)`. Ignored
    /// for every other effect.
    #[serde(default)]
    pub cap_micros: Option<i64>,
}

/// A full, versioned rule-data policy: an ordered list of [`Rule`]s plus the fallback applied
/// when none match, plus (ADR-0015) the three admin-configured amounts that used to live in the
/// compile-time `BudgetTier` enum. Deliberately three separate fields, not one -- see ADR-0015
/// Decisions 5/6 for why "the account's starting budget" and "the fail-closed floor for an
/// outage/unresolvable amount" must never share a value, even though they often will in
/// practice: conflating them once already meant a lookup failure and a brand-new signup were
/// indistinguishable, silently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSet {
    pub policy_revision: String,
    pub rules: Vec<Rule>,
    pub default_effect: Effect,
    pub default_reason_code: String,
    /// The self-service refill amounts a caller may request, strictly ascending, e.g.
    /// `[6_000_000, 15_000_000, 30_000_000]` for $6/$15/$30. Deliberately a discrete set, not a
    /// `min`/`max` range a caller could pick any value inside of -- see ADR-0015 Decision 2.
    /// `requestBudgetRefill` rejects any `requested_amount_micros` not a member of this set
    /// (`BudgetError::AmountNotOffered`) before ever evaluating policy.
    pub allowed_amounts_micros: Vec<i64>,
    /// What an account with no qualifying grant history yet this period starts with (ADR-0015
    /// Decision 5). NOT derived from `allowed_amounts_micros`'s minimum -- a plan may start
    /// callers above or below the lowest self-service step.
    pub starting_amount_micros: i64,
    /// The fail-closed fallback used only when a tier/amount lookup fails outright or resolves
    /// to data matching nothing known (ADR-0015 Decision 6) -- never used for "brand new
    /// account," which is `starting_amount_micros` instead. Enforced by [`validate`] to never
    /// exceed `starting_amount_micros`: an outage must never grant more than a legitimate new
    /// signup would get.
    pub fail_closed_floor_micros: i64,
}

/// ADR-0008's actual policy verbatim: two unaided rungs per period, `manual_review` beyond that.
/// The threshold (`2`) and the field it compares are rule data -- changeable without a deploy,
/// exactly as the ADR requires. Used by this module's own tests and available for whatever later
/// PR wires a real default into config.
///
/// ⚠️ KEEP IN SYNC WITH the seed `rule_data_json` literal in
/// `migrations/20260804000001_budget_policy_sets_and_revisions.sql` -- that migration seeds the
/// `budget-refill` policy set's first revision with this exact JSON, byte-for-byte, because a SQL
/// migration cannot call this function. If you change this literal, change the migration's copy
/// in the same PR.
pub fn default_rule_set_json() -> &'static str {
    r#"{
  "policy_revision": "budget-policy-v1",
  "rules": [
    {
      "id": "within-unaided-allowance",
      "condition": { "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 2 },
      "effect": "auto_approve",
      "reason_code": "within_unaided_allowance"
    }
  ],
  "default_effect": "manual_review",
  "default_reason_code": "unaided_allowance_exhausted",
  "allowed_amounts_micros": [6000000, 15000000, 30000000],
  "starting_amount_micros": 15000000,
  "fail_closed_floor_micros": 6000000
}"#
}

fn validate(rule_set: &RuleSet) -> Result<(), BudgetError> {
    if rule_set.policy_revision.trim().is_empty() {
        return Err(BudgetError::InvalidRuleData(
            "policy_revision must not be empty".to_string(),
        ));
    }
    if rule_set.default_reason_code.trim().is_empty() {
        return Err(BudgetError::InvalidRuleData(
            "default_reason_code must not be empty".to_string(),
        ));
    }

    let mut seen_ids: HashSet<&str> = HashSet::new();
    for rule in &rule_set.rules {
        if rule.id.trim().is_empty() {
            return Err(BudgetError::InvalidRuleData(
                "rule id must not be empty".to_string(),
            ));
        }
        if rule.reason_code.trim().is_empty() {
            return Err(BudgetError::InvalidRuleData(format!(
                "rule '{}' reason_code must not be empty",
                rule.id
            )));
        }
        if !seen_ids.insert(rule.id.as_str()) {
            return Err(BudgetError::InvalidRuleData(format!(
                "duplicate rule id: {}",
                rule.id
            )));
        }
    }

    if rule_set.allowed_amounts_micros.is_empty() {
        return Err(BudgetError::InvalidRuleData(
            "allowed_amounts_micros must not be empty".to_string(),
        ));
    }
    let mut seen_amounts: HashSet<i64> = HashSet::new();
    let mut previous_amount: Option<i64> = None;
    for &amount in &rule_set.allowed_amounts_micros {
        if amount <= 0 {
            return Err(BudgetError::InvalidRuleData(format!(
                "allowed_amounts_micros entries must be positive, got {amount}"
            )));
        }
        if !seen_amounts.insert(amount) {
            return Err(BudgetError::InvalidRuleData(format!(
                "duplicate entry in allowed_amounts_micros: {amount}"
            )));
        }
        if let Some(previous) = previous_amount
            && amount <= previous
        {
            return Err(BudgetError::InvalidRuleData(
                "allowed_amounts_micros must be strictly ascending".to_string(),
            ));
        }
        previous_amount = Some(amount);
    }

    if rule_set.starting_amount_micros <= 0 {
        return Err(BudgetError::InvalidRuleData(format!(
            "starting_amount_micros must be positive, got {}",
            rule_set.starting_amount_micros
        )));
    }
    if rule_set.fail_closed_floor_micros <= 0 {
        return Err(BudgetError::InvalidRuleData(format!(
            "fail_closed_floor_micros must be positive, got {}",
            rule_set.fail_closed_floor_micros
        )));
    }
    if rule_set.fail_closed_floor_micros > rule_set.starting_amount_micros {
        return Err(BudgetError::InvalidRuleData(format!(
            "fail_closed_floor_micros ({}) must not exceed starting_amount_micros ({}): an \
             outage must never grant more than a legitimate new signup would get",
            rule_set.fail_closed_floor_micros, rule_set.starting_amount_micros
        )));
    }

    Ok(())
}

/// Parses `rule_data_json` into a [`RuleSet`] and runs [`validate`] against it. Public so that
/// [`crate::policy_store::PolicyStore`] can run the exact same check `RuleDataEngine::new`/
/// [`RuleDataEngine::load`] use before ever writing an activation attempt to the database --
/// there must be exactly one place this logic lives, not a second, possibly-drifted copy in the
/// storage layer.
pub fn validate_rule_data(rule_data_json: &str) -> Result<RuleSet, BudgetError> {
    let rule_set: RuleSet = serde_json::from_str(rule_data_json).map_err(|err| {
        BudgetError::InvalidRuleData(format!("failed to parse rule data JSON: {err}"))
    })?;
    validate(&rule_set)?;
    Ok(rule_set)
}

fn attempted_policy_revision(rule_data_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(rule_data_json)
        .ok()
        .and_then(|value| {
            value
                .get("policy_revision")
                .and_then(|revision| revision.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Why `evaluate` stopped short of checking every rule.
#[derive(Debug)]
enum EvalAbort {
    /// Walking the active rule set's conditions visited more `Condition` nodes than
    /// `evaluation_budget` allows. See [`RuleDataEngine`]'s doc comment for why this is a
    /// deterministic node-count budget and not a wall-clock timeout.
    BudgetExceeded,
    /// A `Condition::Threshold` referenced a `Field` backed by a `Spend` fact, and that fact was
    /// `Spend::Unavailable`. Per the decision contract's fail-closed rule, this must never be
    /// treated as `false` (would silently fall through, possibly to a more permissive default)
    /// or as `0` (could wrongly satisfy a low-spend threshold) -- it aborts the whole evaluation.
    FieldUnavailable,
}

fn resolve_field(field: Field, facts: &Facts, requested_amount_micros: i64) -> Result<i64, Field> {
    match field {
        Field::SelfServiceGrantCount => Ok(i64::from(facts.self_service_grant_count)),
        Field::EffectiveBalanceMicros => Ok(facts.effective_balance_micros),
        Field::SpendThisPeriodMicros => match facts.spend_this_period {
            Spend::Known(value) => Ok(value),
            Spend::Unavailable => Err(field),
        },
        Field::SpendLastPeriodMicros => match facts.spend_last_period {
            Spend::Known(value) => Ok(value),
            Spend::Unavailable => Err(field),
        },
        Field::RequestedAmountMicros => Ok(requested_amount_micros),
    }
}

fn compare(actual: i64, operator: Operator, expected: i64) -> bool {
    match operator {
        Operator::Lt => actual < expected,
        Operator::Lte => actual <= expected,
        Operator::Gt => actual > expected,
        Operator::Gte => actual >= expected,
        Operator::Eq => actual == expected,
    }
}

fn eval_condition(
    condition: &Condition,
    facts: &Facts,
    requested_amount_micros: i64,
    nodes_evaluated: &mut usize,
    evaluation_budget: usize,
) -> Result<bool, EvalAbort> {
    *nodes_evaluated += 1;
    if *nodes_evaluated > evaluation_budget {
        return Err(EvalAbort::BudgetExceeded);
    }

    match condition {
        Condition::Threshold {
            field,
            operator,
            value,
        } => {
            let actual = resolve_field(*field, facts, requested_amount_micros)
                .map_err(|_field| EvalAbort::FieldUnavailable)?;
            Ok(compare(actual, *operator, *value))
        }
        Condition::All { conditions } => {
            for nested in conditions {
                if !eval_condition(
                    nested,
                    facts,
                    requested_amount_micros,
                    nodes_evaluated,
                    evaluation_budget,
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Condition::Any { conditions } => {
            for nested in conditions {
                if eval_condition(
                    nested,
                    facts,
                    requested_amount_micros,
                    nodes_evaluated,
                    evaluation_budget,
                )? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn decision_for_effect(
    effect: Effect,
    cap_micros: Option<i64>,
    requested_amount_micros: i64,
    reason_code: String,
    matched_rule_ids: Vec<String>,
    policy_revision: String,
) -> Decision {
    let (approved_amount_micros, maximum_amount_micros) = match effect {
        Effect::AutoApprove => (requested_amount_micros, requested_amount_micros),
        Effect::AutoApproveCapped => {
            let cap = cap_micros.unwrap_or(requested_amount_micros);
            (requested_amount_micros.min(cap), cap)
        }
        Effect::ManualReview | Effect::Deny | Effect::NoAction => (0, requested_amount_micros),
    };

    Decision {
        effect,
        approved_amount_micros,
        maximum_amount_micros,
        reason_codes: vec![reason_code],
        matched_rule_ids,
        policy_revision,
        obligations: Obligations::default(),
    }
}

fn abort_decision(
    abort: EvalAbort,
    requested_amount_micros: i64,
    policy_revision: String,
) -> Decision {
    match abort {
        EvalAbort::BudgetExceeded => Decision {
            effect: Effect::Deny,
            approved_amount_micros: 0,
            maximum_amount_micros: requested_amount_micros,
            reason_codes: vec!["evaluation_budget_exceeded".to_string()],
            matched_rule_ids: vec![],
            policy_revision,
            obligations: Obligations::default(),
        },
        EvalAbort::FieldUnavailable => Decision {
            effect: Effect::ManualReview,
            approved_amount_micros: 0,
            maximum_amount_micros: requested_amount_micros,
            reason_codes: vec!["required_fact_unavailable".to_string()],
            matched_rule_ids: vec![],
            policy_revision,
            obligations: Obligations::default(),
        },
    }
}

/// The rule-data [`PolicyEngine`] (ADR-0007): a pure, synchronous, in-memory evaluator over an
/// atomically hot-swappable [`RuleSet`]. Holds no database connection and does no I/O -- loading
/// new rule data and persisting it are different concerns, left to a later PR (the policy
/// lifecycle: storage, an activation RPC, `/health` wiring) that wraps [`RuleDataEngine::load`].
///
/// ## Why `std::sync::RwLock`, not `tokio::sync::RwLock`
///
/// `evaluate` only ever holds the read lock long enough to clone out the active `Arc<RuleSet>`
/// (an `Arc::clone`, not a deep clone of the rule set); the lock is released before any `.await`
/// point (there are none in the actual condition-walking logic -- it is pure computation) and
/// before any `tracing` call. A lock that is never held across an `.await` is exactly the case
/// the plain synchronous `std::sync::RwLock` is for, and using it here avoids pulling `tokio` in
/// as a real (non-dev) dependency of this crate for a lock that doesn't need an async-aware one.
///
/// ## Why the "evaluation timeout" is a node-count budget, not a wall-clock timeout
///
/// ADR-0007 requires that "on any ... evaluation failure the safe default is `manual_review` or
/// `deny`", and #190's acceptance criteria call out "policy evaluation errors or times out ...
/// the request is denied". For an OPA-Wasm engine (a later PR) that is a real wall-clock timeout
/// around an external evaluation. This engine is a pure, synchronous, in-process computation with
/// no I/O and no genuine wall-clock nondeterminism -- a test built on racing a real timeout
/// against it would be flaky (the computation is too fast to reliably exceed any test-safe
/// timeout without an artificial `sleep` or an unrealistically tiny duration, both of which make
/// for a bad, racy test). Instead, `evaluate` counts how many `Condition` nodes it visits while
/// checking rules against a request (walking into `All`/`Any` counts each nested condition too),
/// and aborts to `Effect::Deny` the instant that count would exceed `evaluation_budget`. This is
/// the literal analog of a wall-clock timeout for a synchronous evaluator: it protects against a
/// pathologically large or adversarial rule set exactly the way a timeout protects against a slow
/// one, and it is exactly reproducible in a test (construct a rule set that requires evaluating
/// more conditions than a small configured budget -- no timing races). Do not "fix" this into a
/// real timeout; that would trade a deterministic test for a flaky one without buying anything,
/// since this evaluator has nothing that can actually hang.
#[derive(Debug)]
pub struct RuleDataEngine {
    active: RwLock<Arc<RuleSet>>,
    evaluation_budget: usize,
}

impl RuleDataEngine {
    /// Parses and validates `initial_rule_data_json`. A malformed *initial* load has no previous
    /// rule set to fall back to, so unlike [`Self::load`] it is simply a hard error from the
    /// constructor.
    pub fn new(
        initial_rule_data_json: &str,
        evaluation_budget: usize,
    ) -> Result<Self, BudgetError> {
        let rule_set = validate_rule_data(initial_rule_data_json)?;
        Ok(Self {
            active: RwLock::new(Arc::new(rule_set)),
            evaluation_budget,
        })
    }

    /// Parses and validates `new_rule_data_json`. On success, atomically swaps it in as the
    /// active rule set. On failure, the active rule set is left completely unchanged, the
    /// rejection is logged loudly via `tracing::error!` (including the parse/validation error and,
    /// where recoverable, the rejected `policy_revision`), and the same error is returned so the
    /// caller (a later PR's activation RPC) can propagate it -- the loud log here is this
    /// function's own responsibility, not deferred to a caller that might not log it.
    pub fn load(&self, new_rule_data_json: &str) -> Result<(), BudgetError> {
        match validate_rule_data(new_rule_data_json) {
            Ok(rule_set) => {
                let mut active = self
                    .active
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *active = Arc::new(rule_set);
                Ok(())
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    rejected_policy_revision = %attempted_policy_revision(new_rule_data_json),
                    "rejected rule data load; keeping last-known-good rule set active"
                );
                Err(err)
            }
        }
    }

    /// The `policy_revision` of the rule set currently serving `evaluate` calls. Reflects the
    /// last successful [`Self::load`] (or the constructor's initial rule set if `load` has never
    /// succeeded), including after a `load()` that failed and left the old set in place -- this
    /// is what a later `/health` endpoint reports as "the revision actually serving".
    pub fn active_policy_revision(&self) -> String {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .policy_revision
            .clone()
    }
}

#[lightbridge_authz_core::async_trait]
impl PolicyEngine for RuleDataEngine {
    async fn evaluate(
        &self,
        facts: &Facts,
        requested_amount_micros: i64,
    ) -> Result<Decision, BudgetError> {
        let rule_set = {
            let active = self
                .active
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(&active)
        };

        let mut nodes_evaluated = 0usize;
        for rule in &rule_set.rules {
            match eval_condition(
                &rule.condition,
                facts,
                requested_amount_micros,
                &mut nodes_evaluated,
                self.evaluation_budget,
            ) {
                Ok(true) => {
                    return Ok(decision_for_effect(
                        rule.effect,
                        rule.cap_micros,
                        requested_amount_micros,
                        rule.reason_code.clone(),
                        vec![rule.id.clone()],
                        rule_set.policy_revision.clone(),
                    ));
                }
                Ok(false) => continue,
                Err(abort) => {
                    return Ok(abort_decision(
                        abort,
                        requested_amount_micros,
                        rule_set.policy_revision.clone(),
                    ));
                }
            }
        }

        Ok(decision_for_effect(
            rule_set.default_effect,
            None,
            requested_amount_micros,
            rule_set.default_reason_code.clone(),
            vec![],
            rule_set.policy_revision.clone(),
        ))
    }

    fn allowed_amounts_micros(&self) -> Vec<i64> {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allowed_amounts_micros
            .clone()
    }

    fn starting_amount_micros(&self) -> i64 {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .starting_amount_micros
    }

    fn fail_closed_floor_micros(&self) -> i64 {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_closed_floor_micros
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_with(
        self_service_grant_count: i32,
        spend_this_period: Spend,
        spend_last_period: Spend,
    ) -> Facts {
        Facts {
            effective_balance_micros: 100_000_000,
            self_service_grant_count,
            spend_this_period,
            spend_last_period,
        }
    }

    fn default_facts(self_service_grant_count: i32) -> Facts {
        facts_with(self_service_grant_count, Spend::Known(0), Spend::Known(0))
    }

    #[tokio::test]
    async fn auto_approves_within_unaided_allowance() {
        let engine = RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid rule set");

        for grant_count in [0, 1] {
            let decision = engine
                .evaluate(&default_facts(grant_count), 5_000_000)
                .await
                .expect("evaluation succeeds");

            assert_eq!(decision.effect, Effect::AutoApprove);
            assert_eq!(decision.approved_amount_micros, 5_000_000);
            assert_eq!(decision.reason_codes, vec!["within_unaided_allowance"]);
            assert_eq!(decision.matched_rule_ids, vec!["within-unaided-allowance"]);
        }
    }

    #[tokio::test]
    async fn manual_review_beyond_unaided_allowance() {
        let engine = RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid rule set");

        let decision = engine
            .evaluate(&default_facts(2), 5_000_000)
            .await
            .expect("evaluation succeeds");

        assert_eq!(decision.effect, Effect::ManualReview);
        assert_eq!(decision.reason_codes, vec!["unaided_allowance_exhausted"]);
        assert!(decision.matched_rule_ids.is_empty());
    }

    #[tokio::test]
    async fn malformed_rule_data_keeps_last_known_good() {
        let engine = RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid rule set");

        let result = engine.load("{ this is not valid json");
        assert!(result.is_err());

        assert_eq!(engine.active_policy_revision(), "budget-policy-v1");

        let decision = engine
            .evaluate(&default_facts(0), 5_000_000)
            .await
            .expect("evaluation succeeds");
        assert_eq!(decision.effect, Effect::AutoApprove);
        assert_eq!(decision.approved_amount_micros, 5_000_000);
    }

    #[tokio::test]
    async fn valid_load_replaces_the_active_rule_set() {
        let engine = RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid rule set");

        let replacement = r#"{
          "policy_revision": "budget-policy-v2",
          "rules": [
            {
              "id": "within-unaided-allowance",
              "condition": { "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 5 },
              "effect": "auto_approve",
              "reason_code": "within_unaided_allowance"
            }
          ],
          "default_effect": "manual_review",
          "default_reason_code": "unaided_allowance_exhausted",
          "allowed_amounts_micros": [6000000, 15000000, 30000000],
          "starting_amount_micros": 15000000,
          "fail_closed_floor_micros": 6000000
        }"#;

        engine.load(replacement).expect("valid rule set loads");

        assert_eq!(engine.active_policy_revision(), "budget-policy-v2");

        let decision = engine
            .evaluate(&default_facts(4), 5_000_000)
            .await
            .expect("evaluation succeeds");
        assert_eq!(decision.effect, Effect::AutoApprove);
    }

    #[tokio::test]
    async fn evaluation_timeout_denies() {
        let rule_data = r#"{
          "policy_revision": "budget-policy-v1",
          "rules": [
            {
              "id": "expensive-rule",
              "condition": {
                "type": "all",
                "conditions": [
                  { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
                  { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 }
                ]
              },
              "effect": "auto_approve",
              "reason_code": "should_not_match"
            }
          ],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason",
          "allowed_amounts_micros": [6000000, 15000000, 30000000],
          "starting_amount_micros": 15000000,
          "fail_closed_floor_micros": 6000000
        }"#;
        let engine = RuleDataEngine::new(rule_data, 1).expect("valid rule set");

        let decision = engine
            .evaluate(&default_facts(0), 5_000_000)
            .await
            .expect("evaluation succeeds");

        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.reason_codes, vec!["evaluation_budget_exceeded"]);
    }

    #[tokio::test]
    async fn spend_unavailable_for_a_referenced_field_routes_to_manual_review_not_auto_approve() {
        let rule_data = r#"{
          "policy_revision": "budget-policy-v1",
          "rules": [
            {
              "id": "low-spend-last-period",
              "condition": { "type": "threshold", "field": "spend_last_period_micros", "operator": "lt", "value": 1000000 },
              "effect": "auto_approve",
              "reason_code": "low_spend_last_period"
            }
          ],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason",
          "allowed_amounts_micros": [6000000, 15000000, 30000000],
          "starting_amount_micros": 15000000,
          "fail_closed_floor_micros": 6000000
        }"#;
        let engine = RuleDataEngine::new(rule_data, 1_000).expect("valid rule set");

        let facts = facts_with(0, Spend::Known(0), Spend::Unavailable);
        let decision = engine
            .evaluate(&facts, 5_000_000)
            .await
            .expect("evaluation succeeds");

        assert_eq!(decision.effect, Effect::ManualReview);
        assert_eq!(decision.reason_codes, vec!["required_fact_unavailable"]);
        assert_eq!(decision.approved_amount_micros, 0);
    }

    #[tokio::test]
    async fn auto_approve_capped_clamps_to_the_rule_cap() {
        let rule_data = r#"{
          "policy_revision": "budget-policy-v1",
          "rules": [
            {
              "id": "capped-rule",
              "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
              "effect": "auto_approve_capped",
              "reason_code": "capped",
              "cap_micros": 2000000
            }
          ],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason",
          "allowed_amounts_micros": [6000000, 15000000, 30000000],
          "starting_amount_micros": 15000000,
          "fail_closed_floor_micros": 6000000
        }"#;
        let engine = RuleDataEngine::new(rule_data, 1_000).expect("valid rule set");

        let decision = engine
            .evaluate(&default_facts(0), 5_000_000)
            .await
            .expect("evaluation succeeds");

        assert_eq!(decision.effect, Effect::AutoApproveCapped);
        assert_eq!(decision.approved_amount_micros, 2_000_000);
        assert_eq!(decision.maximum_amount_micros, 2_000_000);
    }

    #[tokio::test]
    async fn rules_evaluated_in_order_first_match_wins() {
        let rule_data = r#"{
          "policy_revision": "budget-policy-v1",
          "rules": [
            {
              "id": "first-rule",
              "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
              "effect": "auto_approve",
              "reason_code": "first_wins"
            },
            {
              "id": "second-rule",
              "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
              "effect": "deny",
              "reason_code": "second_should_not_win"
            }
          ],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason",
          "allowed_amounts_micros": [6000000, 15000000, 30000000],
          "starting_amount_micros": 15000000,
          "fail_closed_floor_micros": 6000000
        }"#;
        let engine = RuleDataEngine::new(rule_data, 1_000).expect("valid rule set");

        let decision = engine
            .evaluate(&default_facts(0), 5_000_000)
            .await
            .expect("evaluation succeeds");

        assert_eq!(decision.effect, Effect::AutoApprove);
        assert_eq!(decision.matched_rule_ids, vec!["first-rule"]);
        assert_eq!(decision.reason_codes, vec!["first_wins"]);
    }

    #[test]
    fn duplicate_rule_ids_rejected_at_load_time() {
        let rule_data = r#"{
          "policy_revision": "budget-policy-v1",
          "rules": [
            {
              "id": "dup",
              "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
              "effect": "auto_approve",
              "reason_code": "a"
            },
            {
              "id": "dup",
              "condition": { "type": "threshold", "field": "requested_amount_micros", "operator": "gte", "value": 0 },
              "effect": "deny",
              "reason_code": "b"
            }
          ],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason"
        }"#;

        let result = RuleDataEngine::new(rule_data, 1_000);
        assert!(matches!(result, Err(BudgetError::InvalidRuleData(_))));
    }

    #[test]
    fn empty_policy_revision_rejected_at_load_time() {
        let rule_data = r#"{
          "policy_revision": "",
          "rules": [],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason"
        }"#;

        let result = RuleDataEngine::new(rule_data, 1_000);
        assert!(matches!(result, Err(BudgetError::InvalidRuleData(_))));
    }

    /// ADR-0015: `default_rule_set_json()` must itself be valid -- if this test fails, the
    /// production seed migration (kept byte-for-byte in sync by convention, not by the compiler)
    /// is very likely invalid too.
    #[test]
    fn default_rule_set_json_is_valid() {
        validate_rule_data(default_rule_set_json()).expect("the shipped default must validate");
    }

    fn rule_set_with(fields_json: &str) -> String {
        format!(
            r#"{{
          "policy_revision": "budget-policy-vtest",
          "rules": [],
          "default_effect": "manual_review",
          "default_reason_code": "default_reason",
          {fields_json}
        }}"#
        )
    }

    #[test]
    fn empty_allowed_amounts_micros_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [], "starting_amount_micros": 15000000, "fail_closed_floor_micros": 6000000"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("allowed_amounts_micros must not be empty")),
            "got {result:?}"
        );
    }

    #[test]
    fn non_ascending_allowed_amounts_micros_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [15000000, 6000000, 30000000], "starting_amount_micros": 15000000, "fail_closed_floor_micros": 6000000"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("strictly ascending")),
            "got {result:?}"
        );
    }

    #[test]
    fn duplicate_allowed_amounts_micros_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [6000000, 6000000, 30000000], "starting_amount_micros": 15000000, "fail_closed_floor_micros": 6000000"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("duplicate entry")),
            "got {result:?}"
        );
    }

    #[test]
    fn non_positive_allowed_amount_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [0, 15000000, 30000000], "starting_amount_micros": 15000000, "fail_closed_floor_micros": 6000000"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("must be positive")),
            "got {result:?}"
        );
    }

    #[test]
    fn non_positive_starting_amount_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [6000000], "starting_amount_micros": 0, "fail_closed_floor_micros": 0"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("starting_amount_micros must be positive")),
            "got {result:?}"
        );
    }

    #[test]
    fn non_positive_fail_closed_floor_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [6000000], "starting_amount_micros": 6000000, "fail_closed_floor_micros": -1"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("fail_closed_floor_micros must be positive")),
            "got {result:?}"
        );
    }

    /// The cross-field invariant that matters most: an outage must never grant more than a
    /// legitimate new signup would get. Proved by construction: the failing case has the floor
    /// strictly above the starting amount; flip the two back to floor <= starting and the same
    /// rule set validates (see the next test), which is what proves this test is actually
    /// checking the ordering and not just "any mismatch."
    #[test]
    fn fail_closed_floor_exceeding_starting_amount_rejected() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [6000000], "starting_amount_micros": 6000000, "fail_closed_floor_micros": 15000000"#,
        );
        let result = validate_rule_data(&rule_data);
        assert!(
            matches!(&result, Err(BudgetError::InvalidRuleData(m)) if m.contains("must not exceed starting_amount_micros")),
            "got {result:?}"
        );
    }

    #[test]
    fn fail_closed_floor_equal_to_starting_amount_is_allowed() {
        let rule_data = rule_set_with(
            r#""allowed_amounts_micros": [6000000], "starting_amount_micros": 6000000, "fail_closed_floor_micros": 6000000"#,
        );
        validate_rule_data(&rule_data).expect("floor == starting amount must be allowed");
    }

    #[test]
    fn engine_exposes_allowed_starting_and_floor_amounts_from_the_active_rule_set() {
        let engine =
            RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid default rule set");
        assert_eq!(
            engine.allowed_amounts_micros(),
            vec![6_000_000, 15_000_000, 30_000_000]
        );
        assert_eq!(engine.starting_amount_micros(), 15_000_000);
        assert_eq!(engine.fail_closed_floor_micros(), 6_000_000);
    }

    /// Proves the three ADR-0015 accessors read the *currently active* rule set, not a value
    /// cached at construction time -- a real risk given `active` is swapped under a lock by
    /// `load()`. Break this by making the accessors read a value captured in `RuleDataEngine::new`
    /// instead of re-reading `self.active` and this test fails because the post-`load()` values
    /// would still be the pre-`load()` ones.
    #[test]
    fn engine_accessors_reflect_a_hot_swapped_rule_set() {
        let engine =
            RuleDataEngine::new(default_rule_set_json(), 1_000).expect("valid default rule set");
        let replacement = rule_set_with(
            r#""allowed_amounts_micros": [9000000, 45000000], "starting_amount_micros": 9000000, "fail_closed_floor_micros": 9000000"#,
        );
        engine.load(&replacement).expect("valid replacement loads");

        assert_eq!(engine.allowed_amounts_micros(), vec![9_000_000, 45_000_000]);
        assert_eq!(engine.starting_amount_micros(), 9_000_000);
        assert_eq!(engine.fail_closed_floor_micros(), 9_000_000);
    }
}
