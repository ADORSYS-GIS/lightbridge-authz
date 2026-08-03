//! The decision contract (ADR-0007): the one shape every policy engine returns, and the one
//! shape every caller consumes. This module intentionally carries no evaluation logic -- it is
//! the seam a Rust rule-data evaluator and, later, an OPA-Wasm evaluator both sit behind, so
//! that swapping or adding an engine never requires the caller (or the other engine) to change.
//!
//! See `docs/budget-decision-contract.md` for the full contract write-up aimed at someone
//! implementing a second engine against this trait without reading the first engine's source.

use serde::{Deserialize, Serialize};

use crate::error::BudgetError;
use crate::facts::Facts;

/// What a policy decision resolves to. Per ADR-0007, `AutoApprove`/`AutoApproveCapped` are the
/// only effects that authorize a grant; everything else must not result in one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    AutoApprove,
    AutoApproveCapped,
    ManualReview,
    Deny,
    NoAction,
}

/// Side conditions attached to a [`Decision`] that the caller must satisfy beyond granting or
/// not granting.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Obligations {
    /// The one concrete example ADR-0007 gives -- which role must review a `ManualReview`
    /// decision. Modeled as a named optional field rather than a free-form map: there is
    /// exactly one obligation kind textually justified right now, and a generic map would be
    /// speculative. Extend with more named fields if/when a second obligation kind is needed,
    /// rather than reaching for a generic `HashMap<String, serde_json::Value>` preemptively.
    pub required_approver_role: Option<String>,
}

/// A policy engine's answer to "should this refill request be granted, and how much". This is
/// the exact wire shape from ADR-0007's decision contract; every field is present on every
/// decision regardless of `effect`, so a caller never has to guess which fields are populated
/// for which effect (unused fields are simply left at their zero/empty value).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub approved_amount_micros: i64,
    pub maximum_amount_micros: i64,
    pub reason_codes: Vec<String>,
    pub matched_rule_ids: Vec<String>,
    pub policy_revision: String,
    pub obligations: Obligations,
}

/// A policy engine that decides refill requests. Implementations must be pure functions of
/// `facts`/`requested_amount_micros` -- no I/O, no clock reads, no state fetching. Per ADR-0007
/// ("OPA decides; this service mutates"), the engine never inserts grants, never touches Redis,
/// never fetches state, and never calls out; the host loads every fact, locks the balance,
/// evaluates, re-validates hard invariants in application and SQL, and applies atomically.
///
/// Any failure (compile error, timeout, malformed rule data) must map to a `Decision` with
/// `effect: Deny` or `ManualReview` -- automatic approval is never the safe default. A
/// `Result::Err` return is reserved for failures the caller itself must react to (e.g. the
/// engine could not be invoked at all); an evaluator that *can* run to completion should prefer
/// returning `Ok(Decision { effect: Deny | ManualReview, .. })` over an `Err`, since a `Decision`
/// carries `reason_codes` that an `Err` cannot.
#[lightbridge_authz_core::async_trait]
pub trait PolicyEngine: Send + Sync + std::fmt::Debug {
    async fn evaluate(
        &self,
        facts: &Facts,
        requested_amount_micros: i64,
    ) -> Result<Decision, BudgetError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend::Spend;

    fn sample_decision() -> Decision {
        Decision {
            effect: Effect::ManualReview,
            approved_amount_micros: 0,
            maximum_amount_micros: 5_000_000,
            reason_codes: vec!["over_unaided_rung_limit".to_string()],
            matched_rule_ids: vec!["rule-42".to_string()],
            policy_revision: "budget-policy-42".to_string(),
            obligations: Obligations {
                required_approver_role: Some("budget-approver".to_string()),
            },
        }
    }

    #[test]
    fn decision_round_trips_through_json() {
        let decision = sample_decision();
        let json = serde_json::to_string(&decision).expect("decision must serialize");
        let parsed: Decision = serde_json::from_str(&json).expect("decision must deserialize");
        assert_eq!(parsed, decision);
    }

    #[test]
    fn effect_variants_serialize_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&Effect::AutoApprove).expect("must serialize"),
            "\"auto_approve\""
        );
        assert_eq!(
            serde_json::to_string(&Effect::AutoApproveCapped).expect("must serialize"),
            "\"auto_approve_capped\""
        );
        assert_eq!(
            serde_json::to_string(&Effect::ManualReview).expect("must serialize"),
            "\"manual_review\""
        );
        assert_eq!(
            serde_json::to_string(&Effect::Deny).expect("must serialize"),
            "\"deny\""
        );
        assert_eq!(
            serde_json::to_string(&Effect::NoAction).expect("must serialize"),
            "\"no_action\""
        );
    }

    #[test]
    fn obligations_default_has_no_required_approver_role() {
        assert_eq!(
            Obligations::default(),
            Obligations {
                required_approver_role: None,
            }
        );
    }

    #[test]
    fn obligations_round_trip_through_json() {
        let obligations = Obligations {
            required_approver_role: Some("budget-approver".to_string()),
        };
        let json = serde_json::to_string(&obligations).expect("obligations must serialize");
        let parsed: Obligations =
            serde_json::from_str(&json).expect("obligations must deserialize");
        assert_eq!(parsed, obligations);
    }

    #[test]
    fn facts_are_constructible_with_unavailable_spend() {
        let facts = Facts {
            effective_balance_micros: 10_000_000,
            self_service_grant_count: 0,
            spend_this_period: Spend::Unavailable,
            spend_last_period: Spend::Known(5_000_000),
        };
        assert!(matches!(facts.spend_this_period, Spend::Unavailable));
    }
}
