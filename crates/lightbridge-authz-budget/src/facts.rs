//! The fact set a [`crate::decision::PolicyEngine`] evaluates against (ADR-0007). Per the ADR,
//! "the host loads every fact, locks, evaluates, re-validates hard invariants in application and
//! SQL, applies atomically" -- the evaluator itself must be a pure function of the facts handed
//! to it; it never fetches state, never touches the DB, never calls out. `Facts` is what the
//! host constructs *before* handing control to the evaluator.
//!
//! This module deliberately does not include a function that populates a `Facts` value from the
//! database (no `load_facts` calling [`crate::repo::BudgetRepo`]/[`crate::spend::SpendReader`]
//! together) -- that belongs to whichever later PR builds the request-handling procedure. This
//! module only defines the shape.

use crate::spend::Spend;

/// Everything a [`crate::decision::PolicyEngine`] needs to evaluate one refill request, gathered
/// by the host ahead of time. See `docs/budget-decision-contract.md` for where each field comes
/// from and how a caller assembles one of these.
#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    /// The account's expiry/revocation-aware effective balance for the requested period, from
    /// `BudgetRepo::effective_balance`.
    pub effective_balance_micros: i64,
    /// How many *unaided* (auto-approved) self-service refills this account has already used
    /// this period -- the number ADR-0008's "two unaided rungs per period" policy caps. Read
    /// directly off the `budget_balances` row (`self_service_grant_count`); do NOT re-derive it
    /// from `rebuild_all_balances` here, that function replays the whole ledger and is not the
    /// right tool for reading one row's current counter.
    pub self_service_grant_count: i32,
    /// Spend for the period being evaluated, from `SpendReader` -- deliberately the `Spend` enum
    /// from `spend.rs`, NOT a bare number: a policy evaluating "how much have they spent" must be
    /// able to see `Spend::Unavailable` and treat it as a distinct case (fail closed), never
    /// silently coerce it to zero.
    pub spend_this_period: Spend,
    /// Spend for the immediately preceding period (ADR-0007's own example: "approve up to 20% of
    /// last period's consumption"). Same `Spend`/`Unavailable` discipline applies.
    pub spend_last_period: Spend,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_hold_the_fields_passed_to_it() {
        let facts = Facts {
            effective_balance_micros: 42_000_000,
            self_service_grant_count: 1,
            spend_this_period: Spend::Known(10_000_000),
            spend_last_period: Spend::Known(20_000_000),
        };

        assert_eq!(facts.effective_balance_micros, 42_000_000);
        assert_eq!(facts.self_service_grant_count, 1);
        assert_eq!(facts.spend_this_period, Spend::Known(10_000_000));
        assert_eq!(facts.spend_last_period, Spend::Known(20_000_000));
    }

    #[test]
    fn unavailable_spend_is_representable_and_not_coerced_to_zero() {
        let facts = Facts {
            effective_balance_micros: 0,
            self_service_grant_count: 0,
            spend_this_period: Spend::Unavailable,
            spend_last_period: Spend::Unavailable,
        };

        assert!(matches!(facts.spend_this_period, Spend::Unavailable));
        assert!(matches!(facts.spend_last_period, Spend::Unavailable));
    }
}
