//! **How much** a starting grant is worth, and the key it is booked under (#697). The *when* and
//! the write live in [`crate::starting_grant`]; split from it only to keep both files under this
//! repo's 200-LoC ceiling.
//!
//! ## The amount rule, stated once
//!
//! **The starting grant equals what [`crate::effective_schedule`] would reset the account to.**
//! Not the policy default, and not a constant. The reset scheduler in `mode: reset` books
//! `delta = target − remaining` ([`crate::reset_scheduler`]), so a starting grant of any OTHER
//! size is silently clawed back by a negative `correction` row on the next window — the exact
//! `$8`-vs-`$15` trap `docs/budget-cli.md` documents, which cost the 2026-09-04 backfill a
//! deliberate decision. Granting the schedule's own target makes that window a no-op
//! (`delta = 0`, and a zero-amount row is rejected by `budget_grants_amount_sign_chk` anyway), so
//! the ledger stays readable at a glance. `mode: top_up` takes the same number for a different
//! reason: a top-up adds a fixed `amount_micros` whatever the balance, so its target *is* its
//! amount.
//!
//! **The policy `starting_amount_micros` (ADR-0015 Decision 5) is the fallback, and only when NO
//! enabled schedule covers the account at all.** With no schedule there is no target to match and
//! nothing to be corrected against, so the policy's own answer to "what does a brand-new account
//! start with" is the right one.
//!
//! ### The consequence nobody should discover in production
//!
//! An account has no `billing_plan` of its own — a plan reaches it through its projects and their
//! API keys (see [`crate::effective_schedule`]). At `createAccount` time an account has neither,
//! so a `billing_plan`-scoped schedule (which is what production runs: `"Refill $8"`, scope
//! `billing_plan=free`) does **not** cover it yet and the policy fallback is what fires. Keep
//! `starting_amount_micros` aligned with the operative plan schedule's `amount_micros`, or the
//! first weekly window after the account acquires a free-plan project books the difference as a
//! `correction`. A `global`-scoped schedule, by contrast, matches from the first second.

use crate::period::Period;

/// `budget-start-<period>-<account_id>` — the one idempotency key a starting grant is ever booked
/// under. Deliberately carries the period: a new period is a new grant, not a replay of the last.
pub fn starting_grant_idempotency_key(period: &Period, budget_account_id: &str) -> String {
    format!("budget-start-{period}-{budget_account_id}")
}

/// Where a starting grant's amount came from — recorded on the booked grant's `reason` and
/// logged, so an operator reading the ledger can tell a schedule-matched grant from the policy
/// fallback without re-deriving the precedence rule by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartingAmount {
    /// The winning [`crate::effective_schedule::EffectiveSchedule`]'s target.
    Schedule {
        schedule_id: String,
        schedule_name: String,
        amount_micros: i64,
    },
    /// No enabled schedule covers this account, so ADR-0015 Decision 5's
    /// [`crate::decision::PolicyEngine::starting_amount_micros`] applies.
    PolicyDefault { amount_micros: i64 },
}

impl StartingAmount {
    pub fn amount_micros(&self) -> i64 {
        match self {
            Self::Schedule { amount_micros, .. } | Self::PolicyDefault { amount_micros } => {
                *amount_micros
            }
        }
    }

    /// The `budget_grants.reason` this amount is booked with. ADR-0009 makes the ledger
    /// append-only and the reason column most of what it is for, so it names the rule that
    /// produced the number rather than restating the number.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Schedule {
                schedule_id,
                schedule_name,
                ..
            } => format!(
                "starting grant at account creation, matching reset schedule '{schedule_name}' \
                 ({schedule_id})"
            ),
            Self::PolicyDefault { .. } => {
                "starting grant at account creation, from the active policy's \
                 starting_amount_micros (no reset schedule covers this account)"
                    .to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_idempotency_key_carries_the_period_and_the_account() {
        let period = Period::parse("2026-09").expect("valid period");
        assert_eq!(
            starting_grant_idempotency_key(&period, "acc-1"),
            "budget-start-2026-09-acc-1"
        );
    }

    #[test]
    fn a_schedule_matched_amount_names_the_schedule_in_its_reason() {
        let amount = StartingAmount::Schedule {
            schedule_id: "sched-1".to_string(),
            schedule_name: "Refill $8".to_string(),
            amount_micros: 8_000_000,
        };
        assert_eq!(amount.amount_micros(), 8_000_000);
        assert!(amount.reason().contains("Refill $8"));
        assert!(amount.reason().contains("sched-1"));
    }

    #[test]
    fn the_policy_fallback_says_so_in_its_reason() {
        let amount = StartingAmount::PolicyDefault {
            amount_micros: 15_000_000,
        };
        assert_eq!(amount.amount_micros(), 15_000_000);
        assert!(amount.reason().contains("starting_amount_micros"));
    }
}
