//! "How much of this period's budget is left, right now" — the one question the gateway's
//! Dynamic Budget Limiter asks (ADR-0034, lightbridge-authz#658).
//!
//! Everything else in this crate answers *control-plane* questions: may this account be granted
//! more, what did a schedule decide, what is on the ledger. This module answers a *data-plane*
//! question, on the critical path of every model request, and that changes the rules it plays by:
//!
//! - **It never invents a number.** `ceiling − spend` is only meaningful when both halves are
//!   known. A ledger read that fails is an `Err`; a spend source that cannot be asked is
//!   [`Remaining::Unavailable`]. Neither is ever `remaining_micros = 0`, because "we don't know"
//!   and "you have nothing left" produce opposite correct behaviours at the gateway (a 503 the
//!   operator can see and a grace window can ride out, versus a 402 that tells the user to top
//!   up money they already have).
//! - **It distinguishes "the spend store answered, and it has no rows" from "the spend store
//!   could not be asked".** [`crate::spend::Spend`] deliberately collapses both into
//!   `Unavailable`, which is the right call for a refill decision — a grant must never be handed
//!   out on unverified spend. It is the wrong call here: on the 1st of every month EVERY account
//!   has zero rows in the current period until its first request completes, so collapsing the two
//!   would 503 the entire fleet at each month boundary. [`crate::spend::SpendObservation`] keeps
//!   them apart for this caller and only this caller; the refill path's semantics are untouched.
//!
//! The ceiling is [`crate::repo::BudgetRepo::effective_balance`] (expiry- and revocation-aware),
//! not the raw `budget_balances.effective_budget_micros` projection. The two agree for every
//! account with no expiring grants; where they disagree, the expiry-aware sum is the stricter and
//! the more honest one — an expired grant must not buy gateway traffic — and it is the same
//! quantity [`crate::facts::Facts::effective_balance_micros`] already means by "balance".

use chrono::{DateTime, NaiveDate, Utc};

use crate::error::BudgetError;
use crate::period::Period;

pub use crate::remaining_service::RemainingService;

/// A fully-known remaining-budget answer for one `(budget account, period)`.
///
/// Money is integer micro-USD throughout. `remaining_micros` is **signed and not clamped**: an
/// account that overshot its ceiling (the gateway charges `llm_custom_total_cost` *after* the
/// response, so one in-flight request can always overshoot — see ADR-0034's overspend-window
/// analysis) reports a negative number rather than a flattering zero. Consumers that render a
/// user-facing figure clamp at zero themselves; consumers that alert on overspend need the sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRemaining {
    pub budget_account_id: String,
    pub period: Period,
    /// Expiry/revocation-aware sum of this period's grants — see the module doc comment for why
    /// this and not the raw `budget_balances` projection.
    pub ceiling_micros: i64,
    /// `SUM(usage_events.total_cost)` for this account over this period, as the usage service
    /// reported it. Zero here means "the usage store answered, and it has nothing for this
    /// account this period" — never "we could not ask".
    pub spent_micros: i64,
    /// `ceiling_micros − spent_micros`, saturating. May be negative; see the struct doc comment.
    pub remaining_micros: i64,
    /// When this account's budget next changes on its own: the winning reset schedule's
    /// `next_run_at` (ADR-0032) when one exists, otherwise the start of the next calendar period.
    /// Never null — an account with no schedule still rolls over on the 1st.
    pub next_reset_at: DateTime<Utc>,
    /// How old `spent_micros` is, in seconds, when this service is serving a cached reading
    /// through the grace window (see [`RemainingService::with_grace`]) — `Some(age)` then, and
    /// `None` when the reading is fresh.
    ///
    /// **`None` does not mean zero staleness, and must never be rendered as `0`.** A fresh
    /// reading still trails reality by the OTLP **ingest** lag: how long ago the newest usage
    /// event for this account actually reached `usage_events`. `/usage/v1/spend/query` returns a
    /// bare `SUM` with no timestamp, so this service has nothing to measure that with, and
    /// reporting the ~0 s round-trip age of a freshly-read number as though it were the ingest lag
    /// would be worse than admitting ignorance — ADR-0034's overspend window is computed *from*
    /// this term. Teaching `/usage/v1/spend/query` to return `MAX(time)` alongside the sum is the
    /// tracked follow-up that would make the fresh case a real number too.
    ///
    /// So: `Some(n)` is a **lower bound** on staleness (cache age, ingest lag on top), and `None`
    /// is "no cache age to report", not "current".
    pub source_lag_seconds: Option<u64>,
}

/// The result of asking for an account's remaining budget.
///
/// There is no variant for "the ledger failed": that surfaces as `Err(BudgetError)` from
/// [`RemainingService::remaining_for_account`], because a ledger read failing is a fault, while a
/// spend source being unreachable is an expected, transient operating condition the gateway is
/// designed to ride out (ADR-0034's cached-grace window). Both end as a `503` at the HTTP edge;
/// they are kept apart here so logs and metrics can tell an outage from a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remaining {
    Known(Box<BudgetRemaining>),
    /// The spend source could not be asked. **Not** `remaining = 0`, and not an error.
    Unavailable,
    /// The id names no account at all — see the `known_account` module for the exact definition and
    /// for the two conditions that are deliberately *not* this one (a suspended account, and a
    /// real account with no grants yet).
    ///
    /// A third outcome rather than a `Known` answer with a zero ceiling, because the two are
    /// opposite facts about the world that happen to share an arithmetic result. A real account
    /// awaiting its first grant has a ceiling of `0` and must be refused as
    /// `budget_exhausted`; an id nothing has ever heard of is a **configuration error upstream**
    /// — a typo in an identity mapping, a stale claim, a mis-scoped token — and refusing it as
    /// "you have spent everything" hides the fault behind a page telling a phantom user to top
    /// up. The HTTP edge renders this as `404 unknown_account`.
    UnknownAccount,
}

/// Reads an account's remaining budget. A trait, not just the concrete [`RemainingService`], so
/// the HTTP handler in `lightbridge-authz-rest` can be exercised against every outcome —
/// including the two that matter most, an unreachable spend source and an unreadable ledger —
/// without a live Postgres. Those are precisely the paths a DB-backed test cannot reach on
/// demand, and they are the ones that must never render as "you have nothing left".
#[lightbridge_authz_core::async_trait]
pub trait RemainingReader: Send + Sync + std::fmt::Debug {
    async fn remaining_for_account(
        &self,
        budget_account_id: &str,
        period: &Period,
        now: DateTime<Utc>,
    ) -> Result<Remaining, BudgetError>;
}

/// Midnight UTC on the 1st of the calendar month **after** `period` — when the ledger's period
/// key rotates, and the same instant the gateway's `x-billing-period` marker flips
/// (`ai-helm` ADR-0111). Used as `next_reset_at` for an account no reset schedule covers.
///
/// Infallible: [`Period`] only ever holds an already-validated `YYYY-MM`, so stepping one month
/// forward always lands on a real calendar date.
pub(crate) fn next_period_start_utc(period: &Period) -> DateTime<Utc> {
    let (year, month) = if period.month() == 12 {
        (period.year() + 1, 1u8)
    } else {
        (period.year(), period.month() + 1)
    };

    NaiveDate::from_ymd_opt(year as i32, u32::from(month), 1)
        .expect("Period invariant: year/month always form a valid calendar date")
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_period_start_is_the_first_of_the_following_month() {
        let period = Period::parse("2026-09").expect("valid period");
        assert_eq!(
            next_period_start_utc(&period).to_rfc3339(),
            "2026-10-01T00:00:00+00:00"
        );
    }

    #[test]
    fn next_period_start_rolls_over_the_year() {
        let period = Period::parse("2026-12").expect("valid period");
        assert_eq!(
            next_period_start_utc(&period).to_rfc3339(),
            "2027-01-01T00:00:00+00:00"
        );
    }
}
