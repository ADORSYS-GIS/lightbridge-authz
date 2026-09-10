//! "Is this budget account a real account at all?" — the existence check
//! [`crate::remaining::RemainingService`] runs before it computes `ceiling − spend`
//! (ADR-0034, owner directive 2026-09-03, lightbridge-authz#658).
//!
//! ## Why this exists, and why it is not just `effective_balance == 0`
//!
//! `EFFECTIVE_BALANCE_SQL` is a `COALESCE(SUM(...), 0)` over `budget_grants`. A row-less account
//! and a *non-existent* account are indistinguishable to it: both sum to `0`. That made the
//! remaining read answer `200 {"remaining_micros": 0}` for an id nothing in the estate has ever
//! heard of — so a typo in an identity mapping arrived at the gateway as a perfectly ordinary
//! `402 budget_exhausted` for a phantom account, which is the single most expensive way to be
//! wrong: it looks exactly like a real user who really did run out.
//!
//! ## The definition, stated once
//!
//! **Known = a row in `accounts` whose `user_id` resolves to a row in `users`.** The ledger keys
//! on `accounts.id` and nothing else — `budget_grants.budget_account_id`,
//! `budget_balances.budget_account_id` and `budget_augmentation_requests.budget_account_id` are
//! all `TEXT NOT NULL REFERENCES accounts(id)` (`20260803000001`, `20260803000002`,
//! `20260804000002`). It is emphatically **not** `users.id`: ADR-0026 makes one identity own many
//! accounts, so keying this on the person would meter their several balances as one.
//!
//! The `users` join is the ADR-0014 intra-DB read pattern, verbatim from
//! `ResetScheduler::matching_accounts` — the same join, against the same
//! two tables, so the endpoint's notion of "an account exists" and the reset scheduler's notion of
//! "an account the estate grants to" cannot drift apart. `accounts.user_id` is `NOT NULL` and
//! FK-bound, so today it filters nothing; it states that a budget account with no owning identity
//! is not one this endpoint reports on, and stays correct if that column ever becomes nullable.
//!
//! ## What is deliberately NOT part of "unknown"
//!
//! - **`status = 'suspended'`.** A suspended account exists, has a ledger, and its balance is a
//!   real number. Suspension is enforced upstream of the budget entirely (`effective_status`,
//!   `20260714000001`); folding it in here would make one condition wear another's error code.
//! - **Zero grants this period.** That is a *known* account with a ceiling of `0` — the state of
//!   every account between its creation and its first grant, and of every account at 00:00 UTC on
//!   the 1st. It answers `200`, not `404`. See [`crate::remaining::Remaining::UnknownAccount`].

use crate::error::BudgetError;
use crate::repo::BudgetRepo;

/// Existence only — no columns are read, so this stays a pure index probe on the `accounts`
/// primary key plus one FK lookup, on the critical path of every metered model request.
const BUDGET_ACCOUNT_EXISTS_SQL: &str =
    "SELECT 1 FROM accounts a JOIN users u ON u.id = a.user_id WHERE a.id = $1";

/// `true` when `budget_account_id` names a real, owned account.
///
/// A storage failure is an `Err`, never a `false`: "the database did not answer" must not render
/// as "that account does not exist", for exactly the reason `Remaining::Unavailable` is not
/// `remaining = 0`. The caller turns the `Err` into a `503`, which is the honest answer.
pub(crate) async fn budget_account_exists(
    repo: &BudgetRepo,
    budget_account_id: &str,
) -> Result<bool, BudgetError> {
    let row: Option<(i32,)> = sqlx::query_as(BUDGET_ACCOUNT_EXISTS_SQL)
        .bind(budget_account_id)
        .fetch_optional(repo.pool())
        .await
        .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;

    Ok(row.is_some())
}
