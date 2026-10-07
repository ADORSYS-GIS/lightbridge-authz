//! The month-start pass: every real account holds its starting grant for the CURRENT period, and
//! during the last [`PREBOOK_WINDOW`] of a month, for the NEXT one too (#765).
//!
//! ## The defect this closes
//!
//! The gateway's ceiling is `SUM(budget_grants WHERE period = <current UTC month>)`
//! ([`crate::repo::BudgetRepo::effective_balance`]). A grant belongs to ONE calendar month, and
//! nothing booked the next month's: [`crate::starting_grant::StartingGrantService::book`] ran only
//! at account creation, and a reset schedule fires on its own cadence (production's is weekly). So
//! at 00:00 UTC on the 1st every account's ceiling was `0` and the gateway answered `402` to
//! everyone until the next schedule window — up to six days.
//!
//! ## What a pass does
//!
//! One `SELECT` finds the accounts that do not yet hold `budget-start-<period>-<account_id>`
//! (an anti-join on [`crate::starting_grant_amount::starting_grant_key_prefix`]); each is booked
//! through [`StartingGrantService`], never a raw `INSERT` — the ledger has one writer (ADR-0009).
//! In steady state the `SELECT` returns nothing, so a tick takes no row lock.
//!
//! Booking only after midnight would still leave every active account at `0` until the first tick
//! after it: the snapshot refresher rolls a reading into the new period within seconds, so that is
//! up to one tick interval of `402` at every boundary. So in the last [`PREBOOK_WINDOW`] the same
//! pass also runs for the next period, current period first. Outside the window it is exactly one
//! `SELECT`. An account created between the pre-book and midnight has only its creation grant and
//! is funded by the first pass after midnight, like any other missing one.
//!
//! **A grant into the next period cannot move this one.** `effective_balance` filters by
//! `period`, and the snapshot delta [`crate::repo::BudgetRepo::grant`] applies is guarded on
//! `period = $2`, so a stored reading for the current month is untouched until it rolls over.
//!
//! The key is the whole contract. A grant already under it — an account created this month, funded
//! ahead of the boundary, or funded by an operator's Job under the same key — drops out of the
//! `SELECT`, and if it were booked anyway the `ON CONFLICT` replay returns the existing row.
//! Presence of the key is what counts, not whether the row is revoked: a revocation is a decision
//! this pass must not undo.
//!
//! ## Replicas and races
//!
//! Several `authz-budget` replicas run this concurrently, and two can pick the same account. That
//! is safe without a lock: `BudgetRepo::grant` locks the `(account, period)` balance row
//! `FOR UPDATE` before inserting, so the loser waits, its insert hits the unique index on
//! `idempotency_key`, `DO NOTHING` returns zero rows, and the already-committed grant is read back
//! — a unique violation can never surface as an error. Each grant is its own transaction on one
//! balance row, so two replicas walking the same list cannot deadlock either.
//!
//! ## Failure handling
//!
//! One account failing is counted and the pass moves on: stopping at the first failure would let
//! one bad account leave every account behind it at a ceiling of `0`. Failing to enumerate the
//! CURRENT period's missing accounts is an `Err`; failing to enumerate the next one is recorded in
//! its [`PeriodReport`] instead, so it cannot discard what the current pass already did. Nothing
//! here grants more on failure — an unfunded account stays at `0` and is retried on the next tick.
//!
//! The amount is [`StartingGrantService::resolve_amount`]'s, so after this pass the reset schedule
//! that produced it is a `delta = 0` no-op (the `$8`-vs-`$15` rule, [`crate::starting_grant_amount`]).
//! The scheduler's own deferral of an account whose spend is unavailable is unchanged, by owner
//! ruling (2026-10-07, #765): a reset window keeps treating an empty spend as "unknown", never as
//! zero. That is harmless now, because this pass funds the account whatever the reset decides.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_core::db::DbPoolTrait;

use crate::error::BudgetError;
use crate::period::Period;
pub use crate::period_start_report::{PeriodReport, PeriodStartReport};
use crate::remaining::next_period_start_utc;
use crate::starting_grant::StartingGrantService;
use crate::starting_grant_amount::starting_grant_key_prefix;

/// How long before a month ends the next month's grants are booked.
///
/// Wide enough to be robust, narrow enough to stay honest. The loop wakes every 60 s and the pass is
/// idempotent, so an hour is about sixty independent chances to land the pre-book before midnight —
/// a database blip, a slow pass over a large estate, or a replica restart cannot make it miss. It
/// is not a day because the amount is resolved when the grant is booked, and the ledger is
/// append-only (a wrong amount can only be corrected by a `correction` row): the longer the window,
/// the longer an operator's last edit to a schedule or the policy's `starting_amount_micros` is
/// locked out of the coming month. Outside it a wake is exactly one `SELECT`.
const PREBOOK_WINDOW: Duration = Duration::hours(1);

/// Same predicate as `known_account` and the `global` schedule scope: an `accounts` row whose
/// owner resolves to a `users` row. `$1` is the key prefix, so the key's shape stays defined once.
const MISSING_START_GRANTS_SQL: &str = "SELECT a.id FROM accounts a \
     JOIN users u ON u.id = a.user_id \
     WHERE NOT EXISTS ( \
         SELECT 1 FROM budget_grants g WHERE g.idempotency_key = $1::text || a.id \
     ) \
     ORDER BY a.created_at ASC";

/// Books the month-start grant for every account that lacks one. Stateless over the pool, so every
/// replica builds its own.
#[derive(Debug, Clone)]
pub struct PeriodStartGrants {
    pool: Arc<dyn DbPoolTrait>,
    starting: StartingGrantService,
}

impl PeriodStartGrants {
    pub fn new(pool: Arc<dyn DbPoolTrait>, starting: StartingGrantService) -> Self {
        Self { pool, starting }
    }

    /// The accounts with no grant under this period's starting-grant key, oldest first.
    pub async fn missing_accounts(&self, period: &Period) -> Result<Vec<String>, BudgetError> {
        sqlx::query_scalar(MISSING_START_GRANTS_SQL)
            .bind(starting_grant_key_prefix(period))
            .fetch_all(self.pool.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))
    }

    /// One pass at `now`. `now` is a parameter, not a clock read; the current period's grants are
    /// booked at `now`, the next period's at its first instant, so each derives its own key.
    pub async fn run(&self, now: DateTime<Utc>) -> Result<PeriodStartReport, BudgetError> {
        let period = Period::current(now);
        let current = self.book_missing(&period, now, false).await?;

        let boundary = next_period_start_utc(&period);
        let ahead = if now >= boundary - PREBOOK_WINDOW {
            let next = Period::current(boundary);
            Some(match self.book_missing(&next, boundary, true).await {
                Ok(report) => report,
                Err(err) => {
                    tracing::warn!(period = %next, error = %err, "could not list accounts to pre-book");
                    PeriodReport {
                        first_error: Some(err.to_string()),
                        ..PeriodReport::new(next, 0)
                    }
                }
            })
        } else {
            None
        };
        Ok(PeriodStartReport { current, ahead })
    }

    async fn book_missing(
        &self,
        period: &Period,
        at: DateTime<Utc>,
        ahead: bool,
    ) -> Result<PeriodReport, BudgetError> {
        let missing = self.missing_accounts(period).await?;
        let mut report = PeriodReport::new(period.clone(), missing.len());

        for account_id in &missing {
            let booked = if ahead {
                self.starting.book_period_start_ahead(account_id, at).await
            } else {
                self.starting.book_period_start(account_id, at).await
            };
            match booked {
                Ok(_) => report.funded += 1,
                Err(err) => {
                    report.failed += 1;
                    if report.first_error.is_none() {
                        tracing::warn!(
                            budget_account_id = %account_id,
                            period = %period,
                            error = %err,
                            "could not book the month-start grant; retrying on the next tick"
                        );
                        report.first_error = Some(err.to_string());
                    }
                }
            }
        }
        Ok(report)
    }
}
