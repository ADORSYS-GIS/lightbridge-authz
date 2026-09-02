//! The budget reset scheduler (ADR-0032): the first background job in this codebase.
//!
//! One `tick(now)` is one pass:
//!
//! 1. Claim every due schedule inside a transaction with
//!    `SELECT … WHERE enabled AND next_run_at <= $now FOR UPDATE SKIP LOCKED`. `SKIP LOCKED` is
//!    what makes several `authz-budget` replicas waking on the same 60-second interval safe: a row
//!    another replica already holds is skipped, not waited on, so each schedule fires exactly once
//!    per window across the fleet.
//! 2. For each claimed schedule, resolve the budget accounts it matches, drop the ones a MORE
//!    SPECIFIC enabled schedule covers (account > billing_plan > global), read spend-to-date
//!    through [`SpendReader`], and write ONE grant per surviving account.
//! 3. Advance `next_run_at` from the schedule (previous window + one cadence step, never from
//!    `now`) and stamp `last_run_at`, still inside the claim transaction, then commit.
//!
//! ## Why the whole pass runs inside the claim transaction
//!
//! The grants themselves go through [`BudgetRepo::grant`], which opens its OWN transaction on its
//! own connection (a different row lock — `budget_balances`, not `budget_reset_schedules`), so
//! there is no deadlock between the two. Holding the claim transaction across the work means a
//! crash mid-pass rolls the `next_run_at` advance back, and the same window is simply reclaimed on
//! the next tick — where every grant already written is deduplicated by its `trigger_key`. The
//! alternative (commit the advance first, then grant) would silently lose a window on a crash.
//!
//! ## Idempotency key shape
//!
//! `budget_grants.trigger_key` carries `"<schedule_id>:<window_start>:<budget_account_id>"`. The
//! story names `schedule_id + window_start`; the account id is appended because
//! `budget_grants_trigger_key_uidx` is a UNIQUE index over the WHOLE table, so a window that
//! matches 100 accounts would collide with itself on the second row without it. The same string is
//! also bound as `idempotency_key`, which is the column [`BudgetRepo::grant`] resolves with
//! `ON CONFLICT … DO NOTHING` — so a replayed window returns the already-committed grant instead of
//! raising a unique-violation.
//!
//! ## What this does NOT do
//!
//! It changes the ledger balance, and therefore the `budget_tier` claim minted at token exchange
//! (ADR-0014). It does NOT change what a request experiences at the gateway: live 429s still come
//! from Envoy's `BackendTrafficPolicy` buckets keyed on the Authorino-stamped `x-billing-plan`
//! header, until Phase 6a lands. See `docs/adr/0032-budget-reset-schedules.md` and
//! `docs/governance-model-and-enforcement.md`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::PgPool;
use sqlx::Row;

use crate::error::BudgetError;
use crate::period::Period;
use crate::repo::{BudgetRepo, GrantRequest};
use crate::reset_schedule::{BudgetResetSchedule, ResetMode, ResetScheduleRepo, ScheduleScopeKind};
use crate::source::GrantSource;
use crate::spend::{Spend, SpendReader};

/// Upper bound on how many due schedules one tick claims. A deliberate ceiling, not a page cursor:
/// anything beyond it is claimed by the next tick 60 seconds later, and in practice an operator
/// has a handful of schedules, not hundreds.
const MAX_CLAIMED_PER_TICK: i64 = 64;

/// How long a window whose spend could not be read stays claimable before the scheduler gives up
/// on it and advances anyway.
///
/// The acceptance criterion is "the account is retried on the next tick", which is only true if
/// the window stays due — so a pass that deferred at least one account leaves `next_run_at` alone
/// and the next tick re-claims the same window (already-written grants are deduplicated by
/// `trigger_key`). Left unbounded, a permanently unreachable usage service would re-scan the whole
/// estate every 60 seconds forever, so the retry stops after this grace period and the window is
/// abandoned with a loud `warn` rather than silently retried into the next decade.
const DEFERRAL_GRACE: Duration = Duration::hours(1);

/// One account's would-be grant for a window: what the console's "Preview" renders, and exactly
/// what a non-dry run writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedGrant {
    pub budget_account_id: String,
    /// `effective_budget − spend_to_date` at plan time, in micro-USD. Can be negative (an account
    /// that overspent its grants).
    pub remaining_micros: i64,
    /// What would be written to the ledger. Positive is a `source = 'automatic'` grant; negative is
    /// the `source = 'correction'` compensating row (ADR-0009). Never zero — a no-op delta is
    /// dropped from the plan entirely rather than booked as an auditless zero-amount row (the DB
    /// `CHECK` rejects one anyway).
    pub delta_micros: i64,
}

/// The result of running one schedule's window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduleRunOutcome {
    /// The grants written (or, for a dry run, the grants that WOULD be written).
    pub planned: Vec<PlannedGrant>,
    /// Accounts whose spend came back [`Spend::Unavailable`] — no grant was written for them, and
    /// the window stays due so the next tick retries them.
    pub deferred_account_ids: Vec<String>,
    /// Accounts matched by this schedule but covered by a more specific enabled one.
    pub superseded_account_ids: Vec<String>,
}

/// What one [`ResetScheduler::tick`] did, for logs and for the concurrency test.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// The ids of the schedules THIS tick claimed. A concurrently running tick claims a disjoint
    /// set (`FOR UPDATE SKIP LOCKED`), which is exactly what the replica-safety test asserts.
    pub claimed_schedule_ids: Vec<String>,
    /// How many ledger rows this tick wrote, across every claimed schedule.
    pub grants_written: usize,
}

/// The winning schedule for one budget account, plus when it next fires — the answer
/// `getEffectiveResetSchedule` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSchedule {
    pub schedule: BudgetResetSchedule,
    pub next_run_at: DateTime<Utc>,
}

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

/// Executes budget reset schedules. Constructed once at `authz-budget` startup and shared by the
/// interval task and by the RPC procedures (`runBudgetResetScheduleNow`,
/// `getEffectiveResetSchedule`), so a dry run and a real tick can never disagree about what a
/// schedule would do — they are literally the same code path with one boolean flipped.
#[derive(Debug, Clone)]
pub struct ResetScheduler {
    pool: Arc<dyn DbPoolTrait>,
    schedules: Arc<ResetScheduleRepo>,
    budget_repo: Arc<BudgetRepo>,
    spend_reader: Arc<dyn SpendReader>,
}

impl ResetScheduler {
    /// `schedules` is built here rather than injected: [`ResetScheduleRepo`] has exactly one
    /// owner in this codebase (this type, which re-exposes it through [`Self::schedules`] for the
    /// CRUD procedures), so threading it through every call site would be an argument that can
    /// only ever be given one value. `budget_repo` IS injected, because it is genuinely shared —
    /// the RPC surface and the refill path hold the same handle.
    pub fn new(
        pool: Arc<dyn DbPoolTrait>,
        budget_repo: Arc<BudgetRepo>,
        spend_reader: Arc<dyn SpendReader>,
    ) -> Self {
        Self {
            schedules: Arc::new(ResetScheduleRepo::new(pool.clone())),
            pool,
            budget_repo,
            spend_reader,
        }
    }

    /// The schedule repository, for the CRUD procedures. Exposed rather than re-wrapped: the
    /// procedures need plain list/get/create/update/delete, and forwarding five methods that add
    /// nothing would be noise.
    pub fn schedules(&self) -> &ResetScheduleRepo {
        &self.schedules
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    /// One scheduler pass. See the module doc for the full shape.
    pub async fn tick(&self, now: DateTime<Utc>) -> Result<TickReport, BudgetError> {
        let enabled = self.schedules.list_enabled().await?;

        let mut tx = self.pool().begin().await.map_err(storage_failed)?;

        let claimed_ids: Vec<String> = sqlx::query(
            "SELECT id FROM budget_reset_schedules \
             WHERE enabled AND next_run_at <= $1 \
             ORDER BY next_run_at ASC \
             LIMIT $2 \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(now)
        .bind(MAX_CLAIMED_PER_TICK)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage_failed)?
        .into_iter()
        .map(|row| row.get::<String, _>("id"))
        .collect();

        let mut report = TickReport {
            claimed_schedule_ids: claimed_ids.clone(),
            grants_written: 0,
        };

        for id in &claimed_ids {
            let schedule = self.schedules.get(id).await?;
            let window_start = schedule.next_run_at;

            let outcome = match self
                .execute(&schedule, window_start, now, &enabled, false)
                .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    // A whole-schedule failure (enumeration or a ledger write blowing up) leaves
                    // `next_run_at` untouched, so the window is reclaimed next tick rather than
                    // silently skipped. The transaction is still committed for the schedules that
                    // did succeed.
                    tracing::warn!(
                        schedule_id = %schedule.id,
                        schedule_name = %schedule.name,
                        error = %err,
                        "budget reset schedule failed this window; leaving it due for the next tick"
                    );
                    continue;
                }
            };

            report.grants_written += outcome.planned.len();

            let deferred = !outcome.deferred_account_ids.is_empty();
            let grace_expired = now >= window_start + DEFERRAL_GRACE;

            if deferred && !grace_expired {
                tracing::warn!(
                    schedule_id = %schedule.id,
                    deferred = outcome.deferred_account_ids.len(),
                    granted = outcome.planned.len(),
                    "spend was unavailable for some accounts; leaving this window due so the next \
                     tick retries them (grants already written are idempotent on trigger_key)"
                );
                sqlx::query(
                    "UPDATE budget_reset_schedules SET last_run_at = $2, updated_at = $2 \
                     WHERE id = $1",
                )
                .bind(&schedule.id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(storage_failed)?;
                continue;
            }

            if deferred {
                tracing::warn!(
                    schedule_id = %schedule.id,
                    deferred = outcome.deferred_account_ids.len(),
                    "spend was still unavailable after the deferral grace period; abandoning this \
                     window and advancing to the next one"
                );
            }

            let next_run_at = schedule.advance_from_next_run(now)?;
            sqlx::query(
                "UPDATE budget_reset_schedules \
                 SET next_run_at = $2, last_run_at = $3, updated_at = $3 \
                 WHERE id = $1",
            )
            .bind(&schedule.id)
            .bind(next_run_at)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage_failed)?;
        }

        tx.commit().await.map_err(storage_failed)?;

        Ok(report)
    }

    /// `runBudgetResetScheduleNow`. Fires the schedule's CURRENT pending window immediately,
    /// whether or not it is due yet — so the `trigger_key` is the one the scheduled tick would have
    /// used, and running now then letting the tick catch up cannot double-grant. A dry run computes
    /// the plan and writes nothing at all: no grant, no `next_run_at` advance, no `last_run_at`.
    pub async fn run_now(
        &self,
        schedule_id: &str,
        now: DateTime<Utc>,
        dry_run: bool,
    ) -> Result<ScheduleRunOutcome, BudgetError> {
        let schedule = self.schedules.get(schedule_id).await?;
        let enabled = self.schedules.list_enabled().await?;
        let window_start = schedule.next_run_at;

        let outcome = self
            .execute(&schedule, window_start, now, &enabled, dry_run)
            .await?;

        if !dry_run {
            let next_run_at = schedule.advance_from_next_run(now)?;
            sqlx::query(
                "UPDATE budget_reset_schedules \
                 SET next_run_at = $2, last_run_at = $3, updated_at = $3 \
                 WHERE id = $1",
            )
            .bind(&schedule.id)
            .bind(next_run_at)
            .bind(now)
            .execute(self.pool())
            .await
            .map_err(storage_failed)?;
        }

        Ok(outcome)
    }

    /// The winning schedule for one budget account: the most specific ENABLED schedule that matches
    /// it (account > billing_plan > global), or `None` when nothing does. Gated at `budget:read`,
    /// not `budget:schedule-manage`, so an account's budget card can render "next reset: <date> →
    /// $X" without granting the caller the ability to author schedules.
    pub async fn effective_schedule(
        &self,
        budget_account_id: &str,
    ) -> Result<Option<EffectiveSchedule>, BudgetError> {
        let enabled = self.schedules.list_enabled().await?;
        if enabled.is_empty() {
            return Ok(None);
        }
        let ids = vec![budget_account_id.to_string()];
        let plans = self.billing_plans_for_accounts(&ids).await?;
        let empty = HashSet::new();
        let account_plans = plans.get(budget_account_id).unwrap_or(&empty);

        Ok(
            winning_schedule(budget_account_id, account_plans, &enabled).map(|schedule| {
                EffectiveSchedule {
                    next_run_at: schedule.next_run_at,
                    schedule: schedule.clone(),
                }
            }),
        )
    }

    /// Resolves the accounts a schedule covers, applies precedence, computes each delta, and (when
    /// `dry_run` is false) writes the grants. The single code path behind the tick, `run_now`, and
    /// the dry run.
    async fn execute(
        &self,
        schedule: &BudgetResetSchedule,
        window_start: DateTime<Utc>,
        now: DateTime<Utc>,
        enabled: &[BudgetResetSchedule],
        dry_run: bool,
    ) -> Result<ScheduleRunOutcome, BudgetError> {
        let candidates = self.matching_accounts(schedule).await?;
        let plans = self.billing_plans_for_accounts(&candidates).await?;
        let period = Period::current(now);
        let empty = HashSet::new();

        let mut outcome = ScheduleRunOutcome::default();

        for account_id in candidates {
            let account_plans = plans.get(&account_id).unwrap_or(&empty);
            let winner = winning_schedule(&account_id, account_plans, enabled);
            if winner.map(|s| s.id.as_str()) != Some(schedule.id.as_str()) {
                outcome.superseded_account_ids.push(account_id);
                continue;
            }

            let effective_budget = self
                .budget_repo
                .effective_balance(&account_id, &period, now)
                .await?;

            // Read once per account, then used for BOTH the delta and the reported remaining, so
            // a preview can never quote a different number from the one the write is derived from.
            // A transport error is mapped to `Unavailable` rather than aborting the pass: an
            // unreachable usage service is "we don't know", the same as a `NULL` sum — see
            // `spend.rs`'s module doc.
            let spend = self
                .spend_reader
                .spend_for_account(&account_id, &period)
                .await
                .unwrap_or(Spend::Unavailable);

            let (remaining_micros, delta_micros) = match (schedule.mode, spend) {
                // A top-up never needs spend to decide: it adds a fixed amount whatever the
                // account has left. `remaining` is still reported when it is knowable, and falls
                // back to the effective budget when it is not.
                (ResetMode::TopUp, Spend::Known(spent)) => (
                    effective_budget.saturating_sub(spent),
                    schedule.amount_micros,
                ),
                (ResetMode::TopUp, Spend::Unavailable) => {
                    (effective_budget, schedule.amount_micros)
                }
                (ResetMode::Reset, Spend::Known(spent)) => {
                    let remaining = effective_budget.saturating_sub(spent);
                    (remaining, schedule.amount_micros.saturating_sub(remaining))
                }
                // Fail-closed (the rule `spend.rs` exists to enforce): `Unavailable` is "we do not
                // know what this account spent", never "it spent nothing". Granting on an unknown
                // spend is exactly the bug that would hand an over-spent account a fresh balance.
                (ResetMode::Reset, Spend::Unavailable) => {
                    tracing::warn!(
                        schedule_id = %schedule.id,
                        budget_account_id = %account_id,
                        period = %period,
                        "spend is unavailable; skipping this account's reset (never grant on \
                         unknown spend)"
                    );
                    outcome.deferred_account_ids.push(account_id);
                    continue;
                }
            };

            if delta_micros == 0 {
                // Already exactly on target. `budget_grants_amount_sign_chk` rejects a zero-amount
                // row anyway, and a no-op ledger entry would be audit noise.
                continue;
            }

            if !dry_run {
                let key = trigger_key(&schedule.id, window_start, &account_id);
                let source = if delta_micros < 0 {
                    // ADR-0009: the ledger is append-only, and `correction` is the ONLY source its
                    // `budget_grants_amount_sign_chk` permits to be negative — the refund-type
                    // compensating row a reset-down is booked as, per the owner's binding ruling.
                    GrantSource::Correction
                } else {
                    GrantSource::Automatic
                };

                self.budget_repo
                    .grant(GrantRequest {
                        budget_account_id: account_id.clone(),
                        account_id: account_id.clone(),
                        project_id: None,
                        period: period.clone(),
                        amount_micros: delta_micros,
                        source,
                        actor_id: None,
                        reason: Some(format!(
                            "budget reset schedule '{}' ({}) for window {}",
                            schedule.name,
                            schedule.mode,
                            window_start.to_rfc3339()
                        )),
                        policy_revision: None,
                        matched_rule_ids: None,
                        idempotency_key: Some(key.clone()),
                        trigger_key: Some(key),
                        expires_at: None,
                    })
                    .await?;
            }

            outcome.planned.push(PlannedGrant {
                budget_account_id: account_id,
                remaining_micros,
                delta_micros,
            });
        }

        Ok(outcome)
    }

    /// The budget accounts a schedule's scope names, before precedence is applied.
    ///
    /// The `users` join on every branch is the ADR-0014 intra-DB read pattern and the story's
    /// "every account with a `users` row" wording made literal. `accounts.user_id` is `NOT NULL`
    /// and FK-bound, so it filters nothing today — it states that a budget account without an
    /// owning identity is not a thing this scheduler grants to, and stays correct if that column
    /// ever becomes nullable.
    async fn matching_accounts(
        &self,
        schedule: &BudgetResetSchedule,
    ) -> Result<Vec<String>, BudgetError> {
        let rows = match schedule.scope_kind {
            ScheduleScopeKind::Account => {
                let scope_id = schedule.scope_id.as_deref().ok_or_else(|| {
                    BudgetError::InvalidSchedule(
                        "an account schedule must carry a scopeId".to_string(),
                    )
                })?;
                sqlx::query(
                    "SELECT a.id FROM accounts a JOIN users u ON u.id = a.user_id \
                     WHERE a.id = $1 ORDER BY a.created_at ASC",
                )
                .bind(scope_id)
                .fetch_all(self.pool())
                .await
            }
            ScheduleScopeKind::BillingPlan => {
                let scope_id = schedule.scope_id.as_deref().ok_or_else(|| {
                    BudgetError::InvalidSchedule(
                        "a billing_plan schedule must carry a scopeId".to_string(),
                    )
                })?;
                sqlx::query(
                    "SELECT DISTINCT a.id, a.created_at FROM accounts a \
                     JOIN users u ON u.id = a.user_id \
                     JOIN projects p ON p.account_id = a.id \
                     LEFT JOIN api_keys k ON k.project_id = p.id \
                     WHERE p.billing_plan = $1 OR k.billing_plan = $1 \
                     ORDER BY a.created_at ASC",
                )
                .bind(scope_id)
                .fetch_all(self.pool())
                .await
            }
            ScheduleScopeKind::Global => {
                sqlx::query(
                    "SELECT a.id FROM accounts a JOIN users u ON u.id = a.user_id \
                     ORDER BY a.created_at ASC",
                )
                .fetch_all(self.pool())
                .await
            }
        }
        .map_err(storage_failed)?;

        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>("id"))
            .collect())
    }

    /// Every billing plan each of `account_ids` touches, through its projects and their API keys.
    /// One query for the whole candidate set, not one per account — a `global` schedule over the
    /// estate would otherwise issue an N+1 storm just to answer "is a plan schedule more specific
    /// than me here".
    async fn billing_plans_for_accounts(
        &self,
        account_ids: &[String],
    ) -> Result<HashMap<String, HashSet<String>>, BudgetError> {
        if account_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = sqlx::query(
            "SELECT p.account_id AS account_id, p.billing_plan AS billing_plan \
             FROM projects p WHERE p.account_id = ANY($1) \
             UNION \
             SELECT p.account_id AS account_id, k.billing_plan AS billing_plan \
             FROM api_keys k JOIN projects p ON p.id = k.project_id \
             WHERE p.account_id = ANY($1)",
        )
        .bind(account_ids)
        .fetch_all(self.pool())
        .await
        .map_err(storage_failed)?;

        let mut out: HashMap<String, HashSet<String>> = HashMap::new();
        for row in rows {
            out.entry(row.get::<String, _>("account_id"))
                .or_default()
                .insert(row.get::<String, _>("billing_plan"));
        }
        Ok(out)
    }
}

/// `"<schedule_id>:<window_start>:<budget_account_id>"` — see the module doc for why the account id
/// is part of it despite the story naming only the first two halves.
pub fn trigger_key(
    schedule_id: &str,
    window_start: DateTime<Utc>,
    budget_account_id: &str,
) -> String {
    format!(
        "{schedule_id}:{}:{budget_account_id}",
        window_start.to_rfc3339()
    )
}

/// The most specific schedule in `enabled` that matches `account_id`, or `None`.
///
/// `enabled` is expected in `ResetScheduleRepo::list_enabled`'s order (`created_at ASC, name ASC`),
/// which makes the tie-break at equal specificity "the oldest schedule wins" without a second sort
/// here: a later candidate only displaces the incumbent on a STRICTLY greater specificity.
fn winning_schedule<'a>(
    account_id: &str,
    account_plans: &HashSet<String>,
    enabled: &'a [BudgetResetSchedule],
) -> Option<&'a BudgetResetSchedule> {
    let mut best: Option<&BudgetResetSchedule> = None;
    for candidate in enabled {
        let matches = match candidate.scope_kind {
            ScheduleScopeKind::Account => candidate.scope_id.as_deref() == Some(account_id),
            ScheduleScopeKind::BillingPlan => candidate
                .scope_id
                .as_ref()
                .is_some_and(|plan| account_plans.contains(plan)),
            ScheduleScopeKind::Global => true,
        };
        if !matches {
            continue;
        }
        let wins = match best {
            None => true,
            Some(incumbent) => {
                candidate.scope_kind.specificity() > incumbent.scope_kind.specificity()
            }
        };
        if wins {
            best = Some(candidate);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reset_schedule::Cadence;
    use chrono::{NaiveTime, TimeZone};

    fn schedule(
        id: &str,
        kind: ScheduleScopeKind,
        scope_id: Option<&str>,
        created_at_day: u32,
    ) -> BudgetResetSchedule {
        BudgetResetSchedule {
            id: id.to_string(),
            name: id.to_string(),
            scope_kind: kind,
            scope_id: scope_id.map(str::to_string),
            cadence: Cadence::Daily,
            anchor: None,
            run_at_utc: NaiveTime::from_hms_opt(0, 0, 0).expect("valid time"),
            amount_micros: 2_000_000,
            mode: ResetMode::Reset,
            enabled: true,
            next_run_at: Utc
                .with_ymd_and_hms(2026, 9, 3, 0, 0, 0)
                .single()
                .expect("valid instant"),
            last_run_at: None,
            created_by: None,
            created_at: Utc
                .with_ymd_and_hms(2026, 9, created_at_day, 0, 0, 0)
                .single()
                .expect("valid instant"),
            updated_at: Utc
                .with_ymd_and_hms(2026, 9, created_at_day, 0, 0, 0)
                .single()
                .expect("valid instant"),
        }
    }

    fn plans(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn the_account_schedule_beats_the_plan_and_global_ones() {
        let enabled = vec![
            schedule("global", ScheduleScopeKind::Global, None, 1),
            schedule("plan", ScheduleScopeKind::BillingPlan, Some("free"), 2),
            schedule("acct", ScheduleScopeKind::Account, Some("acc-1"), 3),
        ];
        let winner = winning_schedule("acc-1", &plans(&["free"]), &enabled).expect("a winner");
        assert_eq!(winner.id, "acct");
    }

    #[test]
    fn the_plan_schedule_beats_global_for_an_account_on_that_plan() {
        let enabled = vec![
            schedule("global", ScheduleScopeKind::Global, None, 1),
            schedule("plan", ScheduleScopeKind::BillingPlan, Some("free"), 2),
        ];
        let winner = winning_schedule("acc-1", &plans(&["free"]), &enabled).expect("a winner");
        assert_eq!(winner.id, "plan");

        let winner = winning_schedule("acc-2", &plans(&["pro"]), &enabled).expect("a winner");
        assert_eq!(winner.id, "global");
    }

    #[test]
    fn nothing_matching_resolves_to_no_schedule() {
        let enabled = vec![schedule(
            "acct",
            ScheduleScopeKind::Account,
            Some("acc-9"),
            1,
        )];
        assert!(winning_schedule("acc-1", &plans(&[]), &enabled).is_none());
    }

    #[test]
    fn at_equal_specificity_the_oldest_schedule_wins() {
        let enabled = vec![
            schedule("older", ScheduleScopeKind::Account, Some("acc-1"), 1),
            schedule("newer", ScheduleScopeKind::Account, Some("acc-1"), 5),
        ];
        let winner = winning_schedule("acc-1", &plans(&[]), &enabled).expect("a winner");
        assert_eq!(winner.id, "older");
    }

    #[test]
    fn trigger_key_carries_schedule_window_and_account() {
        let window = Utc
            .with_ymd_and_hms(2026, 9, 3, 0, 0, 0)
            .single()
            .expect("valid instant");
        assert_eq!(
            trigger_key("sched-1", window, "acc-1"),
            "sched-1:2026-09-03T00:00:00+00:00:acc-1"
        );
    }
}
