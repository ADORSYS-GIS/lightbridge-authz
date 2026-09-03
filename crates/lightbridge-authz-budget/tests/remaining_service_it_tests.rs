#![cfg(feature = "it-tests")]
//! `RemainingService` against a real ledger (ADR-0034, lightbridge-authz#658).
//!
//! The unit-level failure modes (an unreachable spend source, an empty `SUM`) are covered against
//! `httpmock` in `usage_service_spend_reader_tests.rs`, and the HTTP contract in
//! `lightbridge-authz-rest`'s `budget_remaining` module tests. What can only be proved here is the
//! arithmetic against actual `budget_grants` rows: that the ceiling is the **expiry- and
//! revocation-aware** sum, that an expired grant cannot buy gateway traffic, and that an account
//! with no grants at all reports a zero ceiling rather than an error.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::remaining::{Remaining, RemainingReader, RemainingService};
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::{Spend, SpendObservation, SpendReader};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

const PERIOD: &str = "2026-09";

/// A spend source under the test's control. Deliberately NOT `UnavailableSpendReader` for the
/// happy paths: the point of most of these tests is the ceiling arithmetic, and a reader that
/// always reports "unknown" would short-circuit before the arithmetic runs.
#[derive(Debug, Clone, Copy)]
enum StubSpend {
    Answered(i64),
    Empty,
    Unreachable,
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for StubSpend {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(match self {
            Self::Answered(micros) => Spend::Known(*micros),
            Self::Empty | Self::Unreachable => Spend::Unavailable,
        })
    }

    async fn observe_spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        Ok(match self {
            Self::Answered(micros) => SpendObservation::Answered(*micros),
            Self::Empty => SpendObservation::Empty,
            Self::Unreachable => SpendObservation::Unreachable,
        })
    }
}

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

fn grant(account_id: &str, amount_micros: i64, expires_at: Option<DateTime<Utc>>) -> GrantRequest {
    GrantRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(PERIOD).expect("valid period"),
        amount_micros,
        source: GrantSource::Base,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at,
    }
}

fn service(pool: PgPool, spend: StubSpend) -> RemainingService {
    let db: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let repo = Arc::new(BudgetRepo::new(db.clone()));
    let reader: Arc<dyn SpendReader> = Arc::new(spend);
    let scheduler = Arc::new(ResetScheduler::new(db, repo.clone(), reader.clone()));
    RemainingService::new(repo, reader, scheduler)
}

fn known(remaining: Remaining) -> lightbridge_authz_budget::BudgetRemaining {
    match remaining {
        Remaining::Known(known) => *known,
        Remaining::Unavailable => panic!("expected a known remaining balance"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn remaining_is_the_granted_ceiling_minus_reported_spend(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let now = Utc::now();

    let svc = service(pool.clone(), StubSpend::Answered(3_210_000));
    BudgetRepo::new(Arc::new(DbPool::from_pool(pool)))
        .grant(grant(&account_id, 24_000_000, None))
        .await
        .expect("granting must succeed");

    let period = Period::parse(PERIOD).expect("valid period");
    let answer = known(
        svc.remaining_for_account(&account_id, &period, now)
            .await
            .expect("the ledger is readable"),
    );

    assert_eq!(answer.ceiling_micros, 24_000_000);
    assert_eq!(answer.spent_micros, 3_210_000);
    assert_eq!(answer.remaining_micros, 20_790_000);
    assert_eq!(answer.budget_account_id, account_id);
}

/// An account with no grants at all this period has a zero ceiling, and that is an ANSWER, not an
/// error: it is what a new account looks like before its base grant lands, and the gateway must
/// refuse it with `budget_exhausted` rather than `budget_unavailable`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_account_with_no_grants_reports_a_zero_ceiling_not_an_error(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let svc = service(pool, StubSpend::Empty);
    let period = Period::parse(PERIOD).expect("valid period");
    let answer = known(
        svc.remaining_for_account(&account_id, &period, Utc::now())
            .await
            .expect("the ledger is readable"),
    );

    assert_eq!(answer.ceiling_micros, 0);
    assert_eq!(answer.spent_micros, 0);
    assert_eq!(answer.remaining_micros, 0);
}

/// An expired grant must not buy gateway traffic. This is the whole reason the ceiling is
/// `effective_balance` (expiry/revocation-aware) rather than the raw `budget_balances`
/// projection, which counts expired grants -- see `remaining.rs`'s module doc comment.
#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_grant_does_not_count_toward_the_ceiling(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let now = Utc::now();

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    repo.grant(grant(&account_id, 10_000_000, None))
        .await
        .expect("the live grant must be written");
    repo.grant(grant(
        &account_id,
        90_000_000,
        Some(now - Duration::hours(1)),
    ))
    .await
    .expect("the expired grant must be written");

    let svc = service(pool, StubSpend::Answered(0));
    let period = Period::parse(PERIOD).expect("valid period");
    let answer = known(
        svc.remaining_for_account(&account_id, &period, now)
            .await
            .expect("the ledger is readable"),
    );

    assert_eq!(
        answer.ceiling_micros, 10_000_000,
        "the expired 90 USD grant must not be spendable at the gateway"
    );
    assert_eq!(answer.remaining_micros, 10_000_000);
}

/// Overspend is reachable by construction -- the gateway charges `llm_custom_total_cost` only
/// after a response completes -- and must be reported with its sign, not clamped to a flattering
/// zero.
#[sqlx::test(migrations = "../../migrations")]
async fn overspend_is_reported_as_a_negative_remaining(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
        .grant(grant(&account_id, 1_000_000, None))
        .await
        .expect("granting must succeed");

    let svc = service(pool, StubSpend::Answered(1_500_000));
    let period = Period::parse(PERIOD).expect("valid period");
    let answer = known(
        svc.remaining_for_account(&account_id, &period, Utc::now())
            .await
            .expect("the ledger is readable"),
    );

    assert_eq!(answer.remaining_micros, -500_000);
}

/// The load-bearing rule: an unreadable spend source is `Unavailable`, never a zero balance. A
/// `0` here would tell a paying user their budget is gone because OUR usage service is down.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreachable_spend_source_is_unavailable_never_a_zero_balance(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
        .grant(grant(&account_id, 24_000_000, None))
        .await
        .expect("granting must succeed");

    let svc = service(pool, StubSpend::Unreachable);
    let period = Period::parse(PERIOD).expect("valid period");
    let answer = svc
        .remaining_for_account(&account_id, &period, Utc::now())
        .await
        .expect("an unreachable spend source is not an error");

    assert_eq!(answer, Remaining::Unavailable);
}

/// With no reset schedule covering the account, `next_reset_at` is the start of the next calendar
/// period -- the same instant the ledger's period key and the gateway's `x-billing-period` marker
/// both rotate.
#[sqlx::test(migrations = "../../migrations")]
async fn next_reset_defaults_to_the_next_calendar_period(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let svc = service(pool, StubSpend::Empty);
    let period = Period::parse(PERIOD).expect("valid period");
    let answer = known(
        svc.remaining_for_account(&account_id, &period, Utc::now())
            .await
            .expect("the ledger is readable"),
    );

    assert_eq!(
        answer.next_reset_at.to_rfc3339(),
        "2026-10-01T00:00:00+00:00"
    );
}

/// Unknown lag stays unknown. `source_lag_seconds` is `None` because nothing in this process can
/// measure OTLP ingest lag today; reporting `0` would understate ADR-0034's overspend window.
#[sqlx::test(migrations = "../../migrations")]
async fn source_lag_is_unknown_rather_than_a_fabricated_zero(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let svc = service(pool, StubSpend::Answered(0));
    let period = Period::parse(PERIOD).expect("valid period");
    let answer = known(
        svc.remaining_for_account(&account_id, &period, Utc::now())
            .await
            .expect("the ledger is readable"),
    );

    assert_eq!(answer.source_lag_seconds, None);
}

// ── cached grace (ADR-0034) ──────────────────────────────────────────────────────────────────
//
// The grace window is the ONLY place in the chain that can ride out a usage-service outage:
// Envoy's Lua filter has no cross-request state, and Authorino's metadata cache drops an entry on
// a failed fetch rather than serving it stale. These prove it is bounded in both directions --
// it serves the last reading while it is young, and stops serving it once it is not.

/// A spend source that answers once and then goes dark, so a single test can drive both sides of
/// the grace window.
#[derive(Debug)]
struct FlakySpend {
    micros: i64,
    down: AtomicBool,
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for FlakySpend {
    async fn spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(if self.down.load(Ordering::SeqCst) {
            Spend::Unavailable
        } else {
            Spend::Known(self.micros)
        })
    }

    async fn observe_spend_for_account(
        &self,
        _account_id: &str,
        _period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        Ok(if self.down.load(Ordering::SeqCst) {
            SpendObservation::Unreachable
        } else {
            SpendObservation::Answered(self.micros)
        })
    }
}

fn service_with_grace(
    pool: PgPool,
    reader: Arc<dyn SpendReader>,
    grace: Duration,
) -> RemainingService {
    let db: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    let repo = Arc::new(BudgetRepo::new(db.clone()));
    let scheduler = Arc::new(ResetScheduler::new(db, repo.clone(), reader.clone()));
    RemainingService::with_grace(repo, reader, scheduler, grace)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_recent_reading_is_served_through_a_usage_outage_and_marked_stale(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())))
        .grant(grant(&account_id, 24_000_000, None))
        .await
        .expect("granting must succeed");

    let reader = Arc::new(FlakySpend {
        micros: 4_000_000,
        down: AtomicBool::new(false),
    });
    let svc = service_with_grace(pool, reader.clone(), Duration::minutes(2));
    let period = Period::parse(PERIOD).expect("valid period");
    let now = Utc::now();

    // Warm the cache with a real reading.
    let fresh = known(
        svc.remaining_for_account(&account_id, &period, now)
            .await
            .expect("the ledger is readable"),
    );
    assert_eq!(fresh.spent_micros, 4_000_000);
    assert_eq!(
        fresh.source_lag_seconds, None,
        "a fresh reading reports no cache age"
    );

    reader.down.store(true, Ordering::SeqCst);

    let stale = known(
        svc.remaining_for_account(&account_id, &period, now + Duration::seconds(30))
            .await
            .expect("the ledger is readable"),
    );
    assert_eq!(stale.spent_micros, 4_000_000, "the last reading is reused");
    assert_eq!(stale.remaining_micros, 20_000_000);
    assert_eq!(
        stale.source_lag_seconds,
        Some(30),
        "a served-stale reading must declare its age, not pass as fresh"
    );
}

/// The other half: grace is bounded. Past the window the answer goes back to "we don't know",
/// which the HTTP edge renders as `503 budget_unavailable` -- never as a zero balance.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reading_older_than_the_grace_window_is_not_served(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let reader = Arc::new(FlakySpend {
        micros: 4_000_000,
        down: AtomicBool::new(false),
    });
    let svc = service_with_grace(pool, reader.clone(), Duration::minutes(2));
    let period = Period::parse(PERIOD).expect("valid period");
    let now = Utc::now();

    svc.remaining_for_account(&account_id, &period, now)
        .await
        .expect("the ledger is readable");
    reader.down.store(true, Ordering::SeqCst);

    let answer = svc
        .remaining_for_account(&account_id, &period, now + Duration::minutes(3))
        .await
        .expect("an unreachable spend source is not an error");

    assert_eq!(answer, Remaining::Unavailable);
}

/// A refill landing DURING a usage outage must take effect immediately. This is why only
/// `spent_micros` is cached and the ceiling is always re-read from the ledger.
#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_during_an_outage_raises_the_ceiling_of_a_stale_answer(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    repo.grant(grant(&account_id, 5_000_000, None))
        .await
        .expect("granting must succeed");

    let reader = Arc::new(FlakySpend {
        micros: 5_000_000,
        down: AtomicBool::new(false),
    });
    let svc = service_with_grace(pool, reader.clone(), Duration::minutes(2));
    let period = Period::parse(PERIOD).expect("valid period");
    let now = Utc::now();

    let exhausted = known(
        svc.remaining_for_account(&account_id, &period, now)
            .await
            .expect("the ledger is readable"),
    );
    assert_eq!(exhausted.remaining_micros, 0);

    reader.down.store(true, Ordering::SeqCst);
    repo.grant(grant(&account_id, 10_000_000, None))
        .await
        .expect("the refill must be written");

    let after_refill = known(
        svc.remaining_for_account(&account_id, &period, now + Duration::seconds(10))
            .await
            .expect("the ledger is readable"),
    );
    assert_eq!(after_refill.ceiling_micros, 15_000_000);
    assert_eq!(after_refill.remaining_micros, 10_000_000);
    assert_eq!(after_refill.source_lag_seconds, Some(10));
}

/// `RemainingService::new` is zero-grace: no stale serving at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_zero_grace_service_never_serves_a_stale_reading(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let reader = Arc::new(FlakySpend {
        micros: 1_000_000,
        down: AtomicBool::new(false),
    });
    let svc = service_with_grace(pool, reader.clone(), Duration::zero());
    let period = Period::parse(PERIOD).expect("valid period");
    let now = Utc::now();

    svc.remaining_for_account(&account_id, &period, now)
        .await
        .expect("the ledger is readable");
    reader.down.store(true, Ordering::SeqCst);

    assert_eq!(
        svc.remaining_for_account(&account_id, &period, now + Duration::seconds(1))
            .await
            .expect("an unreachable spend source is not an error"),
        Remaining::Unavailable
    );
}
