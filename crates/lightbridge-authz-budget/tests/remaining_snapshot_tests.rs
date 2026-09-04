//! [`SnapshotRemainingService`] — the snapshot-first decorator `GET /budget/v1/remaining` is served
//! through (ADR-0034 §15).
//!
//! No database: the point of these tests is the three routing decisions, which are exactly the
//! ones a live Postgres cannot be made to produce on demand — a usable snapshot, an unusable one
//! (rolled-over period), and a read that fails outright.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::snapshot::{BudgetSnapshot, BudgetSnapshotReader};
use lightbridge_authz_budget::{BudgetRemaining, Period, Remaining, RemainingReader};

/// Counts how often the live path was taken, so a test can prove the snapshot short-circuited it.
#[derive(Debug, Default)]
struct CountingLive {
    calls: AtomicUsize,
}

#[lightbridge_authz_core::async_trait]
impl RemainingReader for CountingLive {
    async fn remaining_for_account(
        &self,
        budget_account_id: &str,
        period: &Period,
        _now: DateTime<Utc>,
    ) -> Result<Remaining, BudgetError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Remaining::Known(Box::new(BudgetRemaining {
            budget_account_id: budget_account_id.to_string(),
            period: period.clone(),
            ceiling_micros: 1,
            spent_micros: 0,
            remaining_micros: 1,
            next_reset_at: Utc::now(),
            source_lag_seconds: None,
            snapshot_age_seconds: None,
        })))
    }
}

#[derive(Debug)]
enum StubSnapshots {
    Row(Box<BudgetSnapshot>),
    Missing,
    Failing,
}

#[lightbridge_authz_core::async_trait]
impl BudgetSnapshotReader for StubSnapshots {
    async fn read(&self, _budget_account_id: &str) -> Result<Option<BudgetSnapshot>, BudgetError> {
        match self {
            Self::Row(row) => Ok(Some((**row).clone())),
            Self::Missing => Ok(None),
            Self::Failing => Err(BudgetError::StorageFailed("pool timed out".to_string())),
        }
    }

    async fn touch(&self, _budget_account_id: &str) -> Result<(), BudgetError> {
        Ok(())
    }
}

fn snapshot(period: Period, remaining_micros: i64) -> BudgetSnapshot {
    let now = Utc::now();
    BudgetSnapshot {
        budget_account_id: "acct_1".to_string(),
        period: Some(period),
        ceiling_micros: Some(24_000_000),
        spent_micros: Some(24_000_000 - remaining_micros),
        remaining_micros: Some(remaining_micros),
        next_reset_at: Some(now + Duration::days(7)),
        refreshed_at: Some(now - Duration::seconds(12)),
        stale_since: None,
        last_seen_at: now,
    }
}

fn service(
    snapshots: StubSnapshots,
) -> (
    lightbridge_authz_budget::SnapshotRemainingService,
    Arc<CountingLive>,
) {
    let live = Arc::new(CountingLive::default());
    (
        lightbridge_authz_budget::SnapshotRemainingService::new(Arc::new(snapshots), live.clone()),
        live,
    )
}

#[tokio::test]
async fn a_usable_snapshot_answers_without_touching_the_live_path() {
    let period = Period::current(Utc::now());
    let (service, live) = service(StubSnapshots::Row(Box::new(snapshot(
        period.clone(),
        20_790_000,
    ))));

    let answer = service
        .remaining_for_account("acct_1", &period, Utc::now())
        .await
        .expect("the snapshot path must not error");

    let Remaining::Known(remaining) = answer else {
        panic!("a usable snapshot must produce a known balance");
    };
    assert_eq!(remaining.remaining_micros, 20_790_000);
    assert_eq!(remaining.snapshot_age_seconds, Some(12));
    assert_eq!(
        live.calls.load(Ordering::SeqCst),
        0,
        "the whole point is that the ledger SUM and the spend query do not run per request"
    );
}

#[tokio::test]
async fn a_snapshot_from_a_rolled_over_period_falls_through_to_the_live_path() {
    let period = Period::current(Utc::now());
    let (service, live) = service(StubSnapshots::Row(Box::new(snapshot(
        period.previous(),
        20_790_000,
    ))));

    service
        .remaining_for_account("acct_1", &period, Utc::now())
        .await
        .expect("the fallback must answer");

    assert_eq!(
        live.calls.load(Ordering::SeqCst),
        1,
        "last month's balance is a different quantity, not a stale approximation of this month's"
    );
}

#[tokio::test]
async fn a_missing_snapshot_falls_through_rather_than_reporting_zero() {
    let period = Period::current(Utc::now());
    let (service, live) = service(StubSnapshots::Missing);

    let answer = service
        .remaining_for_account("acct_1", &period, Utc::now())
        .await
        .expect("the fallback must answer");

    assert!(matches!(answer, Remaining::Known(_)));
    assert_eq!(live.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failing_snapshot_read_degrades_to_the_live_path_never_to_an_error() {
    let period = Period::current(Utc::now());
    let (service, live) = service(StubSnapshots::Failing);

    service
        .remaining_for_account("acct_1", &period, Utc::now())
        .await
        .expect("a snapshot read failure costs latency, never correctness");

    assert_eq!(live.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fresh_skips_the_snapshot_even_when_one_is_usable() {
    let period = Period::current(Utc::now());
    let (service, live) = service(StubSnapshots::Row(Box::new(snapshot(
        period.clone(),
        20_790_000,
    ))));

    let answer = service
        .remaining_for_account_live("acct_1", &period, Utc::now())
        .await
        .expect("the live path must answer");

    let Remaining::Known(remaining) = answer else {
        panic!("the live path must produce a known balance");
    };
    assert_eq!(remaining.snapshot_age_seconds, None);
    assert_eq!(live.calls.load(Ordering::SeqCst), 1);
}
