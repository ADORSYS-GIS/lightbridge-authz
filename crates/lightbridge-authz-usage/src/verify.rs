//! Count-assertion harness for the #588 cutover: asserts the usage store holds the same row
//! counts the governance store's `ingest_manifests` recorded, blocking loudly on mismatch.
//!
//! The governance store is a separate database (ADR-0028 D14 — no service reads another
//! service's tables), so the expected counts are supplied as a manifest exported from
//! `ingest_manifests` by the governance-side cutover tooling. This module is the authz-side
//! half: it reads the usage store, compares against the manifest, and reports every mismatch.
//! The `verify-counts` CLI exits non-zero on any mismatch — the "block loudly" half of the
//! cutover contract (governance#167's no-loss bar).

use chrono::NaiveDate;
use lightbridge_authz_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// The expected counts for the cutover, exported from the governance store's `ingest_manifests`.
#[derive(Debug, Deserialize)]
pub struct VerifyManifest {
    #[serde(default)]
    pub day_facts: Vec<DayFactExpectation>,
    #[serde(default)]
    pub seat_snapshots: Vec<SeatExpectation>,
    #[serde(default)]
    pub executions: Option<i64>,
    #[serde(default)]
    pub model_calls: Option<i64>,
    #[serde(default)]
    pub tool_calls: Option<i64>,
}

/// One per-(day, report) expectation for `usage_day_facts`.
#[derive(Debug, Deserialize)]
pub struct DayFactExpectation {
    pub day: NaiveDate,
    pub report: String,
    pub expected: i64,
}

/// One per-day expectation for `usage_seat_snapshots`.
#[derive(Debug, Deserialize)]
pub struct SeatExpectation {
    pub day: NaiveDate,
    pub expected: i64,
}

/// The result of a count-assertion run: one check per expectation, plus the aggregate `passed`.
#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub passed: bool,
    pub checks: Vec<CountCheck>,
}

/// One asserted count and whether it matched.
#[derive(Debug, Serialize)]
pub struct CountCheck {
    pub label: String,
    pub expected: i64,
    pub actual: i64,
    pub matched: bool,
}

/// Maps an RFC-0001 report name to the `usage_day_facts.subject_kind` it lands under.
fn report_subject_kind(report: &str) -> Option<&'static str> {
    match report {
        "organization-1-day" => Some("org"),
        "users-1-day" => Some("user"),
        "repos-1-day" => Some("repo"),
        _ => None,
    }
}

/// Asserts the usage store's actual counts match the manifest's expected counts.
///
/// Returns a report with one check per expectation; `passed` is false when any check mismatches.
/// The caller (the `verify-counts` CLI) exits non-zero on `!passed`, which is the "block loudly"
/// half of the cutover contract.
pub async fn verify_counts(pool: &PgPool, manifest: &VerifyManifest) -> Result<VerifyReport> {
    let mut checks = Vec::new();

    for exp in &manifest.day_facts {
        let kind = report_subject_kind(&exp.report).ok_or_else(|| {
            Error::BadRequest(format!("unknown day-facts report `{}`", exp.report))
        })?;
        let actual: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM usage_day_facts WHERE day = $1 AND subject_kind = $2",
        )
        .bind(exp.day)
        .bind(kind)
        .fetch_one(pool)
        .await?;
        checks.push(CountCheck {
            label: format!("day_facts {} {}", exp.day, exp.report),
            expected: exp.expected,
            actual,
            matched: actual == exp.expected,
        });
    }

    for exp in &manifest.seat_snapshots {
        let actual: i64 =
            sqlx::query_scalar("SELECT count(*) FROM usage_seat_snapshots WHERE snapshot_day = $1")
                .bind(exp.day)
                .fetch_one(pool)
                .await?;
        checks.push(CountCheck {
            label: format!("seat_snapshots {}", exp.day),
            expected: exp.expected,
            actual,
            matched: actual == exp.expected,
        });
    }

    push_table_check(
        &mut checks,
        pool,
        "executions",
        "usage_executions",
        manifest.executions,
    )
    .await?;
    push_table_check(
        &mut checks,
        pool,
        "model_calls",
        "usage_model_calls",
        manifest.model_calls,
    )
    .await?;
    push_table_check(
        &mut checks,
        pool,
        "tool_calls",
        "usage_tool_calls",
        manifest.tool_calls,
    )
    .await?;

    let passed = checks.iter().all(|c| c.matched);
    Ok(VerifyReport { passed, checks })
}

/// Appends one whole-table count check when the manifest asserts that table.
async fn push_table_check(
    checks: &mut Vec<CountCheck>,
    pool: &PgPool,
    label: &str,
    table: &str,
    expected: Option<i64>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual: i64 = match table {
        "usage_executions" => {
            sqlx::query_scalar("SELECT count(*) FROM usage_executions")
                .fetch_one(pool)
                .await?
        }
        "usage_model_calls" => {
            sqlx::query_scalar("SELECT count(*) FROM usage_model_calls")
                .fetch_one(pool)
                .await?
        }
        "usage_tool_calls" => {
            sqlx::query_scalar("SELECT count(*) FROM usage_tool_calls")
                .fetch_one(pool)
                .await?
        }
        _ => return Err(Error::BadRequest(format!("unknown table `{table}`"))),
    };
    checks.push(CountCheck {
        label: label.to_string(),
        expected,
        actual,
        matched: actual == expected,
    });
    Ok(())
}
