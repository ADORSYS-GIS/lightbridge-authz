#![cfg(feature = "it-tests")]
//! Integration tests for the #588 count-assertion harness (`verify::verify_counts`): the
//! cutover's "block loudly" gate. A matching manifest passes; a deliberately-corrupted row
//! (sabotage-first) is detected and blocks — proving the mismatch path actually fires before
//! the governance telemetry tables are dropped.

use lightbridge_authz_usage_rest::verify::{VerifyManifest, verify_counts};
use serde_json::json;
use sqlx::PgPool;

fn manifest() -> VerifyManifest {
    serde_json::from_value(json!({
        "day_facts": [
            { "day": "2026-09-01", "report": "organization-1-day", "expected": 1 }
        ],
        "seat_snapshots": [
            { "day": "2026-09-01", "expected": 2 }
        ],
        "executions": 1,
        "model_calls": 1,
        "tool_calls": 1
    }))
    .expect("valid manifest")
}

async fn seed(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO usage_day_facts (source, day, subject_kind, subject_id) \
         VALUES ('github-copilot', '2026-09-01', 'org', 'g1')",
    )
    .execute(pool)
    .await
    .expect("seed insert");
    sqlx::query(
        "INSERT INTO usage_seat_snapshots \
         (source, snapshot_day, subject_kind, subject_id, provider_user_id, seat_state) \
         VALUES ('github-copilot', '2026-09-01', 'org', 'g1', '1001', 'active'), \
                ('github-copilot', '2026-09-01', 'org', 'g1', '1002', 'active')",
    )
    .execute(pool)
    .await
    .expect("seed insert");
    sqlx::query(
        "INSERT INTO usage_executions (id, observed_at, source, trace_id, span_id) \
         VALUES ('exec_claude-code_t1_e1', now(), 'claude-code', 't1', 'e1')",
    )
    .execute(pool)
    .await
    .expect("seed insert");
    sqlx::query(
        "INSERT INTO usage_model_calls \
         (id, observed_at, source, execution_id, trace_id, span_id, model) \
         VALUES ('claude-code_t1_m1:mc', now(), 'claude-code', 'exec_claude-code_t1_e1', \
                 't1', 'm1', 'gpt-4.1')",
    )
    .execute(pool)
    .await
    .expect("seed insert");
    sqlx::query(
        "INSERT INTO usage_tool_calls \
         (id, observed_at, source, execution_id, trace_id, span_id, tool_name, duration_ms) \
         VALUES ('claude-code_t1_tc1:tc', now(), 'claude-code', 'exec_claude-code_t1_e1', \
                 't1', 'tc1', 'bash', 100)",
    )
    .execute(pool)
    .await
    .expect("seed insert");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn verify_passes_when_counts_match(pool: PgPool) {
    seed(&pool).await;
    let report = verify_counts(&pool, &manifest())
        .await
        .expect("verify runs");
    assert!(report.passed, "matching counts must pass: {report:?}");
    assert_eq!(report.checks.len(), 5, "one check per manifest expectation");
}

#[sqlx::test(migrations = "../../migrations-usage")]
async fn verify_blocks_on_a_corrupted_row(pool: PgPool) {
    seed(&pool).await;
    // Sabotage-first: delete one seat snapshot so the actual count no longer matches the manifest.
    sqlx::query("DELETE FROM usage_seat_snapshots WHERE provider_user_id = '1002'")
        .execute(&pool)
        .await
        .expect("seed insert");

    let report = verify_counts(&pool, &manifest())
        .await
        .expect("verify runs");
    assert!(!report.passed, "a corrupted row must block the cutover");
    let seat_check = report
        .checks
        .iter()
        .find(|c| c.label.starts_with("seat_snapshots"))
        .expect("seat check present");
    assert_eq!(seat_check.expected, 2);
    assert_eq!(seat_check.actual, 1);
    assert!(!seat_check.matched, "the seat mismatch must be reported");
}
