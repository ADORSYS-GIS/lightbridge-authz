//! Unit tests for the day-grain normalizer (#588): parsing RFC-0001 OTLP log records.
//!
//! These exercise `normalizer::day_grain::parse_day_grain` against the pinned RFC-0001 encoding
//! contract (lightbridge-governance `docs/rfc/0001-github-copilot-connector.md`). They run in CI
//! unconditionally — no database needed.

use std::collections::HashMap;

use lightbridge_authz_usage_rest::models::day_seat::SubjectKind;
use lightbridge_authz_usage_rest::normalizer::day_grain::{DayGrainRecord, parse_day_grain};
use serde_json::{Value, json};

fn attrs(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn common(report: &str, day: &str, kind: &str, subject_id: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("source", json!("github-copilot")),
        ("tenant_id", json!("t1")),
        ("org", json!("g1")),
        ("report", json!(report)),
        ("day", json!(day)),
        ("subject_kind", json!(kind)),
        ("subject_id", json!(subject_id)),
    ]
}

#[test]
fn parses_organization_1_day() {
    let mut a = common("organization-1-day", "2026-08-01", "org", "g1");
    a.extend(vec![
        ("active_users", json!(10)),
        ("engaged_users", json!(4)),
        ("total_interactions", json!(150)),
        ("total_completions", json!(120)),
        ("ai_credits", json!(0)),
        ("net_cost_micro_usd", json!(0)),
    ]);
    let rec = parse_day_grain(&attrs(&a)).expect("ok").expect("day-grain");
    match rec {
        DayGrainRecord::DayFact(f) => {
            assert_eq!(f.source, "github-copilot");
            assert_eq!(f.day.to_string(), "2026-08-01");
            assert_eq!(f.subject_kind, SubjectKind::Org);
            assert_eq!(f.subject_id, "g1");
            assert_eq!(f.active_users, Some(10));
            assert_eq!(f.engaged_users, Some(4));
            assert_eq!(f.total_interactions, Some(150));
            assert_eq!(f.total_completions, Some(120));
            assert_eq!(f.ai_credits, Some(0));
            assert_eq!(f.cost_micro_usd, Some(0));
            assert_eq!(f.provider_user_id, None);
        }
        DayGrainRecord::SeatSnapshot(_) => panic!("expected day fact"),
    }
}

#[test]
fn parses_users_1_day_with_provider_user_id() {
    let mut a = common("users-1-day", "2026-08-01", "user", "1001");
    a.extend(vec![
        ("user_login", json!("octocat")),
        ("total_interactions", json!(42)),
        ("total_completions", json!(20)),
        ("ai_credits", json!(2)),
        ("net_cost_micro_usd", json!(25000)),
    ]);
    let rec = parse_day_grain(&attrs(&a)).expect("ok").expect("day-grain");
    match rec {
        DayGrainRecord::DayFact(f) => {
            assert_eq!(f.subject_kind, SubjectKind::User);
            assert_eq!(f.subject_id, "1001");
            assert_eq!(f.provider_user_id, Some("1001".to_string()));
            assert_eq!(f.total_interactions, Some(42));
            assert_eq!(f.cost_micro_usd, Some(25000));
        }
        DayGrainRecord::SeatSnapshot(_) => panic!("expected day fact"),
    }
}

#[test]
fn parses_repos_1_day() {
    let mut a = common("repos-1-day", "2026-08-01", "repo", "844522530");
    a.extend(vec![
        ("coding_agent_activity", json!(3)),
        ("code_review_activity", json!(1)),
        ("pull_request_activity", json!(2)),
    ]);
    let rec = parse_day_grain(&attrs(&a)).expect("ok").expect("day-grain");
    match rec {
        DayGrainRecord::DayFact(f) => {
            assert_eq!(f.subject_kind, SubjectKind::Repo);
            assert_eq!(f.coding_agent_activity, Some(3));
            assert_eq!(f.code_review_activity, Some(1));
            assert_eq!(f.pull_request_activity, Some(2));
        }
        DayGrainRecord::SeatSnapshot(_) => panic!("expected day fact"),
    }
}

#[test]
fn parses_billing_seats() {
    let mut a = common("billing-seats", "2026-08-07", "org", "g1");
    a.extend(vec![
        ("provider_user_id", json!("1001")),
        ("user_login", json!("octocat")),
        ("seat_assigned_at", json!("2026-01-01T00:00:00Z")),
        ("last_activity_at", json!("2026-08-01T09:30:00Z")),
        ("last_activity_editor", json!("vscode/1.90.0")),
        ("seat_state", json!("active")),
    ]);
    let rec = parse_day_grain(&attrs(&a)).expect("ok").expect("day-grain");
    match rec {
        DayGrainRecord::SeatSnapshot(s) => {
            assert_eq!(s.subject_kind, SubjectKind::Org);
            assert_eq!(s.subject_id, "g1");
            assert_eq!(s.provider_user_id, "1001");
            assert_eq!(s.assignee_login.as_deref(), Some("octocat"));
            assert_eq!(s.seat_state, "active");
            assert_eq!(
                s.seat_created_at.unwrap().to_rfc3339(),
                "2026-01-01T00:00:00+00:00"
            );
        }
        DayGrainRecord::DayFact(_) => panic!("expected seat snapshot"),
    }
}

#[test]
fn returns_none_for_non_day_grain_record() {
    let a = attrs(&[("source", json!("eaig")), ("model", json!("gpt-4.1"))]);
    assert!(parse_day_grain(&a).expect("ok").is_none());
}

#[test]
fn refuses_user_teams_until_known_issue_resolved() {
    let a = attrs(&common(
        "user-teams-1-day",
        "2026-08-01",
        "user_team",
        "1001",
    ));
    let err = parse_day_grain(&a).expect_err("user-teams must be refused");
    assert!(err.to_string().contains("user-teams-1-day"));
}

#[test]
fn refuses_unknown_report() {
    let a = attrs(&common("mystery-report", "2026-08-01", "org", "g1"));
    assert!(parse_day_grain(&a).is_err());
}

#[test]
fn refuses_invalid_day() {
    let a = attrs(&common("organization-1-day", "not-a-date", "org", "g1"));
    assert!(parse_day_grain(&a).is_err());
}
