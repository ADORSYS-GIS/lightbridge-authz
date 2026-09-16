//! The day-grain receiver's normalizer (#588): parses the RFC-0001 OTLP log records
//! governance-ctl emits into [`DayFact`] / [`SeatSnapshot`] rows.
//!
//! The encoding contract is pinned in lightbridge-governance
//! `docs/rfc/0001-github-copilot-connector.md` ("OTLP day-grain encoding contract"): one log
//! record per (report, subject), typed attributes, money as integer micro-USD. This module is
//! the authz-side half of that contract — the governance-side emitter is `governance-ctl`'s
//! `emit.rs` (gov#196). The two must change together; the attribute names/types below are the
//! contract, not an implementation detail.
//!
//! A record is a day-grain record iff it carries a `report` attribute. Records without one are
//! request-grain and are handled by the existing OTLP path. A record that IS day-grain but is
//! malformed is refused (`Err`), never silently dropped — the cutover's count assertions depend
//! on every emitted record landing or the run failing loudly.

use std::collections::HashMap;

use chrono::NaiveDate;
use lightbridge_authz_core::{Error, Result};
use serde_json::Value;

use crate::models::day_seat::{DayFact, SeatSnapshot, SubjectKind};
use crate::normalizer::{extract_i64, extract_string};

/// The trusted-source stamp every RFC-0001 record carries (ADR-0013 invariant 2).
pub const DAY_GRAIN_SOURCE: &str = "github-copilot";

/// A parsed day-grain record: either a day fact or a seat snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DayGrainRecord {
    DayFact(DayFact),
    SeatSnapshot(SeatSnapshot),
}

/// Parse one OTLP log record's attributes into a day-grain record.
///
/// Returns `Ok(None)` when the record is not day-grain (no `report` attribute) — the caller
/// routes it to the request-grain path. Returns `Err` when it IS day-grain but malformed.
pub fn parse_day_grain(attrs: &HashMap<String, Value>) -> Result<Option<DayGrainRecord>> {
    let report = match extract_string(attrs, &["report"]) {
        Some(r) => r,
        None => return Ok(None),
    };

    let source = extract_string(attrs, &["source"])
        .ok_or_else(|| Error::BadRequest("day-grain record missing source".into()))?;
    let day = extract_string(attrs, &["day"])
        .ok_or_else(|| Error::BadRequest("day-grain record missing day".into()))?;
    let day = NaiveDate::parse_from_str(&day, "%Y-%m-%d")
        .map_err(|_| Error::BadRequest(format!("day-grain record has invalid day `{day}`")))?;
    let subject_kind = extract_string(attrs, &["subject_kind"])
        .ok_or_else(|| Error::BadRequest("day-grain record missing subject_kind".into()))?;
    let subject_kind = SubjectKind::from_token(&subject_kind).ok_or_else(|| {
        Error::BadRequest(format!(
            "day-grain record has unknown subject_kind `{subject_kind}`"
        ))
    })?;
    let subject_id = extract_string(attrs, &["subject_id"])
        .ok_or_else(|| Error::BadRequest("day-grain record missing subject_id".into()))?;

    match report.as_str() {
        "organization-1-day" | "users-1-day" | "repos-1-day" => Ok(Some(DayGrainRecord::DayFact(
            parse_day_fact(source, day, subject_kind, subject_id, attrs, &report)?,
        ))),
        "user-teams-1-day" => Err(Error::BadRequest(
            "user-teams-1-day is not cut over: RFC-0001 known-issue #1 (subject_id not unique \
             per record for a multi-team user) must be resolved first"
                .into(),
        )),
        "billing-seats" => Ok(Some(DayGrainRecord::SeatSnapshot(parse_seat(
            source,
            day,
            subject_kind,
            subject_id,
            attrs,
        )?))),
        other => Err(Error::BadRequest(format!(
            "day-grain record has unknown report `{other}`"
        ))),
    }
}

fn parse_day_fact(
    source: String,
    day: NaiveDate,
    subject_kind: SubjectKind,
    subject_id: String,
    attrs: &HashMap<String, Value>,
    report: &str,
) -> Result<DayFact> {
    let provider_user_id = match report {
        "users-1-day" => Some(subject_id.clone()),
        _ => None,
    };
    Ok(DayFact {
        source,
        day,
        subject_kind,
        subject_id,
        provider_user_id,
        active_users: extract_i64(attrs, &["active_users"]),
        engaged_users: extract_i64(attrs, &["engaged_users"]),
        total_interactions: extract_i64(attrs, &["total_interactions"]),
        total_completions: extract_i64(attrs, &["total_completions"]),
        ai_credits: extract_i64(attrs, &["ai_credits"]),
        coding_agent_activity: extract_i64(attrs, &["coding_agent_activity"]),
        code_review_activity: extract_i64(attrs, &["code_review_activity"]),
        pull_request_activity: extract_i64(attrs, &["pull_request_activity"]),
        team_id: None,
        team_slug: None,
        cost_micro_usd: extract_i64(attrs, &["net_cost_micro_usd"]),
        is_aggregate_only: false,
    })
}

fn parse_seat(
    source: String,
    snapshot_day: NaiveDate,
    subject_kind: SubjectKind,
    subject_id: String,
    attrs: &HashMap<String, Value>,
) -> Result<SeatSnapshot> {
    let provider_user_id = extract_string(attrs, &["provider_user_id"])
        .ok_or_else(|| Error::BadRequest("billing-seats record missing provider_user_id".into()))?;
    let seat_state = extract_string(attrs, &["seat_state"])
        .ok_or_else(|| Error::BadRequest("billing-seats record missing seat_state".into()))?;
    let seat_created_at = extract_string(attrs, &["seat_assigned_at"])
        .map(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|t| t.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|_| {
            Error::BadRequest("billing-seats record has invalid seat_assigned_at".into())
        })?;
    let last_activity_at = extract_string(attrs, &["last_activity_at"])
        .map(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|t| t.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|_| {
            Error::BadRequest("billing-seats record has invalid last_activity_at".into())
        })?;

    Ok(SeatSnapshot {
        source,
        snapshot_day,
        subject_kind,
        subject_id,
        provider_user_id,
        seat_state,
        assignee_login: extract_string(attrs, &["user_login"]),
        seat_created_at,
        last_activity_at,
        last_activity_editor: extract_string(attrs, &["last_activity_editor"]),
        plan_type: None,
    })
}
