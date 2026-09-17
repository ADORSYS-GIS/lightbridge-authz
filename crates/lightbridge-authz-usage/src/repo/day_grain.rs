//! Day-grain and seat-grain repo upserts (#588).
//!
//! The day-grain receiver writes normalized [`DayFact`] / [`SeatSnapshot`] rows into
//! `usage_day_facts` / `usage_seat_snapshots` via the natural-key upsert (ADR-0028 D22): the
//! primary key IS the dedup key, so re-emitting a day changes no counts (RFC-0001 idempotency).
//! Nullable measure columns use `COALESCE` so a re-emit that cannot resolve a measure never wipes
//! a value already known — the same correction discipline as the execution grain.
//!
//! ADR-0038 persistence exception, same class as `usage_events`: a natural-key upsert that
//! generated CRUD cannot express. The usage DB is already hand-written SQL.

use std::collections::HashSet;

use lightbridge_authz_core::{Error, Result};
use sqlx::{PgPool, Postgres, QueryBuilder};

use crate::models::day_seat::{DayFact, SeatSnapshot};

/// Upsert day facts on the natural key `(source, day, subject_kind, subject_id)`.
pub async fn upsert_day_facts(pool: &PgPool, facts: &[DayFact]) -> Result<usize> {
    if facts.is_empty() {
        return Ok(0);
    }
    // Dedup on the natural key before building the multi-row statement: a single payload can
    // carry the same (source, day, subject_kind, subject_id) twice (a re-emitted record during
    // the cutover replay), and a multi-row `ON CONFLICT DO UPDATE` refuses a row that appears
    // twice in the SAME statement (Postgres 21000) — the whole batch would be refused.
    let mut seen = HashSet::new();
    let mut deduped: Vec<DayFact> = Vec::with_capacity(facts.len());
    for f in facts {
        let key = (
            f.source.clone(),
            f.day,
            f.subject_kind.clone(),
            f.subject_id.clone(),
        );
        if seen.insert(key) {
            deduped.push(f.clone());
        }
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO usage_day_facts \
         (source, day, subject_kind, subject_id, provider_user_id, active_users, engaged_users, \
          total_interactions, total_completions, ai_credits, coding_agent_activity, \
          code_review_activity, pull_request_activity, team_id, team_slug, cost_micro_usd, \
          is_aggregate_only) ",
    );
    builder.push_values(&deduped, |mut row, f| {
        row.push_bind(&f.source)
            .push_bind(f.day)
            .push_bind(f.subject_kind.as_str())
            .push_bind(&f.subject_id)
            .push_bind(&f.provider_user_id)
            .push_bind(f.active_users)
            .push_bind(f.engaged_users)
            .push_bind(f.total_interactions)
            .push_bind(f.total_completions)
            .push_bind(f.ai_credits)
            .push_bind(f.coding_agent_activity)
            .push_bind(f.code_review_activity)
            .push_bind(f.pull_request_activity)
            .push_bind(&f.team_id)
            .push_bind(&f.team_slug)
            .push_bind(f.cost_micro_usd)
            .push_bind(f.is_aggregate_only);
    });
    builder.push(
        " ON CONFLICT (source, day, subject_kind, subject_id) DO UPDATE SET \
         provider_user_id = COALESCE(EXCLUDED.provider_user_id, usage_day_facts.provider_user_id), \
         active_users = COALESCE(EXCLUDED.active_users, usage_day_facts.active_users), \
         engaged_users = COALESCE(EXCLUDED.engaged_users, usage_day_facts.engaged_users), \
         total_interactions = COALESCE(EXCLUDED.total_interactions, usage_day_facts.total_interactions), \
         total_completions = COALESCE(EXCLUDED.total_completions, usage_day_facts.total_completions), \
         ai_credits = COALESCE(EXCLUDED.ai_credits, usage_day_facts.ai_credits), \
         coding_agent_activity = COALESCE(EXCLUDED.coding_agent_activity, usage_day_facts.coding_agent_activity), \
         code_review_activity = COALESCE(EXCLUDED.code_review_activity, usage_day_facts.code_review_activity), \
         pull_request_activity = COALESCE(EXCLUDED.pull_request_activity, usage_day_facts.pull_request_activity), \
         team_id = COALESCE(EXCLUDED.team_id, usage_day_facts.team_id), \
         team_slug = COALESCE(EXCLUDED.team_slug, usage_day_facts.team_slug), \
         cost_micro_usd = COALESCE(EXCLUDED.cost_micro_usd, usage_day_facts.cost_micro_usd), \
         is_aggregate_only = EXCLUDED.is_aggregate_only",
    );
    let result = builder.build().execute(pool).await?;
    usize::try_from(result.rows_affected())
        .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
}

/// Upsert seat snapshots on the natural key
/// `(source, snapshot_day, subject_kind, subject_id, provider_user_id)`.
pub async fn upsert_seat_snapshots(pool: &PgPool, snapshots: &[SeatSnapshot]) -> Result<usize> {
    if snapshots.is_empty() {
        return Ok(0);
    }
    // Dedup on the natural key before building the multi-row statement (same 21000 rationale as
    // `upsert_day_facts`): a re-emitted seat record during the cutover replay must not refuse the
    // whole batch.
    let mut seen = HashSet::new();
    let mut deduped: Vec<SeatSnapshot> = Vec::with_capacity(snapshots.len());
    for s in snapshots {
        let key = (
            s.source.clone(),
            s.snapshot_day,
            s.subject_kind.clone(),
            s.subject_id.clone(),
            s.provider_user_id.clone(),
        );
        if seen.insert(key) {
            deduped.push(s.clone());
        }
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO usage_seat_snapshots \
         (source, snapshot_day, subject_kind, subject_id, provider_user_id, seat_state, \
          assignee_login, seat_created_at, last_activity_at, last_activity_editor, plan_type) ",
    );
    builder.push_values(&deduped, |mut row, s| {
        row.push_bind(&s.source)
            .push_bind(s.snapshot_day)
            .push_bind(s.subject_kind.as_str())
            .push_bind(&s.subject_id)
            .push_bind(&s.provider_user_id)
            .push_bind(&s.seat_state)
            .push_bind(&s.assignee_login)
            .push_bind(s.seat_created_at)
            .push_bind(s.last_activity_at)
            .push_bind(&s.last_activity_editor)
            .push_bind(&s.plan_type);
    });
    builder.push(
        " ON CONFLICT (source, snapshot_day, subject_kind, subject_id, provider_user_id) \
         DO UPDATE SET \
         seat_state = EXCLUDED.seat_state, \
         assignee_login = COALESCE(EXCLUDED.assignee_login, usage_seat_snapshots.assignee_login), \
         seat_created_at = COALESCE(EXCLUDED.seat_created_at, usage_seat_snapshots.seat_created_at), \
         last_activity_at = COALESCE(EXCLUDED.last_activity_at, usage_seat_snapshots.last_activity_at), \
         last_activity_editor = COALESCE(EXCLUDED.last_activity_editor, usage_seat_snapshots.last_activity_editor), \
         plan_type = COALESCE(EXCLUDED.plan_type, usage_seat_snapshots.plan_type)",
    );
    let result = builder.build().execute(pool).await?;
    usize::try_from(result.rows_affected())
        .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
}
