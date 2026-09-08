//! Day-grain and seat-grain row types (#583) — the schema-first side of the epic's storage
//! foundation. The tables live in `migrations-usage/2026090800000{1,2}_*.sql`; the query
//! endpoints that will read them are #586's story.

use chrono::{DateTime, NaiveDate, Utc};

/// The closed `subject_kind` vocabulary for the day and seat grain tables (#583).
///
/// Mirrors the `CHECK (subject_kind IN (...))` constraints in the migrations. Extensible via a
/// forward migration adding a new value to the constraint — no DB enum (ADR-0028 D4's rationale:
/// vocabulary is closed at the registry/code, not the schema, so a new value is a code change and
/// a constraint amendment, never a schema change that breaks existing rows).
///
/// The three presentations of this vocabulary — serde variant names (below),
/// `SubjectKind::as_str()`, and the migrations' CHECK tokens — are kept in lockstep by
/// `subject_kind_vocabulary_round_trips` in `tests/day_seat_grain_it_tests.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Org,
    User,
    Repo,
    UserTeam,
}

impl SubjectKind {
    /// The SQL CHECK-constraint token that matches this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubjectKind::Org => "org",
            SubjectKind::User => "user",
            SubjectKind::Repo => "repo",
            SubjectKind::UserTeam => "user_team",
        }
    }

    /// Every variant, in the same order as the SQL CHECK constraint.
    pub const ALL: [SubjectKind; 4] = [
        SubjectKind::Org,
        SubjectKind::User,
        SubjectKind::Repo,
        SubjectKind::UserTeam,
    ];

    /// The four CHECK tokens, verbatim — asserted DB-side by the same test.
    pub fn check_vocabulary() -> [&'static str; 4] {
        ["org", "user", "repo", "user_team"]
    }
}

/// A day-grain fact row — one per `(source, day, subject_kind, subject_id)`.
///
/// The table `usage_day_facts` is hypertable-partitioned by `day` and source-dimensioned per
/// ADR-0027 Decision 2. The natural key is the primary key; upserting on it makes reprocessing a
/// day idempotent (ADR-0028 D22).
///
/// Money columns are `Option<i64>` micro-USD: `None` = unknown, never `Some(0)` as a default.
/// A source that does not report a given measure leaves the field `None`, not `0`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UsageDayFact {
    /// Canonical source token (kebab-case, ADR-0028 D4). e.g. `"github-copilot"`.
    pub source: String,
    pub day: NaiveDate,
    pub subject_kind: SubjectKind,
    /// Opaque provider-scoped string. Never shape-validated, never joined across providers
    /// except through `usage_identities` (governance#185).
    pub subject_id: String,
    /// Provider-scoped user identity — join key per governance#185. `None` for org/repo-level
    /// facts.
    pub provider_user_id: Option<String>,
    pub total_suggestions_count: Option<i64>,
    pub total_acceptances_count: Option<i64>,
    pub total_lines_suggested: Option<i64>,
    pub total_lines_accepted: Option<i64>,
    pub total_active_users: Option<i64>,
    pub total_chat_acceptances: Option<i64>,
    pub total_chat_turns: Option<i64>,
    pub total_active_chat_users: Option<i64>,
    /// Cost in integer micro-USD. `None` = unknown; a known-free operation is `Some(0)`.
    pub cost_micro_usd: Option<i64>,
    /// `true` when this row comes from an aggregate-only source (e.g. Copilot's 5-seat floor).
    /// Must not be averaged into per-user breakdowns.
    pub is_aggregate_only: bool,
    pub language: Option<String>,
    pub editor: Option<String>,
    pub model: Option<String>,
    pub raw_schema_version: Option<String>,
    pub ingested_at: DateTime<Utc>,
}

/// A seat-grain snapshot row — one per
/// `(source, snapshot_day, subject_kind, subject_id, provider_user_id)`.
///
/// The table `usage_seat_snapshots` is hypertable-partitioned by `snapshot_day` and
/// source-dimensioned per ADR-0027 Decision 2. The natural key is the primary key.
///
/// `provider_user_id` is the join key per governance#185 — NEVER `assignee_login`.
/// `assignee_login` is stored for display only.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UsageSeatSnapshot {
    /// Canonical source token (kebab-case, ADR-0028 D4).
    pub source: String,
    pub snapshot_day: NaiveDate,
    pub subject_kind: SubjectKind,
    pub subject_id: String,
    /// Provider-scoped user identity — the join key (governance#185). NOT NULL.
    pub provider_user_id: String,
    /// The provider's own seat-state token, stored verbatim (closed at the normalizer).
    pub seat_state: String,
    /// Provider login name — display only. NOT a join key.
    pub assignee_login: Option<String>,
    pub assignee_team: Option<String>,
    pub seat_created_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub last_activity_editor: Option<String>,
    pub pending_cancellation_date: Option<NaiveDate>,
    pub plan_type: Option<String>,
    pub raw_schema_version: Option<String>,
    pub ingested_at: DateTime<Utc>,
}
