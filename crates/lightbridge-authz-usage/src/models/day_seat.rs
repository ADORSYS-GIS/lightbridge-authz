//! The day and seat grain row types plus the `subject_kind` vocabulary (#583, #588).
//!
//! [`DayFact`] and [`SeatSnapshot`] are the wire/normalized shapes the day-grain receiver (#588)
//! produces from the RFC-0001 OTLP log records governance-ctl emits, and the shapes the repo
//! upserts into `usage_day_facts` / `usage_seat_snapshots`. The `subject_kind` vocabulary lives
//! here too, shared by both grains.

/// The closed `subject_kind` vocabulary for the day and seat grain tables (#583).
///
/// Mirrors the `CHECK (subject_kind IN (...))` constraints in the migrations. Extensible via a
/// forward migration adding a new value to the constraint — no DB enum (ADR-0028 D4's rationale:
/// vocabulary is closed at the registry/code, not the schema, so a new value is a code change and
/// a constraint amendment, never a schema change that breaks existing rows).
///
/// The two presentations of this vocabulary — serde variant names (below) and
/// `SubjectKind::as_str()` — are kept in lockstep with the migrations' CHECK tokens by
/// `subject_kind_vocabulary_stays_in_lockstep_with_the_live_check` in
/// `tests/day_seat_grain_it_tests.rs`, which reads the CHECK definition back from the database.
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

    /// The four CHECK tokens, in order — derived from `ALL` so there is a single source of truth
    /// in code. Asserted against the live DB CHECK by
    /// `subject_kind_vocabulary_stays_in_lockstep_with_the_live_check`.
    pub fn check_vocabulary() -> [&'static str; 4] {
        let mut tokens = ["", "", "", ""];
        for (i, kind) in SubjectKind::ALL.iter().enumerate() {
            tokens[i] = kind.as_str();
        }
        tokens
    }

    /// Parse a `subject_kind` token from the RFC-0001 wire (`org`/`user`/`repo`/`user_team`).
    /// `None` for anything else — the normalizer refuses unknown kinds rather than guessing.
    pub fn from_token(s: &str) -> Option<SubjectKind> {
        SubjectKind::ALL.iter().find(|k| k.as_str() == s).cloned()
    }
}

/// One normalized day-grain fact row, matching `usage_day_facts` (#588).
///
/// The measure columns are the RFC-0001 Reports-API vocabulary (see the
/// `20260917000001_usage_day_facts_rfc0001_measures.sql` migration header for why these are
/// dedicated columns rather than a remap onto the #583 Metrics-API columns). Every measure is
/// `Option<i64>` — NULL = unknown (ADR-0028 D0), never zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayFact {
    pub source: String,
    pub day: chrono::NaiveDate,
    pub subject_kind: SubjectKind,
    pub subject_id: String,
    pub provider_user_id: Option<String>,
    pub active_users: Option<i64>,
    pub engaged_users: Option<i64>,
    pub total_interactions: Option<i64>,
    pub total_completions: Option<i64>,
    pub ai_credits: Option<i64>,
    pub coding_agent_activity: Option<i64>,
    pub code_review_activity: Option<i64>,
    pub pull_request_activity: Option<i64>,
    pub team_id: Option<String>,
    pub team_slug: Option<String>,
    pub cost_micro_usd: Option<i64>,
    pub is_aggregate_only: bool,
}

/// One normalized seat-snapshot row, matching `usage_seat_snapshots` (#588).
///
/// `provider_user_id` is the seat holder and part of the natural key (governance#185: the join
/// key is `provider_user_id`, never `user_login`). `assignee_login` is display-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatSnapshot {
    pub source: String,
    pub snapshot_day: chrono::NaiveDate,
    pub subject_kind: SubjectKind,
    pub subject_id: String,
    pub provider_user_id: String,
    pub seat_state: String,
    pub assignee_login: Option<String>,
    pub seat_created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_activity_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_activity_editor: Option<String>,
    pub plan_type: Option<String>,
}
