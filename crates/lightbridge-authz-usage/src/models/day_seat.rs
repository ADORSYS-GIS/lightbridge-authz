//! The `subject_kind` vocabulary for the day and seat grain tables (#583).
//!
//! Only the vocabulary lives here for now: the day/seat row structs are deferred to the story that
//! actually reads them (#586), which may need a different shape.

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
}
