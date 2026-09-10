//! Pure helpers behind `querySessions` (#649): the `status` vocabulary, the computed-status rule,
//! the page-size clamp and the opaque `(createdAt, id)` cursor.
//!
//! Split from [`crate::session_directory`] (which holds the procedure bodies) so both files stay
//! inside the repository's 200-LoC ceiling, and because everything here is a pure function of its
//! arguments — no database, no context, directly unit-testable. [`to_schema_session_row`], the
//! read-model conversion, lives here for the same two reasons.

use chrono::{DateTime, SecondsFormat, Utc};
use cratestack::CratestackError;

/// `limit`'s default when the caller supplies none.
pub const DEFAULT_SESSION_PAGE_LIMIT: i64 = 25;
/// `limit`'s ceiling. CLAMPED, not rejected — asking for "as many as you have" makes no
/// correctness claim about a specific set of ids, the same reasoning `searchUsers` (#647) records
/// for its own limit.
pub const MAX_SESSION_PAGE_LIMIT: i64 = 100;

/// The stored `sessions.status` value for a revoked session. `"expired"` is deliberately absent:
/// ADR-0020 Decision 6 never writes it, it is computed from `expires_at` at read time.
pub const STATUS_REVOKED: &str = "revoked";
/// The stored `sessions.status` value for a live session.
pub const STATUS_ACTIVE: &str = "active";
/// The computed-only status. Never stored, never accepted as a stored value.
pub const STATUS_EXPIRED: &str = "expired";

/// Which sessions a caller asked for. Parsed from the wire string so an unrecognised value is
/// rejected rather than silently widening the query — see [`parse_status_filter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatusFilter {
    /// Stored `active` AND not yet past `expiresAt`. The default.
    Active,
    /// Stored `revoked`, whatever the clock says.
    Revoked,
    /// Stored `active` AND past `expiresAt` — ADR-0020 Decision 6's computed state, selected by
    /// exactly the rule that computes it on the way out ([`computed_status`]).
    Expired,
    /// No status predicate at all.
    All,
}

/// Parses the optional wire `status`, defaulting to [`SessionStatusFilter::Active`].
///
/// An unrecognised value is a `BadRequest`, never a silent fallback to `All`: widening a filter on
/// a typo is how a sensitive list leaks. The error names the accepted set so the caller can fix it
/// without reading the schema.
pub fn parse_status_filter(raw: Option<&str>) -> Result<SessionStatusFilter, CratestackError> {
    match raw.map(str::trim) {
        None | Some("") | Some(STATUS_ACTIVE) => Ok(SessionStatusFilter::Active),
        Some(STATUS_REVOKED) => Ok(SessionStatusFilter::Revoked),
        Some(STATUS_EXPIRED) => Ok(SessionStatusFilter::Expired),
        Some("all") => Ok(SessionStatusFilter::All),
        Some(other) => Err(CratestackError::BadRequest(format!(
            "status: expected one of active, revoked, expired, all; got {other:?}"
        ))),
    }
}

/// The status a client sees, from the stored status plus the clock (ADR-0020 Decision 6).
///
/// Revocation beats expiry: a revoked session that is also past its `expiresAt` reads `"revoked"`,
/// because revocation is the operator-visible act and expiry is just time passing. Any stored
/// value other than `"active"` is returned verbatim rather than reinterpreted — this function
/// computes expiry, it does not normalise unknown states.
pub fn computed_status(stored: &str, expires_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    if stored == STATUS_ACTIVE && expires_at <= now {
        return STATUS_EXPIRED.to_owned();
    }
    stored.to_owned()
}

/// Whether a row is past its expiry, independent of whether it was revoked first. Reported
/// alongside the computed status so a client never re-derives it from a clock it does not share
/// with the server.
pub fn is_expired(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now
}

/// Applies the default and the ceiling to the caller's `limit`.
pub fn resolve_limit(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_SESSION_PAGE_LIMIT)
        .clamp(1, MAX_SESSION_PAGE_LIMIT)
}

/// The opaque page cursor: the last row's `(createdAt, id)` pair.
///
/// Both halves are load-bearing. `createdAt` is the ordering (ADR-0039: a CUID2 encodes no time,
/// so it can never BE the ordering); `id` is the tiebreak that gives two rows sharing a
/// microsecond a total order, without which a page boundary landing inside a tie would skip or
/// repeat rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCursor {
    pub created_at: DateTime<Utc>,
    pub id: String,
}

/// Serialises a cursor. `|` is a safe separator: the left half is an RFC 3339 timestamp and the
/// right half a CUID2, neither of which can contain one.
pub fn encode_cursor(cursor: &SessionCursor) -> String {
    format!(
        "{}|{}",
        cursor
            .created_at
            .to_rfc3339_opts(SecondsFormat::Micros, true),
        cursor.id
    )
}

/// Parses a cursor the server previously emitted.
///
/// A malformed cursor is a `BadRequest`, not an ignored filter: silently serving page 1 for a
/// corrupted `after` would look like a working paginator that loops forever.
pub fn decode_cursor(raw: &str) -> Result<SessionCursor, CratestackError> {
    let (timestamp, id) = raw.split_once('|').ok_or_else(|| {
        CratestackError::BadRequest(
            "after: malformed cursor; pass back the `next` value verbatim".to_owned(),
        )
    })?;
    let created_at = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|error| {
            CratestackError::BadRequest(format!("after: unparseable cursor: {error}"))
        })?
        .with_timezone(&Utc);
    if id.is_empty() {
        return Err(CratestackError::BadRequest(
            "after: cursor carries no row id".to_owned(),
        ));
    }
    Ok(SessionCursor {
        created_at,
        id: id.to_owned(),
    })
}

/// Turns one policy-scoped `Session` row plus its batched annotation into the wire `SessionRow`.
///
/// `facts` is `None` only if the row vanished between the page read and the annotation query;
/// `offline: false` / `subjectUserId: None` are then the fail-closed reading (no known offline
/// grant, no known person), never a fabricated identity — the same contract #647's identity
/// resolution keeps.
pub fn to_schema_session_row(
    session: lightbridge_authz_api::schema::Session,
    facts: Option<&lightbridge_authz_api_key::entities::session_row::SessionFactsRow>,
    now: DateTime<Utc>,
) -> lightbridge_authz_api::schema::SessionRow {
    lightbridge_authz_api::schema::SessionRow {
        status: computed_status(&session.status, session.expiresAt, now),
        expired: is_expired(session.expiresAt, now),
        offline: facts.is_some_and(|f| f.offline),
        subjectUserId: facts.and_then(|f| f.subject_user_id.clone()),
        id: session.id,
        accountId: session.accountId,
        projectId: session.projectId,
        clientId: session.clientId,
        kind: session.kind,
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
        lastUsedAt: session.lastUsedAt,
        expiresAt: session.expiresAt,
        userAgent: session.userAgent,
        subject: session.subject,
    }
}
