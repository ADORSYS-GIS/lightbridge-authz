//! Unit coverage for the pure helpers behind `querySessions`
//! (`lightbridge_authz_rest::session_query`, #649): the status vocabulary, the computed-status
//! rule, the page-size clamp and the opaque cursor.
//!
//! No database and no router — these are the decisions the DB-backed tests in `rpc_it_tests.rs`
//! exercise end to end, pinned here at the level where every branch is cheap to reach.

use chrono::{DateTime, TimeZone, Utc};
use cratestack::CratestackError;
use lightbridge_authz_rest::session_query::{
    DEFAULT_SESSION_PAGE_LIMIT, MAX_SESSION_PAGE_LIMIT, SessionCursor, SessionStatusFilter,
    computed_status, decode_cursor, encode_cursor, is_expired, parse_status_filter, resolve_limit,
};

fn at(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 2, 12, minute, 0)
        .single()
        .expect("a valid timestamp")
}

#[test]
fn status_defaults_to_active_and_accepts_the_documented_vocabulary() {
    assert_eq!(
        parse_status_filter(None).unwrap(),
        SessionStatusFilter::Active
    );
    assert_eq!(
        parse_status_filter(Some("")).unwrap(),
        SessionStatusFilter::Active
    );
    assert_eq!(
        parse_status_filter(Some(" active ")).unwrap(),
        SessionStatusFilter::Active
    );
    assert_eq!(
        parse_status_filter(Some("revoked")).unwrap(),
        SessionStatusFilter::Revoked
    );
    assert_eq!(
        parse_status_filter(Some("expired")).unwrap(),
        SessionStatusFilter::Expired
    );
    assert_eq!(
        parse_status_filter(Some("all")).unwrap(),
        SessionStatusFilter::All
    );
}

/// The fail-closed half: an unrecognised status is REJECTED. Silently widening it to `all` on a
/// typo is how a sensitive list leaks, so this asserts the error rather than a fallback.
#[test]
fn an_unrecognised_status_is_rejected_not_widened() {
    let error = parse_status_filter(Some("ACTIVE")).expect_err("case-varied value must not pass");
    assert!(
        matches!(error, CratestackError::BadRequest(_)),
        "expected BadRequest, got {error:?}"
    );
    assert!(parse_status_filter(Some("anything")).is_err());
}

/// ADR-0020 Decision 6: `"expired"` is computed from the clock, never stored — and revocation
/// beats expiry, because revocation is the operator-visible act.
#[test]
fn computed_status_derives_expiry_but_never_overrides_revocation() {
    let now = at(30);
    assert_eq!(computed_status("active", at(31), now), "active");
    assert_eq!(computed_status("active", at(29), now), "expired");
    assert_eq!(
        computed_status("active", now, now),
        "expired",
        "expiry is inclusive: a session whose deadline is exactly now is past it"
    );
    assert_eq!(computed_status("revoked", at(29), now), "revoked");
    assert_eq!(computed_status("revoked", at(31), now), "revoked");
    assert!(is_expired(at(29), now));
    assert!(
        is_expired(at(29), now) && computed_status("revoked", at(29), now) == "revoked",
        "`expired` reports the clock fact independently of the status a client sees"
    );
}

#[test]
fn limit_defaults_and_clamps_rather_than_rejecting() {
    assert_eq!(resolve_limit(None), DEFAULT_SESSION_PAGE_LIMIT);
    assert_eq!(resolve_limit(Some(7)), 7);
    assert_eq!(resolve_limit(Some(10_000)), MAX_SESSION_PAGE_LIMIT);
    assert_eq!(
        resolve_limit(Some(0)),
        1,
        "a zero page would page forever without ever advancing"
    );
    assert_eq!(resolve_limit(Some(-5)), 1);
}

/// The cursor must survive a round trip exactly, including sub-second precision — Postgres stores
/// `timestamptz` to the microsecond, and a cursor that rounded would re-serve or skip the boundary
/// row it names.
#[test]
fn cursor_round_trips_including_microseconds() {
    let cursor = SessionCursor {
        created_at: Utc
            .with_ymd_and_hms(2026, 9, 2, 12, 30, 45)
            .single()
            .expect("valid")
            + chrono::Duration::microseconds(123_456),
        id: "sxq1v0m2k9d3p7b4c8f6h5j0".to_owned(),
    };
    let decoded = decode_cursor(&encode_cursor(&cursor)).expect("round trip");
    assert_eq!(decoded, cursor);
}

/// A malformed cursor is an error, not an ignored filter: silently serving page 1 for a corrupted
/// `after` looks like a paginator that loops forever.
#[test]
fn a_malformed_cursor_is_rejected() {
    for raw in [
        "no-separator",
        "not-a-timestamp|abc",
        "2026-09-02T12:00:00Z|",
        "",
    ] {
        let error = decode_cursor(raw).expect_err("must reject {raw}");
        assert!(
            matches!(error, CratestackError::BadRequest(_)),
            "{raw:?}: expected BadRequest, got {error:?}"
        );
    }
}
