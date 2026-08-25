// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! OIDC Session Management 1.0 -- the OP browser-state cookie (`session_management.rs`).
//!
//! Mirrors `session_cookie_tests.rs`'s style for the sibling `__Host-authz_session` cookie, but
//! for `__Host-authz_op_state`: a real, byte-exact `Set-Cookie` rendering, and a round trip
//! through the reader. `session_state`/`fresh_session_state` already have dedicated unit tests
//! inside `session_management.rs` itself (`session_state_is_deterministic_and_salt_suffixed`,
//! `session_state_changes_with_every_input`, `session_state_matches_a_hand_computed_vector`) --
//! deliberately not duplicated here.

use axum::http::{HeaderMap, HeaderValue};
use lightbridge_authz_rest::session_management::{
    OP_BROWSER_STATE_COOKIE, build_op_browser_state_cookie, read_op_browser_state,
};
use time::Duration;

#[test]
fn op_browser_state_cookie_name_carries_the_host_prefix() {
    assert_eq!(OP_BROWSER_STATE_COOKIE, "__Host-authz_op_state");
}

/// The whole point of this cookie (see `session_management.rs`'s module doc comment): it must be
/// JS-readable by the embedded check-session iframe, so it must NEVER carry `HttpOnly` -- unlike
/// its sibling `__Host-authz_session`, which always does. Every other `__Host-` attribute
/// (Secure, no Domain, Path=/) still applies since the name carries the prefix.
#[test]
fn op_browser_state_cookie_has_no_http_only_but_keeps_every_other_host_attribute() {
    let cookie = build_op_browser_state_cookie(Duration::hours(8));
    let rendered = cookie.to_string();

    assert!(
        rendered.starts_with("__Host-authz_op_state="),
        "name prefix: {rendered}"
    );
    assert!(
        rendered.contains("; Secure"),
        "Secure attribute: {rendered}"
    );
    assert!(
        rendered.contains("; SameSite=None"),
        "SameSite=None -- the iframe is embedded cross-site on the RP's own origin: {rendered}"
    );
    assert!(rendered.contains("; Path=/"), "Path=/: {rendered}");
    assert!(
        rendered.contains("; Max-Age=28800"),
        "Max-Age mirrors the 8h TTL passed in: {rendered}"
    );
    assert!(
        !rendered.contains("Domain="),
        "no Domain attribute -- required by __Host-: {rendered}"
    );
    assert!(
        !rendered.contains("HttpOnly"),
        "must NOT be HttpOnly -- the check-session iframe's document.cookie read is the entire \
         point of this cookie, unlike __Host-authz_session which is always HttpOnly: {rendered}"
    );
}

#[test]
fn op_browser_state_cookie_value_is_present_and_random_per_call() {
    let a = build_op_browser_state_cookie(Duration::hours(8));
    let b = build_op_browser_state_cookie(Duration::hours(8));

    assert!(!a.value().is_empty());
    assert_ne!(
        a.value(),
        b.value(),
        "each mint must produce a fresh random value -- a repeated value would let an RP's \
         cached session_state keep matching across a fresh login, defeating the mechanism"
    );
}

#[test]
fn read_op_browser_state_extracts_the_value_from_the_cookie_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_static("__Host-authz_op_state=opbs-value-not-a-secret; other=1"),
    );

    let value = read_op_browser_state(&headers);

    assert_eq!(value.as_deref(), Some("opbs-value-not-a-secret"));
}

#[test]
fn read_op_browser_state_returns_none_when_absent() {
    let headers = HeaderMap::new();

    assert_eq!(read_op_browser_state(&headers), None);
}

/// Round trip: whatever `build_op_browser_state_cookie` renders into a `Set-Cookie` header must
/// be readable back off a `Cookie` request header carrying the same name=value pair -- proves
/// `read_op_browser_state`'s `CookieJar`-based parsing actually agrees with the builder's own
/// rendering, not just with a hand-written fixture string.
#[test]
fn op_browser_state_cookie_round_trips_through_set_cookie_and_cookie_headers() {
    let cookie = build_op_browser_state_cookie(Duration::hours(8));
    let name_value = format!("{}={}", cookie.name(), cookie.value());

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_str(&name_value).unwrap(),
    );

    assert_eq!(
        read_op_browser_state(&headers).as_deref(),
        Some(cookie.value())
    );
}
