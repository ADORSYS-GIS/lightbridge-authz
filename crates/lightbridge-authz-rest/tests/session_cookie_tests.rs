// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! NOTE: the session-id fixture in these tests is deliberately low-entropy and
//! self-describing. A realistic CUID2 (24-char base36) trips Gitleaks' `generic-api-key`
//! entropy rule and fails the secret scan. That is a false positive, but this repo has no
//! gitleaks allowlist and adding one for a test fixture would be the wrong precedent. Ids
//! are opaque per ADR-0039 and never shape-validated, so the fixture's shape is irrelevant
//! to what these tests assert.
//!
//! Coverage for the `__Host-` browser-session cookie helper (ADR-0021 Decision 4, #443).
//!
//! `session_cookie_has_every_decision_4_attribute` is the deliverable Acceptance Criterion 1
//! demands: a byte-exact `Set-Cookie` header string, not just "it compiles."
//!
//! `session_cookie_builder_does_not_guard_host_prefix_domain_conflict` is Acceptance Criterion
//! 2's negative test: it proves, against the real `cookie` crate this workspace pins, that the
//! plain `Cookie::build()` API does NOT refuse (compile-time or runtime) a `Domain` attribute set
//! alongside a `__Host-`-prefixed name -- so `build_session_cookie` in
//! `crates/lightbridge-authz-rest/src/session_cookie.rs` must never call `.domain(...)`, and does
//! not.

use axum::http::{HeaderMap, HeaderValue};
use axum_extra::extract::cookie::Cookie;
use lightbridge_authz_rest::session_cookie::{
    SESSION_COOKIE_NAME, build_session_cookie, read_session_cookie,
};
use time::Duration;

#[test]
fn session_cookie_name_carries_the_host_prefix() {
    assert_eq!(SESSION_COOKIE_NAME, "__Host-authz_session");
}

#[test]
fn session_cookie_has_every_decision_4_attribute() {
    let cookie = build_session_cookie(
        "test0session0id0not0a0secret".to_string(),
        Duration::hours(8),
    );

    let rendered = cookie.to_string();

    assert_eq!(
        rendered,
        "__Host-authz_session=test0session0id0not0a0secret; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=28800"
    );

    assert!(rendered.starts_with("__Host-authz_session="), "name prefix");
    assert!(rendered.contains("; Secure"), "Secure attribute");
    assert!(rendered.contains("; HttpOnly"), "HttpOnly attribute");
    assert!(
        rendered.contains("; SameSite=Lax"),
        "SameSite=Lax, never Strict"
    );
    assert!(rendered.contains("; Path=/"), "Path=/");
    assert!(
        !rendered.contains("Domain="),
        "no Domain attribute -- required by __Host-"
    );
    assert!(
        rendered.contains("; Max-Age=28800"),
        "Max-Age mirrors the 8h TTL"
    );
}

#[test]
fn session_cookie_same_site_is_lax_not_strict() {
    let cookie = build_session_cookie("session-id".to_string(), Duration::hours(1));

    assert_eq!(
        cookie.same_site(),
        Some(axum_extra::extract::cookie::SameSite::Lax)
    );
}

#[test]
fn session_cookie_never_sets_domain() {
    let cookie = build_session_cookie("session-id".to_string(), Duration::hours(1));

    assert_eq!(cookie.domain(), None);
}

#[test]
fn read_session_cookie_extracts_the_value_from_the_cookie_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_static("__Host-authz_session=test0session0id0not0a0secret; other=1"),
    );

    let value = read_session_cookie(&headers);

    assert_eq!(value.as_deref(), Some("test0session0id0not0a0secret"));
}

#[test]
fn read_session_cookie_returns_none_when_absent() {
    let headers = HeaderMap::new();

    assert_eq!(read_session_cookie(&headers), None);
}

/// Negative test backing Acceptance Criterion 2: this workspace's cookie crate (`cookie` 0.18.2,
/// pulled in via the `axum-extra` `cookie` feature -- see root `Cargo.toml`'s verification
/// comment on that dependency) does **not** refuse a `Domain` attribute set alongside a
/// `__Host-`-prefixed cookie name through the plain `Cookie::build()` API this workspace uses.
///
/// There IS a stricter, enforcing path in the same crate -- `cookie::CookieJar::prefixed_mut`
/// (`cookie::prefix::Host`) forcibly strips `Domain`/forces `Secure`+`Path=/` on anything added
/// through it -- but axum-extra's own `CookieJar` extractor wrapper does not re-expose that
/// jar-level API (`axum-extra-0.12.6/src/extract/cookie/mod.rs`, no `prefixed`/`prefixed_mut`
/// method), so this workspace cannot reach it without depending on the `cookie` crate directly.
///
/// The upshot, and why this matters: nothing in the type system stops a future edit from
/// re-adding `.domain(...)` to `build_session_cookie` and shipping a cookie that silently
/// violates the `__Host-` contract. `build_session_cookie` simply never calls `.domain(...)` --
/// that is the whole guard, and this test exists so a reviewer (or CI) notices if it starts to.
#[test]
fn session_cookie_builder_does_not_guard_host_prefix_domain_conflict() {
    let misconfigured: Cookie<'static> = Cookie::build(("__Host-authz_session", "value"))
        .domain("example.test")
        .secure(true)
        .path("/")
        .build();

    assert_eq!(
        misconfigured.domain(),
        Some("example.test"),
        "the crate accepted a Domain attribute on a __Host--prefixed cookie without complaint \
         -- proving `build_session_cookie` must never call `.domain(...)` itself, since nothing \
         else will stop it"
    );

    let rendered = misconfigured.to_string();
    assert!(
        rendered.contains("Domain=example.test"),
        "the rendered Set-Cookie header actually carries the (invalid, browser-rejected) \
         combination: {rendered}"
    );
}
