//! Typed helper for the `__Host-` browser-session cookie (ADR-0021 Decision 4, #443).
//!
//! Scope, deliberately narrow: this module only builds and reads the cookie envelope. It does
//! not create, look up, or rotate the underlying `sessions` row (ADR-0021 Follow-up 6, a separate
//! ticket). [`build_session_cookie`] is wired into the RP-leg callback (#441/#424, see
//! `crate::relying_party::KeycloakRelyingParty::complete`'s `Completion::Browser` arm) --
//! `/authorize`'s cookie-lookup precondition (#425) is a separate, still-unbuilt caller of
//! [`read_session_cookie`].

use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration;

/// `__Host-`-prefixed name for the browser-session cookie (ADR-0021 Decision 4).
///
/// The `__Host-` prefix is the strictest cookie-scoping mechanism the platform offers: browsers
/// themselves refuse to honor a `Set-Cookie` carrying this prefix unless it also sets `Secure`,
/// `Path=/`, and omits `Domain` entirely. [`build_session_cookie`] sets exactly that combination
/// and nothing else -- see its doc comment for why the underlying crate does not enforce this for
/// us, and the root `Cargo.toml`'s `axum-extra` comment for the version/capability verification
/// evidence this repo's house rule requires.
pub const SESSION_COOKIE_NAME: &str = "__Host-authz_session";

/// Builds the `Set-Cookie` value for a browser session, per ADR-0021 Decision 4's attribute
/// table in full:
///
/// - `__Host-` name prefix, `Secure`, `HttpOnly`, `Path=/`, no `Domain`.
/// - `SameSite=Lax` -- see the inline comment below for why this is not `Strict`.
/// - `Max-Age` mirroring the session row's own TTL.
///
/// `session_id` is the opaque CUID2 primary key of the session's `sessions` row (ADR-0039) --
/// never a JWT, never a signed/encrypted blob. Decision 4's "Value" row explains why: every
/// `/authorize` call already re-checks `status`/`expires_at` against the row fail-closed, so a
/// self-contained cookie buys no latency win and would reintroduce exactly the
/// "cannot revoke mid-lifetime" problem ADR-0020 exists to solve for the access-token case
/// already.
///
/// `ttl` mirrors the session row's own `expires_at` (Decision 4's `Max-Age`/`Expires` row) --
/// callers must pass the same TTL they used to compute that row's expiry, not an independently
/// chosen value; the server-side row remains the authoritative boundary (Decision 6), the
/// cookie's own expiry is only a convenience for the browser to stop sending a definitely-dead
/// cookie.
pub fn build_session_cookie(session_id: String, ttl: Duration) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, session_id))
        .secure(true)
        .http_only(true)
        // Deliberately `Lax`, NEVER `Strict`. `/authorize` is reached by a cross-site, top-level
        // GET navigation initiated by the requesting client app (e.g. `lightbridge-ss` on a
        // different origin navigating the whole page to this service's `/authorize`).
        // `SameSite=Strict` cookies are withheld on exactly this kind of cross-site top-level
        // request by modern browsers -- silently, with no error surfaced anywhere -- which would
        // make every `/authorize` hit behave as if this cookie never existed, forcing a full
        // Keycloak redirect every single time and defeating the entire point of this cookie
        // (ADR-0021 Decision 4's `SameSite` row). Do not "harden" this to `Strict`.
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(ttl)
        // Deliberately never call `.domain(...)` here. The `__Host-` prefix forbids a `Domain`
        // attribute -- but, verified against the exact `cookie-0.18.2` source this dependency
        // resolves to (root `Cargo.toml`'s `axum-extra` comment), this builder does NOT guard
        // that combination itself; see
        // `session_cookie_builder_does_not_guard_host_prefix_domain_conflict` in
        // `tests/session_cookie_tests.rs` for the proof. The absence of `.domain(...)` here is
        // the only thing keeping this cookie `__Host-`-conformant -- do not add one.
        .build()
}

/// Reads the browser-session cookie's raw value (the opaque `sessions.id`) out of an incoming
/// request's `Cookie` header, if present.
pub fn read_session_cookie(headers: &HeaderMap) -> Option<String> {
    CookieJar::from_headers(headers)
        .get(SESSION_COOKIE_NAME)
        .map(|cookie| cookie.value().to_owned())
}
