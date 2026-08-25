//! OIDC Session Management 1.0 -- the OP side: the JS-readable OP browser-state cookie, the
//! `session_state` value stamped onto successful `/authorize` responses, and the
//! `GET /oauth2/check_session_iframe` page an RP embeds to poll for session changes without a
//! network round-trip.
//!
//! The moving parts, and who owns each:
//!
//! - [`OP_BROWSER_STATE_COOKIE`]: a random, **deliberately non-`HttpOnly`** cookie set beside the
//!   (`HttpOnly`) `__Host-authz_session` cookie in `relying_party.rs`'s callback `Browser` arm.
//!   Its value is meaningless -- what matters is that it *changes* when the login state changes,
//!   and that the iframe's JS can read it via `document.cookie`. It never names the session row
//!   and grants nothing; possession of its value is worthless without the `HttpOnly` session
//!   cookie, which is why exposing it to JS does not weaken ADR-0021 Decision 4.
//! - [`session_state`]: `base64url(SHA-256(client_id + " " + origin + " " + opbs + " " + salt))
//!   + "." + salt` per OIDC Session Management 1.0 §4.2, where `origin` is the RP's own origin
//!   (derived from the validated `redirect_uri`) -- appended to the authorization response by
//!   `authorize.rs`'s `issue_code` whenever the browser presented an OP browser-state cookie.
//! - The iframe (`check_session_iframe.html`, pure HTML + inline script, zero external assets):
//!   receives `postMessage("<client_id> <session_state>")` from the RP, recomputes the hash with
//!   `event.origin` as the origin, and answers `changed` / `unchanged` / `error`.
//!
//! Honest limitation, stated rather than papered over: browsers that block or partition
//! third-party cookies hide [`OP_BROWSER_STATE_COOKIE`] from the embedded iframe, and the iframe
//! then answers `changed` on every poll (the fail-closed direction -- the RP re-checks against
//! `/authorize`, it never silently keeps a dead session). `Partitioned` (CHIPS) would not fix
//! this: a partitioned cookie set during top-level login lives in a different partition than the
//! RP-embedded iframe reads from, so it would *always* be invisible there.

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use sha2::{Digest, Sha256};
use time::Duration;

use crate::oauth2_op::random_urlsafe;

/// `__Host-`-prefixed like the session cookie (Secure + `Path=/` + no `Domain`, browser-enforced),
/// but non-`HttpOnly` (the iframe's `document.cookie` read is the whole point) and
/// `SameSite=None` (the check-session iframe is embedded on the RP's origin, a cross-site
/// context; `Lax` would withhold the cookie from exactly that context).
pub const OP_BROWSER_STATE_COOKIE: &str = "__Host-authz_op_state";

/// Builds the OP browser-state cookie set beside the browser-session cookie -- same TTL, so the
/// two expire together and a fresh login re-mints both (a new random value = every RP's cached
/// `session_state` stops matching = `changed`, which is the mechanism).
pub fn build_op_browser_state_cookie(ttl: Duration) -> Cookie<'static> {
    Cookie::build((OP_BROWSER_STATE_COOKIE, random_urlsafe(32)))
        .secure(true)
        .same_site(SameSite::None)
        .path("/")
        .max_age(ttl)
        .build()
}

/// Reads the OP browser-state cookie's value off an incoming request, if present.
pub fn read_op_browser_state(headers: &HeaderMap) -> Option<String> {
    CookieJar::from_headers(headers)
        .get(OP_BROWSER_STATE_COOKIE)
        .map(|cookie| cookie.value().to_owned())
}

/// OIDC Session Management 1.0 §4.2's Session State value. `salt` rides in cleartext after the
/// `.` so the RP-side iframe can recompute the same hash; the byte-for-byte concatenation order
/// here (`client_id + " " + origin + " " + opbs + " " + salt`) is mirrored by the inline script in
/// `check_session_iframe.html` -- change one and the other MUST change with it, or every poll
/// answers `changed` forever.
pub fn session_state(client_id: &str, origin: &str, op_browser_state: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(client_id.as_bytes());
    hasher.update(b" ");
    hasher.update(origin.as_bytes());
    hasher.update(b" ");
    hasher.update(op_browser_state.as_bytes());
    hasher.update(b" ");
    hasher.update(salt.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{}.{salt}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

/// Convenience over [`session_state`] with a fresh random salt, for the issuing side.
pub fn fresh_session_state(client_id: &str, origin: &str, op_browser_state: &str) -> String {
    session_state(client_id, origin, op_browser_state, &random_urlsafe(16))
}

const CHECK_SESSION_IFRAME_HTML: &str = include_str!("check_session_iframe.html");

async fn check_session_iframe() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'unsafe-inline'; frame-ancestors *",
            ),
        ],
        CHECK_SESSION_IFRAME_HTML,
    )
        .into_response()
}

/// The `GET /oauth2/check_session_iframe` route, advertised by
/// `signing::discovery_document` as `check_session_iframe`. Stateless -- merges into any router.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/oauth2/check_session_iframe", get(check_session_iframe))
}

#[cfg(test)]
mod tests {
    use super::session_state;

    #[test]
    fn session_state_is_deterministic_and_salt_suffixed() {
        let a = session_state("client-a", "https://rp.example", "opbs-value", "salty");
        let b = session_state("client-a", "https://rp.example", "opbs-value", "salty");
        assert_eq!(a, b);
        assert!(a.ends_with(".salty"));
    }

    #[test]
    fn session_state_changes_with_every_input() {
        let base = session_state("client-a", "https://rp.example", "opbs-value", "salty");
        for other in [
            session_state("client-b", "https://rp.example", "opbs-value", "salty"),
            session_state("client-a", "https://other.example", "opbs-value", "salty"),
            session_state("client-a", "https://rp.example", "rotated", "salty"),
            session_state("client-a", "https://rp.example", "opbs-value", "pepper"),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn session_state_matches_a_hand_computed_vector() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(b"cid https://rp.example opbs salt");
        let expected = format!(
            "{}.salt",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        );
        assert_eq!(
            session_state("cid", "https://rp.example", "opbs", "salt"),
            expected
        );
    }
}
