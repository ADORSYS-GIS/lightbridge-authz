//! ADR-0021 (`docs/adr/0021-browser-sso-hosted-login-page-and-session-cookie.md`) Decisions 1 +
//! 10: serves the hosted-login Vite React static build (`web/hosted-login/`) as `authz-idp`'s
//! lowest-priority fallback, with Decision 10's content-hash-aware caching and strict CSP.
//!
//! **Scaffold only (#442).** This module makes the built assets reachable; it does not implement
//! any part of the login flow itself -- the RP leg to Keycloak (#424), `GET /authorize` (#425),
//! or session/cookie issuance (#441, #443) all land as separate, later changes. Nothing in this
//! module reads or writes a cookie, calls Keycloak, or knows what a session is.
//!
//! **Mount order and namespace reservation preserve protocol safety.**
//! [`static_assets_fallback`] must be mounted via `.fallback_service(..)` on
//! `build_idp_router`'s router after every protocol route has already been merged in. Axum tries
//! the route table before the fallback, and this fallback independently refuses its reserved
//! OAuth/OIDC namespaces so an unknown future protocol path cannot become a successful SPA page.

use std::path::Path;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode_str;
use tower_http::services::{ServeDir, ServeFile};

/// Vite's default production output directory for content-hashed JS/CSS
/// (`assets/index-<hash>.js`). Anything under this prefix is safe to cache forever: a content
/// change is a different URL, never a cache-invalidation problem (Decision 10).
const HASHED_ASSET_PREFIX: &str = "/assets/";

/// Decision 10: hashed JS/CSS assets are cached as far as HTTP allows.
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// Decision 10: `index.html` (both the real file and every SPA-fallback response, which is the
/// same file served for an unrecognized path) must always revalidate -- it is the one file whose
/// *content* changes without its own URL changing; it is what references the current hashed
/// bundle.
const NO_CACHE_CONTROL: &str = "no-cache";

/// Decision 10's CSP for the hosted login page: same-origin only, unembeddable by any other
/// origin (mirrors #424's device-grant verification page clickjacking posture, raised stakes here
/// since this page also sets an authentication cookie on success), no inline scripts (Vite's
/// production build does not require any -- verified against a real `vite build` output, not
/// dev-mode HMR injection).
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; frame-ancestors 'none'";

/// Root-level protocol endpoints already named by accepted ADRs or the current roadmap, plus the
/// two discovery/token namespaces (`.well-known`, `oauth2`). Keep device verification out of this
/// list: its `/device/verify` spelling remains hosted UI, not the machine-facing
/// device-authorization endpoint. Matched case-insensitively against the percent-decoded request
/// path -- see [`is_reserved_protocol_namespace`].
const RESERVED_PROTOCOL_ROOTS: &[&str] = &[
    "/authorize",
    "/userinfo",
    "/device_authorization",
    "/idp/callback",
    "/.well-known",
    "/oauth2",
];

/// Builds the static-asset fallback service for `build_idp_router`.
///
/// `static_dir` is the Vite build's `dist/` output (an `index.html` plus a content-hashed
/// `assets/` directory). Serves a matching file when one exists; otherwise serves `index.html`
/// with a `200` for client-side routing. OAuth/OIDC protocol namespaces are reserved before that
/// fallback, so an unknown endpoint can never appear to be a successful hosted page. Every static
/// response -- asset, real `index.html`, or the SPA-fallback `index.html` -- carries Decision 10's
/// cache headers and CSP.
pub fn static_assets_fallback(static_dir: impl AsRef<Path>) -> Router {
    let static_dir = static_dir.as_ref();
    let index_html = static_dir.join("index.html");

    let serve_dir = ServeDir::new(static_dir).fallback(ServeFile::new(index_html));

    Router::new()
        .fallback_service(serve_dir)
        .layer(middleware::from_fn(apply_static_asset_headers))
}

/// Decision 10's cache-control + CSP posture, applied uniformly after the file (or SPA-fallback
/// `index.html`) has already been resolved -- this never changes *which* file is served, only the
/// headers on the response.
async fn apply_static_asset_headers(req: Request, next: Next) -> Response {
    if is_reserved_protocol_namespace(req.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let is_hashed_asset = req.uri().path().starts_with(HASHED_ASSET_PREFIX);
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if is_hashed_asset {
            IMMUTABLE_CACHE_CONTROL
        } else {
            NO_CACHE_CONTROL
        }),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );

    response
}

/// Percent-decodes and lowercases `path` before comparing it against
/// [`RESERVED_PROTOCOL_ROOTS`], so a disguised request (`/oauth2%2Ftoken`, `/OAuth2/token`)
/// cannot slip past the raw, case-sensitive `http::Uri::path()` string and fall through to the
/// SPA fallback as if it were an ordinary unrecognized path.
fn is_reserved_protocol_namespace(path: &str) -> bool {
    let decoded = percent_decode_str(path)
        .decode_utf8_lossy()
        .to_ascii_lowercase();
    RESERVED_PROTOCOL_ROOTS.iter().any(|root| {
        decoded == *root
            || decoded
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}
