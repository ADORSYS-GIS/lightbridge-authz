//! ADR-0021 (`docs/adr/0021-browser-sso-hosted-login-page-and-session-cookie.md`) Decisions 1 +
//! 10, amended by ADR-0029: serves the hosted-login Vite React static build (built in
//! `converse-frontends` as `apps/authz-ui`, consumed here as a digest-pinned OCI artifact, with
//! Vite `base: "/ui/"`) under `authz-idp`'s `/ui` path prefix, with Decision 10's content-hash-aware
//! caching and strict CSP.
//!
//! **Scaffold only (#442).** This module makes the built assets reachable; it does not implement
//! any part of the login flow itself -- the RP leg to Keycloak (#424), `GET /authorize` (#425),
//! or session/cookie issuance (#441, #443) all land as separate, later changes. Nothing in this
//! module reads or writes a cookie, calls Keycloak, or knows what a session is.
//!
//! **Path-scoping is the whole safety property, not mount order.** [`static_assets_fallback`] is
//! mounted via `.nest_service("/ui", ..)` on `build_idp_router`'s router (see that function's doc
//! comment), not as a root-level `.fallback_service(..)`. Nesting under `/ui` means this service
//! only ever receives a request whose original path already started with `/ui` -- it cannot be
//! reached by, and cannot shadow, any protocol route (`.well-known/*`, `/oauth2/*`, `/authorize`,
//! the probe router, all of which live outside `/ui`), regardless of merge order. Within its own
//! `/ui` subtree this router still behaves like an SPA catch-all: any path under `/ui` that does
//! not match a real static file falls back to `index.html` (client-side routing), exactly as
//! before -- only the outer scope changed.
//!
//! **This supersedes #462's `RESERVED_PROTOCOL_ROOTS` denylist, which is removed here.** That
//! list existed only because this service was mounted at the router root, where an unknown
//! protocol path could otherwise fall through and render as a successful SPA page; it had to be
//! kept in step by hand every time a new protocol route was accepted. Nesting removes the
//! condition it defended against: a protocol path never reaches this service at all. Keeping it
//! would also be actively wrong here -- `nest_service` strips the `/ui` prefix, so a legitimate
//! client-side route such as `/ui/authorize` would arrive as `/authorize` and be refused. A
//! structural guarantee replaces an enumerated one; there is no dormant second mechanism.

use std::path::Path;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::Response;
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
///
/// `pub(crate)` so `crate::relying_party` -- whose device-verification/callback 303 redirects
/// (`redirect_to`, lightbridge-authz#598: the RP leg hands off to the SPA now, it no longer
/// renders any HTML of its own) carry the exact same same-origin, unembeddable posture -- can
/// reuse this constant instead of declaring a byte-identical copy of its own.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; frame-ancestors 'none'";

/// Builds the static-asset service `build_idp_router` mounts under `/ui` (`.nest_service("/ui",
/// ..)`).
///
/// `static_dir` is the Vite build's `dist/` output (an `index.html` plus a content-hashed
/// `assets/` directory built with Vite `base: "/ui/"`). This function's own paths (`/`,
/// `/assets/...`) are relative to wherever it is mounted -- `axum::Router::nest_service` strips
/// the `/ui` prefix before a request reaches here, so `GET /ui` and `GET /ui/` both arrive as `/`
/// and `GET /ui/assets/<file>` arrives as `/assets/<file>`, exactly like the caller mounted this
/// router at the origin. Serves a matching file when one exists; otherwise serves `index.html`
/// with a `200` (client-side routing) -- **never a bare `404`**, which would otherwise let a
/// client distinguish "unknown static path under `/ui`" from "protocol route that doesn't exist"
/// by response shape. Every response -- asset, real `index.html`, or the SPA-fallback
/// `index.html` -- carries Decision 10's cache headers and CSP.
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
