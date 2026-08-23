// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml)
// does not reach their free helper functions. Unwrapping in a test is a deliberate assertion
// that the setup held; the workspace gate stays `deny` for shipping code.
#![allow(clippy::unwrap_used)]

//! ADR-0021 Decisions 1 + 10 (#442): `static_assets::static_assets_fallback` serves the hosted
//! login page's Vite build with content-hash-aware caching and a strict CSP. This file proves,
//! against a real (temp-directory) build output rather than a mocked service:
//! 1. A hashed asset under `assets/` gets the immutable long-cache header.
//! 2. `index.html` -- both the real file and the SPA-fallback response for an unrecognized path
//!    -- gets `no-cache`, and the fallback case is a `200`, never a bare `404`.
//! 3. Every response from this fallback carries the Decision 10 CSP.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use lightbridge_authz_rest::static_assets::static_assets_fallback;
use tower::ServiceExt;

/// A real temp directory, not a mock: `ServeDir`/`ServeFile` do real filesystem I/O, so the
/// behavior worth proving here (which file gets served, which headers land) only means something
/// against actual files on disk. Unique per call (nanosecond suffix) so parallel `#[tokio::test]`
/// functions in this file never collide.
fn build_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-static-assets-test-{name}-{nanos}"
    ));
    fs::create_dir_all(dir.join("assets")).unwrap();
    fs::write(
        dir.join("index.html"),
        b"<!doctype html><title>hosted-login</title>",
    )
    .unwrap();
    fs::write(
        dir.join("assets/index-deadbeef.js"),
        b"console.log('placeholder');",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn hashed_asset_gets_immutable_long_cache_control() {
    let dir = build_dir("hashed-asset");
    let router = static_assets_fallback(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/assets/index-deadbeef.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        "default-src 'self'; frame-ancestors 'none'"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"console.log('placeholder');");
}

#[tokio::test]
async fn real_index_html_gets_no_cache() {
    let dir = build_dir("real-index");
    let router = static_assets_fallback(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/index.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-cache"
    );
}

#[tokio::test]
async fn root_path_serves_index_html_with_no_cache() {
    let dir = build_dir("root-path");
    let router = static_assets_fallback(&dir);

    let response = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-cache"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"<!doctype html><title>hosted-login</title>");
}

/// The acceptance-criteria case: an unrecognized client-side route must resolve to `index.html`
/// with a `200`, not a bare `404` -- a `404` here would let a caller distinguish "no such static
/// path" from "no such protocol route" by response shape alone.
#[tokio::test]
async fn unknown_path_falls_back_to_index_html_never_a_bare_404() {
    let dir = build_dir("unknown-path");
    let router = static_assets_fallback(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/some/client/side/route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an unrecognized path must resolve to index.html (SPA routing), not 404"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-cache"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        "default-src 'self'; frame-ancestors 'none'"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"<!doctype html><title>hosted-login</title>");
}

/// A genuinely missing static directory (e.g. the frontend has not been built yet) must not
/// panic the server -- `ServeDir`/`ServeFile` both convert `NotFound` I/O errors into an HTTP
/// `404`, so this degrades to "not found" rather than crashing the process.
#[tokio::test]
async fn missing_static_dir_degrades_to_404_without_panicking() {
    let dir = std::env::temp_dir().join("lightbridge-authz-static-assets-test-does-not-exist");
    let _ = fs::remove_dir_all(&dir);
    let router = static_assets_fallback(&dir);

    let response = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
