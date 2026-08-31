// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml)
// does not reach their free helper functions. Unwrapping in a test is a deliberate assertion
// that the setup held; the workspace gate stays `deny` for shipping code.
#![allow(clippy::unwrap_used)]

//! ADR-0021 Decisions 1 + 10 (#442): `static_assets::static_assets_fallback` serves the hosted
//! login page's Vite build with content-hash-aware caching and a strict CSP. This file exercises
//! the service in isolation, at its own root -- exactly the paths it sees once
//! `build_idp_router` nests it under `/ui` and `axum::Router::nest_service` strips that prefix
//! (`GET /ui/assets/x.js` arrives here as `/assets/x.js`, `GET /ui`/`GET /ui/` both arrive as
//! `/`). The `/ui`-prefixed mounting itself -- bare `/ui`, `/ui/`, `GET /` staying the API route,
//! and a non-`/ui` path 404ing -- is `idp_server_tests.rs`'s job
//! (`ui_bare_and_trailing_slash_both_serve_index_html` and friends), since that behavior only
//! exists once this service is actually mounted on `build_idp_router`. Proves, against a real
//! (temp-directory) build output rather than a mocked service:
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
    // #598: the route allowlist manifest every test in this file now needs. Without this, every
    // test below silently degrades to `load_route_manifest`'s `{"/"}` fallback and several would
    // pass for the wrong reason (D11's fail-closed floor, not the allowlisted-route behavior each
    // test claims to prove).
    fs::write(
        dir.join("routes.json"),
        br#"{"version":1,"basename":"/ui","routes":["/","/device","/device/confirm"]}"#,
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

/// #598: `/ui` is a route ALLOWLIST now, not a catch-all. An unrecognized client-side route --
/// one that is not one of the manifest's entries -- must be a bare `404`, not the SPA shell: a
/// `200` here would mean "this page exists" for a path the SPA has no route for, which is
/// precisely the "works in `vite dev`, 404s in production" drift #598 exists to catch instead of
/// silently masking. This inverts the pre-#598 argument this test used to make (a `404` here
/// would have let a caller distinguish "no such static path" from "no such protocol route" by
/// response shape) -- now a `200` must mean "this page exists", and paths outside `/ui` already
/// 404 (`idp_server_tests.rs`'s `unknown_path_outside_ui_prefix_returns_plain_404`), so the two
/// shapes agree rather than differ.
///
/// Prove-fail-first (recorded verbatim against unfixed code, pre-B4): with `static_assets_fallback`
/// still `ServeDir::new(dir).fallback(ServeFile::new(index))` (the old whole-subtree catch-all),
/// this test failed with:
/// ```text
/// thread 'unknown_path_is_a_bare_404_not_the_spa_shell' panicked at
/// crates/lightbridge-authz-rest/tests/static_assets_tests.rs:167:5:
/// assertion `left == right` failed: an unrecognized path must be a bare 404 under the route allowlist
///   left: 200
///  right: 404
/// ```
#[tokio::test]
async fn unknown_path_is_a_bare_404_not_the_spa_shell() {
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
        StatusCode::NOT_FOUND,
        "an unrecognized path must be a bare 404 under the route allowlist"
    );
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

/// #598's acceptance criterion, stated positively: a client-side route the artifact's
/// `dist/routes.json` actually lists must resolve to `index.html` with a `200`, `no-cache`, and
/// the Decision 10 CSP -- exactly like the pre-#598 catch-all did, just now for allowlisted paths
/// only instead of everything.
///
/// Not a prove-fail-first case: run against unfixed code (pre-B4, `static_assets_fallback` still
/// the old whole-subtree `.fallback(ServeFile::new(index))` catch-all), this test PASSES already
/// -- for the wrong reason, since the old catch-all answers every path with `index.html`
/// regardless of any manifest. `unknown_path_is_a_bare_404_not_the_spa_shell` right above is what
/// actually falsifies the old behavior; this test only starts passing for the RIGHT reason (via
/// `load_route_manifest`/the per-route `router.route_service` loop) once B4 lands -- confirmed by
/// re-running after.
#[tokio::test]
async fn allowlisted_client_route_serves_index_html() {
    let dir = build_dir("allowlisted-route");
    let router = static_assets_fallback(&dir);

    for path in ["/device", "/device/confirm"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache",
            "GET {path}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            "default-src 'self'; frame-ancestors 'none'",
            "GET {path}"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"<!doctype html><title>hosted-login</title>",
            "GET {path}"
        );
    }
}

/// D11's fail-closed shape: an artifact predating #598's manifest (no `routes.json` at all) must
/// degrade to serving only `/`, never panic, and never fall back open to the old catch-all --
/// deep links 404 in this state, which is what makes a stale pin diagnosable rather than silently
/// broken.
///
/// Prove-fail-first (recorded verbatim against unfixed code, pre-B4): with no per-route allowlist
/// loop at all, `/device` fell back through the OLD catch-all and returned `200` instead of the
/// expected `404`:
/// ```text
/// thread 'manifest_absent_degrades_to_root_only' panicked at
/// crates/lightbridge-authz-rest/tests/static_assets_tests.rs:274:5:
/// assertion `left == right` failed: no routes.json means only / should serve
///   left: 200
///  right: 404
/// ```
#[tokio::test]
async fn manifest_absent_degrades_to_root_only() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-static-assets-test-no-manifest-{nanos}"
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("index.html"),
        b"<!doctype html><title>hosted-login</title>",
    )
    .unwrap();
    let router = static_assets_fallback(&dir);

    let root = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        root.status(),
        StatusCode::OK,
        "no routes.json: / must still serve"
    );

    let deep_link = router
        .oneshot(
            Request::builder()
                .uri("/device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        deep_link.status(),
        StatusCode::NOT_FOUND,
        "no routes.json means only / should serve"
    );
}

/// The manifest is UNTRUSTED INPUT from a separately-built artifact, and `axum::Router::route`
/// panics on a malformed route string and on a duplicate registration -- `load_route_manifest`
/// must filter both out before ever calling `route_service`, or a corrupt bundle would crash
/// `authz-idp` at startup rather than degrade.
///
/// Prove-fail-first (recorded verbatim against unfixed code, pre-B4): `static_assets_fallback`
/// does not read `routes.json` at all yet, so `/ok` passes for the wrong reason (the old
/// catch-all answers every path, manifest or not) while `/bad/*` -- expected to 404 as an
/// unusable manifest entry -- instead falls through that same catch-all and returns `200`:
/// ```text
/// thread 'malformed_manifest_route_is_ignored_without_panicking' panicked at
/// crates/lightbridge-authz-rest/tests/static_assets_tests.rs:330:9:
/// assertion `left == right` failed: a malformed manifest entry must never be routable: /bad/*
///   left: 200
///  right: 404
/// ```
#[tokio::test]
async fn malformed_manifest_route_is_ignored_without_panicking() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-static-assets-test-malformed-manifest-{nanos}"
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("index.html"),
        b"<!doctype html><title>hosted-login</title>",
    )
    .unwrap();
    fs::write(
        dir.join("routes.json"),
        br#"{"version":1,"basename":"/ui","routes":["/","/ok","not-a-path","/bad/*","/dup","/dup"]}"#,
    )
    .unwrap();

    // Constructing the router must not panic even though the manifest contains a duplicate and
    // two unusable entries.
    let router = static_assets_fallback(&dir);

    let ok = router
        .clone()
        .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK, "/ok is a valid manifest entry");

    for path in ["/bad/*", "/not-a-path"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a malformed manifest entry must never be routable: {path}"
        );
    }
}
