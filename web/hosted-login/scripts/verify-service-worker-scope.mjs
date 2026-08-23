#!/usr/bin/env node
// ADR-0021 Decision 10 (#442): the SW-level twin of
// `crates/lightbridge-authz-rest/tests/idp_server_tests.rs`'s
// `static_fallback_never_shadows_an_existing_protocol_route` -- this page is served from
// the issuer origin (`auth.ai.camer.digital`), so a service worker registered here
// controls `/oauth2/*`, `/.well-known/*`, `/authorize`, `/healthz`, and the RPC surface
// too, not just this page. Run as part of `npm run build` (see package.json) so a
// regression here fails CI's `frontend` job (`.github/actions/build-frontend`), not just
// a manual review.
//
// src/sw.ts is deliberately written to precache ONLY the content-hashed `assets/**`
// bundle and register no other route (no navigateFallback, no runtime caching) -- see
// that file's own doc comment for why. This script proves the BUILT OUTPUT actually
// has that shape, not just the source: it inspects `dist/sw.js`, the real bundled/
// manifest-injected service worker a browser would install.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const swPath = resolve(process.cwd(), "dist/sw.js");
let source;
try {
  source = readFileSync(swPath, "utf8");
} catch (error) {
  console.error(`verify-service-worker-scope: could not read ${swPath}: ${error.message}`);
  process.exit(1);
}

const failures = [];

// 1. Precache scope: every entry in the injected manifest must be a content-hashed
//    asset under assets/, and none may look like a protocol route this SW must never
//    know about. Matches workbox-build's injected manifest entry shape
//    (`{"revision":...,"url":"..."}`, key order not guaranteed) rather than depending on
//    any particular minified variable name for the `precacheAndRoute(...)` call site,
//    which is not stable across workbox versions.
const manifestEntryPattern =
  /"revision":(?:null|"[^"]*"),"url":"([^"]+)"|"url":"([^"]+)","revision":(?:null|"[^"]*")/g;
const precachedUrls = [];
for (const match of source.matchAll(manifestEntryPattern)) {
  precachedUrls.push(match[1] ?? match[2]);
}

if (precachedUrls.length === 0) {
  failures.push("no precache manifest entries found -- expected the built assets bundle");
}

const deniedPrefixes = ["oauth2/", ".well-known/", "authorize", "healthz", "rpc/"];
for (const url of precachedUrls) {
  if (!url.startsWith("assets/")) {
    failures.push(
      `precached url "${url}" is not under assets/ -- only content-hashed, ` +
        "immutably-cached assets may be precached (Decision 10)",
    );
  }
  const deniedHit = deniedPrefixes.find((prefix) => url.includes(prefix));
  if (deniedHit) {
    failures.push(
      `precached url "${url}" looks like a protocol route (matched "${deniedHit}") -- ` +
        "this service worker must never cache anything under /oauth2/*, /.well-known/*, " +
        "/authorize, /healthz, or the RPC surface",
    );
  }
}

// 2. No navigation interception: `createHandlerBoundToURL(<literal>)` is the call site
//    workbox-precaching uses to wire a precached URL into a NavigationRoute (what
//    `navigateFallback` compiles down to, and what a hand-written `sw.ts` would need to
//    call directly to add the same behavior). The method DEFINITION always ships as
//    part of workbox-precaching's PrecacheController class regardless of whether it's
//    used (so a bare substring check on the method name would always "pass"); a real
//    invocation is always followed immediately by a string-literal argument, which the
//    definition itself is not (it takes a parameter name). Any match here means
//    something now intercepts navigations -- exactly the SW-level shadowing bug this
//    script exists to catch.
const navigationRouteCallPattern = /createHandlerBoundToURL\(\s*["'][^"']*["']\s*\)/;
if (navigationRouteCallPattern.test(source)) {
  failures.push(
    "found a createHandlerBoundToURL(...) call site -- this service worker now wires a " +
      "navigateFallback/NavigationRoute, which would intercept navigations to protocol " +
      "routes unless explicitly denylisted; src/sw.ts must not add this without updating " +
      "this script's denylist and the reasoning in its own doc comment",
  );
}

if (failures.length > 0) {
  console.error("verify-service-worker-scope: dist/sw.js failed scope verification:\n");
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  process.exit(1);
}

console.log(
  `verify-service-worker-scope: ok -- ${precachedUrls.length} precached asset(s), all ` +
    "under assets/, no navigation interception",
);
