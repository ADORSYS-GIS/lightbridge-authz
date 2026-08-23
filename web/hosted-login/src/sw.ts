// ADR-0021 Decision 10 (#442): this service worker is served from `auth.ai.camer.digital`,
// the same origin as `/oauth2/token`, `/oauth2/revoke`, `.well-known/*`, and (once #425
// lands) `/authorize` -- a service worker registered here controls ALL of those requests,
// not just this page. That makes it the highest-risk file in this whole scaffold: a
// stale or over-eager SW can serve a cached login page over a rotated endpoint, or
// intercept an OAuth redirect, and a user cannot clear it themselves the way they'd clear
// a cookie.
//
// This file does exactly one thing on purpose: precache and serve the content-hashed,
// immutably-cached JS/CSS bundle under `assets/**` (the manifest below is injected by
// vite-plugin-pwa's `injectManifest.globPatterns`, restricted to that glob in
// `vite.config.ts` -- see that file's comment). It registers NO other route: no
// `navigateFallback`, no runtime-caching rule, nothing that could intercept a navigation
// or a fetch to a protocol route. Every request this SW does not explicitly precache
// falls straight through to the network, exactly as if no SW were installed at all.
//
// This is a deliberately STRICTER choice than configuring `workbox.navigateFallbackDenylist`
// against a `navigateFallback` route (the more common vite-plugin-pwa pattern for SPAs).
// `navigateFallback` is fundamentally a precache-backed (cache-first) mechanism for
// whatever URL it targets -- using it here would mean precaching `index.html`, directly
// contradicting the `Cache-Control: no-cache` posture `static_assets.rs` already sets for
// it (Decision 10's caching rule exists specifically so `index.html` is always
// revalidated, since it is the one file whose content changes without its own URL
// changing). Precaching only `assets/**` and adding no other route achieves the same
// protective intent -- protocol routes and the app shell can never be served from this
// SW's cache -- with a smaller, more auditable surface: there is no denylist to get
// wrong, because there is nothing here that could match one of those routes to begin
// with. See PR #446's description for the full reasoning and the `verify-service-worker
// -scope.mjs` regression check (`scripts/verify-service-worker-scope.mjs`, run as part of
// `npm run build`) that asserts this file's build output never grows a navigateFallback,
// a runtime-caching rule, or a precache entry outside `assets/`.

import { precacheAndRoute } from "workbox-precaching";

interface WorkboxManifestEntry {
  url: string;
  revision: string | null;
}

declare const self: ServiceWorkerGlobalScope & {
  __WB_MANIFEST: WorkboxManifestEntry[];
};

precacheAndRoute(self.__WB_MANIFEST);
