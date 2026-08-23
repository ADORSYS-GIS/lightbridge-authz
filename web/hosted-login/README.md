# authz-idp hosted login page

Vite + React + TypeScript static build, served same-origin by `authz-idp` under the `/ui` path
prefix (ADR-0021 Decisions 1 and 10 --
`docs/adr/0021-browser-sso-hosted-login-page-and-session-cookie.md`). This project builds to
static assets with Vite `base: "/ui/"`; `authz-idp`'s Rust router serves them via `tower-http`'s
`fs` feature, nested at `/ui`, never at the server root and never a separate origin
(`crates/lightbridge-authz-rest/src/static_assets.rs`) -- see that ADR's Decision 1 for why
same-origin is load-bearing for the `__Host-` session cookie, and Decision 10 for why `/ui`
specifically (`GET /` stays `authz-idp`'s own API-welcome-JSON route; the two never collide).

## Stack

- **React 19 + TypeScript**, routed with **react-router**. Route set is deliberately minimal
  (`src/App.tsx`) -- exactly one real page today, no invented `/login`/`/authorize`/`/callback`
  routes (those belong to #424/#425/#441/#443).
- **Tailwind CSS v4** (`@tailwindcss/vite`, CSS-first config in `src/index.css`) + **daisyUI**
  for semantic color tokens, **Headless UI** for accessible behavior primitives, **cva** +
  **clsx** + **tailwind-merge** (composed as `cn()`, `src/lib/cn.ts`) for variant/className
  composition. All four are wired as plumbing, not a design pass -- no visual direction has
  been decided for this surface (see `src/routes/placeholder-page.tsx`'s own comment).
  Deliberately avoid daisyUI's component classes (`.alert`, `.btn`, `.badge`, `.checkbox`,
  `.radio`, `.toggle`, `.fileinput`, `.menu`, `.svg`) -- every one of them unconditionally sets
  a `background-image: data:image/svg+xml,...` (the `fx-noise` texture effect), which
  `default-src 'self'` (no `data:` carve-out, per ADR-0021 Decision 10) blocks and logs as a CSP
  violation regardless of the active theme's `--noise` value. Use daisyUI's utility-level color
  tokens (`bg-base-200`, `text-base-content`, `border-info`, etc. -- verified to carry no
  `fx-noise` reference) instead. Found via real browser verification, not assumed -- see PR #446.
- **`vite-plugin-pwa`**, `injectManifest` strategy with a hand-written `src/sw.ts` -- see that
  file's own doc comment for the full reasoning. Short version: this page is served from the
  issuer origin, so a service worker here controls `/oauth2/*`, `/.well-known/*`, `/authorize`,
  and `/healthz` too, not just this page. `src/sw.ts` precaches ONLY the content-hashed
  `assets/**` bundle and registers no other route (no `navigateFallback`, no runtime caching) --
  deliberately stricter than the more common `generateSW` + `navigateFallbackDenylist` pattern,
  because `navigateFallback` is fundamentally a precache-backed (cache-first) mechanism for
  whatever URL it targets, which would mean precaching `index.html` and directly contradicting
  Decision 10's `no-cache` posture for it.
- **Biome** for formatting + linting (`biome.json`) -- the house preference for a fresh JS/TS
  project with no pre-existing Prettier/ESLint convention to respect.

## Scope (#442)

This is a scaffold: the static build pipeline, the styling/router/PWA plumbing, and the
Rust-side serving/caching/CSP posture. It does **not** implement the login flow itself:

- the RP leg to Keycloak -- #424
- `GET /authorize` -- #425
- session creation / the `__Host-` cookie -- #441, #443

`src/routes/placeholder-page.tsx` is a deliberately plain placeholder until this surface's
visual direction is decided.

## Commands

```bash
npm ci
npm run dev      # local dev server (not served by authz-idp; SW registration is disabled here
                  # too -- devOptions.enabled: false in vite.config.ts -- only ever verify the
                  # service worker against a real production build)
npm run build    # tsc -b && vite build && scripts/verify-service-worker-scope.mjs --
                  # production build -> dist/ (content-hashed assets/*.js, assets/*.css,
                  # sw.js), every asset/HTML reference and the service worker's own
                  # registration prefixed with /ui/ (vite.config.ts's base: "/ui/"), then
                  # asserts the built service worker only precaches assets/** and never
                  # intercepts navigation (ADR-0021 Decision 10's SW scoping property)
npm run check    # biome check . (format + lint + import order, read-only)
npm run lint     # biome lint . only
npm run format   # biome format --write .
npm run ci       # biome ci . -- what CI actually runs (.github/actions/build-frontend)
```

`npm run build` is what CI runs (`.github/actions/build-frontend`) and what `authz-idp`'s
container image serves from `/app/static` (`Dockerfile`, `Dockerfile.dist`).
