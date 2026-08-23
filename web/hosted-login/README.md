# authz-idp hosted login page

Vite + React + TypeScript static build, served same-origin by `authz-idp` (ADR-0021 Decisions
1 and 10 -- `docs/adr/0021-browser-sso-hosted-login-page-and-session-cookie.md`). This project
builds to static assets; `authz-idp`'s Rust router serves them via `tower-http`'s `fs` feature
(`crates/lightbridge-authz-rest/src/static_assets.rs`), never a separate origin -- see that ADR's
Decision 1 for why same-origin is load-bearing for the `__Host-` session cookie.

## Scope (#442)

This is a scaffold: the static build pipeline and the Rust-side serving/caching/CSP posture.
It does **not** implement the login flow itself:

- the RP leg to Keycloak -- #424
- `GET /authorize` -- #425
- session creation / the `__Host-` cookie -- #441, #443

`src/App.tsx` is a deliberately plain placeholder until this surface's visual direction is
decided.

## Commands

```bash
npm ci
npm run dev      # local dev server (not served by authz-idp)
npm run build    # production build -> dist/ (content-hashed assets/*.js, assets/*.css)
npm run lint
```

`npm run build` is what CI runs (`.github/actions/build-frontend`) and what `authz-idp`'s
container image serves from `/app/static` (`Dockerfile`, `Dockerfile.dist`).
