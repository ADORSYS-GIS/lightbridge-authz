# ADR-0029: the `authz-idp` login UI is a pinned external artifact, not a build stage

- Status: Accepted
- Date: 2026-08-31
- Amends: ADR-0021 (Decisions 1 and 10) — see the Update blocks there
- Implements: ADORSYS-GIS/lightbridge-authz#591, ADORSYS-GIS/converse-frontends#408 (parent epic
  ADORSYS-GIS/converse-frontends#405)

## Context

ADR-0021 Decision 1 put the hosted login page in this repository as `web/hosted-login/`, a Vite
React project built by a `frontend` stage in `Dockerfile` (`npm ci` + `npm run build`) and, on the
CI path, by a `build-frontend` composite action that staged `dist/static` for `Dockerfile.dist`.

That colocation was never the argument. Decision 1's argument was **same-origin serving** (so the
`__Host-` cookie prefix of Decision 4 is available) and **one authentication boundary in Rust** (so
the "does the unavailable branch become the permissive branch" review question has one codebase to
ask it of). Neither requires this repository to compile TypeScript. What colocation actually bought
was a second toolchain — npm, a lockfile, a Biome config, a Node base image in a Rust repo's
`Dockerfile` — inside a workspace whose `deny.toml`, clippy gates and `AGENTS.md` review discipline
cover none of it. Meanwhile `converse-frontends` already operates a design system
(`@lightbridge/ui-web`), a Turbo pipeline, a Buildah+Trivy+GHCR publishing pipeline and the
reviewers who know it. The page was drifting from the design system it was supposed to match.

## Decision

### 1. The source home is `converse-frontends`' `apps/authz-ui`. This repo builds no JavaScript.

`web/hosted-login/` and `.github/actions/build-frontend/` are deleted. There is no `web/` directory
and no `npm`/`pnpm`/Node in this repository. The page is developed, tested, typechecked, linted and
built where the rest of the estate's frontend is.

### 2. The artifact contract

| | |
| --- | --- |
| Image | `ghcr.io/adorsys-gis/converse-frontends/authz-ui` |
| Base | `scratch` — an assets-only image with no shell, no runtime, no OS packages |
| **Bundle path** | **`/dist`** — `index.html`, `assets/*-<hash>.{js,css}`, `sw.js` |
| Platform | `linux/amd64`, single-arch |
| Produced by | `converse-frontends/.github/workflows/authz-ui-image.yml` (rootless Buildah, `--format docker`, Trivy `HIGH,CRITICAL` `ignore-unfixed` gating the push, plus a pull-back step that proves the bundle is in the pushed image) |

`/dist` is a cross-repo contract. Changing it breaks this repo's container build.

The producing pipeline also carries the two assertions this repo used to make, so neither was lost
in the move: **content-hashed output exists** (without which ADR-0021 Decision 10's
`immutable`/`no-cache` split is wrong) and **the service worker's scope is verified** (the SW-level
twin of `static_fallback_never_shadows_an_existing_protocol_route` — a service worker registered on
the issuer origin controls `/oauth2/*`, `/.well-known/*`, `/authorize` and `/healthz`, not just this
page). `.github/actions/stage-authz-ui` re-asserts the content-hash property here, against the
pulled artifact, because the failure it catches on this side is a different one: not "the build
regressed" but "the pin points at something that is not the bundle we think it is."

### 3. Pin policy: one location, by digest, never automated

The pin is the pre-`FROM` global `ARG AUTHZ_UI_REF=` at the top of `./Dockerfile`. That is the only
place in this repository that records which bundle ships. `Dockerfile.dist` deliberately has no pin
of its own — `.github/actions/stage-authz-ui` `sed`s the value out of `./Dockerfile` — because two
pins drift, and an image built from `Dockerfile.dist` serving a different UI than one built from
`Dockerfile` is the kind of divergence nobody notices until they diff two running containers.

**By digest, never by tag, never `latest`.** A tag is mutable; a digest is the artifact. The
staging action refuses a reference without `@sha256:`. A human-readable `tag:` comment sits directly
above the digest so a diff is readable.

**Dependency automation must not float it.** `.github/dependabot.yml`'s `docker` ecosystem ignores
this image explicitly. An automated digest bump would be an unreviewed UI deploy to the
authentication boundary arriving as a "chore" PR.

### 4. Version skew: the UI ships first and stays backward-compatible; the pin bump is the deploy

The two repositories release independently, so at any moment the published `authz-ui` `latest` may
be ahead of what this repo pins. That is the intended steady state, not a problem to engineer away,
and it imposes one rule: **a UI change must work against the currently pinned backend before it is
published.** The page is pure presentation (Decision 1) and every protocol step is served by Rust,
so this is a low bar — but it is a real one: a UI that starts calling an endpoint this repo has not
shipped yet is a broken login page the moment someone bumps the pin.

Correspondingly, **bumping `AUTHZ_UI_REF` is a deploy**, reviewed as one. It is the only action in
this repository that changes what a real user sees at the authentication boundary without changing
a line of Rust.

Rollback is a one-line revert of the pin to the previous digest, followed by the normal image build
— no coordination with the other repository required, because the old artifact is immutable and
still there.

### 5. The page remains pure UI. All protocol stays in Rust.

Restated because it is the property this ADR could plausibly be read as weakening, and does not.
Nothing in the moved bundle reads or writes a cookie, calls Keycloak, verifies a token, or makes an
authentication decision. `/authorize`, the RP leg, session issuance, the `__Host-` cookie and the
CSP all live in `crates/lightbridge-authz-rest`, unchanged by this ADR. If a future change to
`apps/authz-ui` proposes moving any of that into JavaScript, it contradicts ADR-0021 Decision 1 and
needs its own ADR, in this repository.

## Consequences

### Positive

- One toolchain per repository. No Node base image in a Rust `Dockerfile`; no npm lockfile outside
  the estate's dependency policy; `deny.toml` and clippy again cover everything this repo builds.
- The page inherits `@lightbridge/ui-web` and ADR-0010's primitive stack by construction, instead of
  being a divergent one-off that has to be manually kept in step.
- The artifact is immutable, digest-addressable, Trivy-scanned and independently rollback-able.
- CI here gets faster: the `npm ci` + `vite build` in `Dockerfile`'s `frontend` stage and in three
  composite-action call sites is replaced by pulling one small layer.

### Negative

- **A cross-repo hop is now on the critical path for any UI change.** A one-word copy fix is two
  PRs in two repositories. This is the real cost and it is accepted deliberately: the alternative is
  a second frontend toolchain in the authentication-boundary repo, which is what this ADR exists to
  remove.
- **A remote dependency in the container build.** `just up` and every image build now need to reach
  `ghcr.io`. Offline builds of the `runtime` target are no longer possible without a pre-pulled
  image. Mitigated by the package being public and by the image being a few hundred KB.
- **A stale pin is silent.** Nothing alerts when the published bundle is ahead of the pin; that is
  the point of Decision 4, but it means "the login page looks old" has a new possible cause that
  greps in this repo will never explain. The bump procedure at the ARG is the counter-measure.

### Neutral

- `server.idp.static_dir` and its `/app/static` default are unchanged, so no deployment config in
  the separately-owned `ai-helm-values` repo has to change. The cutover is invisible to the cluster.

## Alternatives considered

- **An npm package (`@lightbridge/authz-ui`) with the bundle in `files`.** Rejected: it would add a
  registry, a publish credential and a package-manager install step to a repo that has just removed
  its only Node toolchain — to deliver static files that a `COPY` handles.
- **A release tarball attached to a GitHub Release, fetched by `curl` in the Dockerfile.** Rejected:
  no immutability guarantee without hand-rolled checksum pinning, no Trivy scan, no registry auth
  story, and a second distribution mechanism to operate beside the GHCR one that already exists.
- **A git submodule / subtree of `apps/authz-ui`.** Rejected: it reintroduces the npm toolchain here
  (the whole cost this ADR removes) and adds submodule handling to every checkout and CI job.
- **Keep `web/hosted-login` and sync it from `apps/authz-ui`.** Rejected outright: two sources of
  truth for the authentication boundary's UI is the failure mode, not the fix.
- **Float the pin on a tag (`:main` or `:latest`).** Rejected: it makes every image build
  non-reproducible and turns an unreviewed merge in another repository into a production change
  here. See Decision 3.

## Follow-ups

1. If the GHCR package is ever made private, this repo's `GITHUB_TOKEN` **cannot** read it —
   repository-scoped tokens do not cross repositories. The fix belongs on the producing side (make
   the package public, or grant this repository read access in the package's Actions-access
   settings), not a PAT here. A PAT has already caused one outage in this estate.
2. Nothing currently notices when the pin falls far behind. A scheduled check that compares the
   pinned digest against the published `latest` and opens an issue (never a PR — Decision 3) would
   close that gap.
