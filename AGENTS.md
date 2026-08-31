# AGENTS.md

This repository provides API key management plus usage analytics:

- `authz-api`: OAuth2/JWT-protected CRUD API for Accounts, Projects, and API keys.
- `authz-budget`: OAuth2/JWT-protected RPC API for the budget domain (policy lifecycle,
  self-service refill, the admin review queue, and direct balance/ledger reads/writes) — carried
  off `authz-api` as a hard cutover (ADR-0010, #351).
- `authz-opa`: Basic-auth protected validation API intended to be called by Authorino (or similar external auth components). It validates API keys and returns rich context plus dynamic metadata, and is also the ownership authority for the usage query API (`POST /idp/v1/authorize-usage-scope`, #570).
- `authz-idp`: OIDC broker server (ADR-0012, ADR-0019, ADR-0023) exposing
  `.well-known/openid-configuration`, `.well-known/jwks.json`, `/oauth2/token`, `/oauth2/revoke`,
  `/oauth2/device_authorization`, `/oauth2/userinfo`, `/oauth2/end_session`, `/authorize`,
  `/device/verify`, `/device/verify/context`, and `/idp/callback` — every route is public, the
  presented token/assertion (or completed Keycloak login) is itself the credential. **`authz-idp`
  renders no HTML on the RP/device leg** (ADR-0029, lightbridge-authz#607): `GET /device/verify`
  is a pure 303 handoff into the SPA's `/ui/device` route (the `verification_uri` RFC 8628 names,
  so the path itself cannot move); `POST /device/verify` and `POST /device/verify/continue` decide
  and 303 onward (`/ui/device/confirm`, `/ui/device/invalid`, `/ui/error`); `GET
  /device/verify/context` is a cookie-bound JSON endpoint (uniform `404`/`503`, never `200` with a
  body the cookie doesn't authorize) feeding the SPA's confirmation page. The pages themselves are
  a React SPA (`apps/authz-ui` in the `converse-frontends` monorepo) served under `/ui` — see the
  `web/`-directory bullet under Top-Level Layout below, and ADR-0029. `/oauth2/end_session` (OIDC
  RP-Initiated Logout 1.0) takes its subject from the `__Host-authz_session` cookie, never from
  `id_token_hint`, and cascades to every session that subject holds plus their refresh chains;
  `/oauth2/userinfo` (OIDC Core §5.3) returns identity claims only and never authorization data.
  It is a full IdP: `oauth2.relying_party` and an enabled `oauth2.token_exchange` are both
  MANDATORY, and every route above is mounted unconditionally — see "The authz-idp surface is
  mandatory" below. `/oauth2/token` also serves a machine plane: RFC 6749 §4.4 `client_credentials`
  (M2M, ADR-0030, #534), `private_key_jwt`-only (a new `OauthClientType::Service` config variant,
  behaviorally identical to `Confidential`), intercepted before upstream dispatch the same way the
  device-code grant is. Discovery advertises `client_credentials` unconditionally, in the same
  always-mounted block as the token-exchange/refresh grants (`signing.rs:838-848`) — never gated on
  whether any `oauth2.clients` entry actually lists it. A `client_credentials` token mints
  `sub = "svc:<client_id>"`, carries no `roles` claim, and therefore holds zero permissions against
  every RPC op-id.
- `lightbridge-mcp`: OAuth2/JWT-protected MCP server exposing the authz surface as MCP tools over streamable HTTP (`/mcp`).
- `lightbridge-authz-usage`: split across two listeners (#347) — an unprotected OTLP/HTTP ingest
  API (`/v1/otel/traces`, `/v1/otel/metrics`, `/v1/otel/logs`) and an mTLS-required query listener
  serving the usage query API (`/usage/v1/usage/query`, which since #570 also requires an end-user
  bearer token plus an ownership check — see "Security Notes" below) and the budget domain's
  service-to-service spend read (`/usage/v1/spend/query`, mTLS-only) — backed by Timescale/Postgres.

The authz services (`authz-api`, `authz-budget`, `authz-opa`, `authz-idp`):

- share the same Postgres database
- share the same SQL migrations
- run with TLS (self-signed certs in local Compose)
- `authz-opa` still exposes OpenAPI/Swagger docs; `authz-api`'s CRUD/RPC surface does not (see
  "OpenAPI docs" under Development Workflows)

The **budget domain** (`crates/lightbridge-authz-budget/`) — a per-account ledger of budget
grants, a hot-swappable rule-data policy engine that decides refill requests, and self-service
refill + an admin review queue — is exposed as `/budget/rpc/*` procedures on `authz-budget`, not
`authz-api` (hard cutover; see `docs/architecture/budget.md`). See `docs/rbac.md`'s budget
sections and `docs/budget-decision-contract.md` for the full picture; this is upstream of, and
today has no effect on, the Envoy/Authorino-side rate limiting
`docs/governance-model-and-enforcement.md` describes.

This file documents structure, architecture, workflows, and practices for contributors and agents working on this codebase.

## Quick Reference - Build/Test Commands

### Essential Commands

**Build & Run:**
```bash
# Build all services with Docker
docker compose -p lightbridge-authz -f compose.yaml build

# Start all services
docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans

# Start specific service
docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans authz-api

# View logs
docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f

# Stop all services
docker compose -p lightbridge-authz -f compose.yaml down

# Destroy everything (including volumes)
docker compose -p lightbridge-authz -f compose.yaml down -v
```

**Linting and Formatting:**
```bash
# Format code
cargo fmt

# Run clippy with automatic fixes
cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

# Check code without building
cargo check --all-targets --all-features

# Run all quality checks (fmt + clippy + check)
just all-checks
```

**If a build exhausts your machine's memory**, cap the job count rather than walking away from it:

```bash
CARGO_BUILD_JOBS=4 cargo check --all-targets
```

`--all-targets` builds all 24 integration-test binaries, and Rust links each one statically against
the full ~577-crate graph. Cargo defaults to one job per core, so the end of a build is many
concurrent link steps, each holding a multi-hundred-MB artifact in memory — enough to OOM a
developer laptop and to starve the CI runner until it drops off GitHub. `[profile.dev] debug =
"line-tables-only"` in the root `Cargo.toml` already cuts the artifact size (keeping backtraces with
line numbers); capping jobs bounds the concurrency on top of it. CI sets both. Add `debug = true`
back locally when you need to step through a debugger. Dropping `--all-features` helps too — it
pulls in the goose load-test tree that nothing but `just load-test` needs.

**Testing:**
```bash
# Run all tests in workspace (requires DATABASE_URL for integration tests)
DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz" cargo test --workspace

# Run tests for a specific crate
cargo test -p lightbridge-authz-rest
cargo test -p lightbridge-authz-api-key --features it-tests
cargo test -p lightbridge-authz-usage-rest

# Run a single test by name
cargo test -p lightbridge-authz-rest test_name

# Run integration tests requiring Docker
docker compose -p lightbridge-authz -f compose.yaml up -d postgresql
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz"
cargo test -p lightbridge-authz-api-key --features it-tests --tests

# Run integration tests with Just
just it-tests

# Run load tests (requires AUTHZ_API_KEY)
AUTHZ_API_KEY=<your-secret> just load-test

# Run Authorino integration tests
just it-authorino
just it-authorino-down
```

**Single Test Execution:**
```bash
# Run a specific test in a specific crate
cargo test -p <crate-name> <test-function-name>

# Example: Run a single test in lightbridge-authz-rest
cargo test -p lightbridge-authz-rest validate_bucket_interval_rejects_unexpected_values

# For tests with specific features
cargo test -p lightbridge-authz-api-key --features it-tests <test-name>
```

## Code Style Guidelines

### What the linter enforces — don't hand-review it

`rustfmt.toml`, `clippy.toml` and `[workspace.lints]` in the root `Cargo.toml` cover the
mechanical layer. Flagging these by hand in review is noise: `todo!`/`unimplemented!`/`dbg!`,
`needless_borrow`, `manual_ok_or`, `clone_on_copy`, `large_enum_variant`, `needless_collect`,
and everything in `clippy::all`. Supply-chain policy lives in `deny.toml`.

Three things to know before editing that config:

- **There is no advisory tier.** CI runs `clippy … -- -D warnings`, so `warn` and `deny` both
  fail the build. Every level set there was measured at zero on this workspace first.
- **Measure before adding a lint, and `cargo clean -p <crate>` before believing the number.**
  A cached clippy run reports clean without having looked — verified here: a warm run reported
  **0** `unwrap_used` against a tree containing 55 of them.
- **A `pedantic` measurement does not cover nursery lints.** `redundant_clone` is nursery; it
  was mis-recorded as zero from a pedantic-only run and actually has 4 hits.

The root `Cargo.toml` records, with counts, which lints are deliberately *not* enabled and why
(`pedantic` at 178, `unwrap_used` at 3, `unsafe_code` at 13-in-tests, …). Read that before
proposing to turn one on.

⚠️ **`imports_granularity`/`group_imports` in `rustfmt.toml` are nightly-only.** This repo's CI
runs the fmt check on **stable**, where rustfmt warns and exits 0 — so those two options are
*not* gated here today; they apply only when a human runs `cargo +nightly fmt`. Treat import
grouping as advisory in this repo until the CI step moves to nightly.

### Spend review attention here instead

What no lint can judge, in order of damage done:

1. **Failure modes — does the unavailable branch become the permissive branch?** This is the
   authentication boundary for every protected service on the platform, so it is the highest-yield
   question in any review here. When a dependency is unreachable the answer is *withhold*, never
   *allow*: `unwrap_or(false)` on an authorization check is how an outage becomes a bypass. A
   missing or unparseable claim is **not** a default — it is "unknown", and unknown routes to the
   strictest branch. Write a test per dependency (Redis down, JWKS unreachable, Keycloak slow)
   asserting the operation is *refused*.
2. **Ownership shape.** Does a function take `T` where `&T` would do, forcing callers to clone?
   Any clone in a per-request path? `Arc::clone` to satisfy a `'static` boundary is a refcount
   bump, not a defect — write `Arc::clone(&x)` so that reads as deliberate.
3. **Error types.** Can a caller distinguish the cases they must handle? Keep variants at *this*
   crate's abstraction level; leaking a dependency's error into a public enum makes every
   dependency bump a breaking change.
4. **Do the tests test anything?** Would they fail if the logic were wrong?
5. **Concurrency.** Anything holding a lock across an `.await` (`clippy::await_holding_lock`)?

State the **mechanism**, not the verdict. "This clones per request" is actionable; "non-idiomatic"
is not.

### Testing rules that have caught real bugs here

- **Prove the test catches the bug.** A test written after the fix, that passes, has shown
  nothing. Break the code, watch it fail *for the predicted reason*, restore it, and say you did.
- **Green does not mean tested.** A test that returns early when an env var is missing reports as
  *passed* — if CI never sets it, the job is green having run nothing. This repo has already been
  bitten by the related failure: shared-database integration tests running in parallel wiping each
  other's rows, papered over by retries. **Investigate flakes; don't raise the retry budget until
  you know what you're riding out** (see `.github/actions/integration-test` — the retry budget
  there is documented against a specific, diagnosed DNS flake, which is the bar).
- **An `#[ignore]`d test is not "known failing" — it's absent coverage.** It doesn't run, so it
  can't fail; CI stays green while that assertion silently stops existing. Say "ignored" in docs
  and comments, not "fails deterministically" — the latter reads as "runs and goes red," which is
  a different, much less dangerous thing. A tracking issue number next to `#[ignore]` is not a
  substitute for actually running the test; go run it (#219 sat on 7 silently-absent tests this
  way).
- Prefer a real containerised Postgres over mocks. The bugs that matter live in the seam.

### Suppressions and declined changes

`#[expect(lint, reason = "…")]`, never `#[allow(…)]` — `expect` fails once the suppression is no
longer needed, so it cleans itself up. ⚠️ Note the corollary: an `#[expect]` for a lint that is
*not* enabled becomes an unfulfilled expectation, which under `-D warnings` fails the build.

When you decline something non-obvious, **write the reason in the manifest, not just the PR body** —
the person hitting the confusion in six months is reading `Cargo.toml`, and a PR description is
unreachable from there. This repo already does this well; keep it up. Two live examples worth
copying: the `jsonwebtoken` 10.x pin (with the upstream tracking issue linked) and the cratestack
family lockstep warning.

### Where the fuller rules live

Two corpora, deliberately kept separate rather than merged into one mush:

- **"Is there a rule for X?"** → the `rust-skills` catalogue (265 single-topic rules, each naming
  the clippy lint that catches it).
- **"Which do I pick, and what does it cost?"** → the `rust-coding` skill's decision procedures —
  borrow/clone/`Cow`, which smart pointer, static vs dynamic dispatch, when type-state earns its
  complexity.

Where they conflict, the house rules above win, because each exists because something broke. Two
concrete divergences: the catalogue's own exemplary test uses **float money** (this repo uses
integer micro-units), and it prints `#[allow]` in four rules and `#[expect]` in none of 265.

### Import Conventions

1. **Group imports in this order:**
   - External crate imports (e.g., `axum`, `serde`)
   - Internal crate imports from other modules (e.g., `lightbridge_authz_core`)
   - Local module imports using `crate::` or `super::`

2. **Use compact imports:**
   - Group multiple imports from the same crate: `use serde::{Deserialize, Serialize};`
   - But keep it readable - don't over-group

3. **Relative vs absolute imports:**
   - Use `use crate::` for imports within the same crate
   - Use `lightbridge_authz_core::` for cross-crate imports
   - Avoid `use super::` unless necessary for parent access

4. **Import style examples:**
```rust
// Standard library
use std::sync::Arc;

// External crates
use axum::{Json, Router, extract::State};
use tracing::{info, debug, warn};

// Cross-crate imports
use lightbridge_authz_core::{Result, Error};

// Within same crate
use crate::models::UsageEvent;
use crate::repo::StoreRepo;
```

### Formatting and Layout

1. **No inline comments:** Never include inline comments in code (per .roo rules)
2. **Dedicated test files:** All new tests must be in `tests/` directory, not in `src/`
3. **File organization:**
   - Keep files focused and not too long
   - Each module should have a clear single responsibility
   - Check if functionality already exists before implementing

### Naming Conventions

1. **Variables/functions:** `snake_case`
2. **Types/structs/traits/enums:** `PascalCase`
3. **Constants:** `SCREAMING_SNAKE_CASE`
4. **Module names:** `snake_case`

### Error Handling

1. **Use the centralized Result type:** Always use `Result<T>` from `lightbridge_authz_core::Result`
2. **Centralized Error enum:** All errors go through `lightbridge_authz_core::Error` enum. Propose new variants if needed
3. **Propagate errors with `?`:** Use the `?` operator for error propagation
4. **Custom error types:** Only when truly necessary, otherwise use the centralized Error enum

### Types and Structures

1. **Prefer references:** Use `&T` instead of owned values where possible to avoid cloning
2. **Owned data:** Only use owned data when ownership is explicitly needed
3. **String optimization:** Consider `Cow<str>` for string data optimization
4. **Iterator chains:** Leverage iterator chains for efficient data processing

### Dependency Management

1. **Workspace-level dependencies:** All dependencies must be declared in root `Cargo.toml` `[workspace.dependencies]`
2. **Crate-level references:** Use `workspace = true` in individual crate `Cargo.toml` files
3. **Research dependencies:** Check https://docs.rs/<package_name>/<package_version> before using
4. **Exposing dependencies:** Better to expose a dependency from a module than importing the same dep in all modules

### Idiomatic Rust

1. **No nightly features:** Stick to stable Rust toolchain only
2. **Unsafe code:** Avoid unless absolutely necessary. When using unsafe, provide detailed comments explaining why it's needed
3. **Test attributes:** Use `#[should_panic]` when appropriate for tests that should fail
4. **Module documentation:** Use `///` for public APIs and `//!` for module-level docs

## Top-Level Layout

- `app/`
  - `app/lightbridge-authz/`: package that produces the authz server, MCP server, and TCP healthcheck binaries; the authz binary can run API server, OPA server, both, and migrations.
  - `app/lightbridge-authz-usage/`: usage binary that can run usage server, usage migrations, and config validation.
- `crates/`
  - `crates/lightbridge-authz-core/`: shared types, config, errors, crypto, DB pool.
  - `crates/lightbridge-authz-api/`: CRUD API routing/controllers + OpenAPI.
  - `crates/lightbridge-authz-api-key/`: DB entities + hand-written repository implementation
    (SQLx) — the pre-cratestack layer, retained as an ADR-0038 exception, not new-code guidance
    (see "Persistence" below).
  - `crates/lightbridge-authz-rest/`: Axum server glue (TLS bind, modular layout with handlers, routers, models, and middleware).
  - `crates/lightbridge-authz-bearer/`: JWT validation via JWKS (Keycloak in local compose).
  - `crates/lightbridge-authz-budget/`: budget domain — ledger (`BudgetRepo`), spend readers, the
    `PolicyEngine`/`Facts`/`Decision` contract and its rule-data implementation, `PolicyStore`
    (DB-backed, hot-swappable), and the self-service refill/review orchestration
    (`RefillService`/`ReviewService`). Deliberately hand-written procedures, not cratestack models
    — see ADR-0010.
  - `crates/lightbridge-authz-usage/`: Axum usage server (OTEL ingest handlers, usage query models/routers, TLS bind, OpenAPI).
  - `crates/lightbridge-authz-proto/`: proto-related exports (currently minimal).
- `migrations/`: SQLx migrations.
- `migrations-usage/`: SQLx migrations for usage events storage (Timescale-compatible schema).
- There is **no `web/` directory and no JavaScript in this repository.** `authz-idp` renders no
  HTML on the RP/device leg (see the `authz-idp` bullet above) — its pages are a React SPA built in
  `converse-frontends` as `apps/authz-ui`, on the estate's `ui-web` design system, and consumed here
  as a digest-pinned, assets-only OCI image (`ghcr.io/adorsys-gis/converse-frontends/authz-ui`,
  bundle at `/dist` including `dist/routes.json`, the `/ui` route allowlist `static_assets.rs`
  reads at startup). See ADR-0029.
- `config/`: local default config (non-container paths).
- `.docker/`: docker assets (service config, Keycloak realm import, Envoy example, IT scripts).
- `compose.yaml`: local dev stack (Postgres, Keycloak, API/OPA, migrations, TLS generator).
- `compose.it.yaml`: integration-test overlay (adds `it-authorino`, `it-servers`, `it-idp`, and
  `it-machine-keygen` — the last a one-shot fixture generator, not a test runner itself).
- `docs/`: human docs (manual protocol, Authorino usage).
- `.github/actions/`: composite helpers that encapsulate Rust setup, cargo tooling, docker build/publish, and Helm publishing so workflows stay short.
- `.github/workflows/`: main CI/CD pipeline (`ci.yml`) plus the Helm charts publish workflow (`helm-oci.yml`), both kept lean by calling the shared actions.

## Runtime Services (Compose)

Primary local stack is in `compose.yaml`:

- `authz-tls`: generates self-signed certs into `authz_tls` volume.
- `postgresql`: Postgres backing store.
- `timescaledb`: usage events backing store.
- `redis`: rate limiting + replay protection for `authz-api`/`authz-idp`/`authz-budget`.
- `keycloak`: OAuth2 provider (imports `dev` realm from `.docker/keycloak_config/realm.json`).
- `authz-migrate`: runs authz migrations once at startup.
- `authz-usage-migrate`: runs usage-store migrations once at startup.
- `authz-api`: runs the CRUD API.
- `authz-opa`: runs validation endpoints for OPA/Authorino.
- `authz-idp`: runs the OIDC broker (discovery, JWKS, token exchange, device grant).
- `authz-budget`: runs the budget-domain RPC surface.
- `authz-mcp`: runs the MCP streamable HTTP endpoint.
- `mcp-inspector`: optional MCP Inspector UI/proxy container for MCP debugging.
- `authz-usage`: runs OTEL ingest + usage query endpoints.
- `jaeger`: OTLP trace collector/UI.
- `adminer`: optional DB UI.

## Architecture Overview

### Data Model

Tables (see `migrations/`):

- `accounts`: **`id` is the caller's JWT `sub` for an identity's FIRST (anchor) account, and a
  minted CUID2 for every account after that** (ADR-0006; amended by ADR-0024, then by ADR-0026 —
  see `users` below). Since ADR-0026 one identity may own several accounts; the anchor keeps the
  subject as its id because `federated_identities` adopts by matching `accounts.id == subject`.
  Carries `default_quota` (the governance tier for work in the account's own default project) and
  `user_id` (`NOT NULL`, `BEFORE INSERT`-trigger-provisioned when not supplied — see `users`).
  **`accounts.user_id` is always the owner's anchor-account id**, i.e. always `auth().id`; the
  ownership `@@allow` clauses depend on this and it is pinned by
  `accounts_user_id_is_always_a_home_account_id`. Two id populations coexist permanently — never
  branch on an id's shape (see "Identifier Format").
- `users` (ADR-0024; corrected 2026-08-25): the actual defining identity — "one account = one
  federated identity; a person may hold several." Reached only THROUGH an account:
  `federated_identities.account_id -> accounts.user_id -> users.id`. `id` is always the
  backfilled/trigger-provisioned account's own id verbatim (an id-reuse, not a new mint — ADR-0039
  bans minting, not storing) — the fresh-`cuid2()`-for-a-brand-new-person case no longer arises,
  since a federated identity can no longer exist without an adopted account.
- `federated_identities` (ADR-0024, corrected 2026-08-25; deliberately absent from `authz.cstack`
  — see "Persistence" below): keyed by `(issuer, subject)`, the login federation key. Carries the
  sealed Keycloak token set (`token_envelope`, AES-256-GCM, `lightbridge_authz_core::crypto`) —
  refresh token plus a non-access-token ID-token claims snapshot, never the access token.
  `account_id` is `NOT NULL` (no `user_id` column — the user is always derived) and adopted by AT
  MOST ONE federated identity ever (a partial unique index enforces this): a subject with no
  pre-existing `accounts` row is refused (`Error::Forbidden`, no mint-a-user branch), and a second
  issuer presenting a subject that already adopted an account is refused (`Error::Conflict`), never
  silently merged. `ON DELETE CASCADE` on `account_id`: deleting an account removes its adopted
  federated identity too (the person's `users` row itself is unaffected — it survives via any
  other account, or with none).
- `projects` (belongs to `accounts`): includes `billing_identity` (unique — "who is paying" moved
  here from `accounts`, so one person can bill projects to different parties), `project_quota` (the
  pooled ceiling), `is_default` (the auto-provisioned, roster-less project; server-computed by a
  `BEFORE INSERT` trigger, undeletable), `allowed_models` (list of permitted models — `NULL` or
  `[]` (empty list) are interpreted as "all models allowed" when `model_policy = allow_all`, and
  mean "nothing" when `model_policy = allowlist`; ignored entirely under `deny_all`), and
  `model_policy` (ADR-0018): `allow_all` (default — the sole pre-existing behavior, and what every
  row backfills to on migration), `allowlist` (only `allowed_models` entries), or `deny_all`
  (nothing). Not yet settable through the RPC surface (`@readonly` in `authz.cstack` — see that
  field's own comment for why); returned by introspection and stamped as an access-token claim
  (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs`) alongside `allowed_models`.
- `project_members` (`{project_id, account_id, role: lead|member, quota_tier}`): the project roster.
  Default projects have none by construction. Replaces `account_memberships`, which was dropped
  entirely — there is no account-level membership of any kind.
- `api_keys` (belongs to `projects`).

API keys are stored as:

- `key_hash`: SHA-256 hex digest of the secret (never store plaintext).
- `key_prefix`: derived from the secret for identification/useful listing.
- `status`: `active` or `revoked`.
- `expires_at`: optional expiration.
- usage telemetry: `last_used_at`, `last_ip`.
- `owner_account_id`: the member the key belongs to, set from the acting subject on create/rotate.
  Distinct from the project's owning account -- a lead who is not the owner may mint keys. This is
  what lets introspection resolve the owner's `project_members.quota_tier`, which Authorino stamps
  as `x-quota-tier` and ai-helm's per-member rate-limit rules match on. A key owned by the project's
  account normally has no roster row, so its tier is `NULL` -- meaning no per-member ceiling, only
  the pooled `projects.project_quota`.

**Budget domain** (see `crates/lightbridge-authz-budget/`, `docs/rbac.md`,
`docs/budget-decision-contract.md`):

- `budget_grants`: append-only ledger of every grant/correction, enforced by a DB trigger — never
  updated or deleted, only inserted (ADR-0009). The source of truth; balances are a replayable
  projection over it.
- `budget_balances`: the current-balance projection per `(budget_account_id, period)`, maintained
  transactionally alongside each grant write, and rebuildable from `budget_grants` alone.
- `budget_policy_sets` / `budget_policy_revisions`: versioned rule-data policy documents. Exactly
  one revision per set is active at a time; activation validates before writing, so a bad revision
  never displaces a good one (`PolicyStore`).
- `budget_augmentation_requests`: one row per self-service refill request, from creation through
  auto-approval or admin approve/reject — the audit trail for "who asked, what decided, who
  reviewed."

### Identifier Format (CUID2)

Every id this service mints — `projects.id`, `api_keys.id`, budget grant/ledger/policy-revision
ids, token-exchange session ids, signing `kid`, `jti` — is a CUID2 (24 chars, lowercase `a-z0-9`,
starts with a letter), minted through the one chokepoint, `lightbridge_authz_core::cuid::cuid2()`
(re-exported from the `cuid` crate). Never write a new UUID-generating call site (`Uuid::new_v4`,
`gen_random_uuid()`, …) or a second import path into `cuid2()`. Source: ADR 0039,
https://github.com/ADORSYS-GIS/webank-context/blob/master/decisions/0039-cuid2-is-the-house-id-format.md.

This bans *minting*, not *storing*. `accounts.id` is the caller's JWT `sub` (above) — an id this
service does not mint, sourced from Keycloak/whatever IdP is configured — and it stays exactly as
issued. The same goes for any OIDC claim: JWT `jti`, `sub`, `aud`, `iss` from an external IdP are
read, never rewritten, never regenerated into our own format.

- **Never validate an id's shape** — no regex, no parse, no length check, no `starts_with('c')`/
  hyphen branching. Ids are opaque strings. This is a correctness requirement here, not style: this
  repo already shipped and fixed exactly this failure mode once — cratestack's `Cuid` schema scalar
  rejected any id not starting with `'c'` (regression test:
  `crates/lightbridge-authz-rest/tests/rpc_it_tests.rs:712`). The same mistake applied to `sub`
  would break federation with any IdP that doesn't happen to issue UUID- or CUID2-shaped subjects.
- **Never sort or paginate by id** — CUID2 has no ordering. Use `created_at`.
- **Store as `TEXT`**; no native `uuid` columns, no `DEFAULT gen_random_uuid()`.

### Service Responsibilities

- CRUD API (`authz-api`)
  - Provides create/read/update/delete lifecycle for accounts/projects/api keys.
  - Protected by OAuth2/JWT bearer token middleware.
  - Used by internal services/operators to provision keys.
  - Also hosts the budget domain's RPC procedures on the same surface: policy administration
    (`activateBudgetPolicy`, `getBudgetPolicyStatus`, `simulateBudgetPolicy`), self-service refill
    (`requestBudgetRefill`), and the admin review queue (`listPendingAugmentationRequests`,
    `approveAugmentationRequest`, `rejectAugmentationRequest`). Gated by `budget:*` permissions —
    see `docs/rbac.md`.

- Validation API (`authz-opa`)
  - Validates presented API key secrets by hashing and matching against `key_hash`.
  - Rejects revoked/expired keys.
  - Records usage telemetry (last used timestamp).
  - Returns key/project/account context via RFC 7662 introspection.
  - Is also the ownership authority for the usage query API — see "Identity context resolution" below.

- MCP API (`lightbridge-mcp`)
  - Exposes authz CRUD and validation operations as MCP tools under `/mcp`.
  - Secured with the same JWT bearer/JWKS middleware used by `authz-api`.
  - Derives subject identity from JWT claims (tool input does not include subject).

### Validation Endpoints

On the OPA server:

- `POST /v1/authorino/validate/introspect`
  - RFC 7662 token introspection, form-encoded (`token`/`token_type_hint`), Basic-auth protected.
  - The only key-validation route `authz-opa` exposes. Two earlier endpoints — `POST
    /v1/opa/validate` and a JSON-bodied `POST /v1/authorino/validate` that accepted an arbitrary
    `metadata` object and echoed it back inside a `dynamic_metadata` response — were removed with
    no direct HTTP successor; this is asserted by
    `introspect_endpoint_should_exist_in_opa_openapi` (`crates/lightbridge-authz-rest/src/lib.rs:1788-1807`).
    The same metadata-enrichment shape still exists as the `validate-authorino-api-key` MCP tool
    on `lightbridge-mcp` (bearer-JWT + RBAC gated), but that is not reachable by Authorino's
    `AuthConfig`, which needs a plain HTTP call — see `docs/authorino-usage.md`.
  - Returns `{ active, account_id, project_id, api_key_id, api_key_status, ... }` on success,
    `{ active: false }` (still `200`) for a deleted/revoked/expired/unknown key.

Implemented in `crates/lightbridge-authz-rest/src/handlers/introspect.rs` (shared validation
lookup lives in `crates/lightbridge-authz-rest/src/handlers/opa.rs`).

### Identity context resolution (`subject` + `project` → context)

Backs the `lightbridge-keycloak-spi` IdP adapter, which seals `account_id`/`project_id` into JWTs at token-exchange time. The adapter reads the authenticated `subject` and a `project_id` form param on the exchange, resolves the context, and a dumb protocol mapper copies it into claims. Stateless — no store.

- Resolve — `POST /idp/v1/resolve-context` on the OPA/validation server, **Basic-auth protected** (the adapter presents the OPA credentials; the endpoint returns tenant context so it must not be publicly reachable). Body `{subject, project_id}` → `{account_id, project_id}`. Since ADR-0006 a project resolves when the subject owns its account (`projects.account_id = $2`, the account id being the subject itself) **or** holds a `project_members` row for it; a non-member or unknown project is a uniform `404` — deliberately indistinguishable, so the endpoint never leaks which projects exist. Handler: `crates/lightbridge-authz-rest/src/handlers/idp.rs`; repo method `resolve_context` in `crates/lightbridge-authz-api-key/src/repo.rs`.
- Authorize usage scope — `POST /idp/v1/authorize-usage-scope` on the OPA/validation server, **Basic-auth protected**, added by #570 as the ownership authority `lightbridge-authz-usage`'s query listener calls for `account`/`project` usage-query scopes (D14 of ADR-0028: no service reads another service's tables, so the usage side never grows an authz-DB pool). Body `{issuer, subject, scope, scope_id}` → `200` on ownership, uniform `404` on any miss (unknown `scope_id`, non-member `subject`) — the same non-oracle convention `resolve-context` uses. Handler: `crates/lightbridge-authz-rest/src/handlers/idp.rs`'s `authorize_usage_scope`; repo method `StoreRepo::authorize_usage_scope` in `crates/lightbridge-authz-api-key/src/repo.rs`. Tests: `crates/lightbridge-authz-rest/tests/opa_tests.rs`, `crates/lightbridge-authz-api-key/tests/authorize_usage_scope_tests.rs`.

This exchange (the legacy `lightbridge-keycloak-spi` + protocol-mapper path above) seals only `account_id`/`project_id` into the JWT — never `role`/`quota_tier`/`project_quota`. The consequence is that switching project means requesting a new token, not sending a different header on this path.

**A separate, native RFC 8693 token-exchange path now also seals `budget_tier` and `quota_tier` into the human-plane access token — do not conflate the two mechanisms.** `TokenExchangeOpStore` (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs`, ADR-0011) is the actual token-issuing authority for `authz-idp`'s `POST /oauth2/token`; it calls `resolve_context` itself (in-process, not via the `/idp/v1/resolve-context` HTTP endpoint above) and additionally stamps `budget_tier` (ADR-0014, resolved live from the budget ledger, fail-closed to the policy-configured floor on any lookup error — never omitted) and `quota_tier` (ADR-0017, resolved live from `project_members`, omitted when legitimately absent — an owning account with no roster row, or a member row with a NULL tier — but the whole exchange/refresh is REFUSED, not defaulted, when the lookup itself fails, since there is no safe floor for an unordered tier catalogue the way there is for the budget ladder).

`role`/`project_quota` remain deliberately off both JWT paths and ride the Authorino introspection response only (`docs/governance-model-and-enforcement.md`, "Why introspection and not claims"): a roster or quota change would otherwise only take effect at the human plane's next token refresh, whereas introspection is cached just 30s per key, so a lead's role edit or an owner's `project_quota` bump propagates within that window instead of a token lifetime. `quota_tier` is the one exception to "introspection only" on the human plane, per ADR-0017 — see that ADR for why the general principle otherwise still stands.

## Rust Workspace and Crates

Workspace manifest: `Cargo.toml`

- Crate boundaries follow a layered approach:
  - `core` holds shared domain types and infra primitives.
  - `api-key` holds SQLx entities and the repository.
  - `api` defines the CRUD surface: routers + controllers + OpenAPI.
  - `rest` wires everything into real Axum servers with middleware and TLS.
  - `bearer` validates JWT bearer tokens via JWKS.
  - `budget` is a sibling to `api-key`, not a layer beneath `api`/`rest`: it owns its own
    persistence (`BudgetRepo`, `AugmentationRepo`) and is called directly by hand-written
    `Procedures` methods in `rest`, deliberately bypassing the cratestack model-generation path
    the CRUD surface uses (ADR-0010).

### Key Code Paths

- Binary entrypoints:
  - `app/lightbridge-authz/src/main.rs`
  - `app/lightbridge-authz/src/bin/lightbridge-mcp.rs`
  - `app/lightbridge-authz/src/bin/lightbridge-authz-healthcheck.rs`
  - `app/lightbridge-authz-usage/src/main.rs`

- CRUD API:
  - routing/controllers are generated via cratestack (`cratestack-pg`) from a schema definition in `crates/lightbridge-authz-api`, replacing the previous hand-written `routers.rs`/`controllers/*`; there is no longer a hand-authored OpenAPI module (`openapi.rs` was removed — see "OpenAPI docs" under Development Workflows and `docs/adr/0003-cratestack-crud-migration.md`).

- Budget domain RPC procedures:
  - schema (types + `procedure`/`mutation procedure` declarations): `crates/lightbridge-authz-api/schema/authz.cstack`
  - hand-written procedure bodies (not cratestack-generated — ADR-0010): `Procedures` impl in `crates/lightbridge-authz-rest/src/lib.rs`
  - domain logic: `crates/lightbridge-authz-budget/src/{repo,refill,review,rule_data,policy_store,facts,decision,spend}.rs`
  - permission gating: `crates/lightbridge-authz-rest/src/rpc_authorize.rs`

- OPA/Authorino endpoints:
  - handlers: `crates/lightbridge-authz-rest/src/handlers/*`
  - routers: `crates/lightbridge-authz-rest/src/routers/*`
  - models: `crates/lightbridge-authz-rest/src/models/*`
  - middleware: `crates/lightbridge-authz-rest/src/middleware/*`

- Repository:
  - `crates/lightbridge-authz-api-key/src/repo.rs`
  - `crates/lightbridge-authz-usage/src/repo.rs`
  - `crates/lightbridge-authz-budget/src/repo.rs` (`BudgetRepo`), `crates/lightbridge-authz-budget/src/augmentation.rs` (`AugmentationRepo`)

- MCP endpoints/tools:
  - server + tool handlers: `app/lightbridge-authz/src/mcp.rs`

## Configuration

Runtime config is YAML loaded via `lightbridge-authz-core`:

- `lightbridge_authz_core::config::load_from_path`

In containers, config is mounted at:

- `.docker/authz/container.yaml` -> `/tmp/config.yaml`
- `CONFIG_PATH=/tmp/config.yaml`

Local non-container config example:

- `config/default.yaml`
- `config/usage.yaml`

Key config fields:

- `server.api`: address/port/tls paths — carries no codec key; see below.
- `server.opa`: address/port/tls paths + basic auth credentials
- `server.usage`: address/port/tls paths for `lightbridge-authz-usage`'s unauthenticated ingest
  listener.
- `server.query` (`lightbridge-authz-usage` only, mandatory, non-`Option`): address/port/tls paths
  for the mTLS-required query listener (`/usage/v1/usage/query` + `/usage/v1/spend/query`, #347),
  plus `tls.client_ca_bundle_path` — what actually turns mTLS on. Source: `config.rs:7-52` in
  `crates/lightbridge-authz-usage`.
- `oauth2` (`lightbridge-authz-usage` only, mandatory, non-`Option`): validates the end-user bearer
  token `/usage/v1/usage/query` now requires (#570) — reuses the shared `Oauth2` type but only ever
  reads `jwks_url`.
- `scope_authority` (`lightbridge-authz-usage` only, mandatory, non-`Option`): HTTP client config
  (`base_url`/`username`/`password` required; `insecure_skip_verify`/`ca_bundle_path`/
  `client_cert_path`/`client_key_path`/`timeout_ms` defaulted) for calling `authz-opa`'s
  `POST /idp/v1/authorize-usage-scope` — the ownership authority `/usage/v1/usage/query` calls for
  `account`/`project` scopes (#570).
- `database.url`: Postgres connection string
- `oauth2.jwks_url`: JWKS endpoint (Keycloak in local compose)
- `redis.url`: mandatory for `authz-api`, `authz-idp`, `authz-budget` — see below.
- `oauth2.relying_party`, `oauth2.token_exchange` (with `enabled: true` and `openid` in
  `allowed_scopes`): both mandatory for `authz-idp` (ADR-0023) — see "The authz-idp surface is
  mandatory" below.
- `oauth2.relying_party.token_encryption_key` (ADR-0024): mandatory, base64url-encoded 32 bytes,
  MUST differ from `oauth2.relying_party.state_encryption_key` — `KeycloakRelyingParty::new`
  refuses to start otherwise. Seals the Keycloak token set at rest; rotating it makes every
  previously-sealed row permanently unopenable (treated as "no stored token", never deleted).
- `oauth2.federation.issuer` (ADR-0025) is the ONE issuer field — the `iss` claim value, what the
  browser is sent to, what tokens validate against. `oauth2.relying_party.issuer` was REMOVED (it
  used to have to be kept byte-equal to this by hand). `oauth2.federation.discovery_url` (optional,
  defaults to `issuer`) is a separate LOCATION override for where `authz-idp` dials OIDC discovery
  from inside this deployment's own network — see `docs/auth-reference.md`'s "Identity vs.
  location" section and ADR-0025's amendment for the full story, and
  `.docker/authz/container.yaml` for the local-Compose example where the two diverge.

### CBOR is the only transport codec for the RPC/CRUD surface (ADR-0013)

`authz-api`'s CRUD/RPC surface and `authz-budget`'s RPC surface (both `cratestack::schema::axum::rpc_router`
instances, `crates/lightbridge-authz-rest/src/lib.rs`) accept **only** `application/cbor`, via
`LenientCborCodec` (`codec.rs` — normalizes wire-level `undefined` to `null`, see its doc comment).
There is no `server.api.codec`/environment-driven codec config — never was, despite an ADR-0003
section once describing one; it is a code-level decision, not a config value, so there is nothing to
set in `config/default.yaml`, `.docker/authz/container.yaml`, or `ai-helm-values`. Sending
`application/json` gets `415 Unsupported Media Type`.

Excluded, each for a different external reason (ADR-0013 Decision 3 has the full evidence): OPA/
Authorino endpoints (Authorino dictates the format), the usage service's OTLP ingest (spec'd
protocol), `lightbridge-mcp` (MCP streamable HTTP is spec'd JSON-RPC, a different SDK entirely), and
discovery/JWKS/`/oauth2/token`/`/oauth2/revoke` on both `authz-api` and `authz-idp` (RFC-mandated
JSON, plain `axum::Json` handlers that never touched cratestack's codec to begin with).

### Redis is a mandatory dependency for authz-api / authz-idp / authz-budget

**House rule, from the repo owner:** *"Redis MUST be a default in this system from now on. No
possibility to disable it for the lightbridge-authz components. `-mcp` and `-opa` can be freed from
it. All roles in lightbridge-authz need caching. If caching is required somewhere, we'll enforce
Redis."* Concretely:

- `authz-api`, `authz-idp`, and `authz-budget` **refuse to start** when `redis.url` is absent —
  loudly, at startup, never a silent degradation. This applies to `authz-idp` unconditionally, not
  only when `oauth2.token_exchange` happens to be enabled — do not reintroduce that conditional.
- `authz-opa` and `lightbridge-mcp` are explicitly and permanently freed from this requirement:
  neither takes a `redis` parameter in its `start_*` function at all. Do not add one "for
  consistency" — that is the whole point of freeing them.
- **There is no neutralisation escape hatch.** A deployment that used to "disable" Redis via a
  bogus `REDIS_URL` value (e.g. `"unused"`) for `authz-idp`/`authz-opa` config sharing must instead
  supply a real, reachable-in-principle Redis for every required component — an absent or
  malformed `redis.url` is a hard startup failure for `authz-api`/`authz-idp`/`authz-budget`, by
  design.
- **Enforcement is presence-only, not a startup-time reachability check (no `PING`).** The
  `redis::Client`/`RedisRateLimitStore`/`RedisClientAssertionStore` constructors this codebase uses
  are all lazy — they never dial out until the first real command — so "redis config is required"
  only means "the config key must be set and well-formed," not "a live Redis must already be
  reachable at process startup." This was a deliberate choice: presence-only avoids a hard
  startup-ordering dependency on Redis already being up (simpler, and consistent with how
  `authz-api`/`authz-budget` already behaved before this rule existed); it trades away catching a
  genuinely-unreachable-but-well-formed URL until the first request hits it. If that trade-off ever
  needs revisiting, do it explicitly (a real `PING` in the startup path) rather than accidentally
  via a different constructor.
- `Config.redis` stays `Option<Redis>` at the type level (not `Redis`) because `authz-opa`,
  `lightbridge-mcp`, and the usage service all load the same `Config` type and must keep starting
  with `redis` entirely absent from their YAML. Enforcement lives per-component inside
  `start_api_server`/`start_idp_server`/`start_budget_server`
  (`crates/lightbridge-authz-rest/src/lib.rs`), not on the shared config struct.

### The authz-idp surface is mandatory — every route, every deployment (ADR-0023)

**House rule, from the repo owner:** *"Let's not make something from the IdP optional anymore.
It's a full IDP now."* The same shape as the Redis rule above, applied to `authz-idp`'s two other
dependencies:

- `oauth2.relying_party` and `oauth2.token_exchange` **refuse to start** `authz-idp` when either is
  absent, or when `token_exchange.enabled` is `false`, or when `token_exchange.allowed_scopes`
  omits `openid` — loudly, at startup, never a silent degradation. `Config.oauth2.relying_party`/
  `Config.oauth2.token_exchange` stay `Option` at the type level (`authz-api`/`authz-opa`/
  `authz-budget`/`lightbridge-mcp` load the same `Oauth2` type and never set either), but
  enforcement is unconditional inside `start_idp_server`
  (`crates/lightbridge-authz-rest/src/lib.rs`), not a config-driven mount decision.
- **There is no neutralisation escape hatch and no mount-conditional gate.** `build_idp_router`
  takes `relying_party`/`token_exchange` as owned, non-`Option` parameters — `/authorize`,
  `/device/verify`, `/idp/callback`, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/userinfo`,
  `/oauth2/end_session`, and
  `/oauth2/device_authorization` are all mounted unconditionally, and discovery
  (`DiscoveryCapabilities::full_idp()`) always advertises all of them.
- **Enforcement for `relying_party` is presence PLUS the existing offline validation** — unlike the
  Redis rule's presence-only posture. `KeycloakRelyingParty::new` is fully synchronous and offline
  (validates shape: timeout, TTL, base64url 32-byte state key, exact callback URL/path — never
  dials Keycloak), so validating it at startup costs no ordering dependency on a live third party.
  This deliberately does **not** fetch Keycloak discovery at startup — that would be the same
  mistake the Redis rule's "presence-only, not a `PING`" reasoning warns against, aimed at an
  external IdP instead of an in-cluster Redis.
- **Do not reintroduce PR #473's mount-conditional gate.** #473 (`468084a`) made `relying_party`
  optional again after #463 (`9e0ef4d`) made it (wrongly, unconditionally) required — but #473's fix
  left a live defect: discovery advertised `device_code` (gated only on `token_exchange`) while
  `/device/verify` 404'd, because the RP-leg silently wasn't mounted. "Optional" and "half-broken"
  were the same state for that field. ADR-0023 closes this for good; see that ADR for the full
  chain and the regression test
  (`build_idp_router_mounts_authorize_device_verify_and_callback_unconditionally`,
  `crates/lightbridge-authz-rest/tests/idp_server_tests.rs`) that would have caught it.

### Environment Variable Interpolation

The configuration loader supports these placeholders in YAML files:

- `$VAR`
- `${VAR}`
- `${VAR-default}` (default used only when `VAR` is unset)
- `${VAR:-default}` (default used when `VAR` is unset or empty)

Behavior notes:

- Unset variables for `$VAR`/`${VAR}` resolve to empty strings.
- `${VAR:default}` is not supported and remains literal text.
- Core interpolation behavior is verified by unit tests in `lightbridge-authz-core`.

## Development Workflows

### Docker Compose (Recommended)

Start everything:

- `just up`

Check health:

- `curl -k https://localhost:13000/healthz`
- `curl -k https://localhost:13001/healthz`
- `curl -k https://localhost:13002/healthz`
- `curl -k https://localhost:13003/healthz`
- `curl -k https://localhost:13003/healthz/ready`
- `curl -k https://localhost:13003/healthz/startup`
- `curl -k https://localhost:13004/healthz` (`authz-idp`)
- `curl -k https://localhost:13005/healthz` (`authz-budget`)

OpenAPI docs:

- CRUD API: removed. Swagger UI/OpenAPI generation for the CRUD API was dropped as part of the cratestack migration (see `docs/adr/0003-cratestack-crud-migration.md`); the generated cratestack Rust client is now the primary integration contract.
- OPA/Authorino: `https://localhost:13001/v1/opa/docs`
- Usage API: `https://localhost:13002/usage/v1/usage/docs`

MCP debugging:

- Inspector UI: `http://localhost:6274`

Stop/cleanup:

- `just down` (keeps volumes)
- `just destroy` (removes volumes)

### Running Locally (Without Compose)

You can run binaries directly (requires valid TLS cert/key files at configured paths and a reachable Postgres):

- `cargo run -p lightbridge-authz -- serve --config-path config/default.yaml`
- `cargo run -p lightbridge-authz -- api --config-path config/default.yaml`
- `cargo run -p lightbridge-authz -- opa --config-path config/default.yaml`
- `cargo run -p lightbridge-authz -- migrate --config-path config/default.yaml`
- `cargo run -p lightbridge-authz --bin lightbridge-mcp -- serve --config-path config/default.yaml`
- `cargo run -p lightbridge-authz-usage -- serve --config-path config/usage.yaml`
- `cargo run -p lightbridge-authz-usage -- migrate --config-path config/usage.yaml`

Note: `config/default.yaml` references `./config/tls/*` which may not exist by default.

## Testing

### Workspace Tests

Run all tests in the workspace:

```bash
DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz" cargo test --workspace
```

### Unit/Contract Tests (Rust)

The REST crate contains behavior tests for validation flows and OpenAPI contract checks:

- `cargo test -p lightbridge-authz-rest`
- `cargo test -p lightbridge-authz --lib`
- `cargo test -p lightbridge-authz-usage-rest`

These tests include:

- API key validation success/failure cases (missing/revoked/expired).
- Authorino endpoint dynamic metadata passthrough + enrichment.
- Health probe behavior (`/healthz`, `/healthz/startup`, `/healthz/ready`) including DB-unavailable readiness failures.
- OpenAPI checks ensuring the Authorino endpoint/schemas are published.
- OTLP trace/metrics ingestion extraction and usage query handler validation.

### Persistence tests (it-tests)

The Postgres-backed `lightbridge-authz-api-key` tests (rotate/limits), `lightbridge-authz-budget` tests (ledger writes, replay, policy store, refill/review services), and `lightbridge-authz-usage-rest` tests (`repo_it_tests`, `spend_query_it_tests`, `scope_ownership_it_tests`) are guarded by the `it-tests` feature so they only compile/run when requested. This keeps the default `cargo test` free of database setup, and lets us treat these as Docker-backed integration tests.

Run them with `just it-tests`, which brings up the `postgresql`/`redis` services, waits a moment, then sets `DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz"` before invoking `lightbridge-authz-api-key`, `lightbridge-authz-budget`, `lightbridge-authz-rest`, and `lightbridge-authz-usage-rest` with `--features it-tests`. These tests exercise the migrations under `sqlx::test` — `lightbridge-authz-usage-rest`'s own migrations under `migrations-usage/` are deliberately written to run against this same plain Postgres, not a dedicated TimescaleDB (production runs plain Postgres today; Timescale-shaped CI is deferred to a later phase of #581, gated on that epic's storage-image decision).

### Load Tests

Load tests use the [Goose](https://goose.rs/) framework and run against the OPA endpoint.

```bash
AUTHZ_API_KEY=<your-secret> just load-test
```

These load tests live behind the `load-tests` feature of the `lightbridge-authz-rest` crate, so they are only built/executed when `just load-test` runs (it passes `--features load-tests --test load_tests`). This keeps them out of the regular `cargo test` runs.

`just load-test` now also brings up the TLS generator, Postgres, migrations, and OPA services via `docker compose`, sleeps a few seconds for them to settle, and traps `docker compose ... down` so the stack is brought down once the load test completes (even on failure). That makes the load-test command self-contained in CI/CD and local usage alike.

Findings:
- The system handles ~600-1000 requests per second on a standard development machine with minimal latency (~10-20ms).
- Telemetry (last used timestamp and IP) is correctly updated in the database during load.

### Integration Test (Docker Compose)

Run the full end-to-end test (Keycloak -> CRUD -> Authorino validate):

- `just it-authorino`
- `just it-servers` (JWT+authn coverage for API/MCP, basic-auth coverage for OPA, unprotected usage checks, and probe checks for all servers)

Cleanup:

- `just it-authorino-down`
- `just it-servers-down`

Implementation details:

- test runner: `.docker/it/authorino_it.py`
- overlay: `compose.it.yaml`

## Work Methodology

- Always confirm that the feature or fix you are working on is covered by automated tests. If existing tests do not exercise the new behavior, add targeted tests in the most appropriate crate (unit, integration, or contract) before finishing the change.
- When you add or update behavior, document the need for those tests in your summary so reviewers can spot the linkage quickly.
- Workflow changes should keep the top-level YAML files concise (both `/ .github/workflows/ci.yml` and `/ .github/workflows/helm-oci.yml` stay under ~100 lines) by moving reusable sequences into `.github/actions/` composites (Rust setup, tests, docker build/push, Helm publishing). Confirm the helper action logic lives in the shared directory, and if you edit those helpers, mention why you need the customization and keep their scope focused.
- CI runs on the self-hosted `adorsys-gis-runner`. Container image builds are amd64-only and use **buildah** (rootless: `STORAGE_DRIVER=vfs`, `BUILDAH_ISOLATION=chroot`); avoid reintroducing QEMU-based cross-builds or a per-arch matrix unless explicitly required.
- Rust compilation is cached via **sccache** with an S3 backend; the runner exports `SCCACHE_BUCKET`/`SCCACHE_ENDPOINT` and the AWS credentials. CI Rust steps set `RUSTC_WRAPPER=sccache` (via the `rust-setup` composite), and the Dockerfile builder installs `sccache` and receives the S3 config through build args + secrets. The Dockerfile intentionally carries **no `--mount=type=cache`** layers — sccache is the build cache.
- When the change touches deployment automation (GHCR image or Helm chart pushes), make sure the relevant secrets (`GITHUB_TOKEN` or PAT) still have `packages:write`, rerun the workflow locally if helpful (e.g., `just all-checks`, `just it-authorino`, or `just it-servers`), and note in your summary what credentials need to be present. Charts publish as OCI artifacts to `oci://ghcr.io/adorsys-gis/charts/<chart>`.
- After finishing your work (and ensuring the tests exist), run `just all-checks`. This target runs `cargo fmt`, `cargo fix --allow-dirty`, `cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings`, and `cargo check --all-targets --all-features`, making sure the repository is formatted, linted, and builds cleanly before you stop.

## Observability

The system is instrumented with OpenTelemetry (OTLP). When running in Compose, traces are sent to Jaeger.

- **Jaeger UI**: `http://localhost:16686`
- **OTLP Endpoint**: `http://localhost:4317` (gRPC)

Traces capture the full lifecycle of a validation request, including database lookups and telemetry updates.

## Practices and Conventions

- Prefer adding tests before implementation changes, especially for API surface changes (OpenAPI + behavior).
- Keep secrets out of logs and persisted storage:
  - only store `key_hash` in DB
  - return plaintext `secret` only on create/rotate responses
  - the Keycloak refresh token is sealed AES-256-GCM at rest (`federated_identities.token_envelope`,
    ADR-0024) under `oauth2.relying_party.token_encryption_key`; the access token is never stored
    at all, and every struct carrying a credential-bearing field (`TokenResponse`,
    `KeycloakTokenSet`) gets a hand-written, redacting `Debug` impl — never `#[derive(Debug)]`
- Treat validation endpoints as security-sensitive:
  - do constant-time comparisons where relevant (currently Basic auth is direct string compare; acceptable for local/dev but may be upgraded)
  - avoid leaking details in error responses (validation returns generic `unauthorized`)
- Maintain stable API contracts:
  - changes should update OpenAPI and docs together
- **The `authz-ui` pin is a deploy, not a dependency.** `Dockerfile`'s `ARG AUTHZ_UI_REF=` is the
  single place this repo records which login-page bundle ships, and it is pinned by **digest**,
  never by tag and never by `latest`. Bumping it changes what real users see at the authentication
  boundary, so it is reviewed like a code change: dependency automation is explicitly configured
  not to touch it (`.github/dependabot.yml`'s `docker` `ignore:` block), and the bump procedure is
  documented at the ARG itself. The UI ships first and stays backward-compatible; the pin bump is
  what makes it live (ADR-0029). **Since lightbridge-authz#607, the pin is no longer independently
  revertible** (ADR-0029's Update): the RP leg `303`s into SPA routes (`/ui/device`,
  `/ui/device/confirm`, `/ui/device/invalid`, `/ui/device/success`, `/ui/error`) that only exist in
  artifacts carrying `dist/routes.json`, so reverting the pin alone can leave Rust redirecting into
  paths an older bundle has no manifest for — a 404 at the authentication boundary. The rollback
  unit is the whole cutover PR (pin + handoff + allowlist), not the pin alone.

## Security Notes

- Local TLS certs are self-signed: use `curl -k` for local testing.
- OAuth2 validation relies on JWKS (`oauth2.jwks_url`) and currently does not enforce `aud` (audience) in JWT validation.
- Basic-auth credentials for OPA/Authorino are configured in YAML and should be rotated for non-dev deployments.
- `lightbridge-authz-usage` splits its TLS surface across two listeners (#347): an ingest listener
  (`/v1/otel/{traces,metrics,logs}`) that stays unauthenticated -- its caller is an AI Envoy/
  OpenTelemetry exporter outside this repo's deploy surface, so it cannot be given a client
  certificate without a coordinated change there; safe only because this service is `ClusterIP`-
  only with no ingress -- and a query listener (`/usage/v1/usage/query`, `/usage/v1/spend/query`)
  that **requires and verifies a client certificate (mTLS)**. `authz-api`/`authz-budget` present
  their own TLS cert as that client identity (`Config.usage_service.client_cert_path`/
  `client_key_path`), since the deployed `authz-tls` cert already carries both `serverAuth` and
  `clientAuth` in its `extendedKeyUsage`. mTLS alone authenticates "a legitimate lightbridge
  workload holding a CA-signed cert", not a specific caller identity or what it's entitled to see
  -- see `crates/lightbridge-authz-core/src/server.rs`'s `build_mtls_config` and
  `crates/lightbridge-authz-budget/src/spend.rs`'s `UsageServiceSpendReader` doc comments for the
  full posture and the fail-closed contract (a rejected/missing/expired client cert resolves to
  `Spend::Unavailable`, never a silent bypass).
  - **`/usage/v1/usage/query` now ALSO requires an end-user bearer token plus an ownership check
    (#570/#603/#605), closing the cross-tenant gap mTLS alone left open.** On top of mTLS, the
    handler (`crates/lightbridge-authz-usage/src/handlers/query.rs`) requires
    `Authorization: Bearer <token>` (JWKS-validated via `lightbridge-authz-bearer`) and, for
    `scope=account`/`scope=project`, calls `authz-opa`'s `POST /idp/v1/authorize-usage-scope` to
    confirm the token's subject owns the requested scope. `scope=user` is allowed only when
    `scope_id` equals the caller's own subject (no remote call). `scope=all` (estate-wide) instead
    requires the `usage:read-all` permission (`Permission::UsageReadAll`, ADR granted to
    `lightbridge-admin` by default, #605). `scope=api_key` has no resolvable ownership authority
    and is refused unconditionally. Missing/invalid bearer -> `401`; unauthorized, or the
    authority being unreachable/erroring -> `403`, fail-closed, never treated as authorized.
  - **`/usage/v1/spend/query` stays mTLS-only** -- it is `authz-budget`'s legitimate cross-account
    service-to-service reader with no per-caller ownership check by design -- but now REFUSES any
    request carrying an `Authorization` header (#603), closing a "console catch-all-proxy" hole
    where a misrouted browser bearer token could otherwise reach this ownerless cross-account read.
  - See `docs/lightbridge-query-api.md` and `docs/usage-api.md` for the full contract; this section
    is cited as authoritative by `docs/local-testing.md`.

## Migrations

Migrations are run with SQLx embedded migrations in the owning binary packages:

- authz: `app/lightbridge-authz/src/migrate.rs`
- usage: `app/lightbridge-authz-usage/src/migrate.rs`

In Compose, `authz-migrate` runs before API/OPA start.

This is a documented ADR-0038 exception (see "Persistence" below), not the target state — new
schema goes through `crates/lightbridge-authz-api/schema/authz.cstack` and cratestack's migration
generator where it can.

**Before adding a migration, check that its version prefix is free — including on `main`:**

```bash
git fetch origin && git ls-tree --name-only origin/main migrations/ | sed 's#.*/##; s/_.*//' | sort | uniq -d
```

SQLx keys `_sqlx_migrations` by the numeric **version**, not the filename, so two files sharing a
prefix collide on that table's primary key: the second to apply fails `23505` and aborts the whole
run. Locally that is every `sqlx::test` in the workspace dying at setup; in a deployment it is
`authz-migrate` failing at startup, so nothing comes up at all.

**Neither PR's CI can catch this** — each branch contains only its own migration, so the collision
exists solely in the merge result. Two green PRs turned `main` red exactly this way on 2026-08-30
(#564 × #565, healed by #568). A same-day pair is the common case, since everyone reaches for
today's date as the prefix.

Two rules once a collision has happened:

- **A version any environment has durably applied cannot be reassigned** — `_sqlx_migrations` is
  the record of what actually ran there. The file that moves is the one that has *not* been applied
  anywhere durable. If both have, renumbering is not available and the fix is a new forward
  migration.
- **An applied migration's bytes are frozen.** SQLx stores a checksum per migration and validates
  it on every run, so editing one — *even to add a comment* — aborts the next migrate with a
  version mismatch. Corrections go in the owning ADR, not in the file.

## Persistence: cratestack is the only sanctioned database API (ADR-0038)

webank-context [ADR-0038](https://github.com/ADORSYS-GIS/webank-context/blob/master/decisions/0038-cratestack-is-the-only-database-api.md)
makes cratestack's generated model client the only sanctioned database API estate-wide and bans
hand-written SQL and direct `sqlx` dependencies.

- New queries go through the generated client (`crates/lightbridge-authz-api/schema/authz.cstack` +
  cratestack codegen). Do not add new hand-written SQL, and do not add `sqlx` to any further
  `Cargo.toml`.
- This repo is the estate's largest ADR-0038 exception. The existing `sqlx = "0.9"` surface —
  declared in the root workspace `Cargo.toml` and consumed by eight further crate/app manifests,
  alongside cratestack's own internal sqlx 0.8 (the two-major split rationale is at
  `app/lightbridge-authz/Cargo.toml:31-34`) — is not being removed as part of this rule. ADR-0038
  does not authorise starting that removal here; it needs its own scoping pass. The two-major
  arrangement is load-bearing today.
- Cases that are genuinely not migratable to cratestack today, so nobody burns a day
  rediscovering them:
  - `signing_keys`: a table entirely outside `authz.cstack`, rotated under
    `pg_advisory_xact_lock` for cross-replica JWT key rotation
    (`ensure_active_signing_key` in `crates/lightbridge-authz-api-key/src/repo.rs`).
  - `project_members`: composite primary key `(project_id, account_id)`; modelled in
    `authz.cstack` only as a relation target with a synthetic `id`, explicitly barred from
    cratestack's migration generator (see the `ProjectMember` model comment in
    `crates/lightbridge-authz-api/schema/authz.cstack`).
  - `exchange_refresh_tokens`: CAS rotation via `SELECT ... FOR UPDATE`
    (`rotate_exchange_refresh_token` in `crates/lightbridge-authz-api-key/src/repo.rs`).
  - `device_authorizations`: CAS rotation via `SELECT ... FOR UPDATE`, mirroring
    `rotate_exchange_refresh_token`'s single-use-consume pattern -- a device code must be
    atomically claimed exactly once across concurrent poll requests (ADR-0012 Decision 7, #423;
    `consume_device_authorization`/`approve_device_authorization`/`deny_device_authorization` in
    `crates/lightbridge-authz-api-key/src/repo.rs`).
  - `authorization_codes`: a short-lived opaque code must be claimed exactly once across
    concurrent token redemptions with `UPDATE ... WHERE consumed_at IS NULL ... RETURNING`; the
    code/client/redirect binding is an authentication boundary that generated CRUD cannot express
    (ADR-0019, #425; `consume_authorization_code` in
    `crates/lightbridge-authz-api-key/src/repo.rs`).
  - `lightbridge-authz-usage`: dynamic `QueryBuilder` aggregates against the Timescale-backed
    `usage_events` table (`query_usage` in `crates/lightbridge-authz-usage/src/repo.rs`).
  - `federated_identities`: deliberately ABSENT from `authz.cstack` entirely, not merely
    `@@allow`-less -- it carries the sealed Keycloak token envelope, so a credential-bearing table
    must be unreachable from any generated read path, not just gated behind the coarse-RBAC check
    a present-but-unallowed model would still have (ADR-0024 Q4; created by
    `migrations/20260825000001_users_and_federated_identities.sql`; justified in the `User` model
    comment in `crates/lightbridge-authz-api/schema/authz.cstack`).
  - `secret_claims`: single-use, subject-bound claims for handing an API key secret to a human
    without routing it through a model's context (GHSA-9pc6-965v-2c44, #538); redemption needs a
    single-statement CAS so concurrent requests can never both obtain the same secret, which
    generated CRUD cannot express -- the same exception class as `authorization_codes`
    (`migrations/20260827000001_secret_claims.sql`; `consume_secret_claim` in
    `crates/lightbridge-authz-api-key/src/repo.rs`).
- This repo runs cratestack (`cratestack-pg`) `=0.10.0` (pinned exactly in the root `Cargo.toml`,
  which also documents why the pin cannot float past it -- see that file's `cratestack-core =
  "=0.10.0"` block); ADR-0038's capability findings were verified against 0.7.8. Re-verify any
  capability claim against `0.10.0` here before relying on it -- this line has gone stale at every
  single bump so far ("0.5.1" as of #379 on 2026-08-20, which also corrected #375's own PR
  description, itself already out of date at authoring time; then "0.8.12", which survived the
  0.9.4 bump unnoticed). **Treat it as part of the pin, not as prose:** whoever moves
  `cratestack-core` in `Cargo.toml` moves this line in the same commit.
- **The cratestack version must move in lockstep with the `converse-frontends` monorepo**, which
  consumes the same schema through `@cratestack/*` and regenerates its TypeScript client with the
  matching `@cratestack/cli`. A generated client carries version bounds derived from the generator's
  own release line (cratestack#838), so a one-sided bump leaves the two repos resolving different
  major-equivalent lines. Bump `Cargo.toml` here and, over there, `apps/console/package.json`,
  `packages/authz-rpc/package.json`, and every `@cratestack/*` entry in `pnpm-workspace.yaml`'s
  `minimumReleaseAgeExclude` (that last one is what lets a same-day release install at all).
- **cratestack's MSRV is 1.98.0** (unchanged across the 0.9.4 -> 0.10.0 bump; it was already
  1.98.0 at 0.9.4). CI installs `stable` via `.github/actions/rust-setup`, so it is satisfied
  there automatically. A local toolchain older than 1.98 fails the whole workspace at resolution
  time with `rustc 1.x is not supported by the following packages`, listing every `cratestack-*`
  crate -- that is a stale local `rustup` default, **not** a regression introduced by the bump.
  Fix it with `rustup update stable`, or run a one-off gate as
  `RUSTUP_TOOLCHAIN=1.98.0 just all-checks`.

## Troubleshooting and Gotchas

- If Swagger UI build fails in constrained environments, it can be due to `utoipa-swagger-ui` attempting to download assets during build. Workarounds include:
  - allow network egress during build, or
  - configure the crate to use bundled assets (if/when enabled).
- If Keycloak token fetch fails:
  - verify realm `dev` exists (imported from `.docker/keycloak_config/realm.json`)
  - ensure `sslRequired` is `none` for local HTTP flows (it is set in the realm import)
- If API/OPA cannot start:
  - confirm TLS volume is created and mounted (`authz-tls` service)
  - confirm `CONFIG_PATH` points to a valid YAML

## Docs Index

- Overview and quickstart: `README.md`
- Run the whole platform locally (backend + frontend console) and test it end to end — issuer vs
  discovery split, seeded Keycloak users, RBAC gating, honest usage-chart limitations, automated
  suites, troubleshooting table: `docs/local-testing.md`
- Code size baseline and the 200-LoC burn-down plan — measured counts, split order, what is
  deliberately *not* achievable in the current window, and the rules for a behaviour-preserving
  split: `docs/code-size-baseline.md`
- Manual end-to-end protocol (OAuth2 + OPA): `docs/test-protocol.md`
- Authorino endpoint usage + integration test: `docs/authorino-usage.md`
- Usage ingest/query API: `docs/usage-api.md`
- RBAC (JWT claim → permission mapping): `docs/rbac.md`
- API key approaching-expiry visibility (`listMyExpiringApiKeys`, window/threshold rationale, why
  there is no cross-tenant admin surface): `docs/api-key-expiry-visibility.md`
- Governance data model + how quotas/allowlists are actually enforced at the gateway (accounts,
  projects, roster, keys; introspection, Authorino claim extraction, BackendTrafficPolicy rule
  families; worked scenarios and the gaps that remain): `docs/governance-model-and-enforcement.md`
- CRUD API migration to cratestack (routing/policy generation, Swagger UI removal, CBOR-in-prod): `docs/adr/0003-cratestack-crud-migration.md`
- Dynamic budget refill RFC — the original design proposal for the whole budget domain (ledger,
  policy engine, self-service refill, discrete tiers): `docs/rfc/0001-budget-refill.md`
- Budget refill decision contract (the `Facts`/`Decision`/`PolicyEngine` seam a rule-data
  evaluator and, later, an OPA-Wasm evaluator both sit behind; the fail-closed rule): `docs/budget-decision-contract.md`
- Budget refill UI contract (RPC shapes for self-service refill and the admin review queue, the
  reset-not-add and token-refresh-delay behaviors, status values, oriented for the `lightbridge-ss`
  frontend team): `docs/budget-refill-ui-contract.md`
- Budget domain ADRs: why decisions come from rule-data first, OPA-Wasm later, behind one contract
  (`docs/adr/0007-refill-decisions-rule-data-then-opa-wasm.md`); why refills are discrete tiers, not
  arbitrary amounts (`docs/adr/0008-refills-are-discrete-budget-tiers.md`); why grants are an
  immutable ledger with a materialized balance (`docs/adr/0009-budget-grants-are-an-immutable-ledger.md`);
  why the domain is hand-written procedures, not cratestack models
  (`docs/adr/0010-budget-domain-uses-procedures-not-cratestack-models.md`).
- Operational runbooks (budget tier re-key cutover, a stuck refill request, rolling back a bad
  policy revision): `docs/runbooks/README.md`
- System-level architecture front door — service/caller topology, containers, crate layering, and
  where the rest of the picture lives: `docs/architecture/README.md`, plus
  `docs/architecture/{services,deployment,data-model,budget,auth-flows}.md` and the overview at
  `docs/architecture.md`.
- Usage query API field-by-field reference (request/response shapes, the #570 ownership gate,
  latency semantics): `docs/lightbridge-query-api.md`.
- Auth/token reference dictionary — config key → effect, JWT claim shapes (including the
  `client_credentials`/`service_token_extra` claim set), discovery-document fields:
  `docs/auth-reference.md`.
- Per-platform Helm install/config/deploy commands: `docs/platform-guides.md`.
- OAuth/OIDC standards gap and delivery roadmap: `docs/oauth-oidc-standards-roadmap.md`.
- Task guide for integrating a client against native token exchange:
  `docs/token-exchange-integration.md`.
- Usage-store ADRs: one store partitioned by grain, source is a dimension
  (`docs/adr/0027-one-usage-store-partitioned-by-grain.md`, amended by
  `docs/adr/0028-finops-first-settles-the-usage-store-conventions.md`); the `authz-idp` login UI as
  a pinned external artifact (`docs/adr/0029-the-authz-idp-login-ui-is-a-pinned-external-artifact.md`);
  `client_credentials` as a first-class `authz-idp` grant
  (`docs/adr/0030-client-credentials-is-a-first-class-authz-idp-grant.md`).
- Multi-source usage epic plan of work (decision register D1-D23):
  `docs/plans/0581-multi-source-usage-plan-of-work.md`.
- The F1-F6 genai usage-ingestion audit the usage-store ADRs keep citing:
  `docs/research/2026-08-25-genai-usage-ingestion.md`.
- RFC index: `docs/rfc/README.md`.

There is no `docs/adr/README.md` — this Docs Index is the only ADR index in this repo; browse
`docs/adr/` directly for the full numbered list.

## Helm / deployment notes

- The umbrella chart (`charts/lightbridge-authz-stack`) now documents per-platform install/config/deploy commands in `docs/platform-guides.md`, including:
  * Two documented TLS certificate flows (built-in `global.tls.job` + cert-manager) and the Ubuntu `curl` smoke test against `https://lightbridge-lightbridge-api.default.svc.cluster.local:3000/healthz` when cert-manager owns the `lightbridge-authz-tls` secret.
  * Shared `3000` ports for both API and OPA because we never deploy them together in these guides, and instructions for keeping API ingress enabled while OPA stays internal-only.
  * Manual TLS generation is noted as optional because the chart's hook already creates service-FQDN certs, but the hook can be disabled when cert-manager owns the secret.

- Each subchart renders three secrets per app:
  * `*-api` / `*-opa` holds the database/password stringData used to render the per-service configmaps (mounted into `/etc/lightbridge/config.yaml`).
  * `*-secrets` is created so the controller can mount `DATABASE_URL`/`OPA_PASSWORD` via `secretKeyRef`, keeping credentials out of the primary TLS secret.
  * `*-tls` contains the TLS materials mounted under `/etc/lightbridge/tls`; once cert-manager rotates `lightbridge-authz-tls` downstream consumers need to copy the new cert/key into these per-app secrets (or keep the job enabled).

- Deployments now hardcode `containerPort: 3000` for both controllers so Kubernetes records the exposed port, aligning with service target ports.

- **Correction:** there is no separate `lightbridge-migrate` chart and no `migration` alias.
  `charts/lightbridge-authz-stack`'s six dependencies are `api`/`opa`/`idp`/`budget` (all the same
  `charts/lightbridge-authz` chart, different aliases), `usage`, and `mcp` — see that chart's
  `Chart.yaml`. Schema migrations instead run as `controllers.migrate` INSIDE the shared
  `charts/lightbridge-authz` chart (and, separately, inside `charts/lightbridge-authz-usage` for
  usage-store migrations): `lightbridge-authz migrate --config-path /etc/lightbridge/config.yaml`,
  reusing the ambient config map and the same image. Per ADR-0016 (`docs/adr/0016-migrate-job-sync-
  wave-not-hook.md`) this is deliberately NOT a Helm hook — a `post-install,post-upgrade` hook is an
  ArgoCD PostSync hook that only fires once every non-hook resource (including the main Deployment)
  is already Healthy, which deadlocks the moment a migration is itself a precondition for the new
  pods' readiness probe (hit in prod 2026-08-19). Instead it is an ordinary, ArgoCD-tracked `Job`
  annotated `argocd.argoproj.io/sync-wave: "1"`, one wave earlier than the main Deployment's `"2"`,
  regardless of whether the Deployment's pods are, or will ever be, ready. Its `suffix` folds both
  the image tag AND the rendered config data into the Job name (bjw-s stamps a config-checksum
  annotation into the pod template, so a config-only change would otherwise re-render the SAME Job
  name with a DIFFERENT, immutable `spec.template` and fail the whole app's sync — hit twice in
  prod 2026-08-24, #480); `ttlSecondsAfterFinished: 604800` (7 days) keeps a completed Job
  inspectable via the native Kubernetes Job-controller GC path, not a Helm hook-delete policy.
- Both migrate Jobs (`charts/lightbridge-authz`, `charts/lightbridge-authz-usage`) are built on the
  `bjw-s/common v4` app-template library, so the job/configmap/secret skeletal resources are
  rendered by the shared loader instead of bespoke templates, keeping the chart plumbing consistent
  with the rest of the stack.
- `charts/lightbridge-authz-usage` (#593/#570/#603): `configMaps.config.data."config.yaml"` renders
  BOTH the `server.usage` (ingest) and `server.query` (mTLS) listeners — `UsageServerGroup::query`
  is a non-`Option` field, so a config omitting it fails to load. mTLS is default-ON:
  `config.query.tls.clientCaBundlePath` defaults to `/etc/lightbridge/tls/ca.crt`; setting it to
  `""` explicitly drops BOTH the query listener's containerPort and its Service port entirely
  (`templates/common.yaml`), trading "query endpoint unreachable" for "config still loads," never
  "reachable and unauthenticated." Ports: ingest `3000` (this chart's pre-existing port, left
  unchanged — deliberately NOT full parity with Compose's ingest `3002`) / query `3006` (matching
  every other reference to this listener in the repo). `config.oauth2.jwksUrl` and every
  `config.scopeAuthority.*` field (`baseUrl`/`username`/`password`/`caBundlePath`) are likewise
  mandatory (`UsageConfig::oauth2`/`UsageConfig::scope_authority` are non-`Option`) and MUST be
  supplied correctly in the SAME ROLLOUT that enables this version of the chart — a bad value fails
  the `migrate` Job first (earlier sync-wave), failing the whole ArgoCD app sync, not just this
  chart's own rollout.

<!-- ai-governance:stanza -->
<!-- BEGIN: AI Governance stanza (managed by ADORSYS-GIS/ai-governance) -->
## AI Governance

AI may accelerate the work, but humans own intent, verification, and consequences.
AI output is not truth: review AI-generated code as untrusted, and never submit work you cannot explain.

When opening issues or pull requests in this repo:

- Use the provided **issue forms** (Epic, User Story, Dev Ticket) and the **pull request template** — do not open blank issues/PRs.
- Fill in the **AI Usage Declaration** honestly (what AI was used for, what you verified).
- Include a **source-of-truth link** (a URL or `#123` reference). No source of truth means the work is not ready.
- Provide **verification evidence** (commands, logs, links, or checked verification boxes). No evidence means it is not done.

Source of truth and full doctrine: https://adorsys-gis.github.io/ai-governance/
This stanza is intentionally thin — read the site; do not duplicate the doctrine here.
<!-- END: AI Governance stanza -->
