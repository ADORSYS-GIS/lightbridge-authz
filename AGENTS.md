# AGENTS.md

This repository provides API key management plus usage analytics:

- `authz-api`: OAuth2/JWT-protected CRUD API for Accounts, Projects, and API keys.
- `authz-opa`: Basic-auth protected validation API intended to be called by Authorino (or similar external auth components). It validates API keys and returns rich context plus dynamic metadata.
- `lightbridge-mcp`: OAuth2/JWT-protected MCP server exposing the authz surface as MCP tools over streamable HTTP (`/mcp`).
- `lightbridge-authz-usage`: unprotected OTLP/HTTP ingest API (`/v1/otel/traces`, `/v1/otel/metrics`) plus a single usage query API (`/usage/v1/usage/query`) backed by Timescale/Postgres.

The authz services (`authz-api`, `authz-opa`):

- share the same Postgres database
- share the same SQL migrations
- run with TLS (self-signed certs in local Compose)
- `authz-opa` still exposes OpenAPI/Swagger docs; `authz-api`'s CRUD/RPC surface does not (see
  "OpenAPI docs" under Development Workflows)

`authz-api` also hosts the **budget domain**: a per-account ledger of budget grants
(`crates/lightbridge-authz-budget/`), a hot-swappable rule-data policy engine that decides refill
requests, and self-service refill + an admin review queue, all exposed as `/rpc/*` procedures on
the same RPC surface as the CRUD API. See `docs/rbac.md`'s budget sections and
`docs/budget-decision-contract.md` for the full picture; this is upstream of, and today has no
effect on, the Envoy/Authorino-side rate limiting `docs/governance-model-and-enforcement.md`
describes.

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
  - `crates/lightbridge-authz-api-key/`: DB entities + repository implementation (SQLx).
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
- `config/`: local default config (non-container paths).
- `.docker/`: docker assets (service config, Keycloak realm import, Envoy example, IT scripts).
- `compose.yaml`: local dev stack (Postgres, Keycloak, API/OPA, migrations, TLS generator).
- `compose.it.yaml`: integration-test overlay (adds `it-authorino` and `it-servers` test runners).
- `docs/`: human docs (manual protocol, Authorino usage).
- `.github/actions/`: composite helpers that encapsulate Rust setup, cargo tooling, docker build/publish, and Helm publishing so workflows stay short.
- `.github/workflows/`: main CI/CD pipeline (`ci.yml`) plus the Helm charts publish workflow (`helm-oci.yml`), both kept lean by calling the shared actions.

## Runtime Services (Compose)

Primary local stack is in `compose.yaml`:

- `authz-tls`: generates self-signed certs into `authz_tls` volume.
- `postgresql`: Postgres backing store.
- `timescaledb`: usage events backing store.
- `keycloak`: OAuth2 provider (imports `dev` realm from `.docker/keycloak_config/realm.json`).
- `authz-migrate`: runs migrations once at startup.
- `authz-api`: runs the CRUD API.
- `authz-opa`: runs validation endpoints for OPA/Authorino.
- `authz-mcp`: runs the MCP streamable HTTP endpoint.
- `mcp-inspector`: optional MCP Inspector UI/proxy container for MCP debugging.
- `authz-usage`: runs OTEL ingest + usage query endpoints.
- `adminer`: optional DB UI.

## Architecture Overview

### Data Model

Tables (see `migrations/`):

- `accounts`: **`id` is the caller's JWT `sub`** — one account is one person (ADR-0006). Carries
  `default_quota` (the governance tier for work in the account's own default project).
- `projects` (belongs to `accounts`): includes `billing_identity` (unique — "who is paying" moved
  here from `accounts`, so one person can bill projects to different parties), `project_quota` (the
  pooled ceiling), and `is_default` (the auto-provisioned, roster-less project; server-computed by a
  `BEFORE INSERT` trigger, undeletable).
- `project_members` (`{project_id, account_id, role: lead|member, quota_tier}`): the project roster.
  Default projects have none by construction. Replaces `account_memberships`, which was dropped
  entirely — there is no account-level membership of any kind.
- `api_keys` (belongs to `projects`): includes `allowed_models`.

API keys are stored as:

- `key_hash`: SHA-256 hex digest of the secret (never store plaintext).
- `key_prefix`: derived from the secret for identification/useful listing.
- `status`: `active` or `revoked`.
- `expires_at`: optional expiration.
- `allowed_models`: list of permitted models. `NULL` or `[]` (empty list) are interpreted as "all models allowed".
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
  - Records usage telemetry (last IP + timestamp).
  - Returns key/project/account context to callers.
  - Provides an Authorino-oriented endpoint that supports dynamic metadata.

- MCP API (`lightbridge-mcp`)
  - Exposes authz CRUD and validation operations as MCP tools under `/mcp`.
  - Secured with the same JWT bearer/JWKS middleware used by `authz-api`.
  - Derives subject identity from JWT claims (tool input does not include subject).

### Validation Endpoints

On the OPA server:

- `POST /v1/opa/validate`
  - Minimal validation endpoint returning `{ api_key, project, account }` on success.

- `POST /v1/authorino/validate`
  - Designed for Authorino/external auth integrations.
  - Accepts a typed `AuthorinoMetadata` struct in the request.
  - Returns `dynamic_metadata` in the response which:
    - preserves request metadata keys
    - enriches with `account_id`, `project_id`, `api_key_id`, and `api_key_status`

These are implemented in `crates/lightbridge-authz-rest/src/handlers/authorino.rs`.

### Identity context resolution (`subject` + `project` → context)

Backs the `lightbridge-keycloak-spi` IdP adapter, which seals `account_id`/`project_id` into JWTs at token-exchange time. The adapter reads the authenticated `subject` and a `project_id` form param on the exchange, resolves the context, and a dumb protocol mapper copies it into claims. Stateless — no store.

- Resolve — `POST /idp/v1/resolve-context` on the OPA/validation server, **Basic-auth protected** (the adapter presents the OPA credentials; the endpoint returns tenant context so it must not be publicly reachable). Body `{subject, project_id}` → `{account_id, project_id}`. Since ADR-0006 a project resolves when the subject owns its account (`projects.account_id = $2`, the account id being the subject itself) **or** holds a `project_members` row for it; a non-member or unknown project is a uniform `404` — deliberately indistinguishable, so the endpoint never leaks which projects exist. Handler: `crates/lightbridge-authz-rest/src/handlers/idp.rs`; repo method `resolve_context` in `crates/lightbridge-authz-api-key/src/repo.rs`.

This exchange is also where project context is **sealed into the JWT** for the human plane (`role`, `quota_tier`, `project_quota` alongside `account_id`/`project_id`), which is what lets Authorino read them as claims instead of calling back per request. The consequence is that switching project means requesting a new token, not sending a different header.

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

- `server.api`: address/port/tls paths
- `server.api.codec` (name indicative — see `config/default.yaml`/container config for the exact key): selects the wire codec (`json` or `cbor`) for `authz-api`'s CRUD endpoints; production defaults to CBOR, dev/CI config keeps `json`. Scoped to `authz-api` only — `authz-opa`, the usage service, and the MCP server always speak JSON.
- `server.opa`: address/port/tls paths + basic auth credentials
- `server.usage`: address/port/tls paths for usage service
- `database.url`: Postgres connection string
- `oauth2.jwks_url`: JWKS endpoint (Keycloak in local compose)

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

The Postgres-backed `lightbridge-authz-api-key` tests (rotate/limits) and `lightbridge-authz-budget` tests (ledger writes, replay, policy store, refill/review services) are guarded by the `it-tests` feature so they only compile/run when requested. This keeps the default `cargo test` free of database setup, and lets us treat these as Docker-backed integration tests.

Run them with `just it-tests`, which brings up the `postgresql`/`redis` services, waits a moment, then sets `DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz"` before invoking `lightbridge-authz-api-key`, `lightbridge-authz-budget`, and `lightbridge-authz-rest` with `--features it-tests`. These tests exercise the migrations under `sqlx::test`.

**Known failing tests, tracked separately (do not assume your change caused these):**
`crates/lightbridge-authz-rest/tests/rpc_it_tests.rs` has 7 tests that fail deterministically even
against a freshly migrated database — confirmed unrelated to any specific change, see #219 for the
full list and reproduction steps. `crates/lightbridge-authz-api-key/tests/access_control_scenarios_tests.rs::access_control_allows_members_and_rejects_non_members`
tests an account-level "invited member" scenario ADR-0006 removed; see #220.

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
- Treat validation endpoints as security-sensitive:
  - do constant-time comparisons where relevant (currently Basic auth is direct string compare; acceptable for local/dev but may be upgraded)
  - avoid leaking details in error responses (validation returns generic `unauthorized`)
- Maintain stable API contracts:
  - changes should update OpenAPI and docs together

## Security Notes

- Local TLS certs are self-signed: use `curl -k` for local testing.
- OAuth2 validation relies on JWKS (`oauth2.jwks_url`) and currently does not enforce `aud` (audience) in JWT validation.
- Basic-auth credentials for OPA/Authorino are configured in YAML and should be rotated for non-dev deployments.

## Migrations

Migrations are run with SQLx embedded migrations in the owning binary packages:

- authz: `app/lightbridge-authz/src/migrate.rs`
- usage: `app/lightbridge-authz-usage/src/migrate.rs`

In Compose, `authz-migrate` runs before API/OPA start.

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
- Manual end-to-end protocol (OAuth2 + OPA): `docs/test-protocol.md`
- Authorino endpoint usage + integration test: `docs/authorino-usage.md`
- Usage ingest/query API: `docs/usage-api.md`
- RBAC (JWT claim → permission mapping): `docs/rbac.md`
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

- A brand-new `lightbridge-migrate` chart (aliased `migration` under `charts/lightbridge-authz-stack`) runs `lightbridge-authz migrate --config-path /tmp/lightbridge-config/config.yaml` as a `pre-install/pre-upgrade` job so schema migrations happen before the API/OPA controllers become active. It reuses the ambient `lightbridge-authz-config` config map, shares the same image artifacts, and exposes TTL/backoff knobs to keep the job brief.
- That migration chart is now built on the `bjw-s/common v4` app-template library, so the job/configmap/secret skeletal resources are rendered by the shared loader instead of bespoke templates, keeping the chart plumbing consistent with the rest of the stack.

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
