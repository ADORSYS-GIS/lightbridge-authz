# AGENTS.md

This repository provides API key management plus usage analytics:

- `authz-api`: OAuth2/JWT-protected CRUD API for Accounts, Projects, and API keys.
- `authz-opa`: Basic-auth protected validation API intended to be called by Authorino (or similar external auth components). It validates API keys and returns rich context plus dynamic metadata.
- `lightbridge-mcp`: OAuth2/JWT-protected MCP server exposing the authz surface as MCP tools over streamable HTTP (`/mcp`).
- `lightbridge-authz-usage`: unprotected OTLP/HTTP ingest API (`/v1/otel/traces`, `/v1/otel/metrics`) plus a single usage query API (`/v1/usage/query`) backed by Timescale/Postgres.

The authz services (`authz-api`, `authz-opa`):

- share the same Postgres database
- share the same SQL migrations
- expose OpenAPI/Swagger docs
- run with TLS (self-signed certs in local Compose)

This file documents structure, architecture, workflows, and practices for contributors and agents working on this codebase.

## Top-Level Layout

- `app/`
  - `app/lightbridge-authz/`: main binary that can run API server, OPA server, both, and migrations.
  - `app/lightbridge-mcp/`: MCP binary that runs the streamable HTTP MCP server.
  - `app/lightbridge-authz-usage/`: usage binary that can run usage server, usage migrations, and config validation.
  - `app/lightbridge-authz-migrate-bin/`: standalone migration runner (used by Docker image stage).
  - `app/lightbridge-authz-healthcheck/`: TCP healthcheck binary for container health checks.
- `crates/`
  - `crates/lightbridge-authz-core/`: shared types, config, errors, crypto, DB pool.
  - `crates/lightbridge-authz-api/`: CRUD API routing/controllers + OpenAPI.
  - `crates/lightbridge-authz-api-key/`: DB entities + repository implementation (SQLx).
  - `crates/lightbridge-authz-rest/`: Axum server glue (TLS bind, modular layout with handlers, routers, models, and middleware).
  - `crates/lightbridge-authz-bearer/`: JWT validation via JWKS (Keycloak in local compose).
  - `crates/lightbridge-authz-mcp/`: MCP tool handlers + streamable HTTP server wiring.
  - `crates/lightbridge-authz-migrate/`: SQLx migrations runner library.
  - `crates/lightbridge-authz-usage/`: Axum usage server (OTEL ingest handlers, usage query models/routers, TLS bind, OpenAPI).
  - `crates/lightbridge-authz-usage-migrate/`: SQLx migrations runner for usage storage.
  - `crates/lightbridge-authz-test-utils/`: helpers for DB/migrations in tests (currently minimal).
  - `crates/lightbridge-authz-proto/`: proto-related exports (currently minimal).
- `migrations/`: SQLx migrations.
- `migrations-usage/`: SQLx migrations for usage events storage (Timescale-compatible schema).
- `config/`: local default config (non-container paths).
- `.docker/`: docker assets (service config, Keycloak realm import, Envoy example, IT scripts).
- `compose.yaml`: local dev stack (Postgres, Keycloak, API/OPA, migrations, TLS generator).
- `compose.it.yaml`: integration-test overlay (adds `it-authorino` and `it-servers` test runners).
- `docs/`: human docs (manual protocol, Authorino usage).
- `.github/actions/`: composite helpers that encapsulate Rust setup, cargo tooling, docker build/publish, and Helm publishing so workflows stay short.
- `.github/workflows/`: main CI/CD pipeline (`ci.yml`) plus the Helm charts publish workflow (`helm-gh-pages.yml`), both kept lean by calling the shared actions.

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

- `accounts`: includes `billing_identity` (unique).
- `projects` (belongs to `accounts`)
- `api_keys` (belongs to `projects`): includes `allowed_models`.

API keys are stored as:

- `key_hash`: SHA-256 hex digest of the secret (never store plaintext).
- `key_prefix`: derived from the secret for identification/useful listing.
- `status`: `active` or `revoked`.
- `expires_at`: optional expiration.
- `allowed_models`: list of permitted models. `NULL` or `[]` (empty list) are interpreted as "all models allowed".
- usage telemetry: `last_used_at`, `last_ip`.

### Service Responsibilities

- CRUD API (`authz-api`)
  - Provides create/read/update/delete lifecycle for accounts/projects/api keys.
  - Protected by OAuth2/JWT bearer token middleware.
  - Used by internal services/operators to provision keys.

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

## Rust Workspace and Crates

Workspace manifest: `Cargo.toml`

- Crate boundaries follow a layered approach:
  - `core` holds shared domain types and infra primitives.
  - `api-key` holds SQLx entities and the repository.
  - `api` defines the CRUD surface: routers + controllers + OpenAPI.
  - `rest` wires everything into real Axum servers with middleware and TLS.
  - `bearer` validates JWT bearer tokens via JWKS.

### Key Code Paths

- Binary entrypoints:
  - `app/lightbridge-authz/src/main.rs`
  - `app/lightbridge-mcp/src/main.rs`
  - `app/lightbridge-authz-usage/src/main.rs`
  - `app/lightbridge-authz-migrate-bin/src/main.rs`
  - `app/lightbridge-authz-healthcheck/src/main.rs`

- CRUD API:
  - routing: `crates/lightbridge-authz-api/src/routers.rs`
  - controllers: `crates/lightbridge-authz-api/src/controllers/*`
  - OpenAPI: `crates/lightbridge-authz-api/src/openapi.rs`

- OPA/Authorino endpoints:
  - handlers: `crates/lightbridge-authz-rest/src/handlers/*`
  - routers: `crates/lightbridge-authz-rest/src/routers/*`
  - models: `crates/lightbridge-authz-rest/src/models/*`
  - middleware: `crates/lightbridge-authz-rest/src/middleware/*`

- Repository:
  - `crates/lightbridge-authz-api-key/src/repo.rs`
  - `crates/lightbridge-authz-usage/src/repo.rs`

- MCP endpoints/tools:
  - server + tool handlers: `crates/lightbridge-authz-mcp/src/lib.rs`

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

- `curl -k https://localhost:13000/health`
- `curl -k https://localhost:13001/health`
- `curl -k https://localhost:13002/health`
- `curl -k https://localhost:13003/health`
- `curl -k https://localhost:13003/health/ready`
- `curl -k https://localhost:13003/health/startup`

OpenAPI docs:

- CRUD API: `https://localhost:13000/api/v1/docs`
- OPA/Authorino: `https://localhost:13001/v1/opa/docs`
- Usage API: `https://localhost:13002/v1/usage/docs`

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
- `cargo run -p lightbridge-mcp -- serve --config-path config/default.yaml`
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
- `cargo test -p lightbridge-authz-mcp`
- `cargo test -p lightbridge-authz-usage-rest`

These tests include:

- API key validation success/failure cases (missing/revoked/expired).
- Authorino endpoint dynamic metadata passthrough + enrichment.
- Health probe behavior (`/health`, `/health/startup`, `/health/ready`) including DB-unavailable readiness failures.
- OpenAPI checks ensuring the Authorino endpoint/schemas are published.
- OTLP trace/metrics ingestion extraction and usage query handler validation.

### Persistence tests (it-tests)

The Postgres-backed `lightbridge-authz-api-key` tests (rotate/limits) are now guarded by the `it-tests` feature so they only compile/run when requested. This keeps the default `cargo test` free of database setup, and lets us treat these as Docker-backed integration tests.

Run them with `just it-tests`, which brings up the `postgresql` service, waits a moment, then sets `DATABASE_URL="postgres://postgres:postgres@localhost:5432/lightbridge_authz"` before invoking the crate tests with `--features it-tests`. These tests exercise the migrations under `sqlx::test`.

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
- Workflow changes should keep the top-level YAML files concise (both `/ .github/workflows/ci.yml` and `/ .github/workflows/helm-gh-pages.yml` stay under ~100 lines) by moving reusable sequences into `.github/actions/` composites (Rust setup, tests, docker build/push, Helm publishing). Confirm the helper action logic lives in the shared directory, and if you edit those helpers, mention why you need the customization and keep their scope focused.
- Container CI builds are native per architecture (`ubuntu-24.04` for `linux/amd64` and `ubuntu-22.04-arm` for `linux/arm64`); avoid reintroducing QEMU-based cross-builds unless explicitly required.
- When the change touches deployment automation (GHCR pushes or GitHub Pages), make sure the relevant secrets (`GITHUB_TOKEN` or PAT) still have `packages:write`/`pages:write`, rerun the workflow locally if helpful (e.g., `just all-checks`, `just it-authorino`, or `just it-servers`), and note in your summary what credentials need to be present.
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

Migrations are run with SQLx embedded migrations:

- library: `crates/lightbridge-authz-migrate/src/migrate.rs`
- binary: `app/lightbridge-authz-migrate-bin/src/main.rs`

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

## Helm / deployment notes

- The umbrella chart (`charts/lightbridge`) now documents per-platform install/config/deploy commands in `docs/platform-guides.md`, including:
  * Two documented TLS certificate flows (built-in `global.tls.job` + cert-manager) and the Ubuntu `curl` smoke test against `https://lightbridge-lightbridge-api.default.svc.cluster.local:3000/health` when cert-manager owns the `lightbridge-authz-tls` secret.
  * Shared `3000` ports for both API and OPA because we never deploy them together in these guides, and instructions for keeping API ingress enabled while OPA stays internal-only.
  * Manual TLS generation is noted as optional because the chart's hook already creates service-FQDN certs, but the hook can be disabled when cert-manager owns the secret.

- Each subchart renders three secrets per app:
  * `*-api` / `*-opa` holds the database/password stringData used to render the per-service configmaps (mounted into `/etc/lightbridge/config.yaml`).
  * `*-secrets` is created so the controller can mount `DATABASE_URL`/`OPA_PASSWORD` via `secretKeyRef`, keeping credentials out of the primary TLS secret.
  * `*-tls` contains the TLS materials mounted under `/etc/lightbridge/tls`; once cert-manager rotates `lightbridge-authz-tls` downstream consumers need to copy the new cert/key into these per-app secrets (or keep the job enabled).

- Deployments now hardcode `containerPort: 3000` for both controllers so Kubernetes records the exposed port, aligning with service target ports.

- A brand-new `lightbridge-migrate` chart (aliased `migration` under `charts/lightbridge`) runs `lightbridge-authz migrate --config-path /tmp/lightbridge-config/config.yaml` as a `pre-install/pre-upgrade` job so schema migrations happen before the API/OPA controllers become active. It reuses the ambient `lightbridge-authz-config` config map, shares the same image artifacts, and exposes TTL/backoff knobs to keep the job brief.
- That migration chart is now built on the `bjw-s/common v4` app-template library, so the job/configmap/secret skeletal resources are rendered by the shared loader instead of bespoke templates, keeping the chart plumbing consistent with the rest of the stack.
