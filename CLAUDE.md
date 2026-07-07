# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Canonical guide

[`AGENTS.md`](AGENTS.md) is the detailed contributor/agent guide — code style, per-endpoint layout, testing matrix, Helm notes, gotchas. Read it for depth. This file is the fast orientation; when the two overlap, AGENTS.md wins.

## What this is

A Rust (edition 2024) Cargo **workspace** implementing API-key management plus usage analytics, deployed as several binaries that share one Postgres/Timescale database. The three roles a request can take:

- **CRUD API** (`authz-api`, `:13000`) — OAuth2/JWT-protected lifecycle for Accounts → Projects → API keys.
- **Validation API** (`authz-opa`, `:13001`) — Basic-auth; called *by Authorino*, not end users. Hashes a presented key, rejects revoked/expired, returns enriched `{api_key, project, account}` + Authorino dynamic metadata.
- **MCP server** (`lightbridge-mcp`, `:13003`) — same authz surface exposed as MCP tools over streamable HTTP at `/mcp`; same JWKS bearer flow as `authz-api`.
- **Usage API** (`lightbridge-authz-usage`, `:13002`) — unauthenticated OTLP/HTTP ingest (`/v1/otel/traces`, `/v1/otel/metrics`) + `/v1/usage/query` over a Timescale schema.

Ports above are the host-exposed Compose ports; inside containers services bind `:3000`/`:3001`. All TLS is self-signed locally — use `curl -k`.

## Crate architecture (layered)

`app/*` are thin binaries; `crates/*` hold the logic. Cross-crate flow for the authz surface:

- `lightbridge-authz-core` — shared domain types, YAML config loader (`config::load_from_path`, with `$VAR`/`${VAR-default}`/`${VAR:-default}` interpolation), the **centralized `Result<T>` / `Error` enum**, crypto, DB pool. All errors funnel through here.
- `lightbridge-authz-api-key` — SQLx entities + repository (`repo.rs`). The only crate that talks to the `accounts`/`projects`/`api_keys` tables.
- `lightbridge-authz-api` — CRUD routers/controllers + OpenAPI (`routers.rs`, `controllers/*`, `openapi.rs`).
- `lightbridge-authz-rest` — Axum server glue: TLS bind, middleware, and the OPA/Authorino handlers (`handlers/authorino.rs` is where dynamic-metadata enrichment lives).
- `lightbridge-authz-bearer` — JWT validation via JWKS (Keycloak locally). Note: `aud` is **not** currently enforced.
- `lightbridge-authz-mcp` — MCP tool handlers + server wiring (`src/lib.rs`); derives subject from JWT claims, not tool input.
- `lightbridge-authz-usage` / `-usage-migrate`, `lightbridge-authz-migrate` — usage server + the two independent migration sets (`migrations/` for authz, `migrations-usage/` for usage).

Key security invariant: only `key_hash` (SHA-256) + `key_prefix` are stored; plaintext `secret` is returned **only** on create/rotate. `allowed_models` NULL or `[]` means "all models allowed".

## Commands

Everything is wrapped in the `justfile` (Docker Compose) and plain `cargo` for Rust:

```bash
just up                 # build + start full local stack (Postgres, Keycloak, all services, TLS gen)
just down / just destroy  # stop (keep volumes) / stop + wipe volumes
just logs-api|logs-opa|logs-usage|logs-mcp   # tail one service
just migrate            # run authz migrations once; just usage-migrate for usage schema
just all-checks         # fmt + cargo deny + cargo fix + clippy(-D warnings) + check — run before finishing
```

Rust workflow (no Docker needed for unit tests):

```bash
cargo test -p lightbridge-authz-rest                      # unit/contract tests (validation, OpenAPI, probes)
cargo test -p lightbridge-authz-rest <test_fn_name>       # single test
cargo test --workspace                                    # needs DATABASE_URL for the db-backed crates
```

Feature-gated test suites (kept out of default `cargo test`):

```bash
just it-tests       # Postgres-backed api-key tests (spins up postgresql, sets DATABASE_URL, --features it-tests)
just load-test      # Goose load test vs OPA endpoint, --features load-tests (needs AUTHZ_API_KEY)
just it-authorino   # end-to-end Keycloak → CRUD → Authorino validate (compose.it.yaml overlay)
just it-servers     # JWT/basic-auth/probe coverage across API/OPA/Usage/MCP
```

Run a binary directly (subcommands: `serve`, `api`, `opa`, `migrate` — usage/mcp use `serve`/`migrate`):

```bash
cargo run -p lightbridge-authz -- serve --config-path config/default.yaml
cargo run -p lightbridge-authz-usage -- serve --config-path config/usage.yaml
```

## Conventions that bite (enforced by .roo rules + pre-commit)

- **No comments in code** — not doc-comment guidance for public APIs, but no inline `//` explanatory comments.
- **New tests go in `tests/`, never `src/`.**
- **All dependencies declared at workspace level** in root `Cargo.toml` `[workspace.dependencies]`; crates reference `dep.workspace = true`. Adding a dep to a crate means adding it to the workspace too.
- **Edition 2024, stable toolchain only** — no nightly features, never downgrade a crate version.
- Prefer the centralized `Result`/`Error` and `?` propagation over ad-hoc error types.
- Changes to the API surface must update OpenAPI + docs together, and add/extend tests before finishing.

## Observability

Compose ships OTLP → Jaeger. Jaeger UI at `http://localhost:16686`, OTLP gRPC at `:4317`. MCP Inspector UI at `http://localhost:6274`.

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
