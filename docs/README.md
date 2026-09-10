# Documentation

This is the navigation map for **lightbridge-authz** — API key management plus usage analytics,
built as six independently deployable services sharing two databases. The repository is heavily
documented; this page tells you *where* to look for *what*, so you can get to the right document
without reading everything.

> **New here?** Start with the [architecture overview](./architecture/README.md), then follow its
> links. **Running it locally?** Read [`local-testing.md`](./local-testing.md). **Contributing?**
> Read [`../AGENTS.md`](../AGENTS.md) and [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## The one-paragraph shape of the system

`lightbridge-authz` validates API keys (and other credentials) and accounts for how they are used:

- **`authz-api`** — OAuth2/JWT-protected CRUD for accounts, projects, and API keys (cratestack-generated surface).
- **`authz-opa`** — Basic-auth-protected validation API for Authorino (RFC 7662 introspection, context resolution).
- **`authz-idp`** — the OIDC broker for the human plane (browser SSO, RFC 8628 device flow, RFC 8693 token exchange). Renders no HTML of its own.
- **`authz-budget`** — the budget domain's RPC procedures (policy lifecycle, self-service refill, admin review queue).
- **`lightbridge-mcp`** — the authz surface re-exposed as MCP tools over streamable HTTP.
- **`lightbridge-authz-usage`** — OTEL/OTLP ingest plus Timescale-backed usage/spend analytics.

All but the usage service share one Postgres database (`authz`); usage has its own Timescale store.
`authz-api`, `authz-idp`, and `authz-budget` require Redis. Keycloak is the OIDC provider.

---

## Documentation map — which document for which question

### First stop / orientation

| Want to… | Open |
| --- | --- |
| Know what is done, missing, broken, flaky or waiting on a decision | [`ROADMAP.md`](./ROADMAP.md) |
| Understand the whole system's shape and callers | [`architecture/README.md`](./architecture/README.md) |
| Run the full platform locally and test end to end | [`local-testing.md`](./local-testing.md) |
| Get build/test commands, conventions, and house rules | [`../AGENTS.md`](../AGENTS.md) |
| See the service responsibilities and route tables | [`architecture/services.md`](./architecture/services.md) |
| Contribute (AI governance, PR/issue forms) | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |

### Architecture (current state, code-grounded)

| Want to… | Open |
| --- | --- |
| Service/caller topology and crate layering | [`architecture/README.md`](./architecture/README.md) |
| Per-service responsibility, protection, and routes | [`architecture/services.md`](./architecture/services.md) |
| Postgres schema (authz + usage) — the data model | [`architecture/data-model.md`](./architecture/data-model.md) |
| Authentication & authorization request flows (validation, exchange, refresh, revocation, identity) | [`architecture/auth-flows.md`](./architecture/auth-flows.md) |
| The budget domain (ledger, policy engine, refill, review) | [`architecture/budget.md`](./architecture/budget.md) |
| Deployment / CI-CD pipeline and its silent-failure mode | [`architecture/deployment.md`](./architecture/deployment.md) |
| Legacy (now superseded by `architecture/`) top-level view | [`architecture.md`](./architecture.md) ⚠️ *stale* |

### Domain guides & contracts

| Want to… | Open |
| --- | --- |
| RBAC — JWT claim → permission mapping, platform role grants (ADR-0033) and the `rbac` CLI bootstrap runbook | [`rbac.md`](./rbac.md) |
| Governance model — how quotas/allowlists are enforced at the gateway (introspection, Authorino) | [`governance-model-and-enforcement.md`](./governance-model-and-enforcement.md) |
| Authorino endpoint usage + integration test | [`authorino-usage.md`](./authorino-usage.md) |
| Usage ingest/query API | [`usage-api.md`](./usage-api.md) |
| Lightbridge query API | [`lightbridge-query-api.md`](./lightbridge-query-api.md) |
| Why a usage query is slow, what the covering index and `metrics` buy, how to re-measure on the replica | [`usage-performance.md`](./usage-performance.md) |
| Which build a service is running (`GET /version`, `getBuildInfo`, `--version`) | [`build-info.md`](./build-info.md) |
| One `sharedConfig` object instead of five copies of `config.yaml` (chart contract) | [`single-source-config.md`](./single-source-config.md) |
| Book a budget grant, or author a reset schedule, from a Job or an exec — `budget grant` / `budget schedule` flags, idempotency, the $8-vs-$15 rule, why never raw SQL | [`budget-cli.md`](./budget-cli.md) |
| Budget refill decision contract (`Facts`/`Decision`/`PolicyEngine`) | [`budget-decision-contract.md`](./budget-decision-contract.md) |
| Budget refill UI contract (RPC shapes, for the frontend team) | [`budget-refill-ui-contract.md`](./budget-refill-ui-contract.md) |
| Manual end-to-end protocol (OAuth2 + OPA) | [`test-protocol.md`](./test-protocol.md) |
| API key approaching-expiry visibility | [`api-key-expiry-visibility.md`](./api-key-expiry-visibility.md) |
| Admin identity resolution (`user:read`) | [`admin-identity-resolution.md`](./admin-identity-resolution.md) |
| Sessions API (`querySessions`, `revokeSession`) | [`sessions-api.md`](./sessions-api.md) |
| Auth reference (identity vs. location, OIDC details) | [`auth-reference.md`](./auth-reference.md) |
| OAuth/OIDC standards roadmap | [`oauth-oidc-standards-roadmap.md`](./oauth-oidc-standards-roadmap.md) |
| OIDC token-exchange integration | [`token-exchange-integration.md`](./token-exchange-integration.md) |

### Decision records, RFCs, runbooks, plans

| Want to… | Open |
| --- | --- |
| Architecture Decision Records (33) — why the system is shaped this way | [`adr/`](./adr/) |
| Budget refill RFC (the original design proposal) | [`rfc/`](./rfc/) |
| Operational runbooks (**release & rollout**, tier re-key, stuck refill, policy rollback, signing keys) | [`runbooks/`](./runbooks/) |
| Release narratives — why a batch of PRs was one thing, and what is live | [`releases/`](./releases/) |
| Work/analysis plans | [`plans/`](./plans/), [`research/`](./research/) |
| Migration plans: authkestra `=0.6.3 → 0.7.0`, cratestack `=0.9.4 → 0.10.0` | [`plans/`](./plans/) (`authkestra-0.7.0-migration.md`, `cratestack-0.10.0-migration.md`) |
| The 200-LoC gate, its grandfather baseline, and the behaviour-preserving split rules | [`code-size-baseline.md`](./code-size-baseline.md) |
| Per-platform Helm install/config/deploy commands | [`platform-guides.md`](./platform-guides.md) |

### Working on this repo with an AI coding agent

| Want to… | Open |
| --- | --- |
| Know which skills and agents exist, and how a non-Claude harness (VS Code Copilot, OpenCode, Antigravity, Cursor) picks them up | [`agent-harnesses.md`](./agent-harnesses.md) |
| Add a cratestack procedure, write a migration, verify a change, ship a release, open a governance PR, measure a usage query | `.claude/skills/*/SKILL.md` — indexed in [`../AGENTS.md`](../AGENTS.md#skills-and-agents) |

---

## Crate / package layout at a glance

| Crate | Role |
| --- | --- |
| `crates/lightbridge-authz-core` | Shared types, config, errors, crypto, DB pool, id minting (`cuid2`) |
| `crates/lightbridge-authz-api` | cratestack schema + generated CRUD surface (`authz.cstack`) |
| `crates/lightbridge-authz-api-key` | SQLx entities + hand-written repo (ADR-0038 exception) |
| `crates/lightbridge-authz-rest` | Axum server glue: handlers, routers, models, middleware, RPC procedures |
| `crates/lightbridge-authz-bearer` | JWT validation via JWKS (authkestra-resource) |
| `crates/lightbridge-authz-budget` | Budget domain: ledger, policy engine, refill/review services |
| `crates/lightbridge-authz-usage` | OTEL ingest + usage query server |
| `app/lightbridge-authz` | Binaries: authz server, MCP server, healthcheck, migrations |
| `app/lightbridge-authz-usage` | Usage binary (server, migrations, config validation) |

---

## Key conventions & gotchas (from `AGENTS.md`)

- **Every id minted here is a CUID2** (`authz_core::cuid::cuid2`). Never write a new `Uuid::new_v4`. Never validate an id's shape — ids are opaque strings.
- **CBOR is the only wire codec** for the RPC/CRUD surface (ADR-0013); `application/json` gets `415`.
- **Redis is mandatory** for `authz-api` / `authz-idp` / `authz-budget` — they refuse to start without it.
- **The `authz-idp` surface is mandatory** (ADR-0023) — every route is mounted on every deployment.
- **cratestack is the only sanctioned database API** (ADR-0038); this repo carries the estate's largest hand-written-SQL exception list — read `AGENTS.md` "Persistence" before adding SQL.
- **CI runs `clippy … -- -D warnings`** — there is no advisory tier; `warn` and `deny` both fail the build.
- **The `authz-ui` pin (`Dockerfile` `ARG AUTHZ_UI_REF=`) is a deploy, not a dependency** — pinned by digest, reviewed like a code change (ADR-0029).

See [`../AGENTS.md`](../AGENTS.md) for the full, authoritative version of every rule above.

---

## Keeping this map honest

This page is a *map*, not a source of truth. When a code or doc change moves the system, update the
pointer here rather than duplicating content — the linked documents are the canonical home of their
subject matter. If a linked document moves, fix the link here too.
