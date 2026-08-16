# Services

Per-service responsibility, protection, and routes — each grounded in the router source
(`crates/lightbridge-authz-rest/src/{lib.rs,routers,handlers,signing.rs,token_exchange.rs}`,
`app/lightbridge-authz/src/mcp.rs`, `crates/lightbridge-authz-usage/src/{lib.rs,routers}`), not
copied from prose. Where a route in an existing doc did not match the router source at the time of
writing, the code wins — see "Corrections to prior docs" at the end.

## `authz-api`

**Responsibility:** account/project/API-key CRUD, native OAuth2/OIDC token issuance (self-signed
JWT mode), RFC 8693 token exchange, and RFC 7009 revocation. The budget domain's RPC procedures
moved off this service onto `authz-budget` (hard cutover, not a transitional duplication) — see
below.
**Owns:** the `authz` Postgres database (all tables), plus Redis for rate limiting, request
idempotency, and `private_key_jwt` replay tracking.

Router assembly: `build_api_router` in `crates/lightbridge-authz-rest/src/lib.rs`.

| Route | Method | Protection | Notes |
| --- | --- | --- | --- |
| `/`, `/healthz`, `/healthz/startup`, `/healthz/ready` | GET | none | `/healthz/ready` checks DB reachability. |
| `/.well-known/openid-configuration` | GET | none | Only mounted when `oauth2.type: self` (`signing::well_known_router`). |
| `/.well-known/jwks.json` | GET | none | Same gate as above. |
| `/oauth2/token` | POST | none (credential is the presented token) | RFC 8693 token exchange + `refresh_token` grant. Only mounted when `token_exchange.enabled`. `project_id` is an optional form param — the caller's default project resolves when omitted. |
| `/oauth2/revoke` | POST | none (credential is the presented token) | RFC 7009. Live and functional the moment the router is merged, but absent from `/.well-known/openid-configuration` — `authkestra-op`'s `OidcDiscovery` has no `revocation_endpoint` field yet (upstream issue filed, see `signing.rs`). |
| `/rpc/{op_id}` | POST | Bearer JWT, then `rpc_authorize` RBAC gate (`RpcScope::Crud`), then cratestack's own per-model `@@allow` | The generated CRUD surface (accounts, projects, api-keys, project members) plus the hand-written procedures below. Any `budget:*`-gated op-id 404s here — moved to `authz-budget`. |
| `/rpc/batch` | POST | same as above, per-frame | Batched RPC calls; each frame is authorized individually (#165), including the out-of-scope check — a batch frame aimed at a budget op-id 404s too (`CratestackAuthProvider::authenticate`, not merely the outer gate). |

Hand-written procedures reachable only via `/rpc/{op_id}` (not cratestack-generated —
`crates/lightbridge-authz-api/schema/authz.cstack` declares them, `Procedures` in
`crates/lightbridge-authz-rest/src/lib.rs` implements them):

- Session revocation: `revokeOwnSessions` (self-service "log out everywhere," no subject field on
  the input — structurally incapable of targeting anyone else), `revokeSubjectSessions` (admin
  offboarding kill switch, gated on `session:revoke`) — see [`auth-flows.md`](./auth-flows.md) and
  [`../rbac.md`](../rbac.md).

`build_api_router`'s outermost layer on the RPC surface is `rpc_authorize::rpc_authorize` —
rejected there with `403`/`404` before the request consumes idempotency/rate-limit budget or
reaches cratestack's own membership `@@allow` dispatch. The wire codec is CBOR-primary/JSON-
secondary in production, JSON-only in dev/CI (`AGENTS.md`, `server.api.codec`).

## `authz-budget`

**Responsibility:** the budget domain's RPC procedures — policy lifecycle, self-service refill,
the admin review queue, and direct balance/ledger reads/writes — carried off `authz-api` as a hard
cutover (not a transitional duplication like `authz-idp` below). See
[`budget.md`](./budget.md) for the full domain writeup and
[`../rbac.md`](../rbac.md) for the permission mapping.
**Owns:** nothing of its own — reads/writes the same `authz` Postgres database as `authz-api`
(`budget_grants`, `budget_balances`, `budget_policy_sets`/`budget_policy_revisions`,
`budget_augmentation_requests`), plus Redis for rate limiting and request idempotency (its own
key-prefixed token buckets, isolated from `authz-api`'s).

Router assembly: `build_budget_router` in `crates/lightbridge-authz-rest/src/lib.rs`.

| Route | Method | Protection | Notes |
| --- | --- | --- | --- |
| `/`, `/healthz`, `/healthz/startup`, `/healthz/ready` | GET | none | Same probe wiring as every other server (`probe_router`), `/healthz/ready` checks DB reachability. |
| `/budget/rpc/{op_id}` | POST | Bearer JWT, then `rpc_authorize` RBAC gate (`RpcScope::Budget`), then cratestack's own per-model `@@allow` | Mounted under a **fixed** `/budget` prefix (not the configurable `rpc_base_path` `authz-api` uses — see `config::BudgetServer`'s doc comment). Any non-`budget:*` op-id 404s here, including the whole CRUD surface. |
| `/budget/rpc/batch` | POST | same as above, per-frame | Same per-frame scope + permission enforcement as `authz-api`'s batch endpoint. |

Reachable procedures (all hand-written — ADR-0010 — declared in
`crates/lightbridge-authz-api/schema/authz.cstack`, implemented on the same `Procedures` type
`authz-api` uses; `RpcScope::Budget` is what actually restricts this server to only these 14):

- Policy lifecycle: `activateBudgetPolicy`, `getBudgetPolicyStatus`, `simulateBudgetPolicy`,
  `createBudgetPolicyRevision`.
- Self-service refill + admin review: `requestBudgetRefill`, `listPendingAugmentationRequests`,
  `approveAugmentationRequest`, `rejectAugmentationRequest`.
- Direct balance/ledger reads: `getMyBudgetBalance`, `listMyBudgetGrants`, `getBudgetBalance`,
  `listBudgetGrants`.
- Direct admin grant/revoke: `grantBudget`, `revokeBudgetGrant`.

Every procedure keeps its exact `docs/rbac.md`-mandated permission unchanged by the move — the
split only changes *which host and path prefix* serves it, not what a caller needs to hold to call
it. `authz-budget` constructs its own `AuthzStoreImpl`/cratestack pool/idempotency store the same
way `authz-api` does, purely because `Procedures::new` requires them as a type-level obligation
(the CRUD op-ids they back are never actually dispatchable here) — see `build_budget_router`'s doc
comment for why this is not a real dependency on the CRUD domain.

## `authz-opa`

**Responsibility:** validates presented API-key secrets, resolves subject+project context for the
Keycloak IdP adapter, and records usage telemetry (`last_used_at`, `last_ip`) on every successful
validation. This is the only service Envoy/Authorino ever calls.
**Owns:** nothing of its own — reads the same `authz` Postgres database as `authz-api`, read-mostly
plus telemetry writes.

Router assembly: `build_opa_router` in `crates/lightbridge-authz-rest/src/lib.rs`, protected routes
in `crates/lightbridge-authz-rest/src/routers/mod.rs::opa_router`.

| Route | Method | Protection | Notes |
| --- | --- | --- | --- |
| `/`, `/healthz`, `/healthz/startup`, `/healthz/ready` | GET | none | |
| `/v1/opa/docs`, `/v1/opa/openapi.json` | GET | none | The one server in this repo that still publishes Swagger UI/OpenAPI — see `AGENTS.md`. |
| `/v1/authorino/validate/introspect` | POST | Basic auth | Form-encoded, RFC 7662-shaped. Hashes the presented secret, loads `api_keys` by hash, rejects unknown/revoked/expired/suspended (account or project) as `{"active": false}`, updates telemetry, returns enriched context. |
| `/idp/v1/resolve-context` | POST | Basic auth | `{subject, project_id} -> {account_id, project_id}`. A project resolves when the subject owns its account or holds a `project_members` row for it (ADR-0006); non-member and unknown-project are the same uniform `404`, deliberately, so the endpoint never leaks which projects exist. |

**Correction to prior docs:** `AGENTS.md` and the pre-existing `docs/architecture.md` describe a
`POST /v1/opa/validate` "minimal validation endpoint." No such route exists in
`crates/lightbridge-authz-rest/src/routers/mod.rs` — the only validation route mounted today is
`/v1/authorino/validate/introspect`. Flagged for AGENTS.md maintenance separately; not corrected
here since AGENTS.md is outside this PR's file scope.

## `lightbridge-mcp`

**Responsibility:** exposes the CRUD/validation surface as MCP tools over streamable HTTP, plus
OAuth discovery metadata and dynamic client-registration proxying for MCP clients. Derives caller
identity from the JWT (no subject in tool input).
**Owns:** nothing of its own — calls the same `AuthzStoreImpl` the REST handlers use, backed by the
same `authz` Postgres database, via `crates/lightbridge-authz-rest`.

Router assembly: `app/lightbridge-authz/src/mcp.rs` (search around line 1607).

| Route | Method | Protection | Notes |
| --- | --- | --- | --- |
| `/`, `/healthz`, `/healthz/startup`, `/healthz/ready` | GET | none | |
| `/.well-known/oauth-authorization-server` | GET | none | Proxied OAuth authorization-server metadata. |
| `/.well-known/openid-configuration` | GET | none | |
| `/oauth/register` | POST | none | Proxies dynamic client registration to a configured upstream registration endpoint. Public registration URLs are derived from forwarded/host headers when present. |
| `/mcp` | (streamable HTTP) | Bearer JWT (`bearer_auth` middleware, `nest_service`) | The MCP tool surface itself. Stateless (`with_stateful_mode(false)`) so it works safely behind multi-replica round-robin — see the multi-replica gotcha this repo already hit. |

The tool set is generated from `#[tool]`-annotated methods on the MCP handler in `mcp.rs`, not
duplicated here — the exact set drifts easily and this table would go stale faster than the code;
read the `#[tool]` annotations directly if you need the current list. The budget domain is **not**
exposed over MCP today — only over `authz-api`'s `/rpc/*` surface.

## `lightbridge-authz-usage`

**Responsibility:** ingests OTLP/HTTP traces, metrics, and logs (JSON or protobuf, optional gzip),
normalizes attributes across compatibility aliases, and serves a single aggregated usage-query
endpoint.
**Owns:** the usage database — a Timescale hypertable when the extension is available, plain
Postgres table otherwise, independent of the `authz` database.

Router assembly: `crates/lightbridge-authz-usage/src/{lib.rs,routers/mod.rs}`.

| Route | Method | Protection | Notes |
| --- | --- | --- | --- |
| `/`, `/healthz`, `/healthz/startup`, `/healthz/ready` | GET | none | |
| `/usage/v1/usage/docs` | GET | none | OpenAPI/Swagger UI for the query endpoint. |
| `/v1/otel/traces` | POST | **none** | OTLP trace ingest. |
| `/v1/otel/metrics` | POST | **none** | OTLP metric ingest. |
| `/v1/otel/logs` | POST | **none** | OTLP log ingest. |
| `/usage/v1/usage/query` | POST | **none** | Scoped, date-bin-aggregated usage query; no `scope_id` ownership check either. |

This service has no application-level authentication anywhere on its data-plane routes. That is a
known, accepted gap today — see [`README.md`](./README.md)'s context-diagram notes and
[`deployment.md`](./deployment.md) for why it is currently safe (network topology, not application
auth) and what would need to change before it could be routed externally.

## Crate layering behind `authz-api` / `authz-opa`

Both server binaries above are assembled from the same Cargo workspace. The dependency edges below
are the ones each crate's own `Cargo.toml` declares — not transitive closures — verified against
the manifests directly.

```mermaid
flowchart BT
    core["lightbridge-authz-core"]

    subgraph domain["Domain crates — siblings, not layers"]
        apikey["lightbridge-authz-api-key"]
        budget["lightbridge-authz-budget"]
    end

    bearer["lightbridge-authz-bearer"]
    api["lightbridge-authz-api"]
    rest["lightbridge-authz-rest"]

    apikey --> core
    budget --> core
    bearer --> core
    api --> bearer
    rest --> api
    rest --> apikey
    rest --> budget
    rest --> bearer
    rest --> core
```

- **`core`** is the shared foundation: domain DTOs, config loading, the SQLx pool, crypto (API-key
  hashing), errors, TLS serving, tracing, and the CUID2 chokepoint (`cuid::cuid2()`).
- **`api-key`** persists accounts, projects, project members, API keys, signing keys, and exchange
  refresh tokens — hand-written SQLx (ADR-0038 exception), not cratestack.
- **`budget`** is a **sibling of `api-key`, not a layer beneath `api`** (ADR-0010): it owns its own
  persistence (`BudgetRepo`, `AugmentationRepo`), and `rest` calls it directly from hand-written
  `Procedures` methods, deliberately bypassing the cratestack model-generation path `api` uses for
  the CRUD surface. `api` has no dependency edge on `budget` or `api-key` at all — confirmed by
  `crates/lightbridge-authz-api/Cargo.toml`, which lists only `cratestack`, `serde`, and
  `lightbridge-authz-bearer`.
- **`bearer`** validates JWT bearer tokens via JWKS; both `api` (transitively) and `rest` depend on
  it directly.
- **`api`** owns `schema/authz.cstack` and the cratestack-generated CRUD models, RPC router, and
  `ProcedureRegistry` trait — the schema-first codegen layer. It does not persist anything itself.
- **`rest`** is the only crate that assembles a real Axum server: it wires `api`'s generated router,
  `api-key`'s repository, `bearer`'s validation, and `budget`'s procedures together with TLS,
  middleware, and the OPA/MCP-specific handlers.
- **`proto`** (`crates/lightbridge-authz-proto`) is not a workspace member — it exists in the
  source tree but is not built or depended on by anything (`Cargo.toml`'s `[workspace] members`).

Two further packages sit outside this diagram: the `lightbridge-authz` package (produces the
`lightbridge-authz` and `lightbridge-mcp` binaries; depends on `rest`, `api`, `api-key`, `bearer`,
`core`) and the `lightbridge-authz-usage` package (produces the usage binary; depends on the
sibling `lightbridge-authz-usage-rest` crate — note the crate directory is
`crates/lightbridge-authz-usage` but its declared package name is
`lightbridge-authz-usage-rest` — and `core`). Both are independent of the diagram above; the usage
service shares no crate with `authz-api`/`authz-opa`/`lightbridge-mcp` beyond `core`.

`authz-budget` (and `authz-idp` before it) adds no node to this diagram at all — it is the same
`lightbridge-authz` binary, gated behind its own `Commands::Budget` subcommand
(`app/lightbridge-authz/src/main.rs`), calling `build_budget_router`/`start_budget_server` in the
same `rest` crate that already depended on `budget`/`api-key`/`api`/`bearer`/`core` for
`authz-api`. Splitting the *service* did not require splitting a single crate — see
[`budget.md`](./budget.md), "Why one `Procedures` impl, not a second schema/crate", for why the
RPC-surface split is enforced at the routing layer (`RpcScope`) instead.
