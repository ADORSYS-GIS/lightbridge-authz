# ADR-0003: Migrate authz-api CRUD to cratestack-pg

- Status: Accepted
- Date: 2026-07-21
- Decision owners: Lightbridge Authz maintainers

## Context

`authz-api` is the OAuth2/JWT-protected CRUD surface for `accounts`, `projects`, and `api_keys`. Its
persistence today is hand-written `sqlx` in `StoreRepo`
(`crates/lightbridge-authz-api-key/src/repo.rs`): row structs, `QueryBuilder` assembly for partial
updates, and manual mapping for every read/write path. ADR-0002 explicitly rejected adopting an ORM
for the workspace restructuring, on the grounds that the complex behavior lives in authorization CTEs
and aggregation queries rather than row-mapping boilerplate — that reasoning holds for the
non-CRUD paths and is not being revisited here.

The CRUD paths are a different story. Create/read/update/delete/list for three tables account for a
large share of `StoreRepo`'s size and nearly all of its routine maintenance churn (adding a column,
threading it through the row struct, the `QueryBuilder`, the DTO, and the OpenAPI schema, four times
over). `cratestack-pg` (crates.io `cratestack-pg`, currently 0.4.9, homepage cratestack.dev) is a
schema-first codegen framework built by one of this repository's own maintainers: it generates the
CRUD repository layer and a typed Rust client from the schema, which is exactly the boilerplate this
codebase keeps re-deriving by hand. It is pre-1.0 (documented breaking changes across 0.x releases,
~133 downloads at time of writing) and has no OpenAPI generation.

`StoreRepo` is not a pure CRUD repository, though. It is shared by two different consumers on the
same tables:

- **CRUD**, consumed by `authz-api`: account/project/api-key create, read, update, delete, list.
- **Non-CRUD, security-critical**, consumed by `authz-opa`, the Keycloak SPI adapter, and native
  token exchange: `find_api_key_validation_by_hash`, `record_api_key_usage`, `resolve_context`
  (backs `POST /idp/v1/resolve-context`, see ADR-0001), `get_active_signing_key` /
  `ensure_active_signing_key`, the `exchange_refresh_tokens` methods, and the `account_memberships`
  authorization CTE embedded in nearly every account/project query.

Only the first group is boilerplate CRUD. The second group is exactly the hand-rolled-SQL complexity
ADR-0002 chose to keep hand-rolled, and `cratestack-pg` does not attempt to cover it.

## Decision

Adopt `cratestack-pg` for the CRUD read/write path of `accounts`, `projects`, and `api_keys`, scoped
to `authz-api` only. `authz-opa`, `lightbridge-mcp`, and `lightbridge-authz-usage` are unaffected.

### Scope boundary

- `cratestack-pg` owns: schema definition, generated repository CRUD methods, and the generated Rust
  client for `accounts`, `projects`, `api_keys`, consumed by `authz-api`'s controllers.
- Hand-written `sqlx` continues to own: `find_api_key_validation_by_hash`, `record_api_key_usage`,
  `resolve_context`, signing-key methods, exchange-refresh-token methods, and every query built on
  the `account_memberships` CTE. These are retargeted at the same cratestack-managed tables — they
  keep reading/writing `accounts`/`projects`/`api_keys` directly via `sqlx`, cratestack does not sit
  in front of them.
- Both paths share one Postgres database and the same tables. This is the one place the two
  ownership models touch: a schema change to a CRUD-relevant column (e.g. `allowed_models`) must be
  made once and be visible to both the cratestack-generated code and the hand-written queries.

### RPC transport, not REST

`authz-api`'s schema declares `transport rpc`. This is a real, confirmed schema directive:
`cratestack-pg` supports exactly two mutually exclusive route bindings per schema — REST
(`/accounts`, `/accounts/{id}`, ...) or RPC (`POST /rpc/{op_id}`, `POST /rpc/batch`) — "there is no
runtime flip and no schema runs both." Every model verb and procedure gets a stable dotted op-id
(`model.Account.list`, `procedure.rotateApiKey`) used as the dispatch key in the URL path rather than
being inferred from the HTTP verb and path shape.

This is a larger contract change than "swap the wire format": it replaces authz-api's REST route
shape outright, not just its codec. Any integrator coded against `POST /accounts`-style URLs (there
are none yet in production — this is a pre-GA surface) has to move to the op-id dispatch model.
Batch requests (`POST /rpc/batch`) and per-frame idempotency (an `idem` field per frame, distinct
from the `Idempotency-Key` header used for single requests — see Idempotency below) come as part of
this transport, not as separately-built features.

### Collapse of the `AuthzStore` trait indirection

`crates/lightbridge-authz-api/src/store.rs` (`AuthzStore` trait) and its single implementation
(`StoreRepo`'s CRUD methods) existed to abstract persistence behind a trait boundary. `cratestack-pg`
is usable directly as the CRUD ORM/runtime — controllers and procedure handlers call the generated
model delegates (`cool.account().create(...)`, `cool.project().find_many()...run(ctx)`, etc.)
directly. The `AuthzStore` trait's CRUD methods and its single impl are deleted rather than kept as a
wrapper around the generated client; there was only ever one implementation, so the trait indirection
had no polymorphism to justify keeping. `StoreRepo` survives only for the non-CRUD methods listed in
Scope boundary above.

### Mixins for shared fields

`crates/lightbridge-authz-api/schema/authz.cstack` uses `mixin` blocks (`@use(...)` on the model) for
the `createdAt`/`updatedAt` pair repeated across `Account`, `Project`, and `ApiKey`, instead of
hand-declaring the pair three times. Mixins are field-only (no `@id`, no relations, no policy
attributes) and are expanded into the model before codegen, so this is purely a schema-authoring
convenience — it changes nothing about the generated Rust types or the underlying columns.

### Pagination (`@@paged`) on all four models

`Account`, `Project`, `ApiKey`, and `AccountMembership` all declare `@@paged` (bare form — confirmed
against real cratestack source that configurable paging modes aren't implemented yet). Every
generated `list` route (REST and RPC alike) wraps its response in
`Page<T> { items, totalCount, pageInfo: { limit, offset, hasNextPage, hasPreviousPage } }` instead of
a bare array, and the handler runs a second count-only query per call for `totalCount`. This only
affects HTTP-facing consumers (the RPC surface, and the generated Rust/TS *client*) — the raw
server-side query builder (`cool.account().find_many()...run(ctx)`, what `lib.rs`'s procedures and
`mcp.rs` call directly) is unaffected and still returns a plain `Vec<T>`; confirmed by the workspace
compiling unchanged after `@@paged` was added, and matching the codegen split found in
`cratestack-macros/src/axum/model/handlers_list.rs` / `prep/list_logging.rs` (paging is applied by the
axum handler and the generated client after calling the same underlying query, not inside the sqlx
query builder itself).

**Upstream gap — FIXED in 0.4.11.** cratestack previously did not clamp `limit`/`offset`
server-side (`parse_model_list_query` parsed them as plain unbounded `i64`); filed as
[cratestack/cratestack#123](https://github.com/cratestack/cratestack/issues/123) and fixed in
[cratestack/cratestack#126](https://github.com/cratestack/cratestack/pull/126) (0.4.11, merged
2026-07-22): a new `MAX_LIST_LIMIT = 1000` constant now rejects an explicit `limit` above it with
`400`, and — note the behavior change — **defaults an omitted `limit` to `1000` rather than leaving
it unbounded** (previously the easy way to bypass a would-be cap). Applies identically to REST and
RPC list dispatch (the same fix added `rpc_pagination.rs` proving RPC `model.<M>.list` matches REST's
`Page<T>` envelope and cap). No caller in this codebase currently relies on an unbounded/omitted
`limit` returning more than 1,000 rows — confirmed by the full test suite passing unchanged after the
0.4.11 upgrade.

### Soft-delete for `api_keys` only

`ApiKey` declares `@@soft_delete` with a `deletedAt DateTime?` field (mapped to a fixed `deleted_at`
column). This changes what the generated `delete()` verb does for API keys: instead of a hard
`DELETE FROM api_keys`, it becomes `UPDATE api_keys SET deleted_at = NOW() WHERE id = $1 AND
deleted_at IS NULL`, and every generated read (`find_unique`, `find_many`, `update`, `delete`) adds
`deleted_at IS NULL` to its predicate automatically. `Account` and `Project` are unaffected and keep
hard delete via the existing `ON DELETE CASCADE` foreign keys.

This is deliberately a different axis from the existing `status = 'revoked'` business state
(`set_api_key_status` in `StoreRepo`): soft-delete governs what the CRUD `delete` verb does to the
row; `status`/revocation is an explicit state transition that keeps the row fully live and queryable.
Both continue to exist side by side.

**Coordination hazard, not yet resolved by this ADR**: the hand-written `api_key_validation` SQL view
(`migrations/20260714000001_account_project_status.sql`, consumed by `authz-opa` for the
security-critical validation decision) does not currently filter on any soft-delete column. Once
`deleted_at` exists, that view must add `AND k.deleted_at IS NULL` — otherwise a soft-deleted API key
would still validate successfully at the OPA layer, which is a real security regression, not merely a
staleness inconvenience. This is tracked as an implementation task, called out here so it is not
missed during the cutover.

### Audit log

`Account`, `Project`, and `ApiKey` declare `@@audit`. Every create/update/delete on these models
writes a row to a framework-managed `cratestack_audit` table (actor, before/after snapshots,
operation, primary key, timestamp) inside the same transaction as the mutation — "no audit row
without a row, no row without an audit row." `AccountMembership` (the junction table backing
membership-scoped policy checks) does not get `@@audit` in this ADR; whether membership add/remove
needs audit coverage is left as an open question for the implementation to flag, not decided here.

### Idempotency

`authz-api`'s router is wrapped in `IdempotencyLayer` (Postgres-backed store,
`cratestack_idempotency` table, `SqlxIdempotencyStore`). Clients that send an `Idempotency-Key`
header get exactly-once mutation semantics (request hash = SHA-256 of method + full path + querystring
+ content-type + body; a second identical request replays the cached response instead of re-executing).
Requests without the header are unaffected — this is opt-in middleware, not a schema change.

### Rate limiting (Redis-backed)

`authz-api`'s router is wrapped in `RateLimitLayer` backed by a custom `RateLimitStore`
implementation over Redis. `cratestack-axum` ships the trait and an in-memory reference
implementation, but — confirmed by reading the actual guide — does **not** ship a Redis
implementation; "Redis-backed implementations are the typical choice" for multi-replica deployments,
but the concrete `impl RateLimitStore for RedisRateLimitStore` has to be hand-written against the
trait in this repo. This is new code, not adopted-as-is from cratestack, and needs a Redis instance
added to `compose.yaml` (and Helm values for prod) that does not exist in the stack today.

### Materialized views: scoped to non-security-critical reads only

`cratestack-pg` supports `@@materialized` views, refreshed explicitly (never automatically on write) —
scheduled, on-demand, or event-debounced. Because refresh is explicit and therefore eventually
consistent by design, this ADR **explicitly excludes** applying it to anything in the validation path:
the hand-written `api_key_validation` view stays hand-written, synchronous, and outside cratestack's
materialized-view mechanism, because a stale materialized view could let a revoked or suspended key
keep validating until the next refresh. A materialized view is used only for a genuinely
stale-tolerant read aggregate (e.g. per-account project/key counts for a dashboard-style list read),
never for an authorization or validation decision.

### AuthProvider bridges the existing JWT/JWKS validation

`authz-api`'s existing bearer-token/JWKS validation (`crates/lightbridge-authz-bearer`) is wrapped in
a `CratestackAuthProvider` implementing cratestack's `AuthProvider` trait, rather than reimplemented.
`authenticate()` extracts and validates the bearer token exactly as today, then projects the resulting
subject/role claims into `CoolContext` so `@@allow`/`@@deny` policy expressions can reference
`auth().id` / `auth().role` (or the `lightbridge_api_roles` claim shape already in use, see
`docs/rbac.md`). This is glue code around existing validation, not new authentication logic.

### Crypto reference: no change to secret handling

`cratestack`'s "crypto" reference page covers rustls TLS backend selection (`ring` vs. FIPS-validated
`aws-lc-rs`), not application-layer hashing/encryption. There is no schema attribute for hashing a
column or generating a secret. `api_keys.key_hash` generation and comparison remain exactly as they
are today — hand-written in `lightbridge-authz-core`/`StoreRepo`, on the non-CRUD side of the scope
boundary above, unaffected by this migration.

### CBOR in production, JSON in dev/CI

`authz-api`'s production router will be instantiated with cratestack's CBOR codec. Local/dev/CI
instantiate the same router with the JSON codec instead, so `curl`, Swagger-adjacent tooling, and
debugging stay usable. This is scoped to `authz-api` — `authz-opa`'s and the usage service's routers
are untouched and remain JSON.

RPC transport (above) changes the concrete mechanism available for this: `cratestack-axum` exposes a
`CodecSet<Primary, Secondary>` that implements the codec trait by dispatching on the literal
`Content-Type` of each request, so a single router instance can legitimately accept both `CborCodec`
and `JsonCodec` at once (used this way in cratestack's own RPC example). The environment split stays
the decision — prod defaults to CBOR, dev/CI defaults to JSON — but whether that is implemented as
two differently-constructed router instances (single codec each) or one `CodecSet`-based router with
an environment-driven default/allowlist is an implementation detail for the cutover task to resolve
against real behavior, not a re-litigation of the decision itself.

### Loss of Swagger UI for the CRUD surface

`SwaggerUi::new("/api/v1/docs")` and the `utoipa`-generated `ApiDoc` in
`crates/lightbridge-authz-rest/src/lib.rs` / `crates/lightbridge-authz-api/src/openapi.rs` are removed
for the CRUD surface. `cratestack-pg` has no OpenAPI generation. `authz-opa`'s `/v1/opa/docs` and the
usage service's Swagger UI are unaffected and stay as-is. The generated cratestack Rust client becomes
the primary integration contract for `authz-api` consumers going forward, replacing the OpenAPI
document as the thing integrators code against.

### Pre-1.0 risk, accepted

`cratestack-pg` is early and has broken compatibility across 0.x releases. This is accepted because:

- It is the author's own product, and this migration doubles as production dogfooding that directly
  informs its 1.0 design.
- The alternative is not zero-risk — it is the perpetual cost of hand-maintaining CRUD `sqlx` and its
  `QueryBuilder` assembly across three tables, which is exactly the churn this decision removes.

A spike-then-ADR sequencing was considered — prototype first, write the ADR after — but given time
constraints this ADR reflects the decision to proceed with the full migration directly. A throwaway
spike that validates policy-expressibility (can `account_memberships`-style tenant scoping still be
layered on top of cratestack-generated queries where needed) and CBOR wiring still happens before the
full cutover lands, but it is tracked and executed separately and does not gate this ADR.

**Version pin:** this migration went in against `cratestack-pg` `0.4.9`, then upgraded the whole
family (`cratestack-pg`/`cratestack-core`/`cratestack-axum`/`cratestack-redis`/
`cratestack-codec-{cbor,json}`) to `0.4.10` once released, to pick up the fixes for two of the four
bugs found during the spike — see "Known cratestack-pg 0.4.9 bugs" below for what's fixed and what
workarounds are (deliberately, for now) still in place on top of the fix.

### Known cratestack-pg 0.4.9 bugs found during this migration

The required spike (see Pre-1.0 risk above) surfaced four real, reproduced bugs in `cratestack-pg`
`0.4.9` — worth recording here in one place since this migration is explicitly dogfooding the
author's own product and these are exactly the class of finding that should feed back into it. Items
1 and 2 were filed upstream as
[cratestack/cratestack#116](https://github.com/cratestack/cratestack/issues/116) and
[#117](https://github.com/cratestack/cratestack/issues/117), and both were **fixed and released in
`cratestack-pg` 0.4.10** via
[cratestack/cratestack#120](https://github.com/cratestack/cratestack/pull/120) (merged 2026-07-22),
which this migration adopted (see Pre-1.0 risk's version-pin note below). The workarounds described
below are **intentionally left in place for now** — the fix landing means the underlying bug no
longer blocks anyone, but reverting the workarounds (restoring generated `run_in_tx`/full `@@audit`
coverage on `rotateApiKey`/`revokeApiKey`/`createApiKey`/`createAccount`) is deliberately deferred to
a separate follow-up rather than bundled into the version bump, to keep that change reviewable on its
own.

1. **`run_in_tx` self-deadlock on chained calls — FIXED upstream in 0.4.10 (#116/#120).** Every
   `run_in_tx` call unconditionally re-ran `ensure_audit_table` DDL (including
   `CREATE INDEX IF NOT EXISTS`) against a fresh pool connection, not the caller's transaction. Two
   chained `run_in_tx` calls to `@@audit`-enabled models inside one caller-managed transaction
   deadlocked: the first call's audit insert held a lock the second call's `CREATE INDEX IF NOT
   EXISTS` needed, and the caller's own transaction couldn't advance to commit while blocked on the
   second call. Reproduced with a straightforward two-write rotate procedure. Upstream fix: the
   "audit table ensured" check is now cached per `SqlxRuntime` instead of re-issuing DDL on every
   write. **Workaround still in place here** (not yet reverted): `rotateApiKey`/`revokeApiKey`/
   `createApiKey`/`createAccount` do their writes via hand-written `sqlx` inside their own
   transaction rather than generated `run_in_tx` — which means these four procedures currently
   produce **no `cratestack_audit` rows**, unlike every plain CRUD create/update/delete elsewhere.
   Reverting to generated `run_in_tx` (now deadlock-free) would close that audit-coverage gap; this
   is the deferred follow-up referenced above.
2. **Soft-delete audit snapshot is wrong — FIXED upstream in 0.4.10 (#117/#120).** For `@@soft_delete`
   models, `delete()` ran an `UPDATE ... RETURNING *`, not a hard `DELETE ... RETURNING *`, but the
   audit code unconditionally treated the `RETURNING` row as the `before` snapshot and always wrote
   `after = null`. Confirmed by inspecting a real `cratestack_audit` row after a soft-delete: `before`
   already showed `deleted_at` set (the *post*-update state), `after` was `null`. Upstream fix:
   `before` now comes from a genuine pre-mutation row-locked read, `after` is now populated from the
   `RETURNING` row. This means `ApiKey`'s audit trail for the `delete` verb was misleading as shipped
   under 0.4.9 — that specific caveat no longer applies as of the 0.4.10 upgrade, since `ApiKey`'s
   soft-delete goes through the now-fixed generated path (it was never part of the `run_in_tx`
   workaround in item 1, which only covers the four hand-written procedures).
3. **`@default(dbgenerated())` DDL emitter produces invalid SQL**, and separately **requires a real
   Postgres-level `DEFAULT`** to exist for insert-time omission to work at all (an insert without a
   DB-level default for a `dbgenerated()` field fails with a `NOT NULL` violation, not a graceful
   fallback). See Migration ownership below — this is one of the two findings that changed the
   migration-ownership decision, and this migration works around the second half by adding real
   `DEFAULT now()` at the DB level via hand-written SQL for every `dbgenerated()`-typed column.
4. **`type` blocks cannot reference a model type as a field** (found while authoring the schema, see
   the inline comment on `ApiKeySecret` in `crates/lightbridge-authz-api/schema/authz.cstack`) —
   `type` structs are generated in a sibling module to model structs and the generator never emits the
   cross-module qualifier. Worked around by flattening the referenced model's fields directly into the
   `type` instead of nesting it.

None of these are worked around by silently changing behavior without a comment — each workaround is
documented at its call site with a pointer back to this ADR.

### Migration ownership — REVISED after the spike (schema-source-only, not cratestack-owned)

The original decision here was "`cratestack-pg` manages its own `cratestack_migrations` tracking table
and owns schema evolution for `accounts`/`projects`/`api_keys` going forward." **That decision is
reversed** based on the throwaway spike required by the Pre-1.0 risk section above, which produced a
concrete NO-GO with reproducible evidence, not a hypothetical concern:

- `cratestack migrate diff` in `0.4.9` is snapshot-vs-schema only — `cratestack-migrate`'s own README
  states live-database introspection (`drift`) is not yet implemented. Run with no prior snapshot
  against this repo's real schema, it emitted full `CREATE TABLE` statements for tables that already
  exist in the deployed database, and applying that output against the real, already-migrated,
  seeded `lightbridge_authz` database failed immediately (`relation "account_memberships" already
  exists`).
- A hand-bootstrapped snapshot (manually authoring a prior-state file that mirrors the live schema,
  then diffing against it) does mechanically work and produces a correct delta — but that delta hit a
  second, independent bug: `@default(dbgenerated())` (used by the `AuditFields` mixin, see Mixins
  above) emits literally invalid SQL in the generated `ALTER TABLE` — `DEFAULT dbgenerated()` as a
  literal, non-existent function call — confirmed by actually executing it and getting
  `function dbgenerated() does not exist`.

**Revised decision**: `authz.cstack` remains the source of truth for generated Rust types, the CRUD
repository layer, and policy — but it does not drive DDL. Schema changes to `accounts`/`projects`/
`api_keys` (including the columns this migration itself introduces — `api_keys.deleted_at`,
`api_keys.updated_at`, and DB-level `DEFAULT now()` on the `AuditFields`-mixin columns so
`dbgenerated()` insert-time omission actually works, see the RPC/CBOR item below) are written as
ordinary hand-written SQL migrations under `migrations/`, applied by the existing SQLx runner — the
same runner and the same directory used for every other schema change in this repository. There is
no second migration-tracking table, no dual-runner coordination risk, and no `cratestack_migrations`
table in this deployment. This removes what was previously flagged as "the highest-risk part of this
ADR" by eliminating the two-runner design entirely rather than accepting its risk.

Revisit cratestack-owned migrations once `cratestack migrate diff --backend postgres` supports live
introspection/baselining against an existing schema without emitting conflicting `CREATE TABLE`
statements, and once the `dbgenerated()` DDL emitter bug is fixed upstream.

### Hard cutover

Per repository convention, this lands as one PR that replaces the CRUD implementation in
`authz-api` outright. There is no gradual/parallel/dual-path/back-compat rollout: the hand-written CRUD
`sqlx` code in `StoreRepo` that only serves `authz-api`'s CRUD controllers is deleted in the same
change that introduces cratestack, not deprecated alongside it.

## Consequences

### Positive

- Removes the largest source of routine, low-value churn in `StoreRepo`: adding/changing a
  CRUD-exposed column no longer requires hand-updating a row struct, a `QueryBuilder` assembly, a DTO,
  and an OpenAPI schema in lockstep.
- A generated, typed Rust client becomes available to integrators of `authz-api`, which is a stronger
  contract than a hand-maintained OpenAPI document for Rust consumers.
- Production dogfooding of `cratestack-pg` directly benefits its 1.0 roadmap.
- Audit logging, idempotent mutations, and rate limiting become available on the CRUD surface as
  declarative/middleware concerns instead of hand-rolled code — capabilities the service did not
  have before this migration.
- Collapsing `AuthzStore`'s CRUD methods removes a trait boundary that had exactly one implementation
  and no polymorphism to justify it.

### Negative

- `authz-api` loses Swagger UI (`/api/v1/docs`) for the CRUD surface; non-Rust or ad-hoc integrators
  lose interactive API exploration and have to rely on the generated client or manual inspection of
  cratestack-generated routes. RPC transport (dotted op-ids in the URL path rather than REST-shaped
  routes) makes this loss more pronounced than a codec-only change would have.
- The CRUD contract changes shape, not just format: REST-style routes become RPC-style
  `POST /rpc/{op_id}` / `POST /rpc/batch`. Anything written against the pre-migration REST shape
  (tests, it-scripts, future integrators) has to be rewritten, not just re-encoded.
- Two independent migration tracking systems now operate against the same database. Coordination
  across the CRUD/non-CRUD schema boundary becomes a manual discipline rather than a tooling
  guarantee, and is the most likely source of an operational surprise from this change.
- `authz-api`'s production codec (CBOR) diverges from every other service's JSON codec, and from
  `authz-api`'s own dev/CI codec, which is a source of "works in dev, breaks in prod" class bugs if
  the two paths are not both exercised in CI.
- Taking a pre-1.0 dependency for a security-adjacent CRUD surface (account/project/api-key
  management) means breaking changes in `cratestack-pg` 0.x can force out-of-cycle rework in
  `authz-api`.
- `StoreRepo` becomes a narrower, non-CRUD-only module, but the split itself (CRUD table ownership by
  cratestack vs. hand-written queries against the same tables) is new conceptual surface for anyone
  reading `crates/lightbridge-authz-api-key/src/repo.rs` for the first time; this ADR is the reference
  for why that split exists.
- Rate limiting requires a hand-written `RateLimitStore` impl over Redis (not shipped by
  `cratestack-axum`) and a new Redis instance in the deployment topology — new operational surface
  this service did not previously have.
- Soft-delete on `api_keys` introduces a coordination hazard with the hand-written
  `api_key_validation` view (must add a `deleted_at IS NULL` filter, tracked separately — see
  Soft-delete above) — a missed update there is a fail-open security bug, not just a bug.

## Alternatives considered

### Keep hand-written sqlx CRUD (status quo)

Rejected as the default going forward, though it remains the model for the non-CRUD path. The
recurring cost of manually threading every schema change through row structs, `QueryBuilder`
assembly, DTOs, and OpenAPI schemas for `accounts`/`projects`/`api_keys` is the exact boilerplate
`cratestack-pg` removes, and ADR-0002's rejection of an ORM was scoped to authorization CTEs and
aggregation, not to routine CRUD.

### Adopt a mainstream ORM (SeaORM, Diesel) instead of cratestack-pg

Not pursued. `cratestack-pg` is schema-first codegen from the author's own toolchain, already
targeted at this style of Postgres/axum service, and adopting it also serves as production validation
for a project the author maintains. A mainstream ORM would solve the same CRUD-boilerplate problem
without that dogfooding benefit and without the pre-1.0 risk, but was not evaluated in depth for this
decision.

### Move all of StoreRepo (including validation/idp/token-exchange) to cratestack

Rejected. `cratestack-pg` covers CRUD only; it has no facility for the `account_memberships`
authorization CTE, constant-comparison-sensitive validation lookups, or refresh-token rotation
semantics. Forcing these through a CRUD-shaped codegen layer would either strip out
security-relevant behavior or require escape hatches that erase the benefit of adopting cratestack in
the first place.

### Gradual/dual-path migration (old sqlx CRUD alongside cratestack, feature-flagged)

Rejected per repository convention: no parallel/back-compat paths without an explicit reason to keep
one. A dual-path CRUD implementation would double the surface this ADR is trying to shrink, for the
duration of the flag's life.

### Keep REST transport, adopt cratestack only for persistence

Considered and rejected. `cratestack-pg` can be used purely as a CRUD/ORM layer while keeping
hand-written REST routing on top of it, avoiding the RPC route-shape change entirely. Rejected because
there are no existing external integrators of the current REST shape to protect (pre-GA surface), and
RPC transport is what makes the built-in per-frame idempotency and uniform op-id dispatch available
without hand-building equivalent routing.

### Keep `AuthzStore` as a thin wrapper around the generated cratestack client

Considered and rejected. Wrapping the generated client behind the existing trait would preserve a
mockable seam for tests, but there is exactly one production implementation and no planned second
one; the trait indirection was pure ceremony once the hand-written `sqlx` behind it is gone. Removed
in favor of calling the generated client directly from controllers/procedure handlers.
