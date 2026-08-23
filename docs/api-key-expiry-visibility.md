# API key expiry visibility (lightbridge-authz#436)

## Why this exists

lightbridge-authz#402 (policy issue #395) made `api_keys.expires_at` mandatory: every key now
carries a hard deadline (capped at the operator-configured `ApiKeyExpiry` ceiling, `api_key_expiry`
in config, default 90 days), and there is no more "never expires" key. That migration only handled
the *immediate* blast radius (existing null-expiry rows force-expired on deploy) — it added no
mechanism for the *ongoing* one every subsequent key now carries: a credential that used to never
expire now silently starts returning `401` on a fixed date, with zero prior signal, unless
something proactively watches for that.

Before this ticket the only signal anywhere in the stack was client-side: `converse-frontends`'
self-service app (`apps/self-service/src/lib/api-key-expiry.ts`) renders a warning badge once a key
falls inside a 14-day window, computed from whichever single project's key list a human happens to
have open. That closes the gap for a person who logs in and looks — it does nothing for a machine
credential (a CI key, a service integration) whose owner never opens the app. The investigation
that produced this ticket found a real instance of exactly that: an active key (`last_used_at`
`NULL` — provisioned and never used) with 7 days left before expiring unused.

## What shipped

`procedure.listMyExpiringApiKeys` (`crates/lightbridge-authz-api/schema/authz.cstack`,
implementation in `crates/lightbridge-authz-rest/src/lib.rs`) — a queryable, scriptable surface an
operator, key owner, or a scheduled job can poll, instead of relying on a human having the
self-service UI open for the right project at the right time. One call returns the caller's own
active keys landing inside a "soon" window, aggregated across **every** project the caller can
already see (owner or `project_members` row) — not scoped to one project at a time the way the
self-service list view is.

```
procedure listMyExpiringApiKeys(args: { withinDays: Int? }): ApiKey[]
```

Gated at the existing `apikey:read` permission — not a new one. It returns strictly a filtered
subset of rows a caller holding `apikey:read` could already read one project at a time via
`model.ApiKey.list`; gating it any tighter would add friction with no matching security benefit,
and any looser would be a real widening.

### The predicate

A key is "expiring soon" when all three hold:

- `status = 'active'` (a revoked key isn't going to silently go dark — it already has)
- `expiresAt > now()` (an already-expired key is excluded — that is a separate, pre-existing
  concern this procedure does not re-report)
- `expiresAt <= now() + withinDays days`

### Thresholds (documented here, not left implicit in code)

| Parameter | Value | Rationale |
|---|---|---|
| Default window (`withinDays` omitted) | **14 days** | Matches `apps/self-service/src/lib/api-key-expiry.ts`'s `EXPIRING_SOON_WINDOW_DAYS` in converse-frontends, so the two surfaces agree on what "soon" means instead of silently diverging. |
| Minimum window | 1 day | A caller-supplied `0` or negative value clamps up to 1 rather than being rejected — see "clamp, don't reject" below. |
| Maximum window | 90 days | Mirrors the documented default of the operator-configured `ApiKeyExpiry` ceiling (`api_key_expiry`, `lightbridge_authz_core::config::ApiKeyExpiry::max_lifetime_days`). A window wider than the maximum possible key lifetime cannot surface anything a plain `model.ApiKey.list` call could not already return, so there is no security reason to allow more, and no need to reject a caller who asks for more — it just clamps. |
| Result cap | 500 rows, soonest-expiring first | Comfortably above the estate-wide count of keys expiring within 30 days at the time this ticket was filed (11) — bounds the query rather than assuming that count holds forever. |

`withinDays` is **clamped**, not rejected, when out of `[1, 90]` — the same "clamp, don't reject"
convention `listMyBudgetGrants`'s `limit` parameter already uses for a read-side convenience
parameter (see `docs/rbac.md`, "Direct budget-balance/ledger reads"). This is deliberately
different from `validate_expires_at`'s write-time gate (`crates/lightbridge-authz-rest/src/handlers/mod.rs`),
which fail-closed **rejects** an out-of-range `expiresAt` rather than silently adjusting it — that
function is enforcing a security-relevant invariant on a write; this one is shaping a read-side
convenience parameter, and the two are not held to the same rule.

Implementation constants live in `crates/lightbridge-authz-rest/src/lib.rs`:
`DEFAULT_EXPIRING_SOON_WINDOW_DAYS`, `MAX_EXPIRING_SOON_WINDOW_DAYS`,
`MAX_EXPIRING_API_KEYS_RESULTS`, `clamp_expiring_soon_window_days`.

## Why self-scoped only — no cross-tenant admin surface

The ticket's "an operator ... can poll" framing raised the possibility of a true cross-tenant
surface (every account's expiring keys, not just the caller's own) — the same self/admin split
already used elsewhere in this codebase (`getMyBudgetBalance`/`getBudgetBalance`,
`listMyBudgetGrants`/`listBudgetGrants`). That split was considered here and deliberately dropped,
for a concrete, mechanism-level reason rather than a scoping shortcut:

`listMyExpiringApiKeys` is implemented against the generated cratestack client
(`db.api_key().find_many()`), not a hand-written repository query — ADR-0038 designates cratestack
as the only sanctioned database API for new queries against `ApiKey`, which is not one of that
ADR's three documented exceptions (`signing_keys`, `project_members`,
`exchange_refresh_tokens`). Calling through the generated delegate means this procedure's tenant
isolation is enforced by the **exact same** compiled `@@allow("read", ...)` policy
`model.ApiKey.list`/`get` already go through: `FindMany::run` unconditionally folds that policy
into the query's `WHERE` clause (`push_scoped_conditions` in cratestack-pg's
`query/support/conditions.rs`), with **no bypass available** from a hand-written procedure body.

That is exactly what makes a genuine cross-tenant read impossible to build the same way: there is
no escape hatch on the generated client that skips `@@allow`. Building one would require either

1. weakening `ApiKey`'s shared tenant-isolation clause — which also protects
   `model.ApiKey.list`/`get` for every other caller, not just this new procedure — or
2. new hand-written SQL bypassing cratestack entirely, which ADR-0038 forbids for a model that
   isn't one of its three documented exceptions.

Either is a materially bigger, separate security decision than "add a visibility surface," and is
left for a deliberate follow-up rather than a side effect of this ticket.

This does not leave the motivating machine-credential case uncovered: an account owner or any
project lead/member (not only whoever happens to have the self-service UI open for that one
project) can now poll a single endpoint across every project they can already see, machine-credential
projects included — closing the actual gap ("nobody routinely opens this project's UI") without
widening who can see what.

## What did not ship, and why

- **A cross-tenant admin surface** — see above.
- **A Prometheus/OTel metric or alert.** This repo's observability stack (`lightbridge-authz-core::tracing`,
  wired from `app/lightbridge-authz/src/main.rs`) instruments **traces only** — there is no
  `MeterProvider`/gauge/counter pipeline anywhere in `authz-api`, `authz-opa`, `authz-idp`, or
  `authz-budget` today (confirmed by inspection, not assumed: the only metrics-shaped code in the
  whole repo is `lightbridge-authz-usage`'s OTLP **ingest** endpoint, which receives usage metrics
  from API-key-holding *clients* for billing — the opposite direction, and architecturally
  unrelated). Adding a gauge this service *emits* is a from-scratch metrics-pipeline build (a new
  `SdkMeterProvider` alongside the existing `SdkTracerProvider`, plus a periodic DB-polling
  observable-gauge callback), not a small addition to something already wired — a large enough,
  separately-scopable piece of work that it deserves its own PR rather than being bolted onto this
  one. `procedure.listMyExpiringApiKeys` is pollable by any external scraper/cron in the meantime.
- **A push notification (email/webhook).** Out of scope per the ticket itself ("Building a
  general-purpose notification platform ... scope the implementation to what's needed").
- **An external alerting-stack check.** Whether an alerting stack outside this repo's version
  control (e.g. Grafana/Alertmanager config not vendored here) already covers this was not
  checked — the ticket's own filer flagged this same limitation, and it stands: this doc only
  speaks to what is in this repository.

## Testing

`crates/lightbridge-authz-rest/tests/rpc_it_tests.rs` (live-database, `it-tests` feature):

- `list_my_expiring_api_keys_applies_the_window_boundary_and_excludes_already_expired` — seeds keys
  comfortably inside the window, just inside the window edge, just outside the window edge,
  comfortably outside the window, and an already-expired key (created with a valid future expiry,
  then pushed into the past directly against the DB — `createApiKey` itself refuses a past
  `expiresAt`), asserting exactly which come back.
- `list_my_expiring_api_keys_does_not_leak_another_tenants_keys` — two independent
  account/project/key trees; each caller's call returns only their own expiring key.
- `list_my_expiring_api_keys_aggregates_across_every_project_the_caller_can_see` — one account
  with two projects (one via ownership, one via a `project_members` row for a different caller),
  proving a single call surfaces expiring keys from both, and that a project member does not
  see a project they hold no membership on just because its owner also owns a project they do.

`crates/lightbridge-authz-rest/src/lib.rs` (`#[cfg(test)] mod tests`): unit coverage for
`clamp_expiring_soon_window_days`'s boundary arithmetic (omitted, in-range, non-positive, and
oversized `withinDays`).
