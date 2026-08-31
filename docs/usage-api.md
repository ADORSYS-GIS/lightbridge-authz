# Usage API (lightbridge-authz-usage)

`lightbridge-authz-usage` ingests OTLP/HTTP traces + metrics from AI Envoy/OpenTelemetry exporters and stores normalized usage events in Timescale/Postgres.

> [!WARNING]
> **The ingest routes are unauthenticated.** This service splits its TLS surface
> across two listeners (#347, `UsageServerGroup` in
> [`crates/lightbridge-authz-usage/src/config.rs`](../crates/lightbridge-authz-usage/src/config.rs)):
> an **ingest listener** (`/v1/otel/*`, `routers::ingest_router()`) that applies no JWT,
> Basic-auth, or mTLS check — its caller is an AI Envoy/OpenTelemetry exporter outside
> this repo's deploy surface, so anyone who can reach it can write fabricated
> usage/billing records for any account or project — and a **query listener**
> (`/usage/v1/usage/query` + `/usage/v1/spend/query`, `routers::query_router()`) that
> **requires and verifies a client certificate (mTLS)**. This service is
> `ClusterIP`-only in prod with no external route regardless — see
> [`docs/lightbridge-query-api.md`](lightbridge-query-api.md) for the full detail
> (base URL, blast radius) before giving this service any external route.
>
> **`/usage/v1/usage/query`'s cross-tenant ownership gap (#570) is now fixed.** mTLS
> alone authenticates "a legitimate lightbridge workload holding a CA-signed cert", not
> which `scope_id` the caller is entitled to see, so `/usage/v1/usage/query` now
> ADDITIONALLY requires an end-user `Authorization: Bearer <access token>` (validated
> via JWKS, `lightbridge-authz-bearer::BearerTokenService`) and checks that the
> token's subject actually owns the requested `account`/`project` scope by calling
> `authz-opa`'s `POST /idp/v1/authorize-usage-scope` (`ScopeAuthority`,
> `crates/lightbridge-authz-usage/src/scope_authority.rs`) — the same real,
> Postgres-backed ownership predicate `resolve_context` already enforces for the OIDC
> token-exchange path. `user`/`api_key` scopes have no resolvable ownership authority
> at all and are refused unconditionally (403), matching the console's own guard.
> Missing/invalid bearer → `401`; authenticated but not authorized → `403` with an
> opaque body. `/usage/v1/spend/query` stays exempt from this bearer requirement — it
> is `authz-budget`'s legitimate cross-account service reader, mTLS-only, and now
> REFUSES any request carrying an `Authorization` header (closing the "console
> catch-all-proxy" hole where a misrouted browser bearer token could otherwise reach
> this ownerless cross-account read).
>
> **Divergence from the console's own guard, stated not hidden:** the backend
> predicate here (owner of the account, OR any `project_members` roster row for a
> project scope) is deliberately WIDER than the console UI's own client-side guard
> (owner-only) — a roster member who the console UI would never let ask can still
> query their project's usage through this endpoint directly, matching the exact
> visibility boundary `resolve_context`/`Project`'s `@@allow("read", ...)` already use
> elsewhere in this codebase, not a new, narrower one invented for this endpoint.

## Endpoints

- `POST /v1/otel/traces`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportTraceServiceRequest`.
- `POST /v1/otel/metrics`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportMetricsServiceRequest`.
- `POST /v1/otel/logs`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportLogsServiceRequest`.
- `POST /usage/v1/usage/query`
  - Single query endpoint for scoped, bucketed usage retrieval. Requires
    `Authorization: Bearer <end-user access token>` (#570) — see the warning above.

## Query request

```json
{
  "scope": "project",
  "scope_id": "proj_123",
  "start_time": "2026-02-20T00:00:00Z",
  "end_time": "2026-02-23T00:00:00Z",
  "bucket": "1 hour",
  "filters": {
    "model": "gpt-4.1",
    "signal_type": "metric"
  },
  "group_by": ["model", "metric_name"],
  "limit": 1000
}
```

## Response shape and truncation (#578)

The response is `{ "points": [...], "truncated": bool }`. `truncated: true` means more than
`limit` buckets matched the query and the OLDEST ones were dropped to fit — `points` still holds
at most `limit` entries in ascending `bucket_start` order. Truncation always drops whole buckets
from the oldest end, never the newest; a bucket that straddles the truncation boundary is dropped
or kept as a whole bucket, not split (a known caveat tracked as #586).

## Scope semantics

- `scope=user` filters by `user_id = scope_id` — no resolvable ownership authority; every
  request is refused with `403` regardless of the caller (#570).
- `scope=api_key` filters by `api_key_id = scope_id` — same unconditional `403` as `user` above.
- `scope=project` filters by `project_id = scope_id` — requires the bearer token's subject to
  own the project's account OR hold a `project_members` roster row for it.
- `scope=account` filters by `account_id = scope_id` — requires the bearer token's subject to
  own the account (ADR-0026 anchor semantics: same `accounts.user_id` identity, not merely the
  same `accounts.id`).

`filters` also accepts `api_key_id` and `user_name` (in addition to `account_id`,
`project_id`, `user_id`, `model`, `metric_name`, `signal_type`), and `group_by`
accepts the same set of dimensions. See
[`docs/lightbridge-query-api.md`](lightbridge-query-api.md) for the full field
reference.

## Latency

Each `usage_events` row carries an optional `latency_ms` (a single `DOUBLE PRECISION` column, 8
bytes/row), and `/usage/v1/usage/query` returns `latency_samples` plus `latency_p50_ms` /
`latency_p95_ms` / `latency_p99_ms` per point, computed with Postgres' `percentile_cont`
ordered-set aggregate at query time. Nothing about the distribution is stored -- no sample arrays,
no histogram buckets -- which keeps this out of the unbounded-wide-column territory that made this
table a contributing factor in the 2026-08-29 outage (#549).

Latency is genuinely absent for some signals (aggregate metric data points carry a bucketed
distribution, not one observation), and the API reports that as `latency_samples: 0` with `null`
percentiles rather than a zero. See
[`docs/lightbridge-query-api.md`](lightbridge-query-api.md)'s "Latency, and when it is legitimately
absent" for the full source table and the honesty contract consumers are expected to honour.

## Migrations

Usage storage migrations are separate from authz migrations:

- `migrations-usage/`
- migration module: `app/lightbridge-authz-usage/src/migrate.rs`

The primary table is `usage_events` (hypertable when Timescale is available).
