# Lightbridge Usage Query API

> [!WARNING]
> **This service has no authentication and no ownership check on `scope_id`.** The
> `lightbridge-authz-usage` router
> ([`crates/lightbridge-authz-usage/src/routers/mod.rs`](../crates/lightbridge-authz-usage/src/routers/mod.rs))
> applies no JWT or Basic-auth middleware to any route, including
> `/usage/v1/usage/query`. The handler
> ([`crates/lightbridge-authz-usage/src/handlers/query.rs`](../crates/lightbridge-authz-usage/src/handlers/query.rs))
> validates only the time range, that `scope_id` is non-empty, and `limit` — it does
> **not** bind `scope`/`scope_id` to any caller identity. Concretely: anyone who can
> reach this endpoint and knows a valid CUID2 `scope_id` can read that tenant's usage
> data, cross-tenant, with no credential. `scope_id` values are unguessable (CUID2,
> 24 chars) and the API offers no enumeration, but ids do leak through other
> channels (URLs, logs, JWT claims, error messages), so "unguessable" is not a
> substitute for authorization.
>
> The `/v1/otel/traces`, `/v1/otel/metrics`, and `/v1/otel/logs` ingest endpoints are
> unauthenticated by design too — an unauthenticated write path there means anyone
> who can reach it can fabricate usage/billing records for any account or project.
>
> `lightbridge-authz-usage` is `ClusterIP`-only in prod today, by design — see the
> **Service** section below. **Do not add an external route (Ingress/HTTPRoute/
> Gateway) to this service without first putting real authorization in front of it.**
> See "Recommended direction" below.

## Why?

Usage and cost reporting in Lightbridge depends on a single query surface.

Without a clear reference, it is easy to:

- send subtly wrong queries (wrong grouping or bucket)
- misunderstand what is filtered vs. what is grouped
- misread fields that are always present vs. optional

This document describes the query endpoint as implemented in this repository.

### Service

The query endpoint is exposed by the `lightbridge-authz-usage` service.

In prod, `lightbridge-authz-usage` is deployed `ClusterIP`-only, in the `converse`
namespace, listening on TLS (self-signed, internal CA) — same pattern as
`lightbridge-opa` (`ai-helm-values`
[`environments/base/deps/security-policies/certificate.yaml`](https://github.com/ADORSYS-GIS/ai-helm-values/blob/main/environments/base/deps/security-policies/certificate.yaml)
documents `https://lightbridge-opa.converse.svc.cluster.local:3000`; the usage
subchart's own config in
[`environments/prod/values/lightbridge-app.yaml`](https://github.com/ADORSYS-GIS/ai-helm-values/blob/main/environments/prod/values/lightbridge-app.yaml)
sets `server.usage.port: 3000` plus `server.usage.tls.{cert_path,key_path}` and
reuses the same `authz-tls`-derived secret via `persistence.tls.name: authz-tls`).
There is no Ingress/HTTPRoute/Gateway anywhere in `ai-helm-values` that routes to
it — in particular, `https://self-service.ai.camer.digital` (an earlier, incorrect
version of this doc) does **not** reach this service: that hostname only routes
`/api/v2` to `lightbridge-api` and `/` to the `converse-ui` SPA, so a request to
that URL for this path would hit the SPA's nginx, not `lightbridge-authz-usage`.

In-cluster base URL:

- `https://lightbridge-usage.converse.svc.cluster.local:3000`

This is only reachable from inside the cluster today. There is deliberately no
externally reachable base URL — see the warning above.

### Endpoint

- Method: `POST`
- Path: `/usage/v1/usage/query`
- Content-Type: `application/json`

### Request schema

The request is JSON and matches the `UsageQueryRequest` model.

```json
{
  "scope": "project",
  "scope_id": "proj_123",
  "start_time": "2026-02-20T00:00:00Z",
  "end_time": "2026-02-23T00:00:00Z",
  "bucket": "1 hour",
  "filters": {
    "signal_type": "metric"
  },
  "group_by": ["model"],
  "limit": 1000
}
```

#### Top-level fields

| Field | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `scope` | enum: `user` \| `api_key` \| `project` \| `account` | yes | none | Primary scoping dimension. Adds a mandatory equality filter based on `scope_id`. |
| `scope_id` | string | yes | none | The ID value for the chosen `scope`. Must be non-empty. |
| `start_time` | RFC3339 datetime | yes | none | Inclusive start of the time window (`observed_at >= start_time`). |
| `end_time` | RFC3339 datetime | yes | none | Exclusive end of the time window (`observed_at < end_time`). Must be after `start_time`. |
| `bucket` | string interval | no | `"1 hour"` | Bucket size for time aggregation. Must match `^\d+\s+(second|seconds|minute|minutes|hour|hours|day|days)$`. Examples: `"5 minutes"`, `"1 hour"`, `"30 days"`. |
| `filters` | object | no | `{}` | Additional AND-filters (all equality matches). See below. |
| `group_by` | array of enums | no | `[]` | Adds grouping dimensions beyond time bucket. See below. |
| `limit` | integer (`u32`) | no | `1000` | Maximum number of rows returned after grouping. Must be > 0. |

#### `filters` object

`filters` are optional equality constraints that are applied in addition to the `scope` filter.

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `account_id` | string | no | Adds `AND account_id = <value>` |
| `project_id` | string | no | Adds `AND project_id = <value>` |
| `api_key_id` | string | no | Adds `AND api_key_id = <value>` |
| `user_id` | string | no | Adds `AND user_id = <value>` |
| `user_name` | string | no | Adds `AND user_name = <value>` |
| `model` | string | no | Adds `AND model = <value>` |
| `metric_name` | string | no | Adds `AND metric_name = <value>` |
| `signal_type` | string | no | Adds `AND signal_type = <value>` |

Notes:

- `scope` and `filters` are cumulative; they combine with logical AND.
- If you specify a filter that contradicts `scope` (example: `scope=project, scope_id=proj_1` but `filters.project_id=proj_2`), the query will return an empty result.
- There is no server-side validation of `signal_type`, `metric_name`, or `model` values; unknown values generally yield empty results.

#### `group_by` values

`group_by` controls which dimensions appear as non-null values in each returned point and which columns are included in the SQL `GROUP BY`.

Supported values:

- `account_id`
- `project_id`
- `api_key_id`
- `user_id`
- `user_name`
- `model`
- `metric_name`
- `signal_type`

If a dimension is not in `group_by`, the response will contain that field as `null` for every point.

Implementation detail: the server internally deduplicates group-by entries, so duplicates do not change the output.

### Response schema

Successful response is HTTP `200` with JSON:

```json
{
  "points": [
    {
      "bucket_start": "2026-02-20T00:00:00Z",
      "account_id": null,
      "project_id": "proj_123",
      "api_key_id": null,
      "user_id": null,
      "user_name": null,
      "model": "gpt-4.1-mini",
      "metric_name": null,
      "signal_type": "metric",
      "requests": 120,
      "usage_value": 34567.0,
      "total_cost": 12.34,
      "prompt_tokens": 20000,
      "completion_tokens": 14567,
      "total_tokens": 34567
    }
  ]
}
```

#### Point fields

Each point is an aggregate across matching `usage_events` rows for:

- the selected time window
- the mandatory `scope` constraint
- any optional `filters`
- grouped by `bucket_start` and any chosen `group_by` dimensions

| Field | Type | Always present | Meaning |
|---|---|---:|---|
| `bucket_start` | RFC3339 datetime | yes | Start of the bucket produced by Postgres `date_bin`.
| `account_id` | string or null | yes | Present when `group_by` includes `account_id`, else null.
| `project_id` | string or null | yes | Present when `group_by` includes `project_id`, else null.
| `api_key_id` | string or null | yes | Present when `group_by` includes `api_key_id`, else null.
| `user_id` | string or null | yes | Present when `group_by` includes `user_id`, else null.
| `user_name` | string or null | yes | Present when `group_by` includes `user_name`, else null.
| `model` | string or null | yes | Present when `group_by` includes `model`, else null.
| `metric_name` | string or null | yes | Present when `group_by` includes `metric_name`, else null.
| `signal_type` | string or null | yes | Present when `group_by` includes `signal_type`, else null.
| `requests` | int64 | yes | `SUM(request_count)`.
| `usage_value` | float64 | yes | `SUM(usage_value)`.
| `total_cost` | float64 | yes | `SUM(total_cost)`.
| `prompt_tokens` | int64 | yes | `SUM(prompt_tokens)`.
| `completion_tokens` | int64 | yes | `SUM(completion_tokens)`.
| `total_tokens` | int64 | yes | `SUM(total_tokens)`.

### Error behaviour

This handler performs a small set of input validations (see [`crates/lightbridge-authz-usage/src/handlers/query.rs`](crates/lightbridge-authz-usage/src/handlers/query.rs:1)):

- `start_time` must be before `end_time`
- `scope_id` must be non-empty
- `limit` must be greater than 0
- `bucket` must match the supported interval format (see [`crates/lightbridge-authz-usage/src/repo.rs`](crates/lightbridge-authz-usage/src/repo.rs:257))

Current behaviour to be aware of:

- Many invalid-input cases are returned as `Error::Database(...)`, which maps to **HTTP 500** and a **plain-text** body (not JSON) via the shared error response mapping in [`crates/lightbridge-authz-core/src/error.rs`](crates/lightbridge-authz-core/src/error.rs:1).
- SQLx errors are mapped to status codes based on SQLx error kind. For example, connection pool failures can surface as **503**.

Example invalid time window:

```text
HTTP/1.1 500 Internal Server Error
Database error: start_time must be before end_time
```

## Constraints

- This endpoint is **always aggregated** by `bucket_start` (there is no “raw per-event” mode).
- Sorting is **always** by `bucket_start ASC` (there is no server-side `order_by` for cost or token totals).
- Pagination is limited to a simple `limit`; there is no `offset`.
- Filters are equality filters only.

## Security: recommended fix direction

This section exists because the warning at the top of this document needs somewhere
to point. Before this endpoint is given any externally reachable route, it needs
real authorization in front of it. Two directions, without over-specifying which:

- **Basic-auth, same pattern as `authz-opa`.** Cheapest to add, and consistent with
  how `authz-opa`'s validation endpoints are gated today. Does not solve
  cross-tenant reads by itself — a shared Basic-auth credential authenticates the
  *caller* (e.g. a gateway component), not which `scope_id` that caller is entitled
  to see.
- **Fold the query behind `authz-api`'s JWT middleware, with an ownership check.**
  Resolve the caller's `account_id`/`project_id` from their JWT (the same claims
  `/idp/v1/resolve-context` already resolves and seals into tokens — see
  [`crates/lightbridge-authz-rest/src/handlers/idp.rs`](../crates/lightbridge-authz-rest/src/handlers/idp.rs)),
  and require the requested `scope`/`scope_id` to match — or be owned by — that
  identity before running the query. This is the stronger option because it fixes
  the actual gap (no ownership check), not just "who can call the endpoint at all."

Either direction needs a corresponding fix on the ingest side
(`/v1/otel/traces`, `/v1/otel/metrics`, `/v1/otel/logs`) before it is safe to expose
externally, since those are unauthenticated writes today.

## Findings

### Integration notes

- This repository does not include a Lightbridge frontend, so there are no in-repo UI call sites to enumerate.
- The usage query endpoint is exercised by the integration test runner in [`.docker/it/servers_it.py`](.docker/it/servers_it.py:1).
- The endpoint is also described at a high level in [`README.md`](README.md:118) and [`docs/usage-api.md`](docs/usage-api.md:1).

### Known quirks and limitations

- Input validation errors currently surface as plain-text errors (often with HTTP 500) due to the shared error-to-response mapping in [`crates/lightbridge-authz-core/src/error.rs`](crates/lightbridge-authz-core/src/error.rs:1).
- The API is aggregation-first: no raw events, no server-side ranking/top-N, no offset pagination, and fixed ordering by time bucket.

## How to?

### Example 1: Total cost for a project over the last 30 days

```bash
curl -k https://lightbridge-usage.converse.svc.cluster.local:3000/usage/v1/usage/query \
  -H 'Content-Type: application/json' \
  -d '{
    "scope": "project",
    "scope_id": "proj_123",
    "start_time": "2026-02-20T00:00:00Z",
    "end_time": "2026-03-21T00:00:00Z",
    "bucket": "30 days",
    "group_by": [],
    "filters": {},
    "limit": 1000
  }'
```

Annotated response (single point):

```json
{
  "points": [
    {
      "bucket_start": "2026-02-20T00:00:00Z",
      "account_id": null,
      "project_id": null,
      "user_id": null,
      "model": null,
      "metric_name": null,
      "signal_type": null,
      "requests": 1234,
      "usage_value": 0.0,
      "total_cost": 98.76,
      "prompt_tokens": 500000,
      "completion_tokens": 250000,
      "total_tokens": 750000
    }
  ]
}
```

### Example 2: Cost breakdown per model for an account for a month

If this returns an empty result like `{ "points": [] }`, it means the database has **no `usage_events` rows matching the scope filter**:

- `scope=account` requires rows where `account_id = scope_id`.
- `account_id` is populated only if the ingested OTEL payload contained an account identifier attribute that the ingest pipeline recognizes.

When you are unsure whether `account_id` is being ingested, try the same query with `scope=project` (project IDs are often easier to propagate), or temporarily remove `filters`.

```bash
curl -k https://lightbridge-usage.converse.svc.cluster.local:3000/usage/v1/usage/query \
  -H 'Content-Type: application/json' \
  -d '{
    "scope": "account",
    "scope_id": "acct_123",
    "start_time": "2026-02-01T00:00:00Z",
    "end_time": "2026-03-01T00:00:00Z",
    "bucket": "30 days",
    "group_by": ["model"],
    "filters": {},
    "limit": 1000
  }'
```

Annotated response (one point per model):

```json
{
  "points": [
    {
      "bucket_start": "2026-02-01T00:00:00Z",
      "model": "gpt-4.1-mini",
      "total_cost": 12.34,
      "requests": 100,
      "total_tokens": 20000,
      "usage_value": 20000.0,
      "account_id": null,
      "project_id": null,
      "user_id": null,
      "metric_name": null,
      "signal_type": null,
      "prompt_tokens": 12000,
      "completion_tokens": 8000
    }
  ]
}
```

### Example 3: Token usage for a specific user over a day, grouped by hour

This only works if your ingested telemetry actually sets `user_id`.

- The storage table contains a nullable `user_id` column (see [`migrations-usage/20260223000001_init_usage.sql`](migrations-usage/20260223000001_init_usage.sql:1)).
- Ingest extracts `user_id` only from specific OTEL attribute keys (see `USER_KEYS` in [`crates/lightbridge-authz-usage/src/handlers/ingest.rs`](crates/lightbridge-authz-usage/src/handlers/ingest.rs:42)):
  - `user_id`
  - `user.id`
  - `end_user.id`
  - `authz.user_id`

If your telemetry does not provide one of those keys, stored `user_id` will be null and any `scope=user` query will return `{ "points": [] }`.

```bash
curl -k https://lightbridge-usage.converse.svc.cluster.local:3000/usage/v1/usage/query \
  -H 'Content-Type: application/json' \
  -d '{
    "scope": "user",
    "scope_id": "user_123",
    "start_time": "2026-03-20T00:00:00Z",
    "end_time": "2026-03-21T00:00:00Z",
    "bucket": "1 hour",
    "group_by": ["model"],
    "filters": {"signal_type": "metric"},
    "limit": 1000
  }'
```

### Example 4: “Top N most expensive models” in a period (client-side sorting)

The API does not support ordering by `total_cost`. Use a coarse bucket (for example `"30 days"`) and sort client-side.

```bash
curl -k https://lightbridge-usage.converse.svc.cluster.local:3000/usage/v1/usage/query \
  -H 'Content-Type: application/json' \
  -d '{
    "scope": "account",
    "scope_id": "acct_123",
    "start_time": "2026-02-01T00:00:00Z",
    "end_time": "2026-03-01T00:00:00Z",
    "bucket": "30 days",
    "group_by": ["model"],
    "filters": {},
    "limit": 1000
  }'
```

Then sort the returned points by `total_cost` descending and take the first N.

### Example 5: Closest approximation to “raw per-request records”

This API is always aggregated; it cannot return raw per-event rows. The closest approximation is using the smallest practical bucket (for example `"1 second"`) and grouping by as many dimensions as you have.

```bash
curl -k https://lightbridge-usage.converse.svc.cluster.local:3000/usage/v1/usage/query \
  -H 'Content-Type: application/json' \
  -d '{
    "scope": "project",
    "scope_id": "proj_123",
    "start_time": "2026-03-20T10:00:00Z",
    "end_time": "2026-03-20T10:05:00Z",
    "bucket": "1 second",
    "group_by": ["user_id", "model", "signal_type", "metric_name"],
    "filters": {},
    "limit": 1000
  }'
```

## Conclusion (if any)

The usage query surface in this repository is a compact, aggregation-first API:

- scope + time window are mandatory
- additional filters are simple equality AND-filters
- grouping is explicit and controls which dimension fields are non-null
- output is always time-bucketed aggregates

For dashboard and reporting use-cases, the recommended pattern is:

- choose the coarsest bucket that still answers the question
- group by only what you need
- do ranking (top-N) client-side when needed
