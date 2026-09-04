# Lightbridge Usage Query API

> [!WARNING]
> **This endpoint requires mTLS (#347) AND, as of #570, an end-user bearer token plus
> an ownership check on `scope_id`.** `/usage/v1/usage/query` sits on a dedicated
> query listener (`UsageServerGroup::query` in
> [`crates/lightbridge-authz-usage/src/config.rs`](../crates/lightbridge-authz-usage/src/config.rs),
> `routers::query_router()`) that requires and verifies a client certificate before any
> handler runs — that authenticates "a legitimate lightbridge workload holding a
> CA-signed cert", not which `scope_id` a given end user is entitled to see. The
> handler
> ([`crates/lightbridge-authz-usage/src/handlers/query.rs`](../crates/lightbridge-authz-usage/src/handlers/query.rs))
> closes that gap by ALSO requiring `Authorization: Bearer <end-user access token>`
> (validated via JWKS, `lightbridge-authz-bearer::BearerTokenService`) and calling
> `authz-opa`'s `POST /idp/v1/authorize-usage-scope`
> (`ScopeAuthority`, [`crates/lightbridge-authz-usage/src/scope_authority.rs`](../crates/lightbridge-authz-usage/src/scope_authority.rs))
> to check the token's subject actually owns the requested `account`/`project` scope
> before running the query. `scope=api_key` has no resolvable ownership predicate at
> all and is refused unconditionally (`403`). `scope=user` is allowed ONLY when
> `scope_id` equals the validated token's own `sub` (self-ownership — the caller
> reading their own usage; anything else is `403`, and `scope_authority` is never
> consulted for this scope either way). `scope=all` (estate-wide, no entity filter at
> all) requires the validated token to hold the `usage:read-all` permission
> (`Permission::UsageReadAll`, `lightbridge-authz-core::authz`) — granted to
> `lightbridge-admin` by that role's default `*` grant, configurable like every other
> permission via `oauth2.rbac.role_permissions`; `scope_authority` is not consulted
> for this scope either, since there is no per-row ownership predicate for
> "everything." Missing/invalid bearer → `401`; authenticated but not authorized, or
> the authority being unreachable/erroring (`account`/`project` only) → `403` with an
> opaque body (fail-closed — never treated as authorized).
>
> **Divergence, stated not hidden:** the backend predicate (account owner, OR project
> owner/roster member) is deliberately WIDER than the console UI's own client-side
> guard (owner-only) — see `docs/usage-api.md`'s identical note.
>
> The `/v1/otel/traces`, `/v1/otel/metrics`, and `/v1/otel/logs` ingest endpoints stay
> on a separate, unauthenticated listener (`UsageServerGroup::usage`) — their caller is
> an AI Envoy/OpenTelemetry exporter outside this repo's deploy surface, which cannot
> be given a client certificate without a coordinated change there (out of #347's
> scope). An unauthenticated write path there means anyone who can reach it can
> fabricate usage/billing records for any account or project.
>
> `/usage/v1/spend/query` stays mTLS-only, exempt from the bearer requirement above —
> it is `authz-budget`'s legitimate cross-account service reader — but now REFUSES any
> request carrying an `Authorization` header, closing a live "console catch-all-proxy"
> hole where a misrouted browser bearer token could otherwise reach this ownerless
> cross-account read.
>
> `lightbridge-authz-usage` is `ClusterIP`-only in prod today, by design, regardless of
> mTLS — see the **Service** section below.

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

**#347 needs a companion `ai-helm-values` change before this repo's image can deploy
to prod.** `UsageServerGroup` (`crates/lightbridge-authz-usage/src/config.rs`) now
requires a second, mandatory `server.query` block (address/port/TLS +
`client_ca_bundle_path`) alongside the existing `server.usage` block — prod's current
config sets only `server.usage.port: 3000`. Because this new field is required (not
optional — a deliberate hard-cutover choice, not a dormant flag), `authz-usage` fails
to parse its config and refuses to start entirely if the image rolls out before
`ai-helm-values` adds the `query` block. **Deploy order:** update `ai-helm-values` to
add `server.query` (a distinct port from `server.usage`, e.g. `3001` if unused
locally, TLS reusing the same `authz-tls`-derived secret's `tls.crt`/`tls.key` plus
`client_ca_bundle_path` pointed at that same secret's `ca.crt`) **and** set
`usage_service.client_cert_path`/`client_key_path` on the `api`/`budget` components
(reusing their own mounted cert) **in the same rollout** as this repo's image bump —
not before (the config would reference a port the old image doesn't serve) and not
long after (the new image won't start without it).

**#570 adds two MORE mandatory blocks to that same config, ratified as mandatory (not
optional) exactly like `server.query` above — this is not a new decision, it is the
same "hard-cutover, not a dormant flag" rule applied twice more.** `UsageConfig::
oauth2` and `UsageConfig::scope_authority` (`crates/lightbridge-authz-usage/src/
config.rs`) are also non-`Option` fields: a config omitting `oauth2.jwks_url` or any of
`scope_authority.{base_url,username,password}` fails to load, exactly
the same failure mode `server.query`'s own rollout already produced once.
(`scope_authority.ca_bundle_path` is `#[serde(default)] Option<String>` and does NOT
gate config load — omitting it against a private-CA-signed `authz-opa` instead fails
closed at REQUEST time: TLS verification fails on every `scope=account`/`scope=project`
query, which `RemoteScopeAuthority` treats as "not authorized," i.e. every such query
gets a `403`, not a startup crash.) The consequence of a genuine config-load failure
is the same too, just doubled: it kills BOTH listeners
at once, not just the query one — the ingest listener's OTLP writes are refused
(usage/billing data loss for every request in the outage window) at the same moment
the query listener's spend reads for `authz-budget` degrade to `Spend::Unavailable`
(routing every self-service refill decision that depends on them to `manual_review`,
never `auto_approve`, until the config is fixed). Because the `migrate` Job runs at an
earlier ArgoCD sync-wave than the main Deployment (`docs/adr/0016-migrate-job-sync-
wave-not-hook.md`) and loads this identical config, a bad value here fails the
`migrate` Job first — which fails the WHOLE app's ArgoCD sync, not merely this
service's own rollout. **Deploy order, extended:** `ai-helm-values` MUST set
`oauth2.jwks_url` (the same Keycloak/OIDC JWKS endpoint `authz-api`/`authz-opa`
already point at) and the three mandatory `scope_authority` fields (`base_url` pointing
at `authz-opa`'s in-cluster address, `username`/`password` matching `authz-opa`'s own
`server.opa.basic_auth` credential exactly) — plus the optional-but-effectively-required
`ca_bundle_path`, pointed at the same CA bundle `server.query.tls.client_ca_bundle_path`
already uses, or every account/project query fails closed once TLS verification fails —
**in the same rollout** as this repo's image bump that introduces #570 — the chart's own
`charts/lightbridge-authz-usage/values.yaml` documents this identically at
`config.oauth2`/`config.scopeAuthority`.

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
    "signal_type": "metric",
    "operation_in": ["chat_completions", "responses", "messages"]
  },
  "group_by": ["model", "azp"],
  "limit": 1000
}
```

#### Top-level fields

| Field | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `scope` | enum: `user` \| `api_key` \| `project` \| `account` \| `all` | yes | none | Primary scoping dimension. Adds a mandatory equality filter based on `scope_id`, except `all` (see below). |
| `scope_id` | string | yes | none | The ID value for the chosen `scope`. Must be non-empty for every scope except `all`, where it is ignored -- send `""`. |
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
| `azp` | string | no | Adds `AND azp = <value>` -- the OAuth client / channel (#648). |
| `operation` | string | no | Adds `AND operation = <value>` (#648). For several operations at once, use `operation_in` -- do not issue one query per value. |
| `billing_plan` | string | no | Adds `AND billing_plan = <value>` (#648). |
| `operation_in` | array of strings | no | Adds `AND operation = ANY($n)`, one bound `text[]` parameter (#648). **Closed vocabulary**: every entry must be one of `chat_completions`, `responses`, `messages`, `embeddings`, `other`, and an empty array is refused -- both are `400`, not an empty result set. Rows whose `operation` is `null` never match (SQL `= ANY` is false for `NULL`): "unknown" is not a member of any set of known values. |

Notes:

- `scope` and `filters` are cumulative; they combine with logical AND.
- If you specify a filter that contradicts `scope` (example: `scope=project, scope_id=proj_1` but `filters.project_id=proj_2`), the query will return an empty result.
- There is no server-side validation of `signal_type`, `metric_name`, or `model` values; unknown values generally yield empty results. `operation_in` is the one exception -- its value space is closed, so an unknown entry is a `400` naming the offending value rather than a blank chart the caller cannot tell apart from "no usage this month".

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
- `azp` (#648)
- `operation` (#648)
- `billing_plan` (#648)

If a dimension is not in `group_by`, the response will contain that field as `null` for every point.

`azp`, `operation` and `billing_plan` are the three dimensions #648 promoted out of the
`attributes` JSONB blob into real indexed columns; their source attribute keys and the path-prefix
table `operation` is derived from live in [`docs/usage-api.md`](usage-api.md)'s "Usage dimensions"
section, with the ingest/backfill sequence and the `null`-is-not-`other` state machine drawn there.
That bridge is interim: #581's `usage_request_events` rewrite carries the same three columns and
the same vocabulary forward, and `usage_events` is dropped.

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
      "total_tokens": 34567,
      "latency_samples": 118,
      "latency_p50_ms": 412.0,
      "latency_p95_ms": 1180.5,
      "latency_p99_ms": 2404.0
    }
  ],
  "truncated": false
}
```

`truncated` (#578): `true` when more than `limit` DISTINCT buckets matched the query and the
OLDEST one was dropped WHOLE to fit. `limit` bounds bucket count, not `points.len()` -- with a
non-empty `group_by`, `points` can hold more entries than `limit` (one per series per surviving
bucket), and every surviving bucket keeps its FULL series set, never an arbitrary subset. `false`
means every matching bucket is present. See `docs/usage-api.md`'s "Response shape and truncation"
for the known mid-bucket-cut caveat (#586).

#### Query horizon (#549)

`/usage/v1/usage/query` reads the raw `usage_events` table only. The retention job (#549) rolls
rows older than `retention.raw_days` (default **90**) out of `usage_events` into the
`usage_events_daily` rollup, which does **not** carry latency percentiles -- so this endpoint
cannot serve data older than the raw window at the granularity it promises. A request whose
`start_time` is older than the raw window returns only the data that still exists, and the handler
sets `truncated: true` for such a range (the data older than the window is dropped) -- so the API
never reports `truncated: false` for a range it cannot answer. The dashboard's maximum range is 90
days, so every in-tree caller is within the window; a caller that needs longer-horizon data must
reconcile with the retention configuration.

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
| `azp` | string or null | yes | Present when `group_by` includes `azp`, else null (#648).
| `operation` | string or null | yes | Present when `group_by` includes `operation`, else null. `null` while `operation` IS grouped is a real series: those rows carried no request path at all (#648).
| `billing_plan` | string or null | yes | Present when `group_by` includes `billing_plan`, else null (#648).
| `requests` | int64 | yes | `SUM(request_count)`.
| `usage_value` | float64 | yes | `SUM(usage_value)`.
| `total_cost` | float64 | yes | `SUM(total_cost)`.
| `prompt_tokens` | int64 | yes | `SUM(prompt_tokens)`.
| `completion_tokens` | int64 | yes | `SUM(completion_tokens)`.
| `total_tokens` | int64 | yes | `SUM(total_tokens)`.
| `latency_samples` | int64 | yes | `COUNT(latency_ms)` -- how many of this group's rows actually carried a per-request duration. `0` is a legitimate outcome, not an error (see below).
| `latency_p50_ms` | float64 or null | yes | `percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms)`. `null` exactly when `latency_samples` is `0`.
| `latency_p95_ms` | float64 or null | yes | `percentile_cont(0.95) …`. `null` when `latency_samples` is `0`.
| `latency_p99_ms` | float64 or null | yes | `percentile_cont(0.99) …`. `null` when `latency_samples` is `0`.

#### Latency, and when it is legitimately absent

`latency_ms` is captured per event at ingest, and the percentiles are ordered-set aggregates
computed at query time -- there is no stored histogram and no stored sample array. Sources, in the
order they are tried:

| Signal | Source | Notes |
|---|---|---|
| trace | the span's own `end_time_unix_nano - start_time_unix_nano` | Authoritative; wins over any duration attribute on the same span. |
| trace / log / metric | a duration attribute | Millisecond-named keys (`duration`, `x-envoy-upstream-service-time`, `duration_ms`, …) and second-named keys (every OpenTelemetry semantic-convention `*.duration`, which are seconds) are kept in separate lists so the unit is never guessed. |
| metric (gauge / sum) | the data point's own value, when the metric is *named* as a duration | e.g. `gen_ai.server.request.duration`. |
| metric (histogram / exponential histogram / summary) | **nothing** | A bucketed distribution is not one observation. `sum / count` is a mean, and feeding a mean into `percentile_cont` would fabricate a percentile out of data that never contained one. These rows deliberately store `NULL`. |

What actually reaches this service in the deployed stack today is the **log** path: the AI gateway
configures Envoy's OpenTelemetry access-log sink with `duration: "%DURATION%"` and
`x-envoy-upstream-service-time: "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"` (both milliseconds, both
delivered as OTLP LogRecord attributes on `/v1/otel/logs`). The AI Gateway ExtProc's
`llmRequestCosts` dynamic metadata -- the channel that produces
`io.envoy.ai_gateway.llm_custom_total_cost` -- carries token and cost keys only, never a duration.

Consumers must therefore treat `latency_samples == 0` as a **per-series** fact and say so for that
series, rather than blanking a whole panel. `null` percentiles are never collapsed to `0.0`: "no
latency was reported" and "every request took 0 ms" are different facts.

`latency_p99_ms` needs roughly 100 samples before it means anything; below that it degenerates
towards the group's maximum, and at `latency_samples == 1` all three percentiles collapse onto that
single observation. `latency_samples` is returned precisely so a caller can mark that unstable
instead of drawing a confident tail.

### Error behaviour

This handler performs a small set of input validations (see [`crates/lightbridge-authz-usage/src/handlers/query.rs`](crates/lightbridge-authz-usage/src/handlers/query.rs:1)):

- `start_time` must be before `end_time`
- `scope_id` must be non-empty
- `limit` must be greater than 0
- `bucket` must match the supported interval format (see [`crates/lightbridge-authz-usage/src/repo.rs`](crates/lightbridge-authz-usage/src/repo.rs:257))
- every `filters.operation_in` entry must be a member of the closed `operation` vocabulary, and the array must not be empty (`UsageQueryFilters::validate`, #648)

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
- Filters are equality filters only, with exactly one exception: `operation_in` (`#648`), a set-membership filter over the closed `operation` vocabulary.

## Security: the ownership fix (#570)

This section used to describe a recommended fix direction; #570 implements it.
#347 answered "who can call this endpoint at all" with mTLS (client certificates,
verified at the TLS layer, before this endpoint's own handler runs — see the warning
above and `docs/architecture/budget.md`'s "Spend dependency" section). That is
authentication, not authorization: a shared client-certificate trust anchor
authenticates *a caller* (any lightbridge workload holding a CA-signed cert), not
which `scope_id` that caller is entitled to see.

`/usage/v1/usage/query`'s handler now closes that gap directly, rather than folding
the query behind `authz-api`'s own JWT middleware (a separate service on a separate
port, which would have meant either merging the two services or proxying every query
through `authz-api` first):

1. **Bearer validation.** The request must carry `Authorization: Bearer <token>`, an
   end-user access token validated via JWKS
   (`lightbridge_authz_bearer::BearerTokenService`, the same crate `authz-api`/
   `authz-opa`/`authz-budget` use). Missing or invalid → `401`.
2. **Ownership check.** For `scope=account`/`scope=project`, the validated token's
   `(iss, sub)` is sent to `authz-opa`'s new Basic-auth-protected
   `POST /idp/v1/authorize-usage-scope` endpoint
   ([`crates/lightbridge-authz-rest/src/handlers/idp.rs`](../crates/lightbridge-authz-rest/src/handlers/idp.rs)),
   which runs the SAME real, Postgres-backed ownership predicate `resolve_context`
   already enforces for the OIDC token-exchange path (own the account/project, or hold
   a `project_members` roster row) — see
   [`crates/lightbridge-authz-api-key/src/repo.rs`](../crates/lightbridge-authz-api-key/src/repo.rs)'s
   `authorize_usage_scope`. `scope=api_key` has no resolvable ownership predicate at
   all (no `accounts`/`projects` row is ever keyed by a raw `api_key_id`) and is
   refused unconditionally, before ever calling the authority.
3. **Self-ownership for `scope=user`.** Answered entirely from the already-validated
   token, no remote call: allowed iff `scope_id` equals the token's own `sub`, refused
   otherwise. There is still no `accounts`/`projects` row keyed by a raw `user_id`, so
   there is nothing for `scope_authority` to check even for the caller's own subject —
   this closes the gap #570 left where the console's own `/settings/overview/user` lens
   (a caller reading their own usage) was unconditionally `403`.
4. **Estate-wide `scope=all`.** No entity filter is added at all — the query spans
   every account. There is no per-row ownership predicate for "everything" by
   definition, so this is gated on a coarse RBAC permission instead:
   `Permission::UsageReadAll` (`usage:read-all`,
   [`crates/lightbridge-authz-core/src/authz.rs`](../crates/lightbridge-authz-core/src/authz.rs)),
   read directly off `TokenInfo::has_permission` — the same permission-set machinery
   `authz-api`'s RPC surface uses, reusing the SAME `oauth2.rbac` config this service
   already loads for JWT validation (`docs/rbac.md`). Granted to `lightbridge-admin` by
   that role's default `*` grant, so an unconfigured deployment restricts `scope=all`
   to admins with no extra setup; an operator narrowing `role_permissions` explicitly
   must grant `usage:read-all` (or `usage:*`) back to whichever role should keep
   estate-wide access. This answers the repo-owner ruling that operators should not
   need per-account enumeration to see estate-wide usage — see issue #602.
5. **Fail-closed on every authority failure mode.** A transport error, timeout,
   non-`200`/`404` status, or unparseable response from `authz-opa` is treated as "not
   authorized", never as "authorized" — see
   [`crates/lightbridge-authz-usage/src/scope_authority.rs`](../crates/lightbridge-authz-usage/src/scope_authority.rs)'s
   `RemoteScopeAuthority`, mirroring `UsageServiceSpendReader`'s identical posture for
   the sibling `/usage/v1/spend/query` call. `scope=user` self and `scope=all` never
   reach this authority at all (steps 3/4 above), so this fail-closed contract only
   applies to `scope=account`/`scope=project`.

6. **Admin bypass for `user`/`project`/`account` (#648).** A caller whose token holds
   `Permission::UsageReadAll` may query those three scopes with ANY `scope_id`, skipping
   both the self-ownership check of step 3 and the `authz-opa` round trip of step 2. This
   is not a widening of what that permission can read: step 4's `scope=all` already
   returns every row in the estate to the same holder, so refusing them the same data
   sliced by one account was a missing feature (it is what blocked the console's
   per-actor `/admin/usage` pages), not a boundary. Two deliberate limits: `scope=api_key`
   stays refused for **everyone** — no permission conjures an ownership authority that has
   never existed for a raw `api_key_id` — and a caller **without** `usage:read-all` sees
   steps 1-5 exactly as written, unchanged. Coverage:
   `usage_read_all_holder_may_query_any_scope_id`,
   `caller_without_usage_read_all_is_still_refused_for_other_scope_ids` and
   `api_key_scope_stays_refused_even_for_usage_read_all` in
   [`crates/lightbridge-authz-usage/tests/scope_ownership_it_tests.rs`](../crates/lightbridge-authz-usage/tests/scope_ownership_it_tests.rs).

This still needs a corresponding fix on the ingest side (`/v1/otel/traces`,
`/v1/otel/metrics`, `/v1/otel/logs`) before it is safe to expose externally — those
stay on a separate, unauthenticated listener even after #347/#570 (see the warning
above for why: their caller cannot be given a client certificate without a
coordinated change outside this repo).

## Findings

### Integration notes

- This repository does not include a Lightbridge frontend, so there are no in-repo UI call sites to enumerate.
- The usage query endpoint is exercised by the integration test runner in [`.docker/it/servers_it.py`](../.docker/it/servers_it.py).
- The endpoint is also described at a high level in [`README.md`](../README.md:162) and [`docs/usage-api.md`](usage-api.md).

### Known quirks and limitations

- Input validation errors currently surface as plain-text errors (often with HTTP 500) due to the shared error-to-response mapping in [`crates/lightbridge-authz-core/src/error.rs`](../crates/lightbridge-authz-core/src/error.rs).
- The API is aggregation-first: no raw events, no server-side ranking/top-N, no offset pagination, and fixed ordering by time bucket.

## How to?

Every example below omits `-H 'Authorization: Bearer <token>'` for brevity — since #570 it is
REQUIRED (see the warning at the top of this document); every example as written now returns
`401`, not `200`, without it.

### Example 1: Total cost for a project over the last 30 days

```bash
curl -k https://lightbridge-usage.converse.svc.cluster.local:3000/usage/v1/usage/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <end-user access token>' \
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
