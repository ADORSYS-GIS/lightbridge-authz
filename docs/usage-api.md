# Usage API (lightbridge-authz-usage)

`lightbridge-authz-usage` ingests OTLP/HTTP traces + metrics from AI Envoy/OpenTelemetry exporters and stores normalized usage events in Timescale/Postgres.

> [!WARNING]
> **The ingest routes are unauthenticated, and `/usage/v1/usage/query` does not check
> ownership of `scope_id`.** This service splits its TLS surface across two listeners
> (#347, `UsageServerGroup` in
> [`crates/lightbridge-authz-usage/src/config.rs`](../crates/lightbridge-authz-usage/src/config.rs)):
> an **ingest listener** (`/v1/otel/*`, `routers::ingest_router()`) that applies no JWT,
> Basic-auth, or mTLS check — its caller is an AI Envoy/OpenTelemetry exporter outside
> this repo's deploy surface, so anyone who can reach it can write fabricated
> usage/billing records for any account or project — and a **query listener**
> (`/usage/v1/usage/query` + `/usage/v1/spend/query`, `routers::query_router()`) that
> **requires and verifies a client certificate (mTLS)**. mTLS authenticates "a
> legitimate lightbridge workload holding a CA-signed cert", not which `scope_id` the
> caller is entitled to see — cross-tenant reads by an already-trusted caller are still
> possible. This service is `ClusterIP`-only in prod with no external route regardless
> — see [`docs/lightbridge-query-api.md`](lightbridge-query-api.md) for the full detail
> (base URL, blast radius, recommended fix direction for the remaining ownership gap)
> before giving this service any external route.

## Endpoints

- `POST /v1/otel/traces`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportTraceServiceRequest`.
- `POST /v1/otel/metrics`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportMetricsServiceRequest`.
- `POST /v1/otel/logs`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportLogsServiceRequest`.
- `POST /usage/v1/usage/query`
  - Single query endpoint for scoped, bucketed usage retrieval.

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

## Scope semantics

- `scope=user` filters by `user_id = scope_id`
- `scope=api_key` filters by `api_key_id = scope_id`
- `scope=project` filters by `project_id = scope_id`
- `scope=account` filters by `account_id = scope_id`

`filters` also accepts `api_key_id` and `user_name` (in addition to `account_id`,
`project_id`, `user_id`, `model`, `metric_name`, `signal_type`), and `group_by`
accepts the same set of dimensions. See
[`docs/lightbridge-query-api.md`](lightbridge-query-api.md) for the full field
reference.

## Migrations

Usage storage migrations are separate from authz migrations:

- `migrations-usage/`
- migration module: `app/lightbridge-authz-usage/src/migrate.rs`

The primary table is `usage_events` (hypertable when Timescale is available).
