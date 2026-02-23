# Usage API (lightbridge-authz-usage)

`lightbridge-authz-usage` ingests OTLP/HTTP traces + metrics from AI Envoy/OpenTelemetry exporters and stores normalized usage events in Timescale/Postgres.

## Endpoints

- `POST /v1/otel/traces`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportTraceServiceRequest`.
- `POST /v1/otel/metrics`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportMetricsServiceRequest`.
- `POST /v1/usage/query`
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
- `scope=project` filters by `project_id = scope_id`
- `scope=account` filters by `account_id = scope_id`

## Migrations

Usage storage migrations are separate from authz migrations:

- `migrations-usage/`
- runner crate: `crates/lightbridge-authz-usage-migrate/`

The primary table is `usage_events` (hypertable when Timescale is available).
