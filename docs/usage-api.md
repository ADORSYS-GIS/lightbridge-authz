# Usage API (lightbridge-authz-usage)

`lightbridge-authz-usage` ingests OTLP/HTTP traces + metrics from AI Envoy/OpenTelemetry exporters and stores normalized usage events in Timescale/Postgres.

## Endpoints

- `POST /v1/otel/traces`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportTraceServiceRequest`.
- `POST /v1/otel/metrics`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportMetricsServiceRequest`.
- `POST /v1/otel/logs`
  - Accepts `application/x-protobuf` or OTLP JSON payloads compatible with `ExportLogsServiceRequest`.
- `POST /usage/v1/usage/query`
  - Single query endpoint for scoped, bucketed usage retrieval.
- `GET /usage/v1/usage/docs`
  - Swagger UI for the usage query and OTEL ingest contract.

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

## Query response

```json
{
  "points": [
    {
      "bucket_start": "2026-02-20T00:00:00Z",
      "account_id": null,
      "project_id": null,
      "user_id": null,
      "model": "gpt-4.1",
      "metric_name": null,
      "signal_type": null,
      "requests": 12,
      "usage_value": 34567.0,
      "total_cost": 1.23,
      "prompt_tokens": 20000,
      "completion_tokens": 14567,
      "total_tokens": 34567
    }
  ]
}
```

Dimensions that are not listed in `group_by` are returned as `null`. Numeric fields are aggregates for each `bucket_start` plus selected grouping dimensions.

## Validation errors

Invalid query input returns HTTP `400` with JSON:

```json
{
  "error": "start_time must be before end_time"
}
```

The query endpoint validates:

- `start_time` must be before `end_time`
- `scope_id` must not be blank
- `limit` must be greater than zero
- `bucket` must look like `5 minutes`, `1 hour`, or `1 day`

## Scope semantics

- `scope=user` filters by `user_id = scope_id`
- `scope=project` filters by `project_id = scope_id`
- `scope=account` filters by `account_id = scope_id`

`scope` and `filters` are cumulative. For example, `scope=project` with `scope_id=proj_1` and `filters.project_id=proj_2` is valid JSON, but it returns no points because no row can satisfy both filters.

## Frontend use

For dashboard integration, treat this as a read-model API:

- Keep query construction in one typed client function.
- Use presets for common ranges such as today, 7 days, 30 days, and current billing period.
- Choose the coarsest useful bucket for the chart: `1 hour` for one day, `1 day` for weeks or months.
- Use `group_by: []` for KPI totals, `group_by: ["model"]` for model breakdowns, and `group_by: ["user_id"]` for user tables.
- Sort top-N views client-side because the API always orders by `bucket_start ASC`.

See `usage-frontend-integration.md` for a concrete TypeScript integration plan.

## Migrations

Usage storage migrations are separate from authz migrations:

- `migrations-usage/`
- runner crate: `crates/lightbridge-authz-usage-migrate/`

The primary table is `usage_events` (hypertable when Timescale is available).
