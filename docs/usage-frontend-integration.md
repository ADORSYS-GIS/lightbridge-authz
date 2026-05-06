# Usage Frontend Integration Plan

This guide describes how a frontend should consume the `lightbridge-authz-usage` query API without spreading usage-specific rules across screens.

## API contract

- Base path: `/usage`
- Query endpoint: `POST /usage/v1/usage/query`
- Content type: `application/json`
- Authentication: currently none at the usage service boundary
- Response shape: `{ "points": UsageSeriesPoint[] }`
- Error shape for invalid query input: `{ "error": string }`

The endpoint is aggregation-first. It always returns bucketed timeseries points, not raw usage events.

## TypeScript types

```ts
export type UsageScope = "user" | "project" | "account";

export type UsageGroupBy =
  | "account_id"
  | "project_id"
  | "user_id"
  | "model"
  | "metric_name"
  | "signal_type";

export type UsageQueryFilters = {
  account_id?: string;
  project_id?: string;
  user_id?: string;
  model?: string;
  metric_name?: string;
  signal_type?: string;
};

export type UsageQueryRequest = {
  scope: UsageScope;
  scope_id: string;
  start_time: string;
  end_time: string;
  bucket?: string;
  filters?: UsageQueryFilters;
  group_by?: UsageGroupBy[];
  limit?: number;
};

export type UsageSeriesPoint = {
  bucket_start: string;
  account_id: string | null;
  project_id: string | null;
  user_id: string | null;
  model: string | null;
  metric_name: string | null;
  signal_type: string | null;
  requests: number;
  usage_value: number;
  total_cost: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
};

export type UsageQueryResponse = {
  points: UsageSeriesPoint[];
};
```

## API client

Keep this as the only frontend code that knows the raw endpoint path.

```ts
export async function queryUsage(
  baseUrl: string,
  input: UsageQueryRequest,
  signal?: AbortSignal,
): Promise<UsageQueryResponse> {
  const response = await fetch(`${baseUrl}/usage/v1/usage/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
    signal,
  });

  if (!response.ok) {
    const fallback = `Usage query failed with HTTP ${response.status}`;
    const body = await response.json().catch(() => ({ error: fallback }));
    throw new Error(typeof body.error === "string" ? body.error : fallback);
  }

  return response.json() as Promise<UsageQueryResponse>;
}
```

## Query presets

Use explicit query builders per dashboard need. That keeps chart components simple.

```ts
export function projectUsageTimeseries(params: {
  projectId: string;
  start: Date;
  end: Date;
  bucket: "1 hour" | "1 day";
  model?: string;
}): UsageQueryRequest {
  return {
    scope: "project",
    scope_id: params.projectId,
    start_time: params.start.toISOString(),
    end_time: params.end.toISOString(),
    bucket: params.bucket,
    filters: params.model ? { model: params.model } : {},
    group_by: ["model"],
    limit: 1000,
  };
}

export function accountModelBreakdown(params: {
  accountId: string;
  start: Date;
  end: Date;
}): UsageQueryRequest {
  return {
    scope: "account",
    scope_id: params.accountId,
    start_time: params.start.toISOString(),
    end_time: params.end.toISOString(),
    bucket: "30 days",
    filters: {},
    group_by: ["model"],
    limit: 1000,
  };
}

export function userUsageTable(params: {
  projectId: string;
  start: Date;
  end: Date;
}): UsageQueryRequest {
  return {
    scope: "project",
    scope_id: params.projectId,
    start_time: params.start.toISOString(),
    end_time: params.end.toISOString(),
    bucket: "1 day",
    filters: {},
    group_by: ["user_id", "model"],
    limit: 1000,
  };
}
```

## Dashboard mapping

Recommended first screens:

- Overview KPIs: `group_by: []`, show `requests`, `total_tokens`, `total_cost`.
- Usage over time: `group_by: ["model"]`, render one chart series per model.
- Model breakdown: `group_by: ["model"]`, aggregate returned points client-side by model and sort by `total_cost` or `total_tokens`.
- User breakdown: `group_by: ["user_id"]` or `["user_id", "model"]`, aggregate client-side for a table.
- Filters: expose model and date range first; add user and signal type only when users need debugging depth.

## Frontend data rules

- Treat missing dimension values as `null`, not empty strings.
- Prefer UTC internally and format dates only at the display layer.
- Use `1 hour` buckets for single-day charts and `1 day` buckets for multi-day charts.
- Keep `limit` high enough for `bucket_count * group_count`; otherwise the service may truncate the result.
- For top-N lists, request a coarse bucket and sort in the frontend because the API orders by time.

## Integration sequence

1. Add the typed API client and request/response types.
2. Add date range helpers that output UTC `start_time`, `end_time`, and a bucket.
3. Build query presets for the dashboard views.
4. Add one data hook per preset, with request cancellation for date/filter changes.
5. Normalize `points` into chart series and table rows in selector/helper functions.
6. Add UI states for loading, empty result, and `{ error }` responses.
7. Add contract tests or mocked API tests for the client, especially `400` error parsing.

## Open API questions

These are product/API decisions to make before expanding the dashboard:

- Should the service add dedicated summary endpoints for KPI cards?
- Should top-N sorting and pagination move server-side for large tenants?
- Should usage query become protected by the same bearer middleware as the authz API?
- Should the frontend expose `signal_type` and `metric_name`, or keep them as support/debug filters?
