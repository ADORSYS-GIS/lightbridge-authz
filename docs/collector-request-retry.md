# Collector request replay prerequisites

Source of truth: [governance#358](https://github.com/ADORSYS-GIS/lightbridge-governance/issues/358)
and [ADR-0028 D22](adr/0028-finops-first-settles-the-usage-store-conventions.md).

The proposed request dedup migration adds a nullable `usage_events.dedup_key` and a unique index
on `(observed_at, source, dedup_key)`. Existing rows remain NULL because their natural request IDs
were not persisted. It neither deletes historical duplicates nor fabricates historical keys.

**Release order:** publish/apply the additive schema migration first, then release the writer.
The writer must not deploy against the old schema. No production migration was run while
preparing this change. The index takes a SHARE lock; schedule it with exporter retry capacity
and verify row counts and index validity before deploying the writer.

Logs with a stable event/observed timestamp and an explicit `x-request-id`, `client_request_id`
or `request_id` receive a JSON tuple key scoped by account and user. Tuple encoding avoids
separator collisions; no prompt, completion, tool input/output or content hash is used. A repeated
export of that request is absorbed by `ON CONFLICT DO NOTHING`. NULL keys retain legacy insert
behavior, so this is **not a claim that every signal is idempotent**.

The current receiver's account/user extraction is still payload-based. Trusted edge attribution
must land before admitting public IDE telemetry. The key alone is not an authentication mechanism.

Limits that still block broad replay and #358 acceptance:

- Untimestamped logs, logs without a natural request ID, metrics and legacy request traces still
  lack this dedup guarantee. A daemon batch retry key cannot stand in for each request's key.
- Once retention deletes a raw row, this index no longer remembers its key. Replaying a purged
  window can reintroduce usage already represented in the daily rollup; do not replay such windows.
- Production is currently plain Postgres. Timescale compressed-chunk behavior still requires
  verification against the version selected for that deployment.
- **Fixed** (governance#358): EAIG and native IDE costs are no longer at risk of being added
  together. `spend_for_account` restricts both the raw and rollup arms to
  `source IS NULL OR source = 'eaig'` (`NULL` covers every row written before source-tracking
  existed, which is 100% EAIG traffic in substance -- excluding it would have undercounted legacy
  spend, not just failed to exclude IDE spend). The daily rollup (`ROLLUP_AND_PURGE_SQL`) now
  carries `source` through its key (migration `20260922000002`, additive: nullable column + a
  replaced, not dropped, unique index), so two sources on the same account/day/model land in two
  separate rollup rows instead of merging -- the coordinated raw/rollup change this note used to
  say was still needed.

## Replay manifest

Each object now requires an explicit canonical `source`, independent of its archive key:

```json
{
  "ingest_base_url": "https://usage.internal:3000",
  "objects": [{
    "key": "claude-code/window/logs-1",
    "source": "claude-code",
    "signal": "logs",
    "content_type": "application/json",
    "body_path": "/archive/logs-1"
  }]
}
```

The source must be in the normalizer registry. `ai-cli`, snake_case aliases, missing and empty
sources are refused; never infer a canonical source from the shared fleet prefix or payload.
All manifest sources are validated before the batch sends anything. A valid source is sent as
`X-Source`, and receiver failures report status without echoing response content.

A mixed legacy AI-CLI archive object cannot be safely replayed under one source merely by
setting this field. Establish trusted source provenance first. The internal replay hop remains
ClusterIP/NetworkPolicy restricted per ADR-0028 D8; this change does not add another credential.
