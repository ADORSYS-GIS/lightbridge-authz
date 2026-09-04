# Runbook: reclaim space from `usage_events` (#549 AC5)

**Open it when:** the `usage` database on `lightbridge-main-db` is consuming more volume than the
retention window should allow — in particular, right after the `attributes` column was dropped
(`20260903000003`, #549 AC1), because `DROP COLUMN` is a catalog-only change and does **not**
physically reclaim the ~900 MB of dropped `attributes` data, or after the retention/rollup job
(#549 AC2) has been running long enough that the raw table's dead tuples need reclaiming.

## What this is for

`usage_events` was a contributing factor in the 2026-08-29 volume-exhaustion outage (#549). The
structural fixes are:

- **AC1** — the write-only `attributes` column is dropped at ingest (`20260903000003`).
- **AC2** — a background job rolls rows older than 90 days into `usage_events_daily` and deletes
  them, bounding the raw table's growth.

Neither of those physically shrinks the table on disk. `DROP COLUMN` marks the column dropped but
leaves its data in place until a full rewrite; a long-lived table also accumulates dead tuples and
index bloat. Reclaiming the space is a separate, one-off, **exclusive-lock** operation.

## Before you start

- This takes an **exclusive lock** on `usage_events` — writes (OTLP ingest) block for the duration.
  The only writer is an OTLP exporter that retries, so a short window is acceptable, but schedule
  it for low traffic.
- Confirm the current size so you can verify the reclaim afterwards:

  ```sql
  SELECT pg_size_pretty(pg_total_relation_size('usage_events')) AS total,
         pg_size_pretty(pg_relation_size('usage_events'))       AS heap;
  ```

- Confirm the retention job is healthy so the table does not regrow while you work:

  ```sql
  SELECT COUNT(*) FROM usage_events_daily;
  ```

## Option A — `VACUUM FULL` (simplest, blocks everything)

`VACUUM FULL` rewrites the table and its indexes, reclaiming dropped-column space and dead tuples.
It takes an exclusive lock and blocks **all** concurrent access (reads included) for the duration.

```sql
VACUUM FULL usage_events;
```

## Option B — `pg_repack` (online, needs the extension)

If the table is large enough that a full blocking rewrite is unacceptable, `pg_repack` rebuilds the
table online (no exclusive lock for the whole operation). It requires the `pg_repack` extension and
a maintenance window with a small lock at the end.

```bash
# on the primary, as a superuser
pg_repack -d <usage-db> -t usage_events
```

## After

Verify the space was actually reclaimed:

```sql
SELECT pg_size_pretty(pg_total_relation_size('usage_events')) AS total,
       pg_size_pretty(pg_relation_size('usage_events'))       AS heap;
```

Confirm ingest is still flowing and spend is unaffected:

```sql
SELECT COUNT(*) FROM usage_events WHERE observed_at > now() - interval '1 hour';
SELECT SUM(total_cost) FROM usage_events WHERE account_id = '<an-active-account>';
```

## Notes

- Do **not** run `VACUUM FULL` on the whole database while the retention job is mid-transaction;
  the job's transaction is short, but schedule the reclaim outside the job's window anyway.
- The `usage_events_daily` rollup table is small and does not need this treatment.
- This is a one-off; going forward the retention job (#549 AC2) keeps the raw table bounded, so
  this runbook should not need to be repeated on a schedule.
