---
name: usage-query-perf
description: Diagnose a slow /usage/v1/usage/query in lightbridge-authz-usage — how to EXPLAIN safely against the read-only production replica, the 2M-row production-width local fixture, the baselines every new measurement should be compared against, what the covering index and the `metrics` field each buy, and which conclusions Timescale would and would not change. Use when someone reports the usage/spend query backend as slow, or before proposing an index, a rewrite, or a storage change.
---

# Diagnosing a slow usage query

The measurements, the shipped fixes and their reasoning are
[`docs/usage-performance.md`](../../../docs/usage-performance.md). The *"would Timescale hypertables
fix this?"* question is answered against the same numbers in
[`docs/plans/0581-multi-source-usage-plan-of-work.md` §0a](../../../docs/plans/0581-multi-source-usage-plan-of-work.md).
**Read those before proposing anything** — the expensive cause is not the one people assume.

## Rule 0 — measure, do not reason

Every claim here came from `EXPLAIN (ANALYZE, BUFFERS)`. `ms` on a shared replica is noise;
**`buffers` is the honest column**, and the plan node names (`Index Only Scan` vs `Parallel Seq
Scan`, `HashAggregate` vs `GroupAggregate <- Sort`) are the *reason*. A change in `ms` alone proves
nothing.

## EXPLAINing on production, safely

Two belts, both mandatory:

1. **The replica**, never the primary. `lightbridge-main-db-2` is the physical replica.
2. **`SET LOCAL default_transaction_read_only = on`** inside an explicit transaction, so a mistyped
   statement fails rather than lands.

```bash
zsh -i -c 'kubectl --context hetzner-prod -n converse port-forward pod/lightbridge-main-db-2 55434:5432'
DSN="postgres://<user>:<pw>@localhost:55434/usage"

psql "$DSN" -X -q -v ON_ERROR_STOP=1 -c \
  "BEGIN; SET LOCAL default_transaction_read_only = on;
   EXPLAIN (ANALYZE, BUFFERS, TIMING ON) <statement>;
   COMMIT;"
```

Grep the output for what matters:

```bash
| grep -E "Execution Time|Planning Time|Buffers: shared|Seq Scan|Index|Sort Method|HashAggregate|GroupAggregate|Gather"
```

`converse` namespace, `hetzner-prod` context — the cluster map is in the `authz-release-verify`
skill.

## Reproducing locally, correctly

`.docker/it/seed-usage-perf-fixture.sql` builds a 2M-row table **at production's row width**
(`attributes` 1,454 B, whole row 1,689 B; prod is 1,464 / 1,727). Use it, and match
`shared_buffers = 128MB` / `work_mem = 4MB`.

**A fixture with a narrow `attributes` blob makes the dominant cause vanish and every conclusion
drawn from it wrong.** That is the single biggest way to waste a day here.

## The environment, so you do not re-derive it

Production `usage`, verified 2026-09-03: PostgreSQL 18.4, 933,494 rows, 3,267 MB heap, 625 MB
indexes, `shared_buffers = 128MB`, `work_mem = 4MB`, **no `pg_stat_statements`**, **no
`timescaledb`**. Re-confirm the last one before assuming otherwise:

```sql
SELECT count(*) FROM pg_extension WHERE extname = 'timescaledb';   -- 0
SELECT indexrelname, pg_size_pretty(pg_relation_size(indexrelid))
FROM pg_stat_user_indexes WHERE relname = 'usage_events'
ORDER BY pg_relation_size(indexrelid) DESC;
-- idx_usage_events_query_cover missing => migration 20260903000002 has not run there
```

## Baselines to compare a new measurement against

Estate-wide, 30 days, 1-day buckets, no `group_by` — the shape the console's overview page issues:

| where | state | result |
| --- | --- | --- |
| production replica | before #665 | **34,799 ms**, 453,374 pages (3.5 GB) |
| 2M fixture | before | 561 ms, 283,341 pages |
| 2M fixture | after the covering index | **222 ms, 13,439 pages** |
| 2M fixture | after, `metrics: ["totals"]` | **130 ms, 13,436 pages** |

7-day range on the fixture: 57,951 → 2,785 pages. Index size 436 MB against a 3,906 MB heap
locally; ~215 MB against 3,267 MB at production's shape.

**If a new shape is far off these, the shape is the finding — say which shape, with its own numbers.**

## The three causes, and which lever moves which

| symptom in the plan | cause | lever |
| --- | --- | --- |
| the table appears twice, or a `Sort → Unique` over ~1M rows | the pre-#665 two-statement bucket pick | already fixed — one statement, `dense_rank()` over its own output |
| `Parallel Seq Scan` reading GB to sum narrow columns | `attributes` is 87% of the row (avg 1,445 B) and stays **inline** just under the TOAST threshold, so a page holds ~4 rows instead of ~35 | `idx_usage_events_query_cover` — an `Index Only Scan` that never touches the heap |
| `GroupAggregate <- Sort` with a disk spill, where you expected `HashAggregate` | `percentile_cont` is an ordered-set aggregate and **cannot be hash-aggregated** | `metrics: ["totals"]` in the request — it changes the plan, not just the cost |

## Before proposing anything, check it against what was already measured and rejected

- **BRIN on `observed_at`** — 536 kB, and left the page count **identical** (279,627). BRIN narrows
  *which* heap pages are visited, not *how wide* they are, and a 30-day query against a 30-day
  retention window is the whole table anyway.
- **A `WITH agg AS (…)` CTE** — indistinguishable on speed, rejected on determinism: it only avoids
  the double scan while Postgres *chooses* to materialise it. The nested form has one
  `FROM usage_events` and cannot regress that way.
- **Timescale hypertables** — chunk exclusion buys **~0** for the shapes the console issues, for the
  same retention-window reason. *Compression* and *continuous aggregates* would help; both remain
  gated on the epic's D1–D7, and nothing in the query path may presume them.
- **`VACUUM FULL`** — the heap was ~2× bloated after #648's backfill. That is autovacuum's job, not a
  migration's.

## If you do add an index

Use the `authz-migration` skill. Specifically: no `CREATE INDEX CONCURRENTLY` (sqlx applies a file as
one implicit transaction, and a failed concurrent build leaves a silently INVALID index a re-run
skips), `INCLUDE` payload columns rather than a wide composite key, and end the migration with
`ANALYZE` — stale statistics after a large rewrite are exactly how a plan that should be index-only
comes out sequential.

## The instrumentation trap, while you are in this crate

`#[instrument]` records every **non-skipped argument** into the span at entry. An unskipped
`body: Bytes` logged the whole compressed OTLP payload; a `Vec<UsageEvent>` logged every decoded
`attributes` blob; a `filters` struct logged user and API-key ids the handler above it deliberately
refused to log.

**Always `#[instrument(skip_all, fields(<explicit>))]`, never `skip(a, b)`** — an allow-list of skips
silently starts leaking the next argument somebody adds. Prove a fix with a real `tracing`
subscriber driving the real handler; the failure mode is an attribute macro's behaviour, which source
text does not show. Quiet the success path (`info!` → `debug!`); **rejects stay at `warn!`**.
