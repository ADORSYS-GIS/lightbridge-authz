# Plan of work — Epic #581: Multi-source usage ingestion

Status: draft for maintainer review · Date: 2026-08-31 · Branch: `claude/issue-581-planning-14304a`

Source of truth: #581, ADR-0027 (`docs/adr/0027-one-usage-store-partitioned-by-grain.md`),
governance ADR-0014/ADR-0013, `docs/research/2026-08-25-genai-usage-ingestion.md`.

This plan turns the epic's four phases into concrete PR slices, names what can start **today**
with no decision pending, and consolidates every maintainer-reserved decision found across the
issue corpus, the ADRs, and the governance repo — so none gets settled by accident in code.

---

## 0. Ground truth (verified 2026-08-31)

- **Zero implementation work has landed.** All 15 tracked issues are open with no PRs and no
  comments. What exists: ADR-0027 + gov ADR-0014 (merged), the F1–F6 research audit, and the
  #488 micro-USD fix (`spend.rs` no longer multiplies by 1e6, PR #496).
- `usage_events` is **not a hypertable anywhere** — `PRIMARY KEY (id)` omits the partition
  column and four `EXCEPTION WHEN OTHERS` handlers swallow the failure
  (`migrations-usage/20260223000001_init_usage.sql:25-59`). Prod additionally has no
  TimescaleDB extension at all. No retention, no compression, `attributes` JSONB is 60% of an
  outage-adjacent table (#549, contributed to the 2026-08-29 volume-exhaustion outage).
- There is **no `source` concept, no normalizer layer, no dedup key** anywhere in
  `crates/lightbridge-authz-usage`. Ingest extraction is 15 hard-coded alias arrays in
  `handlers/ingest.rs:28-171`.
- **The usage crate's it-tests (20 repo tests + all 5 spend-contract tests) run in no CI job
  and no `just` recipe** (`.github/actions/tests/action.yml:73`, `justfile:155`). Any change to
  `repo.rs`/`spend_for_account` currently ships ungated.
- **The Helm chart cannot start the usage binary**: `charts/lightbridge-authz-usage/values.yaml:138-144`
  renders no `server.query` block, which is a required config field since #347 — `serve` *and*
  `migrate` should both fail config load on Kubernetes. (Verify against the deployed state.)
- Governance side: gov#84's audience-narrowing is **already landed** (gov PR #142; prod values
  set `aiCliOtel.enabled: true`; `governance-auth` now does device-code login against authz-idp
  directly). Residuals: gov#144 (second credential for Codex/VS Code), the support-matrix doc,
  and the loopback/RFC 8252 §7.3 question.

---

## 0a. "Would Timescale hypertables fix the slow queries?" — measured 2026-09-03

The owner asked this directly. The answer, with the numbers behind it, is **partly — and not the
expensive part**. Everything here was measured read-only on the production replica
(`lightbridge-main-db-2`, database `usage`, PostgreSQL 18.4, 933,494 rows / 3,267 MB heap /
625 MB indexes, `shared_buffers = 128MB`, `work_mem = 4MB`) plus a 2M-row local fixture built to
production's row width (`.docker/it/seed-usage-perf-fixture.sql`). The console's estate-wide
30-day overview query took **34.8 s** on production (2,993 ms picking buckets + 31,806 ms
aggregating).

Where that 34.8 s actually goes, and who fixes each part:

| cost | share | what fixes it |
|------|-------|---------------|
| Reading 3,268 MB of heap for eighteen narrow columns, because inline `attributes` (avg 1,445 B, 87% of the row) makes a page hold ~4 rows instead of ~35 | ~27 s of 31.8 s in the aggregation, plus most of the bucket-pick step | **Shipped today**: the covering index (`migrations-usage/20260903000002`) — 279,627 → 13,436 pages on the fixture, 20.8× fewer. Timescale's **columnar compression** would attack the same cost from the other side and go further (`attributes` is a compressible blob nobody reads), but it is not the only way to get there, and PR-1b's `usage_request_events` split — which moves `attributes` out of the hot table entirely — is the real structural fix. |
| Scanning the same rows a second time for the bucket list | 2,993 ms (8.6%) | **Shipped today**: one statement instead of two. Nothing to do with Timescale. |
| `percentile_cont` forcing `GroupAggregate` + a disk-spilling `Sort` instead of `HashAggregate` | 222 ms vs 130 ms on the fixture with the index; 34,387 ms vs 31,500 ms on production without it | **Partly shipped today**: one multi-quantile call instead of three, and a `metrics` request field so a caller that does not need percentiles does not pay for them. **Continuous aggregates (#587) are the real fix** — they make the percentile a lookup instead of a computation — and they need `timescaledb_toolkit` (D1). |
| Chunk exclusion (only reading the chunks a time range touches) | **~0 for the shapes the console actually issues** | Hypertables. But the console asks for 7d/30d/90d/mtd against a table with a **30-day retention window** — a 30-day query IS the whole table, so there are no chunks to exclude. Chunk exclusion earns its keep only once retention is longer than the typical query range (#582/#583's day/seat facts). |

**Residual after this PR, before any Timescale work:** the estate-wide 30-day query should land
around 1–2 s on production (13,436 pages of index instead of 418,280 of heap, extrapolating the
fixture's 20.8× at production's shape), dominated by the aggregate itself rather than by I/O. That
is the number #587's continuous aggregates would then take further, and the number PR-1a/1b should
be judged against — not the 34.8 s it replaced.

**So: no, hypertables are not the fix for this.** Compression and continuous aggregates are the
two Timescale features that would help, chunk exclusion is not, and both remain gated on D1–D7.
Nothing in this PR introduces or presumes Timescale; it is deliberately confined to plain-Postgres
changes that hold whichever way D1 goes.

---

## 1. Decision register — reserved for the maintainer

Nothing below gets decided by an implementer. Gate decisions block Phase 1 DDL; the rest block
the story they're named under.

> **Ruled 2026-08-31 (owner): D1–D8, D14–D16, D18, D19–D23.** The rulings are recorded, with
> rationale, in **ADR-0028** (`docs/adr/0028-finops-first-settles-the-usage-store-conventions.md`),
> which amends ADR-0027. The one-liners below are the index; the ADR is the source of truth.
> **Still open: D9–D13** (archive + normalizer ownership) **and D17** (`ingest_manifests` —
> recommendation recorded, pending confirmation).

### Gate decisions (block all Phase 1 DDL) — ✅ all ruled

| # | Decision | Where it comes from |
|---|---|---|
| D1 | **Timescale image on the usage CNPG tenant** — plain `timescaledb`, `timescaledb-ha` (needed for `timescaledb_toolkit` → percentile continuous aggregates), or the stock-PG fallback (research §6.6: native partitions, 5–20× storage, no incremental CAGG refresh). Decide once **including the toolkit question** (#587 AC5, gov#163) or #587 reopens it. | #489, #581 assumption 1, #587 AC5 |
| D2 | **Grain taxonomy gap**: the IDE *metric* grain (Claude Code counters — `lines_of_code.count`, `commit.count`, `pull_request.count`, `session.count`, `active_time.total`) has **no home** among ADR-0027's four grains; `usage_metric_points`/`usage_span_events` from the research DDL don't appear in the ADR. Fifth family, fold into day facts, or ADR amendment. This drives `ide_activity_daily` and the adoption KPIs. | ADR-0027 vs research §5/§6 |
| D3 | **Time-column name**: `observed_at` (ADR text, legacy) vs `occurred_at` (all research DDL, indexes, dedup keys). Touches every index, compression clause, and query path — pick before the first migration. | ADR-0027 D4 vs research §6.2 |
| D4 | **Canonical `source` vocabulary**: ADR uses `eaig`/`claude_code`/`github_copilot` (snake); research uses `gateway`/`claude-code`/`copilot` (kebab). It's a `compress_segmentby` + group-by column; fix the set in the normalizer registry before DDL. | ADR-0027 vs research §6.2 |
| D5 | **Space partitioning by `source`**: the epic's design addendum mandates it (`add_dimension` hash + segment-by); the research doc explicitly considered and rejected `add_dimension`. Contradiction — resolve explicitly. | #581 addendum vs research §6.3 |
| D6 | **Per-grain retention/compression windows**: ADR says uniform 90d/7d; research differentiates (90d request/metric, 30d span, 3d compression for metric/span); day/seat facts are small, long-lived, and month-over-month valuable — 90d may be wrong for them. Numbers + rationale are "recorded", i.e. currently undecided. | #582 AC2, #583 AC2, #549 |
| D7 | **`attributes` blob**: dropped at ingest or windowed (#549 AC1)? In direct tension with the addendum's "seed the allowlisted tail generously". The implied reconciliation — raw goes to the S3 archive (#589), hot table keeps only the allowlist — should be *stated*, not assumed. | #549 AC1 vs #582/#583 addendum |

**Rulings (ADR-0028):**

- ✅ **D1** — Constraint, not artifact: whichever image runs on **CNPG** *and* migrates the existing
  usage tenant with **zero data loss**. Image selection delegated to the Phase 1 infra PR (PR-1a,
  ai-helm), which MUST record whether `timescaledb_toolkit` is available — if not, percentile CAGGs
  are approximated/deferred and the API docs say so (#587 AC5). The stock-PG fallback is **not**
  authorised by this ruling; if no image satisfies both constraints it comes back to the owner.
- ✅ **D2** — **Deferred**, per the D20 re-scope. The IDE metric counters are adoption/productivity,
  not FinOps: no metric-grain table ships in this epic, `ide_activity_daily` and adoption KPIs are
  out of phase, and the fifth grain family is a future ADR. The cost-bearing
  `claude_code.api_request` log events **are** in scope (request/execution grain).
- ✅ **D3** — **`observed_at`** everywhere (ADR-0027's name wins); the research doc's `occurred_at`
  DDL is transposed mechanically.
- ✅ **D4** — **kebab-case**, closed at the normalizer registry: `eaig`, `claude-code`, `codex`,
  `opencode`, `microsoft-foundry`, `github-copilot`. Snake_case variants superseded; unknown source
  = refusal (#584). `source` stays `TEXT`, not a PG enum.
- ✅ **D5** — `source` is an indexed dimension column + **leading `compress_segmentby`** member;
  **no `add_dimension` hash space partitioning**. Overrides #581's design-addendum sentence.
  Rationale (corrected): the usage CNPG cluster runs multiple **instances**, but they are
  **replicas** — each a full copy on its own PVC, all writes through the primary. Space
  partitioning pays off only when chunks stripe across multiple tablespaces/disks on the **same**
  node (CNPG declarative tablespaces with dedicated PVCs), which is **not configured here**.
  **Reopens if per-instance declarative tablespaces are ever introduced.**
- ✅ **D6** — **Tiered**: raw **request AND execution grain 13 months**, compression at 7 d; day
  facts, seat snapshots and billing/KPI continuous aggregates **25 months** (YoY). 13 = a full year
  plus the current billing month, so month-boundary queries never truncate; 25 applies the same +1
  to the aggregate tier. Storage: **40 Gi per PVC** (the research doc's §10 Q4 "5 Gi" is **stale** —
  correct it wherever cited); post-D7 request grain ≈ **40 MB/day** → ~15 GB/year uncompressed,
  single-digit GB compressed, comfortably inside 40 Gi.
- ✅ **D7** — **Dropped at ingest** beyond the allowlisted typed tail. #589's S3 raw archive is the
  replay/promotion path; until it lands, drops are unrecoverable, so the allowlist is seeded
  generously (9-of-55 is a floor, not a ceiling). Content and PII are never allowlisted.

> **Interim deviation recorded (#549, 2026-09-04).** The #549 retention PR ships the *irreversible*
> half of D7 (drop the `attributes` blob at ingest) **without** the D7 precondition (seed the
> allowlist to at least the 9-of-55 floor): it keeps only the three #648 bridge columns (`azp`,
> `operation`, `billing_plan`) and drops everything else from every new row, with no replay path
> until #589 lands. It also hard-deletes rolled-up days at `rollup_days: 365` (≈12 months), which is
> **shorter than D6's 13-month raw request grain** — after a day is purged from `usage_events_daily`,
> `spend_for_account` returns `None` → `Spend::Unavailable` for a period that used to be answerable.
> Both are deliberate interim bridges on a table #581's PR-1b will rewrite (the same status the #648
> bridge columns carry); they are recorded here so the D6/D7 reconciliation is explicit, not assumed.
> `usage_events_daily` itself is an interim table that PR-1b drops.

### Phase 2 decisions (authenticated door) — D8 ✅ ruled, D9–D13 open

| # | Decision | Where |
|---|---|---|
| D8 | ✅ **RULED.** **Does the SA-token pattern really sidestep #534?** Epic assumption 2. Sharpened by an unreconciled conflict: gov#196's addendum routes governance-ctl through the **edge** collector (Traefik-fronted, public), while gov#169's SA/TokenReview pattern is by its own rule only valid where the verifier reaches the cluster JWKS. The two credentials must not blur. | #581 assumption 2, gov#169 vs gov#196 |

**Ruling on D8 (ADR-0028 D8):** projected ServiceAccount tokens are **rejected for authz surfaces**
("SA-Token should not work on authz directly"). Three legs:

1. The authenticated door for developer-attributed push sources is the **edge OTEL collector's OIDC
   validation of authz-issued tokens** — the gov#84 chain, already live in prod.
2. Legs **behind** that door inside the cluster are **trusted network paths**: no second credential
   on the collector→usage hop (ClusterIP + NetworkPolicy, same class as the gateway's existing
   exception).
3. Anything **out-of-cluster** that cannot ride the collector needs real machine-to-machine
   credentials from `authz-idp` — so **#534 is pulled INTO scope and gets its own implementation PR
   now** ("propose a PR to #534 directly, to gain in time").

Supersedes **#581 Key Assumption 2** and **ADR-0027 decision 4's** per-collector-projected-SA-token
sentence; **dissolves the gov#169-vs-gov#196 conflict** (no TokenReview reachability question
remains on the authz side). gov#169's SA-token pattern stays a governance-repo concern for
governance's own internal endpoints, not ours.
| D9 | **Archive PII retention + access control** (#589 AC4) — "decided, not defaulted"; compliance weight (ai-helm ADR-0011). | #589 |
| D10 | **May an archive-sink failure block the governed-store leg?** Recommendation on record (no — legs independent, dropped batch alarms), pending ratification. | #589 AC5 |
| D11 | **Archive format** proto vs OTLP-JSON — verify the contrib S3 exporter round-trips through replay *early*. | #589 |
| D12 | **Normalizer crates: move to authz or depend on governance?** "Moving is the default" but not ratified; cross-repo ownership. | #584 |
| D13 | **Cost recomputed from `model_pricing` vs trusted from emitter** (RFC-0003 Q7). Either way the per-source normalizer owns unit conversion (gateway = µUSD, `claude_code.cost.usage` = USD float). | research §9, gov ADR-0013 |

### Phase 3/4 decisions — D14, D15, D16, D18 ✅ ruled; D17 open (recommendation recorded)

| # | Decision | Where |
|---|---|---|
| D14 | ✅ **RULED.** **Scope→tenant resolution authority** for the ownership check: shared-DB lookup vs authz-api call. A service-coupling decision, previously deferred to "in implementation"; D19 made it PR-0d's blocker. | #586 / #570 |
| D15 | ✅ **RULED.** **Wire shape for multi-scope**: `scope_ids: []` vs `scope: owner`. Console depends on the answer. | #578 / #586 |
| D16 | ✅ **RULED.** **gov#181's failing verify job: fix or retire** — decided *before* the irreversible cutover, not during. | #588 |
| D17 | ⏳ **OPEN — recommendation recorded.** **`ingest_manifests`: move server-side or re-point** — gov#196 AC3, explicitly "decide and record". | gov#196 |
| D18 | ✅ **RULED.** **Latency contract landing spot**: shipped `latency_ms` + p50/p95/p99-at-query-time vs research's `duration_ms`/`upstream_ms`; toolkit absence blocks percentile CAGGs on the plain image. The "`latency_samples: 0` + `null`, never `0.0`" honesty rule must survive. | docs/usage-api.md vs research §6.2/§6.7 |

**Rulings (ADR-0028):**

- ✅ **D14** — **No shared-DB lookups across services.** Each app resolves through the **owning
  service's API** (in-cluster HTTP, low latency, accepted deliberately). The #570 fix's authority
  endpoint on **`authz-opa`** is the **ratified pattern** — fail-closed: unreachable/timeout/non-2xx
  ⇒ refuse, never allow. Generalizes both ways: the usage service never grows an authz-DB pool, and
  authz never queries usage tables — **re-affirming the `3b34de2` inversion** (#345/#346:
  `TimescaleSpendReader` deleted, `UsageServiceSpendReader` over HTTP) as a rule rather than one
  refactor's local choice.
- ✅ **D15** — **`scope_ids: []`** (array), not `scope: owner`. Binds #578 and #586. Derived: an
  absent or empty array is a **400**, never "all" (the F3 default-off footgun, and #570's bug).
- ✅ **D16** — gov#181's failing verify job is **RETIRED, not fixed**. Binds #588 and gov#196 AC5.
  Retirement ships **with** its successor controls (#588's per-table and per-`(day, report)` count
  assertions, plus D17's re-pointed verify), never before them.
- ⏳ **D17** — *pending owner confirmation.* Recommendation: `ingest_manifests` **stays
  governance-side** as the collector's sent-bookkeeping; **`verify` re-points at the usage query
  API**; server-side idempotency is carried by the **grain dedup keys** (D22), not by a manifest.
  Confirm before PR-4a writes its assertions.
- ✅ **D18** — the request-grain rewrite adopts the research schema's **`duration_ms INTEGER` /
  `upstream_ms INTEGER`**; `latency_ms DOUBLE PRECISION` is **not** carried forward. The query API's
  `latency_p50/p95/p99_ms` compute from `duration_ms`, `latency_samples = COUNT(duration_ms)`, and
  the honesty contract (**`latency_samples: 0` + `null` percentiles, never `0.0`**) is preserved
  verbatim. `docs/lightbridge-query-api.md`'s per-signal latency-source table needs a **rewrite
  note** (two columns + per-source normalizers, not one alias-list column); `docs/usage-api.md:67`
  goes with it.

### Standing questions (not per-story) — ✅ all ruled

- D19 — **Lift #570 out of Phase 3?** It is a live cross-tenant usage/spend read (any mTLS
  workload — including every console user via the pass-through proxy — can read any tenant by
  posting an arbitrary `scope_id`), currently scheduled behind the image decision and two schema
  stories. Recommendation: fix standalone against the current `usage_events` now (S–M, one
  fail-closed ownership check + a two-tenant it-test); #586 later absorbs it per-grain.
  - ✅ **RULED — yes, lift it.** PR-0d proceeds now against the current `usage_events`, ahead of
    all schema work; #586 absorbs it per-grain later. Makes **D14 urgent** (above).
- D20 — **#491's disposition**: superseded, re-scoped, or kept as the request-grain container?
  Its own text requires owner validation before stories 3+ start; all seven verification boxes
  are unchecked. gov#197 does this on the governance side; there is no authz twin.
  - ✅ **RULED — re-scoped, not superseded.** The epic delivers **LLM FinOps** (cost/spend/token
    accounting) first; performance ops and adoption analytics are a later phase with their own
    ADR. This is what makes D2's deferral free. (ADR-0028 D0.)
- D21 — **gov ADR-0013 is still "Proposed"** while Accepted ADR-0014 adopts its invariants
  verbatim. Worth accepting formally.
  - ✅ **RULED — proceed**; formal acceptance is carried on the governance side (gov twin), not by
    this repo. *(Recorded from the memo; confirm the exact wording before filing it there.)*
- D22 — Spec fix, not a debate: ADR-0027's stated dedup keys (`(trace_id, span_id)` etc.) omit
  the partition column, which is the exact F2 failure. The verified-working shape is
  `UNIQUE (time_col, source, dedup_key)`. Record the corrected shapes in the stories.
  - ✅ **RULED — corrected shapes are binding**: request `UNIQUE (observed_at, source, dedup_key)`;
    execution `UNIQUE (observed_at, trace_id, span_id)`; day `(source, day, subject_kind,
    subject_id)` (already compliant — `day` IS the partition column); seat analogous. Plus: prove
    dedup still holds for a row replayed into a **compressed** chunk. (ADR-0028 D22.)
- D23 — Research Q3, time-sensitive: **was prod spend actually read ~10⁶× high before #496?**
  If `UsageServiceSpendReader` was live against real rows, every refill decision was driven to
  the fail-closed floor. A same-day audit, independent of the epic.
  - ✅ **RULED — run the audit now** (PR-0e), independent of the epic; findings reported, no code.
    *(Recorded from the memo; confirm the exact wording.)*

---

## 2. Work plan

### Lane 0 — start now, no decisions needed (unblockers)

| Slice | What | Size | Why first |
|---|---|---|---|
| **PR-0a** | **CI: run the usage crate's it-tests.** Add a Timescale service container to `.github/actions/tests` (or a dedicated job) and run `lightbridge-authz-usage-rest --features it-tests`; force the failure mode (assert non-zero test count). | S | 25 DB-backed tests incl. all 5 spend-contract tests currently gate nothing. Every later story touches `repo.rs`. |
| **PR-0b** | **Fix the usage Helm chart**: render `server.query` (mTLS listener) and reconcile the 3000-vs-3002/3006 port mismatch; verify against the deployed state first — if prod is running, find out how, before "fixing". | S | Without it nothing in this epic is deployable; both `serve` and `migrate` should fail config load on k8s today. |
| **PR-0c** | **Decision memo → epic comment**: post §1 of this plan on #581 for rulings on D1–D7 (gate) and D19 (lift #570). | S | D1 gates every migration; the memo is the critical path. |
| **PR-0d** | **#570 standalone fix** (D19 ✅): fail-closed ownership check on `/usage/v1/usage/query` + two-tenant it-test. Per **D14**, the check calls an **authority endpoint on `authz-opa`** — no authz-DB pool in the usage service — and refuses when that authority is unreachable (refusal test required). Wire shape per **D15**: `scope_ids: []`, absent/empty = 400. While there, fix #578's real defect — LIMIT truncates by `bucket_start ASC`, silently dropping the *newest* buckets. | S–M | Live cross-tenant exposure; independent of all schema work. |
| **PR-0e** | **D23 audit**: check whether prod spend reads were 10⁶× off pre-#496; report findings, no code. | S | Time-sensitive correctness/trust question the ADR dropped. |
| **PR-0f** | Doc hygiene fold-in (can ride any PR): `docs/usage-api.md:87` falsely claims hypertable; `models/mod.rs:114` says Basic-auth (it's mTLS); ADR-0022's stale line refs. | XS | Prevents planning on false statements. |

### Phase 1 — storage foundation (blocked on D1–D7)

Order: request-grain rewrite establishes the conventions (fail-loud migration style, sabotage
tests, dedup, `usage_identities`), then #582/#583 run in parallel.

| Slice | What | Size |
|---|---|---|
| **PR-1a** | **Infra: Timescale-capable image on the usage CNPG tenant** (#489's infra half — lands in ai-helm/ai-helm-values, per D1). Evidence: `timescaledb_information.hypertables` queryable in the target cluster. | infra |
| **PR-1b** | **Request-grain rewrite** (#489 + #549, under #491): `usage_request_events` hypertable — PK includes the time column, `by_range(<time>, '1 day')` (note: `chunk_time_interval =>` is invalid with `by_range` in TS 2.17, verified), CUID2 `id TEXT`, `source TEXT NOT NULL`, `cost_micro_usd BIGINT NULL` (NULL = unknown, never 0), dedup `UNIQUE (observed_at, source, dedup_key)` (`x-request-id` / `client_request_id`), allowlisted attribute tail, **`duration_ms INTEGER` + `upstream_ms INTEGER` (D18 — no carried-forward `latency_ms DOUBLE PRECISION`; `latency_*` response fields and the `null`-never-`0.0` rule unchanged; rewrite `docs/lightbridge-query-api.md`'s latency section and `docs/usage-api.md:67` in the same PR)**, `usage_identities` side table (PII refs, single-UPDATE erasure, sentinels like `missing:<source>:<claim>` preserved as literals), **`azp TEXT` + `operation TEXT` + `billing_plan TEXT` (the #648 bridge dimensions — carried forward as first-class columns, not re-derived; see the interim-bridge note below for the derivation table that must be reused verbatim)**, compression at 7d segmented by scope columns, retention per D6. **No `EXCEPTION WHEN OTHERS`; sabotage test proves the migration fails loudly.** Ingest writes the new table; `spend_for_account` repointed with the wire contract byte-stable (`SpendQueryResponse { total_cost: Option<f64> }`, µUSD unscaled) — note SUM-over-NULL semantics now differ from SUM-over-`NOT NULL DEFAULT 0`; assert the existing spend it-tests pass unmodified. One-off space reclaim (`pg_repack`/`VACUUM FULL`) scheduled, not improvised. Hard cutover: `DROP TABLE usage_events` ships as the *last* migration in the sequence, only after ingest is live; backfill the `signal_type='log'` subset first (only historical billing record).The query contract the console is on by then must survive the cutover byte-for-byte: `group_by`/`filters` on `azp`/`operation`/`billing_plan`, the `operation_in` set-membership filter, and the three dimension echoes on `UsageSeriesPoint`. | L |
| **PR-1c** | **#582 execution grain**: `usage_executions`/`usage_model_calls`/`usage_tool_calls` ported from governance's proven schema (donor: `governance-core/migrations/postgres/20260803000001_telemetry_models`); dedup on `(<time>, trace_id, span_id)`; identity via `usage_identities`; ADR-0038 exception justified in the migration header; sabotage + replay-idempotency + NULL-money round-trip tests. | L |
| **PR-1d** | **#583 day/seat grain**: `usage_day_facts` keyed `(source, day, subject_kind, subject_id)` with `subject_kind ∈ {org,user,repo,user_team}` + `usage_seat_snapshots`; upsert on natural key; aggregate-only sources tagged in-row (Copilot's 5-seat floor), never averaged into per-user data; join rule: `provider_user_id`, never `user_login` (gov#185); **zero-DDL second-source demonstration in CI** (governance#167's criterion — fixture vs real M365 data is a sub-decision). Watch: governance's day tables have `net_cost_micro_usd NOT NULL` — the port must restore NULL-means-unknown. | M–L |

#### Interim bridge (#648) — `azp` / `operation` / `billing_plan` on `usage_events`, and it dies with the table

Owner ruling, 2026-09-02: **bridge now, do not wait for PR-1b.** Zero of this epic had landed and
the console's `/admin/usage` area needed the dimensions immediately, so #648 added them to the
*current* `usage_events` as three nullable `TEXT` columns
(`migrations-usage/20260902000001..3`), a batched backfill from `attributes`, three
`(<dimension>, observed_at DESC)` indexes, `UsageGroupBy`/`UsageQueryFilters` entries, an
`operation_in` set filter, and a `usage:read-all` admin scope bypass in `handlers/query.rs`.

**This is deliberately disposable and is expected to die with `DROP TABLE usage_events`** in
PR-1b's sequence. What must NOT die with it is the contract the console will be built on by then —
PR-1b carries the three columns (see its row above) and reuses this derivation table **verbatim**:

| Source, first match wins | Column |
|---|---|
| `azp`, `x-oidc-azp`, `oauth.azp`, `client_id` | `azp` |
| `billing_plan`, `x-billing-plan` | `billing_plan` |
| path from `x-envoy-origin-path`, `http.route`, `url.path`, `route_name` | `operation`, per the prefix table below |

| Path prefix | `operation` |
|---|---|
| `/v1/chat/completions` | `chat_completions` |
| `/v1/responses` | `responses` |
| `/v1/messages` | `messages` |
| `/v1/embeddings` | `embeddings` |
| anything else | `other` |
| *no path key at all* | `NULL` (never `other`) |

Prefix match, not equality (a real request target carries a query string). If PR-1b renames the
column to this plan's earlier `operation_name`, or changes a vocabulary value, it must say so in
the same change so the console's `dashboards.yaml` and `openapi/usage.backend.yaml` move with it —
silence here is what turns a rename into a blank dashboard. Source: `#648`, and the owner comment
on this issue dated 2026-09-02.

### Phase 2 — authenticated door (starts in parallel with Phase 1; **D8 ruled — #585 unblocked**)

| Slice | What | Size |
|---|---|---|
| **PR-2a** | **#585 authenticated ingest**: distinct authenticated surface; trusted `source` bound to the credential, never payload (payload mismatch alerts, never overwrites); credential = **authz-issued token OIDC-validated at the edge collector**, and **no projected SA tokens on any authz surface** (D8) — the collector→usage hop is an in-cluster trusted path (ClusterIP + NetworkPolicy), stated as such, not dressed as a boundary; refusal tests written-to-fail-first for no-credential / wrong-audience / disallowed-principal / **auth-dependency-unreachable ⇒ refuse**, with no env-var opt-out that can skip them in CI; acceptance bar is a **live 200 from a real CLI push** (gov#189), not a clean collector start; gateway path documented as the one deliberate exception. No new shared secrets (gov#191: `X-Internal-Token` must not reappear). | L |
| **PR-2b** | **#589 raw OTLP archive**: S3 exporter on the **edge** collector (parallel with, not behind, the Alloy leg — config lives in `charts/lightbridge-governance`), prefixed by trusted source + date; one generic replay job beside the usage service, idempotent via grain dedup keys; **promotion rehearsal demonstrated end-to-end** (add nullable column → replay window → column backfills → counts unchanged). Verify format round-trip (D11) first. | M–L |
| **PR-2c** | **#584 normalizer registry** (after #582 + D12): string-keyed registry, **unknown source = refusal, not passthrough** (fail-first test); port claude_code/codex/foundry with fixture parity against governance's suites; write the net-new `opencode` normalizer (`gen_ai.usage.*`, float-USD → BIGINT µUSD half-away-from-zero, NULL on absence, NaN/negative/overflow → refusal); extend gzip decode to traces/metrics (today logs-only); delete the alias-array extraction. | M–L |
| **PR-2e** | **#534 machine-to-machine credentials from `authz-idp`** — pulled into scope by D8 leg 3 and **opened directly against #534, now**, not queued behind the epic. Covers every out-of-cluster emitter that cannot ride the edge collector. Grant shape is the PR's subject; D8 rules only that it is needed. | M (start now) |
| **PR-2d** | **gov#196** (governance repo, after #583 + #585): governance-ctl emits day-grain reports as OTLP through the collector; direct-Postgres writes *removed*; `sync.rs` (1178 LoC) split per the repo's ratchet; D17 decided in the same change. | L (gov) |

### Phase 3 — query surface (after Phase 1; #587 also needs D1's toolkit answer)

| Slice | What | Size |
|---|---|---|
| **PR-3a** | **#586 per-grain query APIs**: four closed typed endpoints (`requests`/`executions`/`facts`/`seats`), no shared grain parameter, cross-grain aggregation unrepresentable; `source` filter + group-by (enum/bind-bound per ADR-0022's closed-schema rules); absorbs #570 per-grain (**D14**: authority endpoint on `authz-opa`, never a shared-DB read) and #578 (**D15**: `scope_ids: []`); **no `unwrap_or(0)` on any monetary path**, unknown-count reported alongside totals; spend seam byte-stable — existing integration tests pass unmodified; OpenAPI contract tests. JSON/axum stays (ADR-0013 excludes usage from CBOR). | L |
| **PR-3b** | **#587 continuous aggregates**: one named aggregate per KPI measure (#491's list of 10), none spans grains; refresh policies present in `timescaledb_information.jobs` *and demonstrably run in the target cluster*; `EXPLAIN` captured per KPI proving aggregate use (Timescale does **not** auto-route — the repo layer routes explicitly); no zero-gap-filling in storage (`time_bucket_gapfill` is presentation-time only); daily built hierarchically from hourly. | M |

### Phase 4 — cutover (last, deliberately; **D16 ruled — retire gov#181's verify job**, with its successor controls in the same change; D17 still to confirm)

| Slice | What | Size |
|---|---|---|
| **PR-4a** | **#588 cutover**: freeze governance-ctl writes → Copilot dailies/seats replayed from the S3 NDJSON archive **through the authenticated day-grain path** (the only pre-collector history; its retirement sequences *after* this) → executions/model_calls/tool_calls migrated directly → per-table and per-`(day, report)` count assertions vs `ingest_manifests`, mismatch blocks loudly → governance telemetry tables **dropped in the same change** → dashboards repointed/retired (ai-helm#879/#880 noted, not silently broken). Rehearsal: a deliberately corrupted row must block (sabotage-first). | L |
| **PR-4b** | **gov#197** backlog re-scope: post dispositions per ADR-0014 §4; verify each constraint citation (gov#185 join rule, gov#188 no-`unwrap_or(0)`) is demonstrably carried before closing donors; re-plan (don't delete) #159/#161 rollup points. Do the authz twin for #491 (D20). | S–M (gov) |
| **PR-4c** | Consumers: console usage graphs (#508/#274–#276 — mostly converse-frontends), seeding via real authenticated ingest (#528 — becomes M post-#585), Grafana successors. gov#36's headline query answered from this store alone = epic exit criterion. | M (spread) |

### Dependency graph (compressed)

```
Lane 0 (now):  PR-0a CI ─┐   PR-0b chart ─┐   PR-0c memo → D1–D7   PR-0d #570 lift   PR-0e audit
                          └────────────────┴──── all later PRs assume these landed

D1 image ──► PR-1a infra ──► PR-1b request rewrite ──► PR-1c #582 ─┬─► PR-2c #584 ─┐
                                        │              PR-1d #583 ─┤               │
PR-2e #534 (now) ┄► PR-2a #585 ─► PR-2b #589 ───────────────────────┤               ├─► PR-4a #588 ─► PR-4b/4c
                     └──────► PR-2d gov#196 (needs #583 too) ──────┘               │
PR-1c + PR-1d ─► PR-3a #586 ─► PR-3b #587 ─────────────────────────────────────────┘
```

---

## 3. Delivery discipline (applies to every slice)

- **Sabotage tests are the bar** (governance#164): break the migration/refusal path, watch the
  test fail for the predicted reason, restore, say so in the PR.
- **Migration hygiene**: new files only under `migrations-usage/` (separate SQLx stream); never
  edit an applied migration (checksums — this repo was burned once, `eb5ae99`); check the
  version prefix is free on `main` before opening the PR (same-day collisions turned `main` red
  on 2026-08-30).
- **Money**: integer µUSD, `NULL` = unknown, never 0; the spend seam
  (`/usage/v1/spend/query` → `Option<f64>`) byte-stable, proven by its existing tests passing
  unmodified.
- **Ids**: CUID2 via `lightbridge_authz_core::cuid::cuid2()` only; never sort/paginate by id;
  never validate id shape.
- **Config changes need a companion `ai-helm-values` PR with stated ordering** — a stale key
  silently reads as `None` and routes every spend-dependent refill to manual review.
- **No content, ever** — prompts/completions/tool args/results are permanently rejected (#491);
  `trace_id` is the seam to Tempo.
- Sub-agent pipeline per house rules: cheap tier drafts → two adversarial reviewers with
  distinct lenses → remediation reviewed → independent gate re-running the *original* failure.

## 4. Suggested first sprint

1. PR-0c decision memo on #581 (unblocks everything downstream).
2. PR-0a CI it-tests + PR-0b Helm chart fix, in parallel.
3. PR-0d #570 standalone fix (pending D19 yes) + PR-0e prod-spend audit.
4. On D1: PR-1a image (ai-helm) and start PR-1b request-grain rewrite.
5. In parallel with 4: PR-2e #534 M2M credentials (D8 leg 3 — "propose a PR to #534 directly, to
   gain in time"), and draft PR-2a #585's refusal-test skeleton (the auth chain needs no tables).
