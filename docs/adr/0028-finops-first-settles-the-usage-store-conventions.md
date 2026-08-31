# ADR-0028: FinOps first — the usage store's storage conventions, its ingest door, and its service boundaries, settled before the first migration

- Status: Accepted
- Date: 2026-08-31
- Decision owners: Stephane Segning Lambou
- Amends: ADR-0027 (`docs/adr/0027-one-usage-store-partitioned-by-grain.md`) — decision 3's dedup
  key shapes and its uniform 90-day retention figure, decision 2's snake_case `source` tokens, and
  decision 4's per-collector projected-ServiceAccount-token mechanism. ADR-0027's boundary
  decision, its four-grain taxonomy, "grain partitions storage, vendor never does", and decision
  4's *principle* (no unauthenticated door for developer-attributed telemetry) are **unchanged**;
  this ADR fixes the conventions the first migration has to spell out and that ADR-0027 left as
  prose.
- Overrides: [#581](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/581)'s design-addendum
  sentence mandating Timescale space partitioning by `source` (D5 below), and its **Key Assumption
  2** (SA tokens sidestep #534 — D8 below).
- Pulls into scope: [#534](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/534)
  (machine-to-machine credentials from `authz-idp`), which gets its own implementation PR now
  rather than being sidestepped (D8 leg 3).
- Re-scopes: [#491](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/491) — re-scoped, not
  superseded (D0 below).
- Source of truth: [#581](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/581) and the
  decision memo posted against it (`docs/plans/0581-multi-source-usage-plan-of-work.md` §1,
  decisions D1–D8, D14–D18 and D19–D23 — all ruled). The rulings
  recorded here are the repo owner's, 2026-08-31.
- Re-affirms as a rule: the #345/#346 spend-data dependency inversion (`3b34de2`) — see D14.
- Mirror: ADR-0027's mirror in `lightbridge-governance`
  (`docs/adr/0014-usage-telemetry-consolidates-into-the-authz-usage-store.md`) adopts the text this
  ADR amends. D4, D8 and D22 need a corresponding note there — see Consequences, "Elsewhere".

## Context

ADR-0027 settled *where* AI-usage telemetry lives and *how it partitions* (by grain; `source` is a
dimension, never a table name). It deliberately did not settle the dozen smaller questions that a
migration file cannot avoid answering — what the time column is called, what values `source` takes,
how long each grain is kept, what a dedup key looks like on a hypertable.

Planning epic #581 against ADR-0027 surfaced those questions as concrete contradictions rather than
gaps, because two documents describe the same tables in incompatible detail: ADR-0027's prose and
`docs/research/2026-08-25-genai-usage-ingestion.md`'s DDL (`observed_at` vs `occurred_at`,
`claude_code` vs `claude-code`, uniform 90 days vs per-grain windows, `add_dimension` mandated by
#581's addendum and explicitly rejected by the research doc). Every one of them is load-bearing on
the first migration: they appear in the primary key, the unique indexes, the compression clause and
every query path, and none of them is cheap to change after rows exist and chunks are compressed.

One question of the same kind sits on the ingest side rather than the storage side: ADR-0027 named
per-collector projected ServiceAccount tokens as the in-cluster credential, while the two governance
issues implementing it (gov#169's SA/TokenReview pattern, gov#196's addendum routing through the
Traefik-fronted edge collector) contradict each other about where the credential is even verifiable.
D8 settles it by removing the mechanism from this side entirely.

**Nothing has been built yet** — all 15 issues under #581 are open, no PRs — which is the only
reason these are still free choices. That window closes with the request-grain rewrite.

## Decision

### D0 — The epic delivers **LLM FinOps** first. Performance and adoption ops are a later phase.

#491 is **re-scoped, not superseded**. The store it describes is the store being built; the
ambition it carries — full GenAI observability, including developer-productivity and adoption
analytics — is phased. Phase one is cost and spend accounting: which account, project, key, user,
model and provider consumed what, in integer micro-USD, with `NULL` meaning *unknown, never zero*.
Everything that does not carry money or tokens waits for a Performance-ops phase with its own ADR.
This is the frame for D2 below, and it is why deferring a grain family costs the epic nothing it
was contracted to deliver.

### D1 — The Timescale image is chosen by constraint; the name is delegated to the infra PR

The ruling is the **constraint**, not the artifact: whichever image runs on CNPG *and* brings the
existing usage tenant across **without data loss**. Both halves are hard requirements — an image
that satisfies one is not a candidate.

The concrete selection (plain `timescaledb`, `timescaledb-ha`, or another CNPG-compatible build)
lands in the Phase 1 infra PR in `ai-helm`/`ai-helm-values` (plan slice PR-1a). That PR carries two
obligations:

- **Evidence, not intent**: `timescaledb_information.hypertables` queryable in the target cluster,
  and the existing tenant's rows accounted for across the change.
- **Record whether `timescaledb_toolkit` is present**, because #587 AC5 depends on the answer. With
  the toolkit, percentile continuous aggregates (p50/p95/p99 latency) are exact. Without it, they
  are approximated or deferred — and **the API documentation must say which**, in the same PR that
  ships the endpoint. A percentile that is silently an approximation is the same class of defect as
  `latency_samples: 0` reported as `0.0` instead of `null`; the honesty rule from `docs/usage-api.md`
  survives this ADR intact.

**This ruling does not authorise the stock-PostgreSQL fallback.** If no CNPG-compatible image
satisfies both constraints, that comes back to the owner as a decision, not down to an implementer
as a fallback. The fallback costs compression, continuous aggregates and retention policies at
once — and D6's 13-month raw window is sized *assuming* compression from day 7 (Consequences,
storage sizing). Falling back silently would mean either an unbudgeted footprint or a quiet
retention trim, and the retention floor is a correctness property, not a knob.

### D2 — No metric-grain table ships in this epic. The gap is deferred, not closed.

The IDE *metric* counters have no home among ADR-0027's four grains. That gap is real and stays
open; under D0 it is simply **not this epic's problem**, because the counters are adoption and
productivity signals, not FinOps signals:

`claude_code.lines_of_code.count`, `claude_code.commit.count`, `claude_code.pull_request.count`,
`claude_code.session.count`, `claude_code.active_time.total`, `claude_code.code_edit_tool.decision`.

None of them carries cost or tokens. They answer "is the tool being adopted and is it helping",
which is the Performance-ops question. Consequently:

- **No fifth hypertable family in this epic.** The research doc's `usage_metric_points` and
  `usage_span_events` DDL (§6.3) is **not** ordered by #581 and no migration creates them.
  `usage_span_events`' function — model calls and tool calls with trace correlation — is already
  served by ADR-0027's execution grain (`usage_executions`/`usage_model_calls`/`usage_tool_calls`),
  so the deferral is specifically the *metric datapoint* family.
- `ide_activity_daily` and the adoption KPIs derived from it are **out of the FinOps phase**. They
  are not silently dropped; they are the opening scope of the Performance-ops phase.
- **The cost-bearing Claude Code signal is in scope**: `claude_code.api_request` log events carry
  `cost_usd`/`cost_usd_micros`, `input_tokens`, `output_tokens`, `cache_read_tokens`,
  `cache_creation_tokens`, `model` and `duration_ms`. That is request/execution grain by ADR-0027's
  own test (a Claude Code `api_request` record and a gateway access-log record are the same grain),
  and it lands in an existing table with a normalizer and a registry row — exactly the zero-DDL
  property governance#167 demands. Note the unit trap the normalizer owns: `claude_code.cost.usage`
  is a **USD float** while `api_request.cost_usd_micros` is already micros.
- The fifth family, when it comes, is a **new ADR** — not an implementer's schema call inside a
  FinOps PR, and not an `attributes` key smuggling counters into a fact table.

### D3 — The partition column is `observed_at`. Everywhere it is an event timestamp.

ADR-0027's name wins; the research doc's `occurred_at` DDL is **transposed, not adopted verbatim**.
This is a pure naming ruling with no semantic content, decided so that it is decided: the column
appears in the primary key, in `by_range(...)`, in every dedup unique index, in `compress_orderby`,
in every covering index's trailing position, and in every query predicate. Two names for it means a
silent mismatch in whichever artifact was copied from the wrong document.

One name, no alias, no compatibility view. Where the research DDL says `occurred_at`, the migration
says `observed_at`, and the transposition is mechanical.

**Reading, stated explicitly because "everywhere" is doing work here:** `observed_at TIMESTAMPTZ` is
the name wherever the partition column is an *observation instant* — the request grain, the
execution grain, and any future family that partitions on a timestamp. The day and seat grains
partition on a calendar `day` (a DATE that is also part of the natural key, D22); renaming that
column `observed_at` would misdescribe a daily bucket as an instant and break the natural key's
readability. If the intent was literal — one identifier on all four families — that is a correction
the owner should make now rather than after the first migration.

### D4 — The canonical `source` vocabulary is **kebab-case**, and the set is closed at the registry

Derived from ADR-0027's own list, normalised to one casing convention:

| token | what it is |
|---|---|
| `eaig` | the AI gateway's Envoy access-log sink — the only source live today |
| `claude-code` | Claude Code CLI (OTLP push via the `aiCliOtel` collector) |
| `codex` | Codex CLI |
| `opencode` | OpenCode (third-party OTLP plugin; also identifiable at the gateway by user-agent) |
| `microsoft-foundry` | Microsoft Foundry platform reports |
| `github-copilot` | GitHub Copilot org/user/repo dailies and seat reports |

**Superseded:** the snake_case tokens in ADR-0027's decision-2 mermaid diagram (`claude_code`,
`microsoft_foundry`, `github_copilot`) and the matching identifiers in the governance normalizer
fixtures. Also superseded are the research doc's short forms `gateway`, `copilot`, `foundry` — the
ADR-0027 names win on identity (the gateway is `eaig`), the research doc wins on casing.

Rules that ride with the set:

- **Normalizers emit exactly these tokens.** Not the vendor's own spelling, not the collector's
  `service.name`, not a `user-agent` substring — the normalizer's job includes producing the
  canonical token, and the registry is the single place the set is written down (#584).
- **Unknown source = refusal, not passthrough** (#584, fail-first test). A row whose source cannot
  be resolved to a registry token is rejected at ingest; it is never written with a guessed,
  empty or `unknown` token. This is the same fail-closed posture the rest of the platform takes on
  an unresolvable input.
- **`source` stays `TEXT NOT NULL`, not a PostgreSQL enum.** The vocabulary is closed at the
  *registry*, which is code, so adding a source remains "a normalizer and a registry row" with no
  schema change — ADR-0027's definition of done for the first migration. A DB enum would convert
  every new source into a migration, which is the property ADR-0027 exists to protect.

### D5 — `source` is a dimension column and a compression segment. It is **not** a space dimension.

`source` remains everything ADR-0027 said it was: `TEXT NOT NULL`, indexed, filterable, group-by-able,
and a `compress_segmentby` column on every grain family.

There is **no** `add_dimension(..., by_hash('source', N))`. #581's design-addendum sentence
mandating space partitioning is overridden.

The reasoning turns on what space partitioning actually buys, and on the shape of this cluster —
which is easy to get wrong from the outside. The usage CNPG cluster runs **multiple instances**
(two today, three soon), but those instances are **replicas**: each holds a full copy of the
database on its own PVC, and every write flows through the primary. More instances is availability
and read fan-out; it is not more spindles under one writer.

Timescale space partitioning pays off when chunks **stripe across multiple tablespaces or disks on
the same node**, so concurrent chunk scans hit independent devices — i.e. CNPG declarative
tablespaces with dedicated PVCs. **That is not configured here.** Without it, hashing multiplies
chunk count by N — more chunks, more planning time, more per-chunk overhead, more policy jobs — and
buys no query benefit, because the pruning that filtering by `source` actually needs comes from
**compression segment-by**: segmented columns keep per-segment min/max, so `WHERE source = 'eaig'`
skips segments without decompressing them.

Note for whoever writes the clause: column *order* inside `compress_segmentby` carries no semantic
weight in Timescale — the pruning comes from the column being segmented at all. Listing `source`
first is a readability convention that makes the ruling visible in the DDL. `compress_orderby` is
the clause where order is load-bearing (`observed_at DESC` leads).

Revisit conditions, either of which reopens this as a new ADR rather than an implementer's call:
**per-instance declarative tablespaces being introduced** (the premise above changes, and striping
becomes real), or a single day-chunk ceasing to fit comfortably in shared buffers.

#### D5 appendix — what changes if declarative tablespaces are adopted later

Written down now, while the reasoning is fresh, so the reopen is a review rather than a
rediscovery. If CNPG gains per-instance declarative tablespaces on dedicated PVCs:

- **`add_dimension(..., by_hash('source', N))` becomes worth re-evaluating** — striping across
  independent devices is the premise this ADR says is absent. Re-evaluate, do not assume: hash on
  `source` is only useful if the source cardinality and per-source volume are actually balanced,
  which today they are not (`eaig` dominates).
- **A chunk-to-tablespace placement policy has to exist** — `set_chunk_time_interval`'s sibling
  question. Timescale places new chunks across attached tablespaces; unmanaged, that interacts
  badly with per-tablespace capacity and with retention dropping chunks unevenly.
- **`compress_segmentby` should be re-derived, not inherited.** Its column set was chosen assuming
  segment-level min/max pruning is the *only* pruning mechanism; with a space dimension, part of
  that work moves to chunk exclusion and the segment set may want to shrink.
- **ai-helm side**: the CNPG manifests gain tablespace declarations plus their own PVC specs,
  storage-class and size per tablespace, and backup/restore coverage for each — a `Cluster` with
  tablespaces is not restorable from a manifest that predates them.
- **Trigger and owner**: the trigger is the tablespace change landing in `ai-helm`, not a query
  getting slow; the owner is whoever proposes that infra change, and the deliverable is an ADR
  amending this D5 — not a migration adding `add_dimension` quietly alongside it.

### D6 — Retention is **tiered**, and the raw windows are months, not days

ADR-0027's single "retention 90 days" figure is replaced by a per-tier table. The principle: raw
rows answer per-request questions and feed the aggregates; **budgeting and year-over-year questions
are answered from continuous aggregates and day-grain facts, which are tiny and are kept
longer.** Both tiers are sized for *enterprise budgeting*, which is the epic's product.

| tier | window | compression |
|---|---|---|
| request grain — raw (`usage_request_events`) | **13 months** | at **7 days** |
| execution grain — raw (`usage_executions`/`usage_model_calls`/`usage_tool_calls`) | **13 months** | at **7 days** |
| day-grain facts (`usage_day_facts`) | **25 months** | at 30 days (small tables; tune, do not guess) |
| seat snapshots (`usage_seat_snapshots`) | **25 months** | as above |
| billing-period and KPI continuous aggregates | **25 months** | n/a |

**Why 13 and not 12.** The owner's floor is *"at least 12 months for enterprise budgeting"*. Twelve
months exactly is the wrong number for the same reason a 30-day window was: the budget period is a
**calendar month** (up to 31 days) and a query may be issued on its last day, so a bare 12-month
window truncates the far end of a full-year comparison mid-month. **13 months = a full year plus the
current billing month**, which makes "this month versus the same month last year" always whole.
**25 months** applies the same +1 to the two-year aggregate tier, so a year-over-year comparison has
both endpoints complete.

**Never truncate the current billing period** — that rule survives and is now met with enormous
margin. It was the reason the store's current (non-functional) 30-day setting was a *correctness*
hazard rather than a capacity choice, and it is why every window here is expressed in months.

Compression at **7 days** for both raw grains is unchanged from ADR-0027; only the retention figure
moves.

Retention and compression policies must be **present in `timescaledb_information.jobs` and
demonstrably run in the target cluster** — the F2 lesson is that a policy nobody verified is
indistinguishable from no policy.

### D7 — The untyped `attributes` JSONB blob is **dropped at ingest**

Beyond the explicitly allowlisted, typed tail, non-promoted fields are discarded at ingest and
never written. The verbatim blob is 60 % of the current table's storage, is write-only in practice,
and is how PII (`oidc_email`, `oidc_name`, `lc_user_email`, `lc_user_name`, `x-forwarded-for`,
`oidc_jti`) reached a table with no retention (F6, #549). It does not come back windowed; it goes
away.

**The interplay that makes this safe — stated, not assumed:** the raw OTLP **S3 archive (#589)** is
the replay/backfill path for a field that turns out to matter later. Promotion is: add a nullable
column → replay the archive window → the column backfills → row counts unchanged (the rehearsal
#589 owes). Fields are recoverable *because the raw payload was archived*, not because the hot
table hoarded them.

**Until #589 lands, that recovery path does not exist**, and a non-allowlisted field dropped by new
ingest is gone for good. Two consequences follow, both binding on Phase 1:

- **Seed the allowlist generously.** The current ingest promotes **9 of ~55** access-log keys; that
  9 is a **floor, not a ceiling**, and the request-grain rewrite promotes the ~25 further typed
  fields the research doc enumerates plus a deliberately broad allowlisted tail. Erring wide is
  cheap (a typed column or an allowlist entry); erring narrow is unrecoverable until #589.
- **Generous never means content or PII.** The §8.1 content list (prompts, completions, tool
  arguments and results, request/response bodies, `llm.*_messages`, `gen_ai.input/output.messages`)
  is permanently rejected — content lives in Tempo and `trace_id` is the seam. Identity fields move
  to `usage_identities` (joined, not embedded, erasable with one UPDATE), preserving the
  `missing:<source>:<claim>` / `unstamped:<field>` sentinels as literal values. `x-forwarded-for`
  and `downstream_remote_address` are dropped outright.

### D8 — Ingest authentication topology: the edge collector is the door. Projected SA tokens are not.

ADR-0027 decision 4's principle stands untouched — **developer-attributed telemetry never enters
through an unauthenticated door**, and authenticated ingest is a prerequisite of, not a follow-up
to, any non-gateway source going live. What changes is the *mechanism* that decision named for the
in-cluster leg. The ruling, in the owner's
words: **"SA-Token should not work on authz directly."** Projected ServiceAccount tokens are
rejected as a credential for any authz surface. Three legs replace it:

1. **The door is the edge OTEL collector's OIDC validation of authz-issued tokens.** This is the
   gov#84 chain, and it is **already live**: `aiCliOtel.enabled: true` in prod, `governance-auth`
   doing device-code login against `authz-idp` directly (gov PR #142). Laptop-origin CLIs (Claude
   Code, Codex, OpenCode) authenticate to the collector with a real authz-issued token; the
   collector validates it and forwards under its own workload identity. Source identity comes from
   that credential or from the trusted collector processor, **never from the payload** — a
   payload-asserted identity remains a cross-check that alerts on mismatch and never overwrites
   (ADR-0027 decision 4, unchanged).
2. **Legs behind that door, inside the cluster, are trusted network paths.** The collector→usage hop
   carries **no second credential**. The posture that makes this sound is the same one that already
   covers the gateway's unauthenticated ingest exception: `ClusterIP`-only with no ingress, plus
   NetworkPolicy. Adding a token on a hop that is already topology-pinned buys an audit line and a
   rotation liability, not a boundary — and a credential that is not a real boundary is worse than
   no credential, because it reads like one in a review.
3. **Anything out-of-cluster that cannot ride the collector needs real machine-to-machine
   credentials from `authz-idp`.** There is no third option and no SA-token shortcut. So
   **[#534](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/534) is pulled into scope now**
   and gets its own implementation PR — proposed directly against #534 rather than queued behind
   the epic, to buy the schedule back. ADR-0027 described the SA-token pattern as a way to
   *sidestep* #534; this ADR stops sidestepping it and closes it.

**What this supersedes:** ADR-0027 decision 4's second bullet ("In-cluster collectors … authenticate
with per-collector projected ServiceAccount tokens (governance#169/#191's pattern), which sidesteps
the authz-idp machine-to-machine gap (#534) rather than blocking on it"), and **#581 Key Assumption
2**, which rested on it.

**What this dissolves:** the unreconciled gov#169-vs-gov#196 topology conflict — gov#196's addendum
routing governance-ctl through the Traefik-fronted **edge** collector, against gov#169's SA/TokenReview
pattern, which is only valid where the verifier reaches the cluster JWKS. With SA tokens off the authz
side entirely, **no TokenReview reachability question remains here**: everything developer-attributed
arrives through the edge collector's OIDC leg. gov#169's pattern stays a governance-repo concern for
governance's own internal endpoints; it is simply not a credential this repo accepts.

### D14 — No cross-service shared-DB lookups. Each app resolves through the owning service's API.

**No service reads another service's tables.** Where app A needs a fact app B owns, A calls B's API
over in-cluster HTTP; it does not open a pool against B's database, and it does not model B's tables
in its own schema. The hop is in-cluster and low-latency, and that cost is accepted deliberately.

The immediate application is the ownership check the standalone **#570** fix needs (D19): the usage
service must **not** resolve `scope_id → tenant` by querying authz tables. It calls an authority
endpoint on **`authz-opa`**, which is hereby the **ratified pattern** — the same posture as the
existing `/idp/v1/resolve-context` (Basic-auth protected, tenant context, never publicly reachable).
Fail-closed, per this repo's first review question: unreachable, timeout, non-2xx or malformed
response ⇒ **refuse the query**, never fall through to allow, never `unwrap_or(true)`.

This generalises in both directions, and both directions are load-bearing:

- **The usage service never grows an authz-DB pool** — not for ownership, not for roster lookups,
  not "just for a join".
- **The authz side never queries usage tables** — which is exactly the **3b34de2 inversion** (#345 /
  #346). `TimescaleSpendReader` opened a second pool against the usage database and queried
  `usage_events` directly; it and `Config.usage_database` were deleted outright and replaced by
  `UsageServiceSpendReader` calling `/usage/v1/spend/query` over HTTP, with every failure mode
  resolving to `Spend::Unavailable`. **That inversion is re-affirmed here as a rule, not left as
  one refactor's local choice.**

Why the HTTP hop is worth its latency: two services querying one service's tables couples their
deploy and migration order, duplicates the owner's authorization logic in a place the owner cannot
see, and turns a schema change into a cross-service breaking change with no compile-time signal.
The fail-closed contract is also *expressible* on an HTTP seam — unreachable is an observable event
with one obvious answer — whereas a shared pool makes "the other service's table changed under me"
silent. If a measured hot path ever makes the hop hurt, the answer is a bounded cache with a stated
TTL (the 30-second introspection cache is the precedent), not a pool.

### D15 — The multi-scope wire shape is `scope_ids: []`

An **array**, not `scope: owner`. Binds **#578** and **#586**, and the console depends on it.

One shape serves one scope and many, so there is no singular/plural branch on either side, and an
array of ids binds cleanly as a single parameter under ADR-0022's closed-schema rules. `scope:
owner` was rejected because it makes the *caller* assert a relationship ("these are mine") that only
the server can establish — the server resolves ownership per D14 regardless, so the keyword would be
either redundant or, worse, trusted.

Derived and stated so it is not re-litigated in a PR: **an absent or empty `scope_ids` is not
"everything."** It is a client error, not a wildcard. An optional filter that defaults to *off* is
the F3 failure that double-counted every KPI, and in a tenant-scoped read it is also the #570 bug.

### D16 — gov#181's failing verify job is **retired**, not fixed

Binds **#588** and **gov#196 AC5**. The job has been red; a red control is not a control, and
repairing it would restore a check over bookkeeping that D17 re-points anyway.

**Retirement must not leave zero controls**, which is the only way this ruling goes wrong. The
successors are named: #588's cutover count assertions (per-table and per-`(day, report)`, mismatch
blocks loudly, rehearsed with a deliberately corrupted row that must block), plus the re-pointed
verify described under D17. The retirement lands in the same change as its successor, not before it.

### D17 — `ingest_manifests` stays governance-side — **ruled 2026-08-31**

- `ingest_manifests` **stays governance-side**, as the collector's own *sent*-bookkeeping — what it
  believes it shipped, which is a fact about the collector, not about the store.
- **`verify` re-points at the usage query API** — comparing "what the store actually holds" against
  that bookkeeping across the service boundary, which is the D14-shaped way to ask the question.
- **Server-side idempotency is carried by the grain dedup keys** (D22), not by a manifest. Manifests
  describe intent; the unique index is what makes replay safe.

#588 (PR-4a) writes its count assertions against this shape: manifest counts (governance-side)
compared with usage-query-API counts, across the boundary, never via a shared-DB read (D14).

### D18 — Latency is stored as `duration_ms` / `upstream_ms`; the honesty contract is untouched

The request-grain rewrite adopts the **research schema's** `duration_ms INTEGER` and
`upstream_ms INTEGER`. The current `latency_ms DOUBLE PRECISION` column is **not carried forward** —
this is a rewrite, and carrying a single conflated float column into it would preserve the one thing
the two-column shape exists to separate (total request duration vs. upstream service time, which the
Envoy access log already emits distinctly as `duration` and `x-envoy-upstream-service-time`).

**The wire contract does not move.** `/usage/v1/usage/query` keeps `latency_samples`,
`latency_p50_ms`, `latency_p95_ms`, `latency_p99_ms` under those exact names; the percentiles are
computed at query time from **`duration_ms`**, and `latency_samples` is `COUNT(duration_ms)`. The
storage column is renamed and split; the response field names are a published contract and stay put.

**The honesty rule survives verbatim**, and is restated here because a column rename is exactly when
it gets dropped: `latency_samples: 0` is a legitimate per-series outcome, the three percentiles are
`null` in precisely that case, and **`null` is never collapsed to `0.0`** — "no latency was
reported" and "every request took 0 ms" are different facts. The histogram/summary rule survives
too: a bucketed distribution yields `NULL`, never a mean fed into `percentile_cont`.

Derived guidance, not rulings: `INTEGER` is deliberate (4 bytes against the current 8, on the widest
table in the store; ~24.8 days of milliseconds is far beyond any real request), and a duration that
is negative or out of range is stored `NULL` — unknown, never clamped, the same discipline
`cost_micro_usd` follows.

`docs/lightbridge-query-api.md`'s "Latency, and when it is legitimately absent" section — the
per-signal source table and the `latency_ms is captured per event at ingest` sentence above it —
**needs a rewrite** in the same PR: with two columns and per-source normalizers, that table must say
which normalizer populates `duration_ms` versus `upstream_ms`, rather than describing one column
filled by an alias-list search. `docs/usage-api.md:67`'s `DOUBLE PRECISION` sentence goes with it.

### D22 — Every dedup unique key includes the partition column

Not a debate; a spec correction. A hypertable **cannot** carry a unique index that omits its
partitioning column — that is precisely the F2 failure that left `usage_events` a plain table for
months while the migration reported success. ADR-0027's decision 3 states one key in the failing
shape; it is corrected here.

| grain | table(s) | corrected unique key |
|---|---|---|
| request | `usage_request_events` | `UNIQUE (observed_at, source, dedup_key)` |
| execution | `usage_executions`, `usage_model_calls`, `usage_tool_calls` | `UNIQUE (observed_at, trace_id, span_id)` — was `(trace_id, span_id)` in ADR-0027 |
| day | `usage_day_facts` | `(source, day, subject_kind, subject_id)` — **already compliant**: `day` *is* the partition column |
| seat | `usage_seat_snapshots` | analogous — `(source, day, subject_kind, subject_id)`; the exact subject columns land with #583, but the partition column is in the key |

`dedup_key` on the request grain is the ingest-content key (`x-request-id` / `client_request_id`);
replay re-inserts the same tuple and is absorbed by `ON CONFLICT DO NOTHING`, which is what makes
"retried ingest never double-bills" true rather than aspirational.

**Verify, do not assume:** that dedup still holds for a row replayed into an already-**compressed**
chunk, in the exact Timescale version D1 selects. Unique-constraint enforcement and `ON CONFLICT`
behaviour against compressed chunks have changed across Timescale releases; a dedup key that
silently stops enforcing after the 7-day compression boundary is a double-billing bug with a
one-week fuse. This belongs in the request-grain PR's test set, not in a reviewer's memory.

## Consequences

### What this supersedes in ADR-0027

Read ADR-0027 with these four substitutions:

1. **Decision 2's mermaid tokens** — `claude_code`, `codex`, `opencode`, `microsoft_foundry`,
   `github_copilot` — are superseded by D4's kebab-case set. The diagram's *structure* (four grains,
   source as a dimension) is untouched; only the token spellings are.
2. **Decision 3's dedup keys** — "`(trace_id, span_id)` for the execution grain" is superseded by
   `(observed_at, trace_id, span_id)` (D22). The day-grain key survives verbatim; it was already
   partition-compliant.
3. **Decision 3's "retention 90 days"**, read as a uniform figure across all grains, is superseded
   by D6's tiered table (13 months raw, 25 months for day/seat facts and aggregates). "Compression
   at 7 days" survives for the raw event grains.
4. **Decision 4's second bullet** — per-collector projected ServiceAccount tokens as the in-cluster
   credential — is superseded by D8. The decision's *principle* is untouched; only the mechanism is.
5. **#581's design addendum and Key Assumption 2** (not ADR-0027 text): the `add_dimension` hash
   mandate is overridden by D5, the SA-token assumption by D8.

Unchanged and re-affirmed: the boundary (#535), the four-grain taxonomy, "vendor is never a table
name", authenticated ingest as a prerequisite for developer-attributed telemetry, source identity
from the credential and never from the payload, the per-grain closed query surface,
`NULL`-means-unknown money, PII isolation in `usage_identities`, and **no `EXCEPTION WHEN OTHERS`
in any of these migrations**.

### What the request-grain rewrite (PR-1b, #489 + #549) must now do differently

Against the plan of work's current description of that slice:

- The time column is **`observed_at`**, not `occurred_at` — in the PK (`PRIMARY KEY (observed_at,
  id)`), in `by_range('observed_at', INTERVAL '1 day')`, in all seven covering indexes' trailing
  position, in `compress_orderby`, and in the dedup index. Transpose the research §6.2 DDL, do not
  copy it.
- Dedup is `UNIQUE (observed_at, source, dedup_key)`, with a test proving it still dedups **after
  compression**.
- Gateway rows carry `source = 'eaig'`, **not** `'gateway'`. Ingest refuses a row whose source does
  not resolve to a registry token.
- `compress_segmentby` includes `source` (with `account_id`, `project_id`, `model`);
  `compress_orderby = 'observed_at DESC, user_id'`. **No `add_dimension` call anywhere.**
- Retention `13 months`, compression at `7 days`. Not 30 days, and not 90. The retention policy's
  existence is asserted against `timescaledb_information.jobs`, not assumed from the migration
  having run.
- **No verbatim `attributes` column.** The allowlisted typed tail only, seeded well beyond the
  current 9 keys, with the content/PII exclusions hard-coded rather than left to the allowlist's
  author.
- **Latency is `duration_ms INTEGER` + `upstream_ms INTEGER`** (D18). `latency_ms DOUBLE PRECISION`
  is not carried forward; the `latency_*` response fields and their `null`-not-`0.0` contract are.
  `docs/lightbridge-query-api.md`'s latency section and `docs/usage-api.md:67` are rewritten in the
  same PR.
- The `claude_code.api_request` mapper is in scope for the FinOps phase; the Claude Code **counters**
  are not, and no `usage_metric_points`/`usage_span_events` migration ships under #581.
- Unchanged from the plan and worth restating because D6/D7 do not soften it: the hard cutover
  (`DROP TABLE usage_events` as the last migration, after the `signal_type='log'` backfill), the
  byte-stable spend seam, and the sabotage test proving the migration fails loudly.

### Storage sizing — why 13 months of raw fits

**Correct the stale figure first:** the research doc's §10 Q4 reasons from a **5 Gi** shared volume.
That is out of date. The usage CNPG cluster provisions **40 Gi per PVC**, one full copy per instance
(D5). Every sizing statement below uses 40 Gi; anywhere else in the corpus still citing 5 Gi is
wrong and should be read against this paragraph.

- **Dropping the blob (D7) cuts roughly 60 % of per-row weight**, taking the request grain from
  ~100 MB/day to **≈ 40 MB/day**. That is the single largest win in this ADR and it lands in
  Phase 1, before any long retention window is switched on.
- **13 months of raw request grain ≈ 15 GB/year uncompressed**, i.e. **single-digit GB compressed**
  from day 7 — comfortably inside 40 Gi with room for the execution grain, indexes, WAL and the
  aggregate tiers. The long window is affordable *because* D7 ships first.
- **The 25-month tiers are negligible.** Day facts and seat snapshots are one row per
  `(source, day, subject_kind, subject_id)` — order 10⁴–10⁵ rows per year, not 10⁷ — and continuous
  aggregates are bucketed roll-ups. Two years of them is a rounding error against a month of raw
  request grain, which is what makes the retention asymmetry in D6 nearly free.
- **Compression is still what keeps the headroom comfortable**, which is one more reason D1's image
  and D6's window are one decision rather than two: a compression-less fallback turns a single-digit-GB
  footprint into ~16 GB of raw request grain plus the execution grain, on a volume that also carries
  everything else. That is a conversation with the owner, not a quiet retention trim below the
  calendar-month floor.

Unbounded growth on this exact table contributed to the 2026-08-29 outage, so re-measure against
real volume in PR-1a rather than treating the above as a capacity plan; it is an order-of-magnitude
argument that says the window is safe, not a substitute for the measurement.

### What the authenticated-ingest slice (PR-2a, #585) must now do differently

- **No projected ServiceAccount tokens, and no new shared secret** (gov#191's `X-Internal-Token`
  stays dead). The credential under test is an **authz-issued token OIDC-validated at the edge
  collector**; the collector→usage hop is an in-cluster trusted path with no second credential, and
  the PR states that posture (ClusterIP + NetworkPolicy) rather than implying a boundary it does
  not have.
- The refusal tests keep their fail-first bar and their fail-closed rule — no-credential,
  wrong-audience, disallowed-principal, and **auth-dependency-unreachable ⇒ refuse** — with no
  env-var opt-out that can skip them in CI. The acceptance bar is still a live 200 from a real CLI
  push (gov#189), not a clean collector start.
- **#585 is no longer blocked on a decision**; it is blocked only on the work. In its place,
  **#534 becomes real scheduled work** (D8 leg 3) with its own PR, opened directly against that
  issue.

### What the #570 standalone fix (PR-0d) and the query slice (PR-3a, #586) must now do

- **#570's ownership check calls an authority endpoint on `authz-opa`** (D14). It does not add an
  authz-DB pool to the usage service, and its refusal test covers the authority being unreachable —
  refuse, not allow. This is the ratified pattern for every later per-grain absorption of the same
  check.
- **The multi-scope parameter is `scope_ids: []`** (D15), in #578's fix and in all four #586
  endpoints. Absent or empty is a 400, never "all". The `bucket_start ASC` LIMIT defect #578 records
  is unaffected by the shape change and still needs fixing.
- **The percentile fields compute from `duration_ms`** (D18); `no unwrap_or(0)` on any monetary path
  extends to latency, where the equivalent sin is `0.0` for "unknown".

### Elsewhere

- **The governance mirror needs a note.** `lightbridge-governance` ADR-0014 is written to agree with
  ADR-0027 verbatim, and its normalizer fixtures emit the snake_case tokens D4 supersedes. The
  rename lands with the normalizer port (#584 / plan slice PR-2c); the mirror ADR gets an amendment
  note covering D4, D22 **and D8** so the two repos do not silently disagree the way #535 documented.
- **gov#196 loses its open topology question.** With D8, governance-ctl's day-grain reports ride the
  edge collector's OIDC leg like every other developer-attributed source; there is no SA/TokenReview
  variant to reconcile on this side.
- **#587 inherits a documented conditional** from D1: the percentile aggregates' exactness depends
  on the toolkit answer, and the API docs state which regime is in force.
- **#587's KPI list shortens.** It is scoped as "one named aggregate per KPI measure (#491's list of
  10)"; under D0/D2 the adoption measures in that list are out of phase, so #587 ships the FinOps
  subset and names the deferred ones rather than quietly building aggregates over a grain that does
  not exist. One aggregate per measure, none spanning grains — unchanged.
- **The Performance-ops phase now has a named opening scope** (D2): the fifth grain family, the IDE
  counters, `ide_activity_daily`, and the adoption KPIs — with its own ADR, after FinOps ships.

## Open questions this ADR does not close

- **D3's literal reach into the day and seat grains** — see the reading recorded under D3. The
  reading stands unobjected; the confirm flag stays until it is stated one way or the other.
- ~~D17~~ — ruled 2026-08-31: `ingest_manifests` stays governance-side (see D17 above).
- **#534's grant shape** (D8 leg 3): which machine-to-machine grant authz-idp issues, and to whom,
  is the subject of the #534 PR itself — this ADR rules that it is *in scope and needed*, not what
  it looks like.
- Everything the plan of work still lists as open: **D9–D13** (the archive and normalizer-ownership
  questions).

## Related

- ADR-0027 (amended here), ADR-0022 (the closed query-contract prior art), ADR-0038 (cratestack is
  the only sanctioned database API — the usage crate's dynamic aggregates are a recorded exception),
  ADR-0039 (CUID2 is the house id format — `id TEXT`, never `BIGSERIAL`, never sorted on)
- This repo: #581 (epic), #491 (re-scoped), #489, #549, #534 (pulled into scope by D8), #535, #570,
  #578, #582, #583, #584, #585, #586, #587, #588, #589; #345/#346 (`3b34de2`, the inversion D14
  re-affirms)
- `docs/lightbridge-query-api.md` (latency section rewritten by D18), `docs/usage-api.md`
- governance: ADR-0014 (mirror), ADR-0013, ADR-0008, #84 (the live OIDC ingest chain D8 builds on),
  #163, #164, #166, #167, #169, #185, #187, #189, #191, #196
- `docs/research/2026-08-25-genai-usage-ingestion.md` (the F1–F6 audit; its DDL is authoritative on
  shape and superseded on the `occurred_at` name)
- `docs/plans/0581-multi-source-usage-plan-of-work.md` §1 (the decision register these rulings close)
