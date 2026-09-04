# Runbook — the budget remaining snapshot (ADR-0034 §15)

What to do when the gateway starts refusing metered requests with `503 budget_unavailable`, when
`budget_snapshot_age_seconds` climbs, or when a refill "did not take effect".

Scope: the **backend** half. The gateway/values half (`budgetLimiter` flags, the AuthConfig, shadow
mode) is `ai-helm-values docs/runbooks/budget-limiter-rollout.md`.

---

## 1. The shape, in one diagram

```mermaid
sequenceDiagram
    autonumber
    participant O as authz-opa (introspection)
    participant DB as budget_remaining_snapshots
    participant B as authz-budget (refresher)
    participant U as authz-usage

    Note over B,U: background, every server.budget.snapshot_refresh_seconds
    B->>DB: SELECT accounts with last_seen_at >= now() - active_window
    B->>U: POST /usage/v1/spend/query (≤ snapshot_concurrency in flight)
    alt spend answered
        B->>DB: UPDATE period/ceiling/spent/remaining/next_reset_at, clear stale_since
    else unreachable
        B->>DB: stamp stale_since, KEEP the previous reading
    end

    Note over O,DB: request path — one indexed read
    O->>DB: SELECT … WHERE budget_account_id = $1
    O--)DB: (spawned, ≤1 / 30 s / account) UPDATE last_seen_at
```

```mermaid
stateDiagram-v2
    [*] --> NoRow
    NoRow --> Seen: introspection touch
    Seen --> Fresh: tick, spend answered
    Fresh --> Stale: tick, spend unreachable (reading KEPT)
    Stale --> Fresh: tick, spend answered
    Fresh --> RolledOver: UTC month boundary
    RolledOver --> Fresh: tick for the new period
    note right of Seen
        Seen / RolledOver / NoRow all render as ABSENT
        introspection fields ⇒ known:false ⇒ 503.
        There is no transition that produces a fabricated 0.
    end note
```

---

## 2. Symptom: `503 budget_unavailable` on metered requests

`503` means the gateway could not learn the balance. It never means the account is out of money —
that is `402 budget_exhausted`, a different status with a different body.

Work down this list; each step distinguishes one cause from the next.

1. **Is there a row at all?**
   ```sql
   SELECT budget_account_id, period, remaining_micros, refreshed_at, stale_since, last_seen_at
   FROM budget_remaining_snapshots WHERE budget_account_id = '<acct>';
   ```
   - **No row** → the request path has never touched this account, or the account was just created.
     The next introspection creates it and the next tick fills it. If requests *are* arriving and no
     row appears, the touch is failing — grep `authz-opa` for `failed to touch the budget
     snapshot's last_seen_at`.
   - **Row with `remaining_micros IS NULL`** → seen, never successfully refreshed. Go to 2.
   - **Row whose `period` is not the current `YYYY-MM`** → the month rolled over and no tick has run
     since. Go to 2.

2. **Is the refresher running?** On `authz-budget`, at startup:
   `starting the budget remaining-snapshot refresher`. Per tick (at `debug`):
   `budget remaining snapshot refresh tick`. A tick that fails logs
   `budget snapshot refresh tick failed; retrying on the next interval`.
   - No startup line at all → this process has no `server.budget` block, or it is not the
     `budget` subcommand. Only `authz-budget` runs the refresher.

3. **Is `authz-usage` answering?** `stale_since` non-NULL is the direct signal, and
   `budget snapshot refresh failed for one account` names the error. Check
   `usage_service.base_url`, the CA bundle, and the client certificate — a spend read that cannot
   be made is `SpendObservation::Unreachable`, which keeps the previous reading and stamps
   `stale_since`. An account with **no** previous reading stays `NULL` and therefore `503`.

4. **Is another replica holding the advisory lock and wedged?**
   ```sql
   SELECT pid, granted, query_start FROM pg_locks l
   JOIN pg_stat_activity a USING (pid)
   WHERE l.locktype = 'advisory' AND l.objid = 1397905232;   -- 0x4255_4447_5F53_4E50 low word
   ```
   A tick releases the lock explicitly; a crashed backend releases it when its session ends. A held
   lock with no live query is the case to escalate.

5. **Confirm the ledger itself is fine**, bypassing every layer above:
   ```
   GET /budget/v1/remaining?account_id=<acct>&fresh=true
   ```
   `?fresh=true` skips the snapshot and recomputes live (ledger `SUM` + spend query). If that
   answers `200` and the snapshot path does not, the fault is in the refresher, not in the ledger.

---

## 3. Symptom: `budget_snapshot_age_seconds` is climbing

Expected steady state is `< snapshot_refresh_seconds + one tick` (≈ 30 s at the default 15 s).

| Age | Read it as |
|---|---|
| < 30 s | normal |
| 30 s – 5 min | ticks are overrunning: the active set is larger than `snapshot_batch`, or the spend reads are slow. Raise `snapshot_concurrency` first, `snapshot_batch` second. |
| > 5 min, `stale_since` NULL | the refresher is not running, or the advisory lock is held by a wedged session (§2.4). |
| > 5 min, `stale_since` set | `authz-usage` has been unreachable since `stale_since`. The balance being served is that old. |

The account's own `last_seen_at` also matters: an account outside
`snapshot_active_window_minutes` is deliberately not refreshed, and its age grows until it is used
again. That is the design, not a fault.

---

## 4. Symptom: "I granted a refill and nothing changed"

A booked grant moves the snapshot **inside the grant's own transaction**, so the new balance is
visible on the very next request. If it is not, exactly one of these is true:

- **The account had no reading yet** (`remaining_micros IS NULL`). There was no number to move; the
  next tick computes the first one. Correct behaviour — a delta is not a balance.
- **The grant's period is not the snapshot's period.** A grant booked into next month must not move
  this month's balance.
- **Authorino is still serving a cached introspection.** The `lightbridgeintrospect` step caches per
  `jti` for 30 s. Wait it out; this is the first term of ADR-0034 §15.1's window.

---

## 5. Knobs, and what each one trades

All on `server.budget` (`config/default.yaml`, `charts/lightbridge-authz/values.yaml`).

| Key | Default | Raising it | Lowering it |
|---|---|---|---|
| `snapshot_refresh_seconds` | 15 | less load on `authz-usage`; more forgiven overspend | fresher balances; one spend query per active account per tick |
| `snapshot_active_window_minutes` | 10 | bursty accounts stay warm between bursts | less background work; a returning account pays one live read |
| `snapshot_batch` | 500 | a bigger active set is covered per tick | shorter, more predictable ticks |
| `snapshot_concurrency` | 8 | ticks finish faster | gentler on `authz-usage`, which also serves the console |

`snapshot_refresh_seconds: 0` is refused at startup — a zero-second interval is a busy loop against
the database, not a configuration.

---

## 6. What must never be "fixed" by writing a zero

If you are tempted to `UPDATE budget_remaining_snapshots SET remaining_micros = 0` to clear a 503:
don't. That converts our outage into `402 budget_exhausted` for the account — a bill for our own
latency, and indistinguishable to the user from genuinely running out. Every layer of this design
keeps "unknown" and "nothing left" apart on purpose (ADR-0034 D5). Fix the refresher, or accept the
503 while `authz-usage` is down.
