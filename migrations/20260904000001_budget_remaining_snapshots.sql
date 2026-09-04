-- ADR-0034 §15 (the single-call design, owner directive 2026-09-04): the precomputed remaining
-- balance the request path reads.
--
-- WHY THIS TABLE EXISTS. Before it, every metered model request could cost the gateway TWO
-- Authorino metadata calls -- one introspection into `authz-opa` and one `/budget/v1/remaining`
-- into `authz-budget`, the latter fanning out to a third service (`authz-usage`) for the spend
-- `SUM`. The owner's directive is one call per request. Folding the budget into the introspection
-- response is only possible if answering "what is left" costs `authz-opa` a single indexed read of
-- the database it already has open -- which is exactly what one row here is.
--
-- ONE ROW PER BUDGET ACCOUNT, not per (account, period). The request path only ever asks about the
-- CURRENT period, so a composite key would buy history nobody reads and make the hot path's lookup
-- a range scan instead of a primary-key probe. `period` is therefore a COLUMN: it records which
-- period the numbers describe, so a reader can refuse a snapshot that the month boundary has
-- already invalidated rather than serving last month's balance.
--
-- NULL MEANS UNKNOWN, NEVER ZERO -- the rule this whole domain is built on (see
-- `crates/lightbridge-authz-budget/src/remaining.rs`). A row can legitimately exist with every
-- money column NULL: that is "the request path has SEEN this account, and the refresher has not
-- produced a reading for it yet". The introspection response then OMITS the budget fields, the
-- gateway's Lua reads that as `known: false`, and refuses with 503 `budget_unavailable` -- never
-- with 402 `budget_exhausted`, and never by inventing a zero.
CREATE TABLE budget_remaining_snapshots (
    -- The BUDGET account id (`budget_grants.budget_account_id`), not `users.id` and not a token
    -- `sub`: ADR-0026 makes one identity own many accounts, and keying money on the person would
    -- meter their several balances as one. FK to `accounts` for the same reason every other
    -- budget-domain table has one, and ON DELETE CASCADE because a snapshot of a deleted account
    -- is not a fact worth keeping.
    budget_account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    -- 'YYYY-MM', UTC -- which period the four money columns describe. NULL until the first
    -- successful refresh. A reader whose current period differs from this treats the snapshot as
    -- absent (the balance rolled over; last month's number is not a conservative approximation of
    -- this month's, it is a different quantity).
    period            TEXT NULL,
    -- Expiry/revocation-aware SUM(budget_grants.amount_micros) -- `BudgetRepo::effective_balance`,
    -- NOT the raw `budget_balances.effective_budget_micros` projection, which counts grants that
    -- have since expired. Integer micro-USD, like every amount in this domain.
    ceiling_micros    BIGINT NULL,
    -- SUM(usage_events.total_cost) for this account this period, as `authz-usage` reported it.
    spent_micros      BIGINT NULL,
    -- `ceiling_micros - spent_micros`. SIGNED and NOT clamped: the gateway charges a request's
    -- cost only after the response completes, so overspend is reachable by construction and a
    -- flattering zero would hide the one number an overspend alert needs.
    remaining_micros  BIGINT NULL,
    -- When this account's budget next changes on its own: the winning ADR-0032 reset schedule's
    -- `next_run_at`, else midnight UTC on the 1st of the next month.
    next_reset_at     TIMESTAMPTZ NULL,
    -- When the four money columns were last recomputed from the ledger and the spend source. NULL
    -- until the first successful refresh. The request path reports `now() - refreshed_at` as
    -- `budget_snapshot_age_seconds`, so a consumer can see exactly how stale the figure it is
    -- acting on is instead of assuming it is current.
    refreshed_at      TIMESTAMPTZ NULL,
    -- Non-NULL while the spend source has been unreadable since that instant, with the PREVIOUS
    -- reading still in place. Fail-soft, deliberately: a usage-service outage must not erase a
    -- known balance and turn the whole fleet's requests into 503s. It is cleared on the next
    -- successful refresh, and it is what an operator greps for when `budget_snapshot_age_seconds`
    -- starts climbing.
    stale_since       TIMESTAMPTZ NULL,
    -- Last time the request path asked about this account. The refresher recomputes ONLY accounts
    -- seen inside its active window, so the background work scales with concurrently-active
    -- accounts rather than with the size of the estate. Written write-behind and at most once per
    -- account per touch interval, so the hot path stays read-mostly.
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The refresher's own selection: "every account seen since <cutoff>, oldest reading first". Both
-- columns are in the index so the ordering is served without touching the heap for the sort.
CREATE INDEX idx_budget_remaining_snapshots_active
    ON budget_remaining_snapshots (last_seen_at DESC, refreshed_at ASC NULLS FIRST);

-- Standalone `last_seen_at` for the reaper/inspection queries that only bound on recency.
CREATE INDEX idx_budget_remaining_snapshots_last_seen_at
    ON budget_remaining_snapshots (last_seen_at);
