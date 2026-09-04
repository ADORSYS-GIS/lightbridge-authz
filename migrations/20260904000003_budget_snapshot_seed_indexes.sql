-- ADR-0034 §15.6 (coverage): the two index range scans the snapshot refresher's seed drives from.
--
-- The seed runs on every tick (default: every 15 s) and asks exactly two questions of this
-- database: "which accounts had a budget grant booked since <cutoff>?" and "which accounts own an
-- active, undeleted API key that has been used since <cutoff>?". Both were previously answerable
-- only by a sequential scan -- `budget_grants` has an index on (budget_account_id, period) and
-- `api_keys` one on owner_account_id, and neither leads with the timestamp the seed filters on.
--
-- At this estate's present size (hundreds of rows) a seq scan is free and these indexes buy
-- nothing measurable. They exist because the seed's cadence is what makes that stop being true:
-- a statement that runs 5 760 times a day must not be the one thing whose cost grows linearly with
-- the ledger. Adding them now is cheaper than discovering it later from a CPU graph.

-- `budget_grants` is append-only (ADR-0009: an immutable ledger), so this index only ever grows at
-- the tail and never rewrites -- the cheapest possible shape for a timestamp index.
CREATE INDEX IF NOT EXISTS idx_budget_grants_created_at
    ON budget_grants (created_at);

-- Partial on `deleted_at IS NULL` because the seed only ever asks about live keys, and soft-deleted
-- rows accumulate forever: the predicate keeps the index the size of the working set rather than
-- the size of the history. `last_used_at` is NULL for a key that has never been used, and NULLs are
-- excluded from a `>=` range scan anyway, so they cost nothing here.
CREATE INDEX IF NOT EXISTS idx_api_keys_last_used_at_live
    ON api_keys (last_used_at)
    WHERE deleted_at IS NULL;
