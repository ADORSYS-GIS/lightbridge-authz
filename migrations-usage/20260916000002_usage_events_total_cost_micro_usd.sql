-- #745: make usage_events.total_cost uniformly MICRO-USD, and rescale the rows that are not.
--
-- THE INCIDENT. On 2026-09-16, 40 of 49 production accounts returned
-- `budget_exhausted` with remaining_micros around -969,756,339,413 against an
-- $8.97 ceiling. Spend was inflated by ~10^6.
--
-- THE CAUSE. `apply_normalizer` (crates/lightbridge-authz-usage/src/handlers/ingest.rs)
-- had two branches writing two different units into this one column:
--
--   norm.cost_micros.map(|c| c as f64 / 1_000_000.0)   -- dollars
--       .or_else(|| extract_f64(attrs, &COST_KEYS))    -- micro-USD
--
-- so the unit of a row depended on which writer produced it. The budget side's
-- `validate_total_cost_micros` sees a bare f64 and cannot tell them apart, which is why
-- #488 (read as micro-USD) and #737 (read as dollars) were each half right and each
-- shipped an incident. #745 fixes the WRITER: both branches now emit micro-USD.
--
-- WHAT THIS MIGRATION DOES. Rescales the rows written in dollars. The predicate is
-- `source = 'eaig'`, which was verified against production to be exactly the dollar-scale
-- set and nothing else:
--
--   source | first               | last                | rows      | fractional
--   -------+---------------------+---------------------+-----------+-----------
--   eaig   | 2026-09-15 15:02:50 | 2026-09-16 06:15:03 |    30,845 |     30,845
--   (none) | 2026-08-14 22:53:20 | 2026-09-10 11:38:36 | 1,204,037 |          0
--
-- Every eaig row is fractional (dollars); no other row is (micro-USD integers). The two
-- populations do not overlap in time either, but `source` is the real discriminator --
-- date is not, because the normalizer went live per-source, not per-day.
--
-- IDEMPOTENCE. Guarded on `total_cost <> floor(total_cost)`: a value already rescaled to
-- micro-USD is a whole number and is skipped. Re-running this migration cannot double-scale
-- a row. (sqlx will not re-run it anyway -- this is defence against a hand re-run.)
--
-- NOT A TIMESCALE CONCERN. usage_events_daily is empty in production and `spend_for_account`
-- reads usage_events raw only (crates/lightbridge-authz-usage/src/repo.rs:186), so there is
-- no rollup to rescale alongside this.

UPDATE usage_events
SET total_cost = total_cost * 1000000
WHERE source = 'eaig'
  AND total_cost IS NOT NULL
  AND total_cost <> floor(total_cost);

COMMENT ON COLUMN usage_events.total_cost IS
    'MICRO-USD, always, from every writer (#745). NOT dollars. apply_normalizer is the only '
    'writer and both of its branches emit this unit; a normalizer reporting another unit must '
    'convert inside itself. The budget domain reads this column unscaled via '
    'validate_total_cost_micros -- if spend ever looks ~10^6 out, a writer scaled, not the reader.';
