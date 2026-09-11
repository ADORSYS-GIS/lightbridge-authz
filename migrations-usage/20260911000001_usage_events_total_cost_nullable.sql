-- governance#188: "unknown cost" must survive to the wire as NULL, never 0.0.
--
-- F4 of docs/research/2026-08-25-genai-usage-ingestion.md: `total_cost DOUBLE PRECISION
-- NOT NULL DEFAULT 0` plus `push_bind(event.total_cost.unwrap_or(0.0))` destroyed the
-- absent-vs-zero distinction at the storage layer -- `Spend::Unavailable` became
-- unreachable the moment any row existed. This migration makes the column nullable so
-- the repo layer can store NULL for "the signal carried no cost" (the ingest path binds
-- the `Option` directly; see `StoreRepo::insert_usage_events`).
--
-- Existing rows keep their values: a historical `0` is indistinguishable from a
-- genuinely-free request and is not rewritten. The `DEFAULT 0` is retained for ad-hoc
-- writers that omit the column; the production writer always binds explicitly.
--
-- Consequence for the spend seam: `SUM(total_cost)` over a range whose rows all carry
-- NULL cost now returns NULL (previously 0.0), so `/usage/v1/spend/query` reports
-- `total_cost: null` and the budget domain's `UsageServiceSpendReader` maps that to
-- `SpendObservation::Empty` (fail-closed) instead of `Answered(0)` -- unknown spend no
-- longer counts as free. Catalog-only change on PG 11+; no table rewrite.
ALTER TABLE usage_events ALTER COLUMN total_cost DROP NOT NULL;

COMMENT ON COLUMN usage_events.total_cost IS
    'Cost in US dollars. NULL = the signal carried no cost -- unknown, never 0 (governance#188).';