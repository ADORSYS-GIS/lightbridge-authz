-- ADR-0035 is withdrawn (see its withdrawal note): the code that wrote credit pools, lots and
-- settlement rows is reverted in the same release as this file. This file changes no schema.
--
-- It refuses to migrate a database where that code booked anything the reverted ledger would
-- miscount, in two cases:
--
-- 1. Any `granted` or `paid` row, ever. Those rows carry no period, so every pre-ADR-0035 balance
--    read (which sums the current period) would silently drop that credit. Purchased credit is
--    money; an operator decides what it becomes before this can apply.
--
-- 2. A `consumption` or `expiry` row in the CURRENT period (UTC calendar month, as
--    `spend_units::period_bounds_utc` defines it). The pre-ADR-0035 read sums the period's rows
--    and then subtracts the period's live spend, so a settled `consumption` row would be
--    subtracted twice. Rows from past periods are left alone: `budget_grants` is append-only
--    (ADR-0009), and no automated balance read (the reset scheduler, the snapshot refresher, the
--    token mint) looks at a past period. A caller can still ask for one explicitly, and gets that
--    period's history as it was booked. The safe order is therefore: set
--    `server.budget.settlement_seconds` to 0 on every running pod, let the period roll over, then
--    deploy.
--
-- No `EXCEPTION WHEN OTHERS`; the RAISE is the point. The migration is recorded as applied only
-- once it passes, so a refused deploy simply runs it again on the next attempt.
--
-- The ADR-0035 schema itself (`20261021000001_credit_pools_lots_settlement.sql`) stays: an applied
-- migration is frozen. Its columns and tables are dead from this release, and a contract migration
-- drops them one release later, so pods of the previous release never meet a schema they cannot
-- read (ADR-0031).
DO $$
DECLARE
    current_period TEXT := to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM');
BEGIN
    IF EXISTS (SELECT 1 FROM budget_grants WHERE pool <> 'allowance') THEN
        RAISE EXCEPTION 'ADR-0035 withdrawal: budget_grants holds granted or paid credit, which the reverted balance read would drop; decide what that credit becomes before this migration can apply';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM budget_grants
        WHERE source IN ('consumption', 'expiry')
          AND period = current_period
    ) THEN
        RAISE EXCEPTION 'ADR-0035 withdrawal: settlement booked consumption or expiry rows in the current period %, which the reverted balance read would subtract twice; set server.budget.settlement_seconds to 0 and deploy after the period rolls over', current_period;
    END IF;
END
$$;
