-- ADR-0035 is withdrawn (see its withdrawal note): the code that wrote credit pools, lots and
-- settlement rows is reverted in the same release as this file. This file changes no schema.
--
-- It refuses to migrate a database holding any `granted` or `paid` row. Those rows carry no
-- period, so every pre-ADR-0035 balance read (which sums one period) would silently drop that
-- credit. Purchased credit is money; an operator decides what it becomes before this can apply.
--
-- Settlement's allowance rows (`consumption`, and `expiry`, which settlement only ever booked
-- against a lot) need no guard. The reverted reads skip both sources by name, so rows already
-- booked, and any an old pod books while the rollout replaces it, are never counted as credit
-- (`crates/lightbridge-authz-budget/src/balance_read.rs`). Nothing has to be quiesced first.
--
-- No `EXCEPTION WHEN OTHERS`; the RAISE is the point. The migration is recorded as applied only
-- once it passes, so a refused deploy simply runs it again on the next attempt.
--
-- The ADR-0035 schema itself (`20261021000001_credit_pools_lots_settlement.sql`) stays: an applied
-- migration is frozen. Its columns and tables are dead from this release, and a contract migration
-- drops them one release later, so pods of the previous release never meet a schema they cannot
-- read (ADR-0031).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM budget_grants WHERE pool <> 'allowance') THEN
        RAISE EXCEPTION 'ADR-0035 withdrawal: budget_grants holds granted or paid credit, which the reverted balance read would drop; decide what that credit becomes before this migration can apply';
    END IF;
END
$$;
