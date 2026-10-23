-- ADR-0035 is withdrawn (see its withdrawal note): the code that wrote credit pools, lots and
-- settlement rows is reverted in the same release as this file. This file changes no schema.
--
-- It refuses to migrate a database where that code already booked anything the reverted ledger
-- would miscount. Pre-ADR-0035 balance reads sum every row of the current period and then subtract
-- the live spend read from authz-usage, so a settled `consumption` row would be subtracted twice,
-- and a `granted`/`paid` row (period NULL) would silently drop out of every balance. Stopping the
-- release here is the correct outcome: an operator decides what those rows mean before this
-- applies. No `EXCEPTION WHEN OTHERS`; the RAISE is the point.
--
-- The ADR-0035 schema itself (`20261021000001_credit_pools_lots_settlement.sql`) stays: an applied
-- migration is frozen. Its columns and tables are dead from this release, and a contract migration
-- drops them one release later, so pods of the previous release never meet a schema they cannot
-- read (ADR-0031).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM budget_grants
        WHERE pool <> 'allowance'
           OR source IN ('purchase', 'purchase_reversal', 'referral', 'consumption', 'expiry')
    ) THEN
        RAISE EXCEPTION 'ADR-0035 withdrawal: budget_grants holds pool or settlement rows that the reverted ledger would miscount; resolve them before this migration can apply';
    END IF;
END
$$;
