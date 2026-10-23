-- ADR-0035 withdrawal, contract half (ADR-0031 expand/contract). Drops what
-- `20261021000001_credit_pools_lots_settlement.sql` added -- `pool`, `lot_id` and `external_ref` on
-- `budget_grants`, the per-pool snapshot columns, `credit_lots`, `settlement_state` -- and returns
-- `budget_grants` to its pre-#774 shape with ONE deliberate exception: `consumption` and `expiry`
-- stay admitted as historical sources (see below).
--
-- WHY THIS IS A SEPARATE RELEASE. ADR-0035 was withdrawn and its code reverted in the release that
-- shipped `20261023000001_adr_0035_withdrawal_guard.sql`. That release changed no schema: pods of
-- the release before it (the #774 code) were still serving while its migration ran, and they read
-- and wrote these columns and tables. Dropping them under those pods would have failed their
-- writes mid-rollout. One release later the only code still running is the reverted code, which
-- names none of them (every statement it issues lists its columns, and its grant insert never binds
-- `pool`, so it has been filling it from the column default since the revert). Dropping them now is
-- invisible to it.
--
-- WHAT IS REFUSED, AND WHY ONLY THAT. The question this file asks is narrower than the guard's: not
-- "would the reverted read miscount this row" (the guard owned that, and an allowance row reads
-- the same to the reverted code with or without a `pool` column) but "does dropping
-- `pool`/`lot_id` strip this row of its meaning". That is true of exactly one population: a
-- `granted` or `paid` row. With `pool` gone it would read as allowance credit, and with `lot_id`
-- gone a debit could no longer say which lot it drew from. The guard already refuses any such row; this file checks again
-- because the guard ran before the reverted pods replaced the #774 ones, and the #774 funding port
-- and settlement worker could book one in the window between the guard's transaction and the last
-- old pod terminating. Also refused: `period IS NULL` (`budget_grants_pool_period_chk` makes it the
-- same rows, but SET NOT NULL below would otherwise be what trips, with a less useful message), any
-- `credit_lots` row (a lot is a projection of a granted/paid row; one existing while the ledger
-- holds none is a contradiction to stop on, not a row to drop silently), and any non-NULL
-- `external_ref`. No CHECK ever tied that column to the paid pool, so an allowance row could in
-- principle carry a payment reference; dropping the column would erase it without a sound.
--
-- NOT refused: `settlement_state` rows. They hold a spend watermark and the debt spend ran up past
-- the pools; the reverted read recomputes both live, as `ceiling - SUM(usage_events.total_cost)`
-- for the current period, so dropping the table loses no fact any running code uses. They exist on
-- every estate where settlement ran, including one the guard passed.
--
-- WHY `consumption` AND `expiry` STAY IN THE CHECKS. Settlement ran in production
-- (`settlement_seconds: 60`, #776): it booked allowance `consumption` rows, and the #774 reset
-- scheduler booked a reset-down as allowance `expiry` instead of `correction`. `budget_grants` is
-- append-only (ADR-0009), so those rows exist forever, and the pre-#774 `budget_grants_source_chk`
-- (nine sources) and `budget_grants_amount_sign_chk` (only `correction` may be negative) are false
-- about them. Two ways out were weighed:
--
--   * Re-add the pre-#774 text `NOT VALID`. Rejected. A NOT VALID check still binds new rows, but
--     it can never be validated (the rows that violate it can never be deleted), so the catalog
--     would carry, permanently, a constraint whose stated invariant is false of the table -- read by
--     every future author as "source is one of nine" -- and any later VALIDATE CONSTRAINT, or a
--     re-add in a future migration, fails on rows nobody can remove.
--   * Admit the two sources, negative only, as the #774 sign rule did. Chosen. Both constraints stay
--     VALIDATED: they are true of every row in the table and enforced on every new one. The cost is
--     that the database would accept a new hand-written `consumption`/`expiry` row; no code path
--     can write one, because the only insert into this table binds `source` from the nine-variant
--     `GrantSource` enum. Narrowing the admission with a `created_at < <withdrawal instant>` literal
--     was also rejected: that instant differs per environment, and `created_at` is caller-settable
--     anyway, so it would add an environment-specific failure mode while buying little.
--
-- Every row this file lets through is an `allowance` row with a period and one of those eleven
-- sources, positive unless it is a `correction` (non-zero) or a `consumption`/`expiry` (negative) --
-- which is precisely what `budget_grants_source_pool_chk` + the #774 sign rule admitted in the
-- allowance pool. The validation scans below therefore cannot fail on a row the check allowed.
--
-- THE APPEND-ONLY TRIGGER (ADR-0009) IS NOT ASKED TO PERMIT ANYTHING. `budget_grants_no_update` and
-- `budget_grants_no_delete` are row-level; no statement below updates or deletes a row. DROP COLUMN
-- only marks the attribute dropped in the catalog (no rewrite); ADD CONSTRAINT ... CHECK and SET NOT
-- NULL scan the table to validate, which reads rows and fires nothing. Dropping `credit_lots`
-- removes its ON DELETE CASCADE foreign key into `budget_grants`, and dropping
-- `budget_grants_lot_id_fkey` the self-referencing one; both only remove RI triggers, never run them.
--
-- `idx_budget_grants_lot_id`, the four #774 constraints and the self-FK are dropped by name rather
-- than left to DROP COLUMN's implicit cascade, so a schema that is not the one #774 produced fails
-- here loudly instead of half-applying. No `DROP ... IF EXISTS`, no `EXCEPTION WHEN OTHERS`; the
-- file is one transaction, so a refusal leaves the ADR-0035 schema exactly as it was.
--
-- LOCKING. The `budget_grants` ALTER takes ACCESS EXCLUSIVE for one validation scan of the ledger
-- (one row per grant event); the snapshot ALTER is catalog-only. Grant writes and snapshot touches
-- queue behind it for that long; none is lost.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM budget_grants
        WHERE pool <> 'allowance'
           OR period IS NULL
    ) OR EXISTS (SELECT 1 FROM credit_lots) THEN
        RAISE EXCEPTION 'ADR-0035 contract: budget_grants holds granted or paid rows (or credit_lots is not empty), which dropping pool and lot_id would turn into allowance credit; decide what that credit becomes before this migration can apply';
    END IF;
    IF EXISTS (SELECT 1 FROM budget_grants WHERE external_ref IS NOT NULL) THEN
        RAISE EXCEPTION 'ADR-0035 contract: a budget_grants row carries an external_ref, which dropping the column would erase; record what it references before this migration can apply';
    END IF;
END
$$;

DROP TABLE settlement_state;

-- Before `lot_id`: its primary key is a foreign key into `budget_grants(id)`.
DROP TABLE credit_lots;

DROP INDEX idx_budget_grants_lot_id;

ALTER TABLE budget_grants
    DROP CONSTRAINT budget_grants_lot_chk,
    DROP CONSTRAINT budget_grants_source_pool_chk,
    DROP CONSTRAINT budget_grants_pool_period_chk,
    DROP CONSTRAINT budget_grants_pool_chk,
    DROP CONSTRAINT budget_grants_lot_id_fkey,
    DROP CONSTRAINT budget_grants_source_chk,
    -- The nine pre-#774 sources, then the two that settlement left in the ledger for good.
    ADD CONSTRAINT budget_grants_source_chk CHECK (source IN (
        'base', 'self_service', 'admin', 'automatic',
        'manual_approval', 'refund', 'correction', 'promotion', 'migration',
        'consumption', 'expiry'
    )),
    DROP CONSTRAINT budget_grants_amount_sign_chk,
    ADD CONSTRAINT budget_grants_amount_sign_chk CHECK (
        (source = 'correction' AND amount_micros <> 0)
        OR (source IN ('consumption', 'expiry') AND amount_micros < 0)
        OR (source NOT IN ('correction', 'consumption', 'expiry') AND amount_micros > 0)
    ),
    ALTER COLUMN period SET NOT NULL;

ALTER TABLE budget_grants
    DROP COLUMN lot_id,
    DROP COLUMN external_ref,
    DROP COLUMN pool;

ALTER TABLE budget_remaining_snapshots
    DROP COLUMN allowance_remaining_micros,
    DROP COLUMN granted_remaining_micros,
    DROP COLUMN paid_remaining_micros,
    DROP COLUMN debt_micros;
