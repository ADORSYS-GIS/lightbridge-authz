-- ADR-0035: credit lives in three pools; granted and paid credit are lots; spend is settled into
-- the ledger. Additive: every existing row is valid as it stands -- all history is allowance
-- (backfilled by the column default), keeps its period, and carries no lot or external ref.
--
-- Adding a column with a constant default is a catalog-only change in Postgres 11+: it rewrites
-- no row, so the append-only trigger (ADR-0009) is never asked to permit an UPDATE.

ALTER TABLE budget_grants
    ADD COLUMN pool TEXT NOT NULL DEFAULT 'allowance',
    -- D3: a negative granted/paid row names the lot it draws from. ON DELETE CASCADE only ever
    -- fires when the account itself is deleted -- the one DELETE the trigger permits.
    ADD COLUMN lot_id TEXT NULL REFERENCES budget_grants(id) ON DELETE CASCADE,
    -- D4: the opaque reference of whatever caused the row (a purchase: the vpay intent id).
    -- Stored, never branched on.
    ADD COLUMN external_ref TEXT NULL,
    -- D2: only the allowance pool has a period.
    ALTER COLUMN period DROP NOT NULL;

ALTER TABLE budget_grants
    DROP CONSTRAINT budget_grants_source_chk,
    ADD CONSTRAINT budget_grants_source_chk CHECK (source IN (
        'base', 'self_service', 'admin', 'automatic', 'manual_approval', 'refund',
        'correction', 'promotion', 'migration',
        'purchase', 'purchase_reversal', 'referral', 'consumption', 'expiry'
    )),
    ADD CONSTRAINT budget_grants_pool_chk CHECK (pool IN ('allowance', 'granted', 'paid')),
    ADD CONSTRAINT budget_grants_pool_period_chk CHECK ((pool = 'allowance') = (period IS NOT NULL)),
    -- D4: the sign follows what the row does, not merely whether it is a correction.
    DROP CONSTRAINT budget_grants_amount_sign_chk,
    ADD CONSTRAINT budget_grants_amount_sign_chk CHECK (
        (source IN ('base', 'self_service', 'admin', 'automatic', 'manual_approval', 'refund',
                    'promotion', 'migration', 'purchase', 'referral')
            AND amount_micros > 0)
        OR (source IN ('purchase_reversal', 'consumption', 'expiry') AND amount_micros < 0)
        OR (source = 'correction' AND pool = 'allowance' AND amount_micros <> 0)
        OR (source = 'correction' AND pool <> 'allowance' AND amount_micros < 0)
    ),
    -- D1: which pools each source may write. `promotion` is also admitted in `allowance` because
    -- it was a valid source before pools existed and any such row was backfilled there; the
    -- funding port only ever writes it to `granted`.
    ADD CONSTRAINT budget_grants_source_pool_chk CHECK (
        (source IN ('base', 'self_service', 'automatic', 'manual_approval', 'migration', 'refund')
            AND pool = 'allowance')
        OR (source IN ('admin', 'promotion') AND pool IN ('allowance', 'granted'))
        OR (source = 'referral' AND pool = 'granted')
        OR (source IN ('purchase', 'purchase_reversal') AND pool = 'paid')
        OR source IN ('correction', 'consumption', 'expiry')
    ),
    -- D3: allowance rows never reference a lot; a positive granted/paid row opens one (and so
    -- names none); a negative granted/paid row names exactly one. Same-pool and same-account are
    -- enforced by the write path, which a CHECK cannot see across rows.
    ADD CONSTRAINT budget_grants_lot_chk CHECK (
        (pool = 'allowance' AND lot_id IS NULL)
        OR (pool <> 'allowance' AND amount_micros > 0 AND lot_id IS NULL)
        OR (pool <> 'allowance' AND amount_micros < 0 AND lot_id IS NOT NULL)
    );

CREATE INDEX idx_budget_grants_lot_id ON budget_grants (lot_id) WHERE lot_id IS NOT NULL;

-- D5: a projection of the ledger, one row per granted/paid lot. Written in the same transaction
-- as the ledger row that changes it; rebuildable by replaying budget_grants.
CREATE TABLE credit_lots (
    lot_id            TEXT PRIMARY KEY REFERENCES budget_grants(id) ON DELETE CASCADE,
    budget_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    pool              TEXT NOT NULL CHECK (pool IN ('granted', 'paid')),
    amount_micros     BIGINT NOT NULL CHECK (amount_micros > 0),
    -- No debit may overdraw a lot; spend that finds no credit is debt (D7), never a negative lot.
    remaining_micros  BIGINT NOT NULL CHECK (remaining_micros >= 0),
    expires_at        TIMESTAMPTZ NULL,
    opened_at         TIMESTAMPTZ NOT NULL,
    closed_at         TIMESTAMPTZ NULL,
    CONSTRAINT credit_lots_remaining_le_amount_chk CHECK (remaining_micros <= amount_micros)
);

-- Settlement's draw order and the refresher's per-pool sums both read only open lots.
CREATE INDEX idx_credit_lots_open ON credit_lots (budget_account_id, pool, expires_at, opened_at)
    WHERE remaining_micros > 0;

-- D6/D7: how far each account's spend has been settled into the ledger (by usage ingestion time,
-- `usage_events.created_at`), and the spend that found no credit. `allowance_period` is the
-- period of the last settlement: when it differs from the current one, the allowance renewed and
-- the debt is forgiven.
CREATE TABLE settlement_state (
    budget_account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    settled_through   TIMESTAMPTZ NOT NULL,
    debt_micros       BIGINT NOT NULL DEFAULT 0 CHECK (debt_micros >= 0),
    allowance_period  TEXT NULL CHECK (allowance_period ~ '^\d{4}-\d{2}$'),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D9: the snapshot keeps one number per pool. NULL means "not computed by the pool-aware
-- refresher yet", never zero -- the same rule as every other money column on this table.
ALTER TABLE budget_remaining_snapshots
    ADD COLUMN allowance_remaining_micros BIGINT NULL,
    ADD COLUMN granted_remaining_micros   BIGINT NULL,
    ADD COLUMN paid_remaining_micros      BIGINT NULL,
    ADD COLUMN debt_micros                BIGINT NULL;
