-- ADR-0009: budget_balances is a materialized view of the budget_grants ledger -- a real table
-- (not a Postgres `MATERIALIZED VIEW`; unlike `AccountSummary`'s explicit-refresh materialized
-- view elsewhere in this repo, this one is updated transactionally by the live write path, in
-- lockstep with the grant insert that produced it) so that reading the current balance for an
-- account/period never has to replay the whole ledger. It must remain rebuildable by replaying
-- `budget_grants` from scratch -- that replay/rebuild function is a LATER PR in the #188 epic;
-- this migration only owns the table shape. The write path itself (the transaction that inserts
-- a grant and updates this table under a lock) lands in the same PR as this migration.
--
-- Source-to-bucket mapping -- `budget_grants.source` has nine values but this table only carries
-- five `*_total_micros` buckets plus `effective_budget_micros`. This is a real design decision,
-- already made for this PR, but it is NOT directly specified by ADR-0009's text (which lists the
-- columns but not this mapping) -- it is documented here as the resolved-but-reviewable call it
-- is, not as something beyond question:
--
--   * `base` and `migration` -> `base_total_micros`. `migration` represents historical data being
--     backfilled into ledger form; it conceptually IS whatever the base allocation was at the
--     time, so it shares the bucket rather than getting its own column for one rare,
--     backward-looking source.
--   * `self_service` -> `self_service_total_micros`, AND increments `self_service_grant_count`.
--     That counter is specifically "how many *unaided* self-service refills has this account used
--     this period" -- the thing ADR-0008's "two unaided rungs per period, beyond that
--     manual_review" policy caps. It must NOT be incremented by `manual_approval` (see below) -- a
--     request that had to go to review is, by definition, not one of the unaided ones, and
--     double-counting it against the same cap would be backwards (the whole point of the review
--     path is that it does NOT consume the unaided allowance).
--   * `admin`, `manual_approval`, and `promotion` -> `admin_total_micros`. `manual_approval` is
--     bucketed with `admin` because a reviewer/admin is the one who actually authorized the
--     amount (mirroring `admin`), and `promotion` is a similar business-initiated grant, not
--     something to give its own column for. Neither increments any grant-count column -- ADR-0009's
--     RFC companion doc states administrative grants are "unlimited at the business-policy level
--     only", i.e. not capped by a counter the way self-service is.
--   * `automatic` -> `automatic_total_micros`, AND increments `automatic_grant_count`.
--   * `refund` -> `refund_total_micros`.
--   * `correction` -> adjusts `effective_budget_micros` directly and ONLY -- it does not touch any
--     of the five named buckets. A correction's `amount_micros` may be negative (per the
--     `budget_grants` sign CHECK), and it exists specifically to compensate a bad grant without
--     touching the original row (see docs/runbooks/roll-back-a-budget-policy.md); crediting it to
--     a bucket would misattribute the adjustment to whichever source it's compensating for, when
--     its whole point is to be a separate, visible correction.
--   * `effective_budget_micros` is always `+= amount_micros` regardless of source (including
--     corrections, whose negative amount naturally reduces it) -- it is the actual total the
--     account may spend; the buckets above are for audit/breakdown only.
CREATE TABLE budget_balances (
    budget_account_id           TEXT NOT NULL REFERENCES accounts(id),
    period                      TEXT NOT NULL,
    base_total_micros           BIGINT NOT NULL DEFAULT 0,
    self_service_total_micros   BIGINT NOT NULL DEFAULT 0,
    admin_total_micros          BIGINT NOT NULL DEFAULT 0,
    automatic_total_micros      BIGINT NOT NULL DEFAULT 0,
    refund_total_micros         BIGINT NOT NULL DEFAULT 0,
    effective_budget_micros     BIGINT NOT NULL DEFAULT 0,
    self_service_grant_count    INTEGER NOT NULL DEFAULT 0,
    automatic_grant_count       INTEGER NOT NULL DEFAULT 0,
    version                     BIGINT NOT NULL DEFAULT 0,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (budget_account_id, period),
    CONSTRAINT budget_balances_period_format_chk CHECK (period ~ '^\d{4}-\d{2}$')
);
