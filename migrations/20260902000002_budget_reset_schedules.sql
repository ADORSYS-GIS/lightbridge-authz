-- ADR-0032: configured budget reset schedules — the first scheduler in this codebase.
--
-- One row is one policy: "reset remaining to $2 every day at 00:00 UTC for every account on the
-- `free` billing plan". A background task in the authz-budget process claims due rows
-- (`WHERE enabled AND next_run_at <= now() FOR UPDATE SKIP LOCKED`), resolves the budget accounts
-- each row matches, and writes ONE grant per account per window into `budget_grants` — the
-- append-only ledger of ADR-0009 remains the only place a balance ever changes.
--
-- Deliberately CHECK-constrained TEXT rather than Postgres `CREATE TYPE ... AS ENUM`: this schema
-- has zero enum types today (`grep -rn 'CREATE TYPE' migrations/` returns nothing) and
-- `budget_grants.source` — the closest analogue, nine closed values mirrored 1:1 by a Rust enum —
-- is a CHECK-constrained TEXT column. Adding the repo's first enum type here for three tiny
-- domains would buy nothing and cost the well-known `ALTER TYPE ... ADD VALUE`-cannot-run-in-a-
-- transaction migration hazard (every migration file in this repo is applied as one transaction).
--
-- `enabled` defaults to FALSE, and the create RPC never lets a caller override that: a
-- misconfigured `global` schedule would grant across the whole estate, so a schedule is authored,
-- dry-run (`runBudgetResetScheduleNow { dryRun: true }`), and only then enabled.
CREATE TABLE budget_reset_schedules (
    -- CUID2, minted by `lightbridge_authz_core::cuid::cuid2` (ADR-0039: never ordered on, never
    -- paginated by).
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    -- 'global' | 'billing_plan' | 'account'. Precedence when several enabled schedules match one
    -- budget account is account > billing_plan > global, resolved in the budget crate, NOT here:
    -- it is a property of the whole schedule set, not of any single row.
    scope_kind      TEXT NOT NULL,
    -- NULL for 'global'; a `projects.billing_plan`/`api_keys.billing_plan` value for
    -- 'billing_plan'; an `accounts.id` for 'account'. Deliberately NOT a foreign key: the same
    -- column carries a plan name (no table to reference) and an account id, so an FK could only
    -- ever cover one of the two scope kinds — a half-enforced constraint that reads as a whole one.
    scope_id        TEXT NULL,
    -- 'daily' | 'weekly' | 'monthly'.
    cadence         TEXT NOT NULL,
    -- ISO weekday 1..7 (Mon..Sun) for 'weekly'; day-of-month 1..28 for 'monthly' (28, not 31, so
    -- every month has the day and no schedule silently skips February); NULL for 'daily'.
    anchor          SMALLINT NULL,
    -- Time of day the schedule fires, always UTC (the column is `TIME`, not `TIMETZ`: there is no
    -- second zone in this system, and `TIMETZ` is a documented Postgres foot-gun).
    run_at_utc      TIME NOT NULL DEFAULT '00:00',
    -- Integer micro-USD, like every other amount in the budget domain. For 'reset' this is the
    -- remaining balance the account is clamped TO (0 is meaningful: "cut everyone off daily"); for
    -- 'top_up' it is the amount added, which must be strictly positive because
    -- `budget_grants_amount_sign_chk` rejects a non-`correction` grant that is not > 0.
    amount_micros   BIGINT NOT NULL,
    -- 'reset' (clamp remaining to exactly `amount_micros`, in BOTH directions — a negative delta
    -- is booked as the `source = 'correction'` compensating row ADR-0009 already defines) or
    -- 'top_up' (add `amount_micros`).
    mode            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    -- The next window this schedule fires. Advanced from the PREVIOUS `next_run_at` plus one
    -- cadence step (never from `now()`), so ticks cannot drift; a schedule that missed several
    -- windows catches up to the next FUTURE instant in one step instead of firing once per missed
    -- window.
    next_run_at     TIMESTAMPTZ NOT NULL,
    last_run_at     TIMESTAMPTZ NULL,
    created_by      TEXT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT budget_reset_schedules_name_chk CHECK (length(btrim(name)) > 0),
    CONSTRAINT budget_reset_schedules_scope_kind_chk
        CHECK (scope_kind IN ('global', 'billing_plan', 'account')),
    CONSTRAINT budget_reset_schedules_cadence_chk
        CHECK (cadence IN ('daily', 'weekly', 'monthly')),
    CONSTRAINT budget_reset_schedules_mode_chk CHECK (mode IN ('reset', 'top_up')),
    -- `scope_id` is populated for exactly the two scoped kinds and NULL for 'global' — the
    -- structural half of "global means every account", so a global row can never carry a stray
    -- target nobody reads.
    CONSTRAINT budget_reset_schedules_scope_id_chk CHECK (
        (scope_kind = 'global' AND scope_id IS NULL)
        OR (scope_kind <> 'global' AND scope_id IS NOT NULL AND length(btrim(scope_id)) > 0)
    ),
    CONSTRAINT budget_reset_schedules_anchor_chk CHECK (
        (cadence = 'daily' AND anchor IS NULL)
        OR (cadence = 'weekly' AND anchor BETWEEN 1 AND 7)
        OR (cadence = 'monthly' AND anchor BETWEEN 1 AND 28)
    ),
    CONSTRAINT budget_reset_schedules_amount_chk CHECK (
        (mode = 'top_up' AND amount_micros > 0)
        OR (mode = 'reset' AND amount_micros >= 0)
    )
);

-- The claim query's index, in its exact predicate order: `WHERE enabled AND next_run_at <= now()
-- ... FOR UPDATE SKIP LOCKED`. Leading `enabled` (not a partial `WHERE enabled` index) so a
-- disabled schedule's row is still covered when an operator lists or re-enables it.
CREATE INDEX idx_budget_reset_schedules_enabled_next_run_at
    ON budget_reset_schedules (enabled, next_run_at);

-- `updated_at` maintenance mirrors the rest of this schema: the writer sets it explicitly (see
-- `ResetScheduleRepo::update`), so no trigger is added here — a trigger would silently disagree
-- with the value the repo already binds.
