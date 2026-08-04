-- `budget_augmentation_requests` is the ledger for *decisions about requests* -- approved and
-- refused alike -- kept deliberately separate from `budget_grants`, the ledger for *actual
-- money-granting events* only. Every refill request's outcome gets a row here, matching #191's
-- own non-functional requirement: "Every path through this story writes a ledger entry --
-- including refusals and rejections. An unrecorded decision is the thing this epic exists to
-- eliminate." `budget_grants` cannot represent a refusal at all -- its `CHECK` constraint
-- requires `amount_micros > 0` for every non-`correction` source, so there is no way to write a
-- "granted zero" row there, and semantically a denial isn't a grant. A request that results in a
-- grant links to it via `grant_id` (below) -- the two tables tell the complete story together,
-- neither alone.
--
-- `status` is the exact request state machine from `docs/rfc/0001-budget-refill.md`'s "Domain
-- (ADR-0009)" section, quoted verbatim: "`budget_augmentation_requests` carrying the request
-- state machine: `created`, `evaluating`, `auto_approved`, `pending_review`, `approved`,
-- `partially_approved`, `denied`, `cancelled`, `expired`, `applied`."
--
-- `requested_tier` stores the wire label a `crates/lightbridge-authz-budget::BudgetTier` renders
-- via `.label()` (e.g. `"b-30"`), kept as plain `TEXT` here rather than a foreign key or enum --
-- this table doesn't need to join against a tier catalog, just record what was asked for.
--
-- `grant_id` is `NULL` until (and unless) the request results in an actual grant -- populated
-- only for `auto_approved`/`approved`/`applied`/`partially_approved` outcomes, never for
-- `denied`/`cancelled`/`expired`, or for `pending_review` while it's still waiting.
--
-- No append-only trigger on this table (unlike `budget_grants`) -- a request's `status`
-- legitimately transitions over its lifecycle (`pending_review` -> `approved`/`denied`, etc.), so
-- `UPDATE` is the normal, expected write pattern here, not a violation of any ledger discipline.
-- What must NOT happen is deleting a row or silently overwriting `policy_reason_codes`/
-- `policy_effect` once evaluation has recorded them -- that discipline lives in the repository
-- code (`crates/lightbridge-authz-budget/src/augmentation.rs`, `AugmentationRepo::record_decision`
-- is the ONLY place those fields are ever written after creation), not a DB-level trigger.
--
-- Idempotency: `idempotency_key`'s partial unique index works exactly like `budget_grants`' own
-- -- NULLs never collide (most requests carry no idempotency key at all), a genuine duplicate
-- submission conflicts, and `AugmentationRepo::create` resolves that the same way
-- `BudgetRepo::grant` does: `INSERT ... ON CONFLICT (idempotency_key) WHERE idempotency_key IS
-- NOT NULL DO NOTHING`, then a fallback `SELECT` returning the original row rather than erroring
-- or inserting a duplicate.
CREATE TABLE budget_augmentation_requests (
    id                        TEXT PRIMARY KEY,
    budget_account_id         TEXT NOT NULL REFERENCES accounts(id),
    account_id                TEXT NOT NULL REFERENCES accounts(id),
    project_id                TEXT NULL REFERENCES projects(id),
    period                    TEXT NOT NULL,
    requested_tier            TEXT NOT NULL,
    requested_amount_micros   BIGINT NOT NULL,
    status                    TEXT NOT NULL,
    policy_effect             TEXT NULL,
    policy_reason_codes       TEXT[] NULL,
    matched_rule_ids          TEXT[] NULL,
    policy_revision           TEXT NULL,
    approved_amount_micros    BIGINT NULL,
    grant_id                  TEXT NULL REFERENCES budget_grants(id),
    idempotency_key           TEXT NULL,
    reviewed_by               TEXT NULL,
    rejection_reason          TEXT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at                TIMESTAMPTZ NULL,

    CONSTRAINT budget_augmentation_requests_status_chk CHECK (status IN (
        'created', 'evaluating', 'auto_approved', 'pending_review',
        'approved', 'partially_approved', 'denied', 'cancelled', 'expired', 'applied'
    )),
    CONSTRAINT budget_augmentation_requests_period_format_chk CHECK (period ~ '^\d{4}-\d{2}$')
);

CREATE UNIQUE INDEX budget_augmentation_requests_idempotency_key_uidx
    ON budget_augmentation_requests (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_budget_augmentation_requests_budget_account_period
    ON budget_augmentation_requests (budget_account_id, period, created_at DESC);
CREATE INDEX idx_budget_augmentation_requests_pending_review
    ON budget_augmentation_requests (status, created_at) WHERE status = 'pending_review';
