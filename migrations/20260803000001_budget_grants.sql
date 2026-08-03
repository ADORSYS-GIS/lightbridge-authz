-- ADR-0009: budget_grants is the immutable ledger every budget allocation/adjustment writes to.
-- Nothing is ever updated or deleted in place -- corrections are new rows (see the append-only
-- enforcement below). `budget_balances`, a materialized rebuild of this ledger, lands in a later
-- PR in the #188 epic; this migration only owns the ledger table itself.
--
-- Why three separate account/project-shaped columns instead of one:
--
--   * `budget_account_id` is the aggregation key balances roll up on -- this is what the future
--     `budget_balances` table will key its primary key on, alongside `period`. For this phase it
--     is always identical to `account_id`, because ADR-0008 makes budget refills an account-level,
--     OIDC-users-only concept (no project-pooled budget exists yet). It is kept as its own column
--     now, deliberately, rather than collapsed into `account_id`, for the same reason
--     `Project.billing_identity` was split out from `Account` early in ADR-0006: cheaper to carry a
--     redundant column from day one than to split one column apart later once rows exist and code
--     depends on the single meaning.
--   * `account_id` is the account this specific grant is attributed to, always populated, used
--     directly by the queries the runbooks (docs/runbooks/stuck-augmentation-request.md) already
--     write against (`WHERE account_id = :account AND period = :period`) -- don't break that shape.
--   * `project_id` is optional context (which project a request was made from, if any), not the
--     aggregation key -- NULL is the common case until project-pooled budget exists.
--
-- `revoked_at` can only ever be populated **at insert time** (e.g. importing already-superseded
-- historical data) -- it is NOT how a live grant gets revoked, because the append-only trigger
-- below makes an UPDATE on an existing row impossible. Revoking an already-committed grant is a
-- compensating `correction` row (negative `amount_micros`), never a mutation of the original --
-- this is the mechanism docs/runbooks/roll-back-a-budget-policy.md already documents. Making this
-- explicit here so nobody later wires a "revoke" RPC that does
-- `UPDATE budget_grants SET revoked_at = ...` and is confused when the trigger rejects it.
CREATE TABLE budget_grants (
    id                  TEXT PRIMARY KEY,
    budget_account_id   TEXT NOT NULL REFERENCES accounts(id),
    account_id          TEXT NOT NULL REFERENCES accounts(id),
    project_id          TEXT NULL REFERENCES projects(id),
    period              TEXT NOT NULL,
    amount_micros       BIGINT NOT NULL,
    source              TEXT NOT NULL,
    actor_id            TEXT NULL,
    reason              TEXT NULL,
    policy_revision     TEXT NULL,
    matched_rule_ids    TEXT[] NULL,
    idempotency_key     TEXT NULL,
    trigger_key         TEXT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NULL,
    revoked_at          TIMESTAMPTZ NULL,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT budget_grants_period_format_chk CHECK (period ~ '^\d{4}-\d{2}$'),
    CONSTRAINT budget_grants_source_chk CHECK (source IN (
        'base', 'self_service', 'admin', 'automatic',
        'manual_approval', 'refund', 'correction', 'promotion', 'migration'
    )),
    -- Amounts are integer micro-USD (#189 non-functional criterion). Ordinary grants must be
    -- strictly positive; a `correction` is the ONLY source allowed to carry a negative amount,
    -- because it is how a bad grant is compensated without ever editing or deleting the original
    -- row (see docs/runbooks/roll-back-a-budget-policy.md, step 3) -- it must not be zero either,
    -- since a zero-amount correction would be a no-op row with no auditable effect.
    CONSTRAINT budget_grants_amount_sign_chk CHECK (
        (source = 'correction' AND amount_micros <> 0)
        OR (source <> 'correction' AND amount_micros > 0)
    )
);

CREATE UNIQUE INDEX budget_grants_idempotency_key_uidx
    ON budget_grants (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX budget_grants_trigger_key_uidx
    ON budget_grants (trigger_key) WHERE trigger_key IS NOT NULL;
CREATE INDEX idx_budget_grants_budget_account_period
    ON budget_grants (budget_account_id, period, created_at DESC);

-- Append-only enforcement (the acceptance-critical part of ADR-0009): a trigger, not just a
-- convention. Postgres fires triggers regardless of role -- including for the `postgres`
-- superuser -- so this is what actually stops a mutation everywhere, in prod and in every local/CI
-- environment alike.
CREATE OR REPLACE FUNCTION budget_grants_forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'budget_grants is append-only: % is not permitted (id=%)', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER budget_grants_no_update
    BEFORE UPDATE ON budget_grants
    FOR EACH ROW EXECUTE FUNCTION budget_grants_forbid_mutation();

CREATE TRIGGER budget_grants_no_delete
    BEFORE DELETE ON budget_grants
    FOR EACH ROW EXECUTE FUNCTION budget_grants_forbid_mutation();

-- Secondary, documented belt-and-suspenders layer. This REVOKE has NO VISIBLE EFFECT
-- locally/in CI: the dev/test connection string
-- (postgres://postgres:postgres@postgresql:5432/lightbridge_authz) connects as the `postgres`
-- superuser, and superusers bypass GRANT/REVOKE privilege checks entirely. The trigger above is
-- what actually enforces append-only everywhere, including for a superuser -- this REVOKE only
-- matters in a deployment where the application connects as a non-superuser role. Do not add a
-- test asserting this REVOKE has an effect; it won't, under the local/CI connection, and the
-- trigger it-tests below are the real proof of append-only behavior.
REVOKE UPDATE, DELETE ON budget_grants FROM PUBLIC;
