-- ADR-0020: sessions becomes a first-class, revocable table; `sid` becomes its id, and
-- introspection fails closed on revocation. This migration covers Follow-up 1 (the table +
-- `exchange_refresh_tokens.session_id` backfill, #440) and folds in ADR-0021 Decision 3's `kind`
-- column + nullable `client_id` (#441) since `sessions` does not exist in production yet -- no
-- live-data cost to getting the full column set right in one migration, per that ADR's own
-- sequencing note.
--
-- See docs/adr/0020-sessions-are-a-first-class-revocable-table.md (Decisions 1, 6, 7, 8, 9) and
-- docs/adr/0021-browser-sso-hosted-login-page-and-session-cookie.md (Decision 3) for the full
-- design.
--
-- Column-level FK note: `account_id`/`project_id` are plain `TEXT NOT NULL`, NOT
-- `REFERENCES accounts(id)`/`REFERENCES projects(id)` -- deliberately matching
-- `exchange_refresh_tokens`'s own convention (see `20260709000002_exchange_refresh_tokens.sql`),
-- not `budget_grants`'s stricter one. `sessions` is architecturally the direct successor of that
-- table's `chain_id`/`chain_expires_at` columns (this migration's own backfill below reuses
-- `chain_id` values verbatim as `sessions.id`), so it inherits that table's looser convention
-- rather than budget_grants's FK'd one.
--
-- ADR-0038 note: unlike `exchange_refresh_tokens`/`project_members`/`signing_keys` (this repo's
-- three documented ADR-0038 exceptions), `sessions` IS a normal cratestack-modelled table --
-- see the `Session` model added to `crates/lightbridge-authz-api/schema/authz.cstack` in this
-- same PR (ADR-0020 Decision 9).
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    -- Nullable per ADR-0021 Decision 3: NULL for a `kind = 'browser'` row (not scoped to any one
    -- OAuth client -- the whole point of SSO); always set for `kind = 'token'`.
    client_id TEXT,
    -- "token" (ADR-0020's original scope) or "browser" (ADR-0021 Decision 3). Plain string, this
    -- schema's established convention for closed-set values (see `Project.modelPolicy`'s own
    -- comment) -- parsed fail-closed on the Rust side, never validated by shape here.
    kind TEXT NOT NULL DEFAULT 'token',
    -- "active" / "revoked" -- "expired" is never written, only computed at read time (ADR-0020
    -- Decision 6) by comparing `expires_at` to `now()`.
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    -- Raw `User-Agent` header string, best-effort, ADR-0020 Decision 7. `ip_address` is
    -- deliberately NOT included -- that ADR flags it as proposed, not decided, and this migration
    -- takes the "drop it from the first cut" branch the ADR says is acceptable.
    user_agent TEXT,
    CONSTRAINT sessions_kind_client_id_check CHECK (
        (kind = 'token' AND client_id IS NOT NULL) OR
        (kind = 'browser' AND client_id IS NULL)
    )
);

CREATE INDEX idx_sessions_account_id_status ON sessions (account_id, status);

-- Backfill (ADR-0020 Decision 1): every existing exchange_refresh_tokens chain already satisfies
-- this ADR's definition of a session -- an id-reuse, not a remap. `chain_id` becomes the new
-- `sessions.id` verbatim (chain_id values are already valid CUID2s, minted via `cuid2()` at chain
-- birth -- see `20260815000001_exchange_refresh_tokens_add_chain.sql`'s own comment), so this
-- needs no separate mapping table.
--
-- Per-chain aggregation: `account_id`/`project_id`/`client_id`/`chain_expires_at` are expected to
-- be consistent across every row sharing a `chain_id` (the migration that introduced `chain_id`
-- inherits them unchanged across every rotation) -- this takes the first value by `created_at`
-- rather than re-deriving/asserting consistency in SQL; the Rust-side migration-verification test
-- added alongside this migration cross-checks that assumption against a real seeded chain.
-- `status = 'active'` iff ANY row in the chain currently has `status = 'active'` (a chain with its
-- live member still active is an active session; a fully-superseded/revoked chain is a revoked
-- session). `created_at` is the chain's earliest row; `last_used_at` is the chain's most recent.
INSERT INTO sessions (id, account_id, project_id, client_id, kind, status, created_at, expires_at, last_used_at)
SELECT
    chains.chain_id,
    chains.account_id,
    chains.project_id,
    chains.client_id,
    'token',
    CASE WHEN chains.any_active THEN 'active' ELSE 'revoked' END,
    chains.created_at,
    chains.chain_expires_at,
    chains.last_used_at
FROM (
    SELECT
        chain_id,
        (ARRAY_AGG(account_id ORDER BY created_at))[1] AS account_id,
        (ARRAY_AGG(project_id ORDER BY created_at))[1] AS project_id,
        (ARRAY_AGG(client_id ORDER BY created_at))[1] AS client_id,
        (ARRAY_AGG(chain_expires_at ORDER BY created_at))[1] AS chain_expires_at,
        MIN(created_at) AS created_at,
        MAX(last_used_at) AS last_used_at,
        BOOL_OR(status = 'active') AS any_active
    FROM exchange_refresh_tokens
    GROUP BY chain_id
) AS chains;

ALTER TABLE exchange_refresh_tokens ADD COLUMN session_id TEXT;

UPDATE exchange_refresh_tokens SET session_id = chain_id WHERE session_id IS NULL;

ALTER TABLE exchange_refresh_tokens ALTER COLUMN session_id SET NOT NULL;
ALTER TABLE exchange_refresh_tokens ADD CONSTRAINT exchange_refresh_tokens_session_id_fkey
    FOREIGN KEY (session_id) REFERENCES sessions(id);
CREATE INDEX idx_exchange_refresh_tokens_session_id ON exchange_refresh_tokens (session_id);

-- `chain_id`/`chain_expires_at` are kept, completely unchanged, in this migration -- ADR-0020
-- explicitly leaves retiring them to a later release (Decision 1's own deferral); this migration
-- only adds `session_id` alongside them.
