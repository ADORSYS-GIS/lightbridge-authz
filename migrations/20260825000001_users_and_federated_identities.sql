-- Lock-safety note (measured against a 100k-row accounts table): every ALTER on accounts below
-- (ADD COLUMN, the UPDATE backfill, ALTER ... SET NOT NULL, ADD CONSTRAINT, CREATE INDEX) takes
-- AccessExclusiveLock and, because sqlx applies this whole file as one transaction, that lock is
-- held from the first ALTER through COMMIT -- not released between statements. Intrinsic work at
-- that scale measured ~500ms total (UPDATE accounts SET user_id = id: 355ms; CREATE INDEX
-- idx_accounts_user_id: 113ms; ADD CONSTRAINT accounts_user_id_fkey: 22ms; SET NOT NULL: 8ms), but
-- Postgres queues ALL later lock requests (including plain SELECTs) strictly FIFO behind a pending
-- AccessExclusiveLock request -- so if any reader/writer already holds so much as AccessShareLock
-- on accounts when this migration starts, every request that arrives after this migration's own
-- ALTER queues behind it too, and this migration itself waits on the pre-existing holder to
-- COMMIT/ROLLBACK. With the authz-migrate hook running while OLD pods still serve live traffic,
-- an already-long-running transaction elsewhere in the fleet turns this from "~500ms of exclusive
-- work" into an unbounded stall of the live API. `SET LOCAL lock_timeout` scopes correctly here
-- specifically because the whole file is one transaction: it converts that unbounded FIFO stall
-- into a fast, visible, retryable migration failure instead -- the migrate hook can simply run
-- again once the blocking transaction clears.
SET LOCAL lock_timeout = '5s';

-- ADR-0024: we own our users; accounts are federated identities. A person's defining identity
-- moves from accounts.id (the historical "one account = one person" property, ADR-0006) to a new
-- users.id -- a person may hold several federated identities (Keycloak realms/issuers), each still
-- backed by an `accounts` row for backward compatibility (existing project/budget/API-key
-- ownership is entirely accounts-keyed and stays that way -- see the ADR's "Compatibility line").
--
-- ADR-0038 note: `users` IS a normal cratestack-modelled table (see the `User` model added to
-- `crates/lightbridge-authz-api/schema/authz.cstack` in this same PR) -- a plain single-column
-- `id` PK, no CAS-rotation race, no cross-replica coordination need. `federated_identities` is
-- deliberately NOT modelled in authz.cstack -- same class of exception as `signing_keys`/
-- `exchange_refresh_tokens`/`device_authorizations`/`authorization_codes`: it carries a sealed
-- credential (`token_envelope`) that must be unreachable from any generated read path.
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backfill (ADR-0024 Q5): every existing account becomes its own user, keyed by the SAME id --
-- accounts.id is the caller's stored Keycloak `sub` (ADR-0006), and ADR-0039 bans *minting* a new
-- id in place of a stored one, not reusing a stored one verbatim. This is an id-reuse, not a
-- remap (same idiom `20260823000002_sessions.sql`'s chain_id backfill and
-- `20260725000001_default_account_project.sql`'s trigger-based backfill both already use).
INSERT INTO users (id, created_at, updated_at)
SELECT a.id, a.created_at, a.updated_at FROM accounts a;

ALTER TABLE accounts ADD COLUMN user_id TEXT;
UPDATE accounts SET user_id = id;
ALTER TABLE accounts ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE accounts ADD CONSTRAINT accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id);
CREATE INDEX idx_accounts_user_id ON accounts (user_id);

-- BEFORE INSERT trigger, not an application-side default: every existing Rust writer
-- (`StoreRepo::create_account`) and every raw-SQL test fixture across the workspace inserts
-- `accounts (id, ...)` without a `user_id` -- mirrors `set_project_is_default`'s established
-- precedent (`20260725000001_default_account_project.sql`) for the exact same "don't touch every
-- existing INSERT call site" reason. A caller that DOES supply `user_id` (a future explicit-link
-- flow) is left alone; only a NULL is auto-provisioned.
CREATE OR REPLACE FUNCTION set_account_user() RETURNS trigger AS $$
BEGIN
    IF NEW.user_id IS NULL THEN
        INSERT INTO users (id) VALUES (NEW.id) ON CONFLICT (id) DO NOTHING;
        NEW.user_id := NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER accounts_set_user BEFORE INSERT ON accounts FOR EACH ROW EXECUTE FUNCTION set_account_user();

-- The federation key: (issuer, subject) identifies a Keycloak identity uniquely and permanently.
-- token_envelope/token_sealed_at/access_expires_at/refresh_expires_at/scope hold the sealed
-- Keycloak token set (AES-256-GCM, lightbridge_authz_core::crypto) plus its non-secret queryable
-- metadata -- see StoreRepo::upsert_federated_identity's doc comment for the full write path.
CREATE TABLE federated_identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    -- Nullable, ON DELETE SET NULL: a federated identity survives its adopted account's deletion
    -- -- deleting a tenant's `accounts` row (and everything under it) must not delete the person
    -- who logged in as that tenant. NULL means "no accounts row was ever adopted", which is the
    -- steady state for any identity minted after this migration whose (issuer, subject) never
    -- matches a pre-existing accounts.id.
    account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    token_envelope TEXT,
    token_sealed_at TIMESTAMPTZ,
    access_expires_at TIMESTAMPTZ,
    refresh_expires_at TIMESTAMPTZ,
    scope TEXT,
    last_authenticated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Security role 1/2: the federation key itself. A given (issuer, subject) pair can only ever back
-- ONE federated_identities row -- this is what makes cross-issuer subject collisions structurally
-- impossible to merge silently: a second issuer presenting the same `sub` value gets its OWN row
-- (different issuer => different uniqueness), never overwrites the first issuer's row.
CREATE UNIQUE INDEX federated_identities_issuer_subject_uidx ON federated_identities (issuer, subject);

-- Security role 2/2: at most ONE federated identity may ever adopt a given grandfathered
-- `accounts` row (the "id == subject" legacy account created before this migration, or by a
-- pre-ADR-0024 client). The partial index (WHERE account_id IS NOT NULL, so any number of rows
-- may share account_id = NULL) means the FIRST issuer to log in as that subject adopts the
-- account; every subsequent issuer presenting the same subject value hits 23505 on THIS index
-- (not the issuer/subject one, since it's a different issuer) and is refused with Error::Conflict
-- rather than silently merged onto someone else's account/projects/budget.
CREATE UNIQUE INDEX federated_identities_account_uidx ON federated_identities (account_id) WHERE account_id IS NOT NULL;

CREATE INDEX idx_federated_identities_user_id ON federated_identities (user_id);
