-- ADR-0026: one identity may own many accounts.
--
-- Renumbered from 20260830000001 to 20260830000003 after the fact. #565 landed the same day with
-- its own 20260830000001 (`federated_identities_add_profile_claims`), and sqlx keys
-- `_sqlx_migrations` by the numeric VERSION, not the filename -- so two files sharing a prefix
-- collide on `_sqlx_migrations_pkey` and the second one to apply fails with 23505. Neither PR's CI
-- could see it: each branch contained only its own migration, and the collision existed only in
-- the merge. Nothing had applied this version anywhere durable yet, which is the only reason
-- renumbering is legitimate here rather than a new migration -- same bar as the 20260724 -> 20260727
-- renumber recorded in ADR-0006.
--
-- `accounts.user_id -> users.id` (ADR-0024) has ALWAYS been a 1:N-capable edge -- a plain FK with
-- a NON-unique index (`idx_accounts_user_id`, 20260825000001:50). What pinned it to exactly one
-- row on the N side was never the schema; it was this trigger:
--
--     IF NEW.user_id IS NULL THEN
--         INSERT INTO users (id) VALUES (NEW.id) ON CONFLICT (id) DO NOTHING;
--         NEW.user_id := NEW.id;          -- <-- a fresh user per account, always
--     END IF;
--
-- So every account minted its own user and the edge could never fan out. This migration keeps the
-- trigger (every one of the ~17 raw `INSERT INTO accounts (id, ...)` test fixtures across the
-- workspace depends on it, exactly as ADR-0024 Q5 intended) but makes the self-owning branch the
-- FALLBACK rather than the only behaviour: an INSERT that names a `user_id` now keeps it.
--
-- NO BACKFILL. 20260825000001:43-47 already ran `users.id := accounts.id` for every pre-existing
-- row, so `users.id == accounts.id == subject` holds for all of them and stays holding. That is
-- the wire-invariance ADR-0026 D2 is graded on: on the day this ships, every `user_id` is
-- byte-identical to the `id` beside it, and nothing downstream observes a change until an account
-- is created that could not have existed before.
--
-- DELIBERATELY NOT TOUCHED: `federated_identities_account_uidx` (20260825000001:108). Dropping it
-- is the obvious-looking way to let one login own many accounts, and it is the wrong one -- it
-- removes the structural guarantee that a second issuer presenting a colliding `sub` cannot
-- silently merge onto an existing account, which is the cross-tenant-merge bug ADR-0024 exists to
-- close, and whose `Error::Conflict` depends on that index's 23505. Ownership does not need it:
-- a person's HOME account (the one their login adopts, the one that becomes `auth().id`) stays
-- 1:1 with their identity; the accounts they OWN are the 1:N dimension, carried by `user_id`.
-- Two different relations, kept apart on purpose. See ADR-0026 D6.

SET LOCAL lock_timeout = '5s';

-- Replaces the function in place; the `accounts_set_user` trigger binding is unchanged, so no
-- DROP/CREATE TRIGGER and no window during which inserts are unguarded.
CREATE OR REPLACE FUNCTION set_account_user() RETURNS trigger AS $$
BEGIN
    -- An explicit owner wins: this is the path `StoreRepo::create_account` now takes, passing the
    -- CALLER's user id so a second account joins an existing person instead of inventing one.
    -- FK enforcement on accounts.user_id -> users(id) still applies to whatever is supplied.
    IF NEW.user_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- Fallback, unchanged from 20260825000001: an account that names no owner owns itself. Keeps
    -- every raw `INSERT INTO accounts (id, ...)` fixture working untouched, and remains the path
    -- a grandfathered account was created through.
    INSERT INTO users (id) VALUES (NEW.id) ON CONFLICT (id) DO NOTHING;
    NEW.user_id := NEW.id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- `list my accounts` stops being `WHERE id = $1` (a PK lookup) and becomes `WHERE user_id = $1`
-- ordered by `created_at` -- ADR-0039 bans ordering by id, so the sort key has to be in the index
-- or every page costs a sort. Composite, not a plain `user_id` index: `idx_accounts_user_id`
-- (20260825000001:50) already covers equality alone.
CREATE INDEX IF NOT EXISTS idx_accounts_user_id_created_at
    ON accounts (user_id, created_at);
