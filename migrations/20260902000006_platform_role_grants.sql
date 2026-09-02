-- ADR-0033: platform roles are a table, stamped at mint.
--
-- Before this, "who is an admin" was not a decision anyone made: prod's claim mapper
-- (`ai-helm-values/environments/prod/values/lightbridge-app.yaml:266-273`) reads
-- `owner -> ["lightbridge-admin"]`, and under ADR-0026 every signed-in person owns an account, so
-- EVERY authenticated user was minted `lightbridge-admin`. This table makes the grant an explicit,
-- auditable row with a granter, a timestamp and a reason; the accompanying
-- `ClaimSource::PlatformRoles` mapper reads it at mint time (the ADR-0014 pattern: claims come
-- from our own tables while minting, never from Keycloak).
--
-- ADR-0038 note: hand-written SQL, deliberately. `platform_role_grants` is NOT modelled in
-- `crates/lightbridge-authz-api/schema/authz.cstack` and must not be: it is read on the token-mint
-- path by `authz-idp` (which builds no cratestack client at all), and its grant path needs the
-- "insert unless an active row already exists" upsert the partial unique index below enforces --
-- neither is expressible through the generated model client. Recorded in AGENTS.md's exception
-- list.
--
-- Lock posture: this is a CREATE TABLE plus its own indexes on a brand-new relation, so nothing
-- here can block a live reader or writer -- there is no pre-existing table to take an
-- AccessExclusiveLock on. `SET LOCAL lock_timeout` is kept anyway for the same fail-fast reason
-- every migration in this directory carries it: sqlx applies the whole file as one transaction,
-- and the `users` foreign key below takes a ShareRowExclusive lock on `users`, which a
-- long-running transaction elsewhere in the fleet could otherwise queue this migration behind
-- indefinitely.
SET LOCAL lock_timeout = '5s';

CREATE TABLE platform_role_grants (
    -- CUID2, minted by the caller (`lightbridge_authz_core::cuid::cuid2`), never a serial.
    id TEXT PRIMARY KEY,
    -- The PERSON (ADR-0024/ADR-0026), not an account: one identity may own many accounts, and a
    -- platform role follows the human, not whichever tenant they happen to be acting in.
    -- ON DELETE CASCADE because a grant to a deleted person is not a fact worth keeping.
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- A role name from `oauth2.rbac.role_permissions` (e.g. `lightbridge-admin`). Deliberately
    -- free TEXT with no CHECK constraint and no enum: the role catalogue is operator
    -- configuration, so a database constraint would hard-code one deployment's config into the
    -- schema. Validation happens where the catalogue is actually known -- `grantPlatformRole` and
    -- the `rbac grant` CLI both refuse a role absent from the configured map.
    role TEXT NOT NULL,
    -- The user id of the admin who granted it. NULL means CLI bootstrap
    -- (`lightbridge-authz rbac grant`), which is how the FIRST admin exists at all: there is no
    -- admin to grant it, by construction. No foreign key -- a granter's account may later be
    -- deleted, and an audit row must not lose who did it when that happens.
    granted_by TEXT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL = active. Revocation is a soft delete on purpose: "X was an admin between these two
    -- timestamps, granted by Y, for reason Z" is the whole point of the table.
    revoked_at TIMESTAMPTZ,
    reason TEXT
);

-- The active-grant uniqueness rule, partial so any number of REVOKED (user_id, role) rows may
-- coexist -- granting, revoking and re-granting the same role to the same person is a normal
-- history, not a conflict. This index is also what makes `grantPlatformRole` idempotent: the
-- insert is an `ON CONFLICT ... DO NOTHING` against exactly this index, so a repeat grant returns
-- the existing active row instead of minting a second one.
CREATE UNIQUE INDEX platform_role_grants_active_uidx
    ON platform_role_grants (user_id, role)
    WHERE revoked_at IS NULL;

-- The mint-path read: "every active role for this person", run once per token minted with a
-- `platform_roles` claim mapper configured. Partial (active rows only) so it stays small no matter
-- how much revocation history accumulates.
CREATE INDEX idx_platform_role_grants_user_active
    ON platform_role_grants (user_id)
    WHERE revoked_at IS NULL;

-- The admin console's `listPlatformRoleGrants` walk: newest first, cursored on `granted_at`.
-- ADR-0039 bans ordering by id (CUID2 has no defined ordering), so the sort key has to be in the
-- index or every page costs a sort.
CREATE INDEX idx_platform_role_grants_granted_at
    ON platform_role_grants (granted_at DESC);

-- The `role=` filter of the same listing (e.g. "who are the admins"), with the same sort key
-- trailing so a filtered page is also sort-free.
CREATE INDEX idx_platform_role_grants_role_granted_at
    ON platform_role_grants (role, granted_at DESC);
