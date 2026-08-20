-- lightbridge-authz#395 ("all api-keys created from our system MUST have an expiry date... max
-- 90 days"): a direct user instruction, relayed in-session, and a deliberate HARD CUTOVER --
-- explicitly chosen over any softer migration, knowingly accepting that any integration still
-- relying on a non-expiring key stops working the moment this deploys.
--
-- Order matters here (backfill, then constrain): dropping straight to `SET NOT NULL` against a
-- table that may still contain NULL `expires_at` rows would fail the migration outright.
--
-- Backfill choice: every existing NULL-expiry row is force-expired to `created_at + 1 second` --
-- always in the past for a pre-existing row (it was created before this migration runs), and
-- always strictly after `created_at` (relevant to the "considered and rejected" CHECK constraint
-- discussion below). This is NOT "no expiry" reinterpreted as "some generous default" -- it is an
-- immediate, deliberate invalidation. `api_key_validation`'s cascade
-- (`crates/lightbridge-authz-api-key/src/repo.rs`,
-- `migrations/20260731000001_api_keys_owner_account.sql`) already reads
-- `k.expires_at <= now()` as `key_expired`, so these rows fail validation at `authz-opa` the
-- instant this migration lands -- no separate code change needed to make the backfill "count" as
-- invalid; the existing read path already treats it as such.
--
-- Visibility: the cluster is unreachable for a pre-flight count at authoring time, so this
-- `DO $$ ... RAISE NOTICE ... $$` block is the ONLY place anyone gets to see the blast radius --
-- it counts affected rows BEFORE the backfill runs and logs both the total and the still-active
-- subset (status = 'active', not soft-deleted -- i.e. keys someone could otherwise still be
-- presenting today). Postgres NOTICE messages surface as `tracing` INFO events through sqlx's
-- Postgres driver, so this appears in the migration's normal log output
-- (`crates/lightbridge-authz-core/src/migrate.rs::run_migrations`), not just in a psql session.
DO $$
DECLARE
    total_null_expiry INT;
    active_null_expiry INT;
BEGIN
    SELECT COUNT(*) INTO total_null_expiry FROM api_keys WHERE expires_at IS NULL;
    SELECT COUNT(*) INTO active_null_expiry
      FROM api_keys
     WHERE expires_at IS NULL AND status = 'active' AND deleted_at IS NULL;
    RAISE NOTICE 'lightbridge-authz#395 api_keys expiry backfill: % total key(s) with a null expires_at, % of them still active (status=active, not soft-deleted) and about to be force-expired immediately',
      total_null_expiry, active_null_expiry;
END $$;

UPDATE api_keys
   SET expires_at = created_at + INTERVAL '1 second'
 WHERE expires_at IS NULL;

ALTER TABLE api_keys ALTER COLUMN expires_at SET NOT NULL;

-- A `CHECK (expires_at > created_at [AND expires_at <= created_at + INTERVAL 'N days'])`
-- constraint here was considered -- the house rule that a DB CHECK "makes the invariant true
-- regardless of code path" is right in general -- and deliberately NOT added, for a
-- data-safety reason specific to this table, not a change of heart on the principle:
--
-- Neither `createApiKey` nor `rotateApiKey` validated `expires_at` in any way before this PR --
-- no "must be in the future" check, no upper bound -- so a real deployment may already hold rows
-- that violate either half of that constraint, and the cluster is unreachable to check (same
-- constraint noted above for the backfill count). Adding the constraint `NOT VALID` (the standard
-- safe pattern for a live table with unknown data -- see e.g.
-- `migrations/20260819000001_budget_policy_adr0015_amounts.sql`'s neighbors for how this repo
-- otherwise treats "cluster state unknown at authoring time") avoids failing THIS migration on
-- such a row, but does NOT grandfather it afterwards: Postgres re-checks every constraint on a
-- row's FULL resulting state on its next UPDATE, even one that never touches `expires_at` at all.
-- Any pre-existing violating row would then start failing its next unrelated write -- telemetry
-- (`record_api_key_usage` touches `last_used_at`/`last_ip` on every validated request),
-- `revokeApiKey`, rotation's own old-row status update -- turning a defense-in-depth addition into
-- a live landmine against literally-unknown production data, i.e. a NEW outage risk this PR did
-- not sign up to introduce.
--
-- The invariant is instead enforced entirely at the application layer, which has the config
-- context (the operator-set `max_lifetime_days`, unknowable to a migration) and can be tuned
-- without a schema change: `AuthzStoreImpl::validate_expires_at`
-- (`crates/lightbridge-authz-rest/src/handlers/mod.rs`), called from both `create_api_key` and
-- `rotate_api_key` before any write. `NOT NULL` above is the one invariant safe to enforce at the
-- DB layer today, because this migration backfills every row it could possibly violate, in the
-- same transaction, before adding it.
