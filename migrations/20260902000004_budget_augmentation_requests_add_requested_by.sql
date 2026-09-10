-- RENUMBERED 20260902000002 -> 20260902000004 (#647). #653 (budget reset schedules) and #654
-- (this file) merged within minutes of each other and both claimed version `20260902000002`.
-- sqlx keys `_sqlx_migrations` on the numeric prefix alone, so the pair made `sqlx migrate run`
-- abort against ANY database with
-- `duplicate key value violates unique constraint "_sqlx_migrations_pkey"` after applying the
-- first of the two -- i.e. every fresh deploy's migrate init container (ADR-0031) would fail, and
-- with it every service behind it. Renumbering THIS file (rather than #653's) is the safe half of
-- the pair: a partially-migrated environment has `20260902000002` already recorded against
-- #653's checksum, so moving that one would trip sqlx's "previously applied but has been
-- modified" check instead. This file has never been successfully recorded anywhere, so a new
-- version number is a clean first application. Contents unchanged from #654.

-- Story #646 (epic #645): persist WHO asked for a refill.
--
-- `budget_augmentation_requests` already records the *reviewer* (`reviewed_by`) and the *account*
-- the budget lands in (`budget_account_id`/`account_id`), but not the human who submitted the
-- request. The requester was known at request time -- it is `auth().id` inside the
-- `requestBudgetRefill` procedure -- and then thrown away. An approval workflow that cannot name
-- the requester is not auditable, which is the thing the whole `budget_augmentation_requests`
-- ledger exists to fix (see `20260804000002_budget_augmentation_requests.sql`'s header).
--
-- Additive and NULLable, deliberately:
--
--   * NULL means "unknown, pre-migration" -- it is NOT backfilled and cannot be. No other table
--     can reconstruct which subject submitted a historical request (`budget_grants.actor_id` is
--     only written for admin/correction grants, never for the self-service path this column
--     covers). A permanent, legitimate NULL is the honest encoding; inventing a placeholder
--     subject would be worse than admitting the gap.
--   * NULLable also keeps every existing write path unblocked while the two repos are mid-flight:
--     the console (`converse-frontends`, story C1) regenerates its client from this schema in a
--     separate PR, and nothing anywhere must fail in between.
--
-- No foreign key to `users(id)`, matching `reviewed_by` on this same table: the value is the
-- token subject as presented by the IdP, and a subject that has never been provisioned as a local
-- `users` row is a perfectly ordinary case. A FK here would turn an audit record into a write
-- barrier -- exactly backwards for a column whose entire purpose is to record what happened.
--
-- This is an AUDIT column only. Nothing in the authorization path reads it, and nothing may start
-- to: `requestBudgetRefill` is gated by `budget:self-refill` and the review procedures by
-- `budget:review`, both evaluated from the caller's token, never from a stored row.
--
-- No index: the console reads it as a per-row display field on pages already served by
-- `idx_budget_augmentation_requests_pending_review` /
-- `idx_budget_augmentation_requests_budget_account_period`. "Every request by user X" is not a
-- query anything issues today; add the index with the feature that needs it, not before.
ALTER TABLE budget_augmentation_requests
    ADD COLUMN requested_by_user_id TEXT NULL;

COMMENT ON COLUMN budget_augmentation_requests.requested_by_user_id IS
    'Token subject (auth().id) of the caller that submitted this refill request. NULL for rows created before story #646. Audit only -- never read by an authorization decision.';
