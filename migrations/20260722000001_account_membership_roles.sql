-- Explicit per-membership roles (owner/admin/member), per ADR-0002's original "Data model
-- direction" (never implemented until now). Gates account-scoped destructive/membership-management
-- operations: addAccountMember, removeAccountMember, disableAccount, enableAccount, deleteAccount,
-- setAccountMemberRole (new). Resource read/update on projects and api-keys stays open to any member,
-- unchanged.
ALTER TABLE account_memberships
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('owner', 'admin', 'member'));

-- Backfill: the earliest member per account (by created_at, ties broken by subject for determinism)
-- becomes owner. This matches createAccount's existing behavior of seeding the creator as the sole
-- initial member -- that creator is the natural owner. Every other existing membership row already
-- defaults to 'member' via the column default above, so only the "first member per account" rows
-- need an explicit UPDATE.
WITH first_member AS (
    SELECT DISTINCT ON (account_id) account_id, subject
    FROM account_memberships
    ORDER BY account_id, created_at ASC, subject ASC
)
UPDATE account_memberships
SET role = 'owner'
FROM first_member
WHERE account_memberships.account_id = first_member.account_id
  AND account_memberships.subject = first_member.subject;
