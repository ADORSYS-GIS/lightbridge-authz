CREATE TABLE account_memberships (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, subject)
);

INSERT INTO account_memberships (account_id, subject)
SELECT
    accounts.id,
    member.value
FROM accounts,
LATERAL jsonb_array_elements_text(accounts.owners_admins) AS member(value);

CREATE INDEX IF NOT EXISTS idx_account_memberships_subject ON account_memberships(subject);

ALTER TABLE accounts
    DROP COLUMN owners_admins;

CREATE FUNCTION delete_account_without_memberships() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM accounts WHERE id = OLD.account_id)
       AND NOT EXISTS (SELECT 1 FROM account_memberships WHERE account_id = OLD.account_id)
    THEN
        DELETE FROM accounts WHERE id = OLD.account_id;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prune_account_without_memberships
    AFTER DELETE ON account_memberships
    FOR EACH ROW
    EXECUTE FUNCTION delete_account_without_memberships();
