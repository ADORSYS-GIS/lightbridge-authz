-- Add unique constraint to accounts.billing_identity
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_billing_identity ON accounts(billing_identity);

-- Change projects.allowed_models to be nullable
ALTER TABLE projects ALTER COLUMN allowed_models DROP NOT NULL;
ALTER TABLE projects ALTER COLUMN allowed_models DROP DEFAULT;

-- Convert empty arrays to NULL to represent "all models" if preferred, 
-- but the instruction says "can remain or be converted to NULL".
-- I'll leave them as is for now to avoid data loss if someone specifically wanted an empty array (deny all),
-- but the logic in the repo will handle the mapping.
-- Actually, the plan says:
-- DB [] (empty array) -> Domain Some(vec![]) (Deny All).
-- DB null -> Domain None (Allow All).
-- So I should probably convert existing '[]' to NULL if we want them to mean "Allow All" by default now.
-- However, the safest is to just allow NULL and let the application decide.
