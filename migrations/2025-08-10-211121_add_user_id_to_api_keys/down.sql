-- Migration: remove user_id column from api_keys
-- Reversible counterpart to up.sql for 2025-08-10-211121_add_user_id_to_api_keys

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'api_keys'
          AND column_name = 'user_id'
    ) THEN
        ALTER TABLE api_keys DROP COLUMN IF EXISTS user_id;
    END IF;
END
$$;
