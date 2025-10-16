-- Migration: replace UUID columns with TEXT to support cuid2 identifiers
-- This migration checks the current column type and alters it only when it is uuid.
-- It alters the referenced (acls) id first, then dependent FK columns to avoid FK type mismatch.
-- Note: converting UUID -> TEXT is safe. Converting TEXT -> UUID (in down.sql) requires the text values to be valid UUIDs.

DO $$
BEGIN
    -- 1) If acls.id is UUID, convert it to TEXT first (referenced by other tables).
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'acls'
          AND column_name = 'id'
          AND udt_name = 'uuid'
    ) THEN
        ALTER TABLE acls ALTER COLUMN id TYPE TEXT USING id::text;
    END IF;

    -- 2) Convert api_keys.acl_id (FK) from UUID -> TEXT if needed
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'api_keys'
          AND column_name = 'acl_id'
          AND udt_name = 'uuid'
    ) THEN
        ALTER TABLE api_keys ALTER COLUMN acl_id TYPE TEXT USING acl_id::text;
    END IF;

    -- 3) Convert api_keys.id from UUID -> TEXT if needed
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'api_keys'
          AND column_name = 'id'
          AND udt_name = 'uuid'
    ) THEN
        ALTER TABLE api_keys ALTER COLUMN id TYPE TEXT USING id::text;
    END IF;

    -- 4) Convert acl_models.acl_id (FK) from UUID -> TEXT if needed
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'acl_models'
          AND column_name = 'acl_id'
          AND udt_name = 'uuid'
    ) THEN
        ALTER TABLE acl_models ALTER COLUMN acl_id TYPE TEXT USING acl_id::text;
    END IF;
END
$$;
