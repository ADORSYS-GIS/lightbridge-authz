-- Rollback: convert TEXT columns back to UUID
-- WARNING: This will fail if the text values are not valid UUIDs.
-- The migration will drop relevant FK constraints (if present), convert types, and recreate FK constraints using the original names if possible.

DO $$
BEGIN
    -- Drop foreign key constraints referencing acls(id) to allow type change
    ALTER TABLE IF EXISTS api_keys DROP CONSTRAINT IF EXISTS fk_acl;
    ALTER TABLE IF EXISTS acl_models DROP CONSTRAINT IF EXISTS fk_acl_model;

    -- 1) Convert api_keys.acl_id from TEXT -> UUID if currently TEXT
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'api_keys'
          AND column_name = 'acl_id'
          AND udt_name = 'text'
    ) THEN
        ALTER TABLE api_keys ALTER COLUMN acl_id TYPE uuid USING (acl_id::uuid);
    END IF;

    -- 2) Convert api_keys.id from TEXT -> UUID if currently TEXT
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'api_keys'
          AND column_name = 'id'
          AND udt_name = 'text'
    ) THEN
        ALTER TABLE api_keys ALTER COLUMN id TYPE uuid USING (id::uuid);
    END IF;

    -- 3) Convert acl_models.acl_id from TEXT -> UUID if currently TEXT
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'acl_models'
          AND column_name = 'acl_id'
          AND udt_name = 'text'
    ) THEN
        ALTER TABLE acl_models ALTER COLUMN acl_id TYPE uuid USING (acl_id::uuid);
    END IF;

    -- 4) Convert acls.id from TEXT -> UUID if currently TEXT (parent last to keep referential integrity on recreate)
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'acls'
          AND column_name = 'id'
          AND udt_name = 'text'
    ) THEN
        ALTER TABLE acls ALTER COLUMN id TYPE uuid USING (id::uuid);
    END IF;

    -- Recreate foreign key constraints if tables/columns exist
    -- Using the original constraint names that were used in initial schema (if present).
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'api_keys')
       AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'acls')
    THEN
        BEGIN
            ALTER TABLE api_keys
              ADD CONSTRAINT fk_acl FOREIGN KEY (acl_id) REFERENCES acls(id) ON DELETE CASCADE;
        EXCEPTION WHEN duplicate_object THEN
            -- Constraint already exists, ignore
            NULL;
        END;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'acl_models')
       AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'acls')
    THEN
        BEGIN
            ALTER TABLE acl_models
              ADD CONSTRAINT fk_acl_model FOREIGN KEY (acl_id) REFERENCES acls(id) ON DELETE CASCADE;
        EXCEPTION WHEN duplicate_object THEN
            NULL;
        END;
    END IF;
END
$$;
