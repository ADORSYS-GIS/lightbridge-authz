-- Add user_id column to api_keys
ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT '';

-- Remove default so future inserts must provide value explicitly
ALTER TABLE api_keys ALTER COLUMN user_id DROP DEFAULT;
