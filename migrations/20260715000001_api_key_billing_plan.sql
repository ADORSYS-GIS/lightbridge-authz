-- Each API key now carries its own billing plan, chosen at creation time from the
-- operator-configured (env-driven) plan set. Existing keys inherit their project's plan so the
-- column can be made NOT NULL without data loss.
ALTER TABLE api_keys ADD COLUMN billing_plan TEXT;

UPDATE api_keys
SET billing_plan = projects.billing_plan
FROM projects
WHERE projects.id = api_keys.project_id;

ALTER TABLE api_keys ALTER COLUMN billing_plan SET NOT NULL;
