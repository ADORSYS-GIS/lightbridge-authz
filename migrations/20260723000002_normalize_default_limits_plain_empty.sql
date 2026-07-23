-- Legacy projects (pre-cratestack) stored an empty `default_limits` as plain JSON `{}`. cratestack's
-- Json columns persist/expect its externally-tagged `Value` form -- an empty map is `{"Map": {}}`
-- (verified against a cratestack-written row) -- so a plain `{}` fails to decode with
-- `expected value at line 1 column 2`, 500-ing every `model.Project.list`/`get` for every account.
--
-- `default_limits` is NOT NULL (unlike `allowed_models`), so we can't normalize to SQL NULL; instead
-- rewrite the plain empty object into cratestack's tagged empty map, which decodes to an empty
-- limits map (== "no default limits"). The `= '{}'::jsonb` predicate matches ONLY the plain legacy
-- rows, never cratestack's already-correct `{"Map": {}}`.
UPDATE projects SET default_limits = '{"Map": {}}'::jsonb WHERE default_limits = '{}'::jsonb;
