-- Legacy projects created by the pre-cratestack app stored an empty `allowed_models` as the jsonb
-- `null` LITERAL (`'null'::jsonb`), not SQL NULL. cratestack decodes `allowedModels Json?` as sqlx
-- `Option<Json<Value>>`, which fails on the jsonb null literal with
-- `expected value at line 1 column 1` (reproduced in rpc_it_tests) -- so `model.Project.get`/`list`
-- 500 for every account that owns such a project. SQL NULL decodes cleanly to `None`, and both mean
-- "all models allowed" per the domain semantics, so normalize the literal to SQL NULL.
UPDATE projects
SET allowed_models = NULL
WHERE jsonb_typeof(allowed_models) = 'null';
