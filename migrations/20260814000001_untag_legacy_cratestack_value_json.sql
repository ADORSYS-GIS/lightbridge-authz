-- The cratestack lockstep bump (0.5.1 -> 0.7.16, PR closing the red-`main` breakage tracked in
-- the accompanying issue) changes how `cratestack_core::Value` persists/decodes `Json`-typed
-- columns. Through cratestack-pg 0.5.1 -- the version this service has run in production for its
-- entire history up to this migration -- `Value` used serde's externally-tagged representation
-- for BOTH persistence and the wire: an empty map was stored as `{"Map": {}}`, a string list as
-- `{"List": [{"String": "gpt-4"}, ...]}`, and so on. cratestack/cratestack#162 (landed 0.7.2)
-- moved column persistence to plain JSON via `cratestack_sqlx::Json<T>`, and
-- cratestack/cratestack#506 (landed 0.7.11) made `Value`'s own `Serialize`/`Deserialize` impl
-- untagged too, matching what #162 already persisted.
--
-- The untagged decoder does NOT error on an old tagged row -- it decodes the tag wrapper
-- literally as ordinary JSON content, silently. Verified empirically against a live 0.7.16
-- server (not just reasoned about): a project's `defaultLimits` seeded as the old tagged
-- `{"Map": {}}` now round-trips through `model.Project.get`/`list` as literally
-- `"defaultLimits": {"Map": {}}` instead of `{}`, and an `allowedModels` seeded as
-- `{"List": [{"String": "gpt-4"}, {"String": "gpt-3.5"}]}` now returns
-- `"allowedModels": {"List": [{"String": "gpt-4"}, {"String": "gpt-3.5"}]}` instead of
-- `["gpt-4", "gpt-3.5"]`. `projects.allowed_models` (`Json?`) and `projects.default_limits`
-- (`Json`, `NOT NULL`) are the only two `Json`-typed columns in `schema/authz.cstack` -- confirmed
-- via `grep -n '\bJson\b' crates/lightbridge-authz-api/schema/authz.cstack`, both on `Project`,
-- neither on `Account`/`ApiKey`/`ProjectMember`. Because every row was written by 0.5.1, this
-- affects every non-default row in both columns, not a rare legacy corner case -- ship this
-- migration in lockstep with the version bump, not as a follow-up.
--
-- `cratestack_untag_value` recursively strips one layer of external tagging at a time (a tagged
-- `Map`/`List` nests tagged children, e.g. `{"Map": {"k": {"Int": 5}}}`), and is deliberately
-- conservative: it only unwraps a JSON object that has EXACTLY ONE key matching one of
-- `cratestack_core::Value`'s own variant names (`Null`, `Bool`, `Int`, `Float`, `String`,
-- `Bytes`, `List`, `Map` -- confirmed against cratestack-core 0.5.2's `enum Value` definition,
-- the version this repo's production `cratestack-pg 0.5.1` pin resolves to). Anything else --
-- already-plain data (a no-op, so this migration is idempotent and safe to re-run), or a
-- genuinely ambiguous shape -- is left untouched rather than guessed at.
CREATE FUNCTION cratestack_untag_value(input jsonb) RETURNS jsonb AS $$
DECLARE
    tag_key text;
    inner_value jsonb;
    result jsonb;
    elem jsonb;
    map_key text;
    map_value jsonb;
BEGIN
    IF input IS NULL OR jsonb_typeof(input) = 'null' THEN
        RETURN input;
    END IF;

    IF jsonb_typeof(input) = 'object'
        AND (SELECT count(*) FROM jsonb_object_keys(input)) = 1 THEN
        SELECT key INTO tag_key FROM jsonb_object_keys(input) AS key LIMIT 1;
        inner_value := input -> tag_key;

        IF tag_key IN ('Null', 'Bool', 'Int', 'Float', 'String', 'Bytes') THEN
            RETURN inner_value;
        ELSIF tag_key = 'List' AND jsonb_typeof(inner_value) = 'array' THEN
            result := '[]'::jsonb;
            FOR elem IN SELECT * FROM jsonb_array_elements(inner_value) LOOP
                result := result || jsonb_build_array(cratestack_untag_value(elem));
            END LOOP;
            RETURN result;
        ELSIF tag_key = 'Map' AND jsonb_typeof(inner_value) = 'object' THEN
            result := '{}'::jsonb;
            FOR map_key, map_value IN SELECT key, value FROM jsonb_each(inner_value) LOOP
                result := result || jsonb_build_object(map_key, cratestack_untag_value(map_value));
            END LOOP;
            RETURN result;
        END IF;
    END IF;

    RETURN input;
END;
$$ LANGUAGE plpgsql;

UPDATE projects
SET allowed_models = cratestack_untag_value(allowed_models)
WHERE allowed_models IS NOT NULL;

UPDATE projects
SET default_limits = cratestack_untag_value(default_limits);

DROP FUNCTION cratestack_untag_value(jsonb);
