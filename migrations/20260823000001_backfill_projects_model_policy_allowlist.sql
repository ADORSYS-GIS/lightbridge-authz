-- ADR-0018 sequencing follow-up (owner-reported, in-session): `20260821000001_projects_model_policy`
-- defaulted EVERY project to `model_policy = 'allow_all'` -- correct at the time, since no code path
-- could yet write `allowlist` -- but #418 also shipped `modelPolicy` `@readonly`, so `allowlist`
-- stayed unreachable and any project with a real `allowed_models` list silently stopped being
-- restricted at the RPC layer. Confirmed empirically by the owner: a key scoped to
-- `allowed_models: [adorsys-frontend-pro, qwen3-5-2b-local]` completed against `minimax-m2p5` with
-- a 200. A stopgap now restores enforcement at the gateway
-- (ai-helm-values#295: https://github.com/ADORSYS-GIS/ai-helm-values/pull/295, merged and live) --
-- a non-empty `allowed_models` restricts regardless of stored `model_policy`. That stopgap is
-- explicitly temporary and contradicts ADR-0018 (policy should be authoritative, not
-- list-non-emptiness). This migration is what makes it SAFE to eventually remove: once the
-- stopgap is gone, an `allow_all` project reverts to unrestricted, so any project the owner
-- actually intends to restrict needs `model_policy = 'allowlist'` stored for real before that
-- day comes -- otherwise removing the stopgap is a silent widening of every such project's
-- allowed model set. Behaviourally this migration is a NO-OP today: while the stopgap is live,
-- `allow_all` + non-empty list and `allowlist` + non-empty list both restrict identically at the
-- gateway. It only matters at stopgap-removal time.
--
-- Deliberately untouched: `deny_all` rows (an operator's explicit "nothing allowed" is never
-- overwritten by a backfill) and already-`allowlist` rows (nothing to do, and re-touching would
-- make a re-run non-idempotent in spirit even though the WHERE clause already excludes them by
-- construction).
--
-- Stale catalogue ids inside some projects' `allowed_models` (e.g. the owner's own project
-- carries `qwen3p7-plus`/`qwen3-5-9b-local`, no longer in the model catalogue) are left exactly
-- as-is. Under `allowlist` a stale id is simply a non-matching entry -- harmless. #417's catalogue
-- validation only guards fresh writes (`setProjectAllowedModels`), not pre-existing rows, and
-- cleaning them up is converse-frontends#195 (merged), not this migration's job.
--
-- The stored encoding of `allowed_models` was verified against THIS database, not assumed, before
-- writing the WHERE clause below -- this repo has already shipped a bug from exactly that
-- assumption once (#282/#283, cratestack's tagged-`Value` era). Confirmed live:
--   * `StoreRepo::vec_to_json`/`json_to_vec` (crates/lightbridge-authz-api-key/src/repo.rs) map
--     `Some(vec)` to a PLAIN jsonb array via `serde_json::json!(v)` (untagged since
--     `20260814000001_untag_legacy_cratestack_value_json` ran) and `None` to SQL NULL, never the
--     jsonb `null` literal.
--   * `SELECT jsonb_typeof(allowed_models), model_policy, count(*) FROM projects GROUP BY 1,2`
--     against this database's live data shows FOUR shapes today, all `model_policy = 'allow_all'`
--     except the 3 `deny_all` rows: 651 SQL NULL, 72 plain `array` (36 of length 1, 36 of length 2
--     -- confirmed no length-0 arrays currently exist, but the WHERE clause still guards for one),
--     and -- notably -- 36 rows holding the jsonb `null` LITERAL, not SQL NULL. That third shape is
--     not hypothetical: it is live, current data (recent `created_at` timestamps), despite
--     `20260723000001_normalize_allowed_models_json_null` having already run against this same
--     database. Both SQL NULL and jsonb `null` mean "no restriction" per `json_to_vec` (`v.is_null()
--     => None`), so both must be excluded here.
--
-- The "guard `jsonb_array_length` behind `jsonb_typeof(...) = 'array'` using plain `AND`" version
-- of this predicate was actually tried first and FAILED the prove-fail-first migration test below
-- with `22023 cannot get array length of a scalar` on the jsonb-null-literal fixture row: Postgres
-- does not guarantee left-to-right short-circuit evaluation of `AND`-ed quals in a WHERE clause
-- (see the Postgres manual, "Expression Evaluation Rules") -- the planner is free to evaluate
-- `jsonb_array_length(allowed_models)` before `jsonb_typeof(allowed_models) = 'array'` has had a
-- chance to filter the row out, and it did, on real seeded data, not just in theory. A `CASE`
-- expression IS documented as evaluation-order-safe (each branch's condition is checked in order,
-- and only the matching branch's result expression is evaluated), so the length check below is
-- expressed as one CASE that maps every non-array shape (SQL NULL, the jsonb `null` literal, and
-- any other non-array jsonb value) to `0` without ever calling `jsonb_array_length` on it.
DO $$
DECLARE
    to_backfill INT;
    skipped_empty_or_null INT;
BEGIN
    SELECT COUNT(*) INTO to_backfill
      FROM projects
     WHERE model_policy = 'allow_all'
       AND (CASE WHEN jsonb_typeof(allowed_models) = 'array'
                 THEN jsonb_array_length(allowed_models)
                 ELSE 0
            END) > 0;

    SELECT COUNT(*) INTO skipped_empty_or_null
      FROM projects
     WHERE model_policy = 'allow_all'
       AND (CASE WHEN jsonb_typeof(allowed_models) = 'array'
                 THEN jsonb_array_length(allowed_models)
                 ELSE 0
            END) = 0;

    RAISE NOTICE 'ADR-0018 model_policy backfill: % project(s) with a non-empty allowed_models moving allow_all -> allowlist; % allow_all project(s) left untouched (NULL/jsonb-null/empty allowed_models, i.e. genuinely unrestricted)',
      to_backfill, skipped_empty_or_null;
END $$;

UPDATE projects
   SET model_policy = 'allowlist'
 WHERE model_policy = 'allow_all'
   AND (CASE WHEN jsonb_typeof(allowed_models) = 'array'
             THEN jsonb_array_length(allowed_models)
             ELSE 0
        END) > 0;
