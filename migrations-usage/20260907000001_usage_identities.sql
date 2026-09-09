-- usage_identities: PII-isolated identity references for the usage store's grain tables.
--
-- ADR-0038 persistence exception, same class as `secret_claims` and the other recorded
-- exceptions in this repo: identity fields must be JOINED, not embedded, so a single UPDATE
-- erases a person's PII everywhere at once (ADR-0028 D7). Generated CRUD cannot express a
-- side table whose whole purpose is to be referenced by hand-written grain tables that live
-- outside the cratestack model path -- the usage DB is already hand-written SQL (see
-- `usage_events`), and this table is a prerequisite for the execution grain (#582).
--
-- `subject_id` is the opaque identity value, or a literal sentinel like
-- `missing:<source>:<claim>` / `unstamped:<field>` when the source did not assert one.
-- Sentinels are stored as literal values, never NULL -- "no identity was asserted" is a
-- distinct fact from "an identity exists but is unknown".
--
-- Mint/dedup/erasure protocol (implemented by the ingest PR; documented here so it is not
-- guessed):
--   * `id` is minted via the `cuid2()` chokepoint (ADR-0039).
--   * dedup is `ON CONFLICT (source, subject_kind, subject_id) DO NOTHING` -- the natural key
--     is the (source, subject_kind, subject_id) triple, so re-asserting the same identity
--     reuses the existing row instead of minting a duplicate.
--   * erasure is a single `UPDATE usage_identities SET subject_id = 'erased:' || id WHERE id = $1`:
--     every grain table that references this row BY ID (a real `identity_id` FK, e.g.
--     `usage_executions.identity_id` in #582) has its PII removed by that one UPDATE
--     (ADR-0028 D7). The sentinel embeds the row's own id (`erased:<id>`) so it is unique per
--     row: a constant sentinel (e.g. `'erased'`) would collide with the
--     UNIQUE (source, subject_kind, subject_id) natural key the moment a second identity of the
--     same (source, subject_kind) is erased, failing the UPDATE with 23505. After erasure the
--     row no longer matches the original natural key, so a later re-assertion of the same
--     identity mints a fresh row.
--   * this guarantee covers ONLY tables that carry an `identity_id` FK into this table. A grain
--     table that instead embeds a provider-scoped identifier directly as its own TEXT column
--     (matched by value, not by FK -- e.g. `usage_day_facts`/`usage_seat_snapshots`'s
--     `provider_user_id` from #583) is NOT touched by this UPDATE: the raw value stays in that
--     table's rows regardless of what happens here. Before relying on "erase once, gone
--     everywhere" for the whole usage store, confirm every PII-bearing grain table actually
--     joins through `identity_id` -- a table that doesn't needs its own erasure path.
CREATE TABLE usage_identities (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, subject_kind, subject_id)
);
