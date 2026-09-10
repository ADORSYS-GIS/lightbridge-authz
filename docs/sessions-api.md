# Sessions API — `querySessions` and `revokeSession`

ADR-0020 Follow-up 4 (lightbridge-authz#649). Two RPC procedures on `authz-api` (`RpcScope::Crud`)
that make the `sessions` table readable and let one session be closed on its own, instead of only
"all of mine" (`revokeOwnSessions`) or "all of theirs" (`revokeSubjectSessions`), which are
unchanged.

- Schema: `crates/lightbridge-authz-api/schema/authz.cstack` (the `Session` model's
  `@@allow("read", ...)` clause and the two procedures at the end of the file)
- Handlers: `crates/lightbridge-authz-rest/src/session_directory.rs`, helpers in
  `session_query.rs`
- Queries: `crates/lightbridge-authz-api-key/src/session_listing.rs`,
  `session_revocation.rs`
- Permission table: `docs/rbac.md`

> **The name.** It is `querySessions`, not `listSessions`, which is what #649 and its console
> consumer both call it. cratestack emits `handle_list_sessions` for the generic
> `model.Session.list` verb, so a procedure named `listSessions` is a hard `E0428` at codegen time.
> Every other name in the story survives verbatim.

## `querySessions`

```
querySessions({
  status?:    "active" | "revoked" | "expired" | "all",   // default "active"
  kind?:      "token" | "browser",
  accountId?: string,
  subject?:   string,
  clientId?:  string,
  after?:     string,   // opaque; pass back `next` verbatim
  limit?:     number,   // default 25, clamped to 100
}) -> { rows: SessionRow[], next: string | null }
```

`SessionRow` is every `sessions` column plus three derived fields:

| Field | Meaning |
| --- | --- |
| `status` | The **computed** status (ADR-0020 Decision 6). Stored `active` + past `expiresAt` reads `"expired"`; a revoked row reads `"revoked"` even when it is also past expiry, because revocation is the operator-visible act and expiry is just time passing. |
| `expired` | The clock fact on its own, independent of `status`, so a client never re-derives it from a clock it does not share with the server. |
| `subjectUserId` | `accounts.user_id` for the account named by `subject` — the PERSON (ADR-0026: one identity may own many accounts, so the account id is not the identity). `null` when `subject` is null or names no account. Feed it to `resolveUserProfiles` (#647) for a label; nothing here fabricates one. |
| `clientId` | The OAuth client (`azp`). Always set for `kind = "token"`. For `kind = "browser"` it is the client whose `/authorize` request STARTED the login — provenance, not scope: a browser session is still reusable by every client (ADR-0021 Decision 3, amended 2026-09-03). `null` only for a browser row minted before `migrations/20260903000001_sessions_browser_client_id.sql`; no backfill is possible, so a client renders its own sentinel rather than guessing. |
| `offline` | The session's refresh chain carries the `offline_access` scope — the discriminator for a CLI/device login (OIDC Core §11: access that outlives the end-user's browser session) versus a browser one. Derived from the chain's stored `scope`, matched as a whole space-delimited word. No chain, no `scope` recorded, or a lookalike scope such as `offline_access_readonly` all read `false`. |

**Ordering and paging.** `ORDER BY created_at DESC, id DESC`, cursor `(created_at, id) <
(cursor_created_at, cursor_id)`. The `id` half is a **tiebreak, never a sort key**: ADR-0039 forbids
ordering by a CUID2 because it encodes no time. `created_at` remains the only ordering that means
anything; `id` exists so two sessions minted in the same microsecond have a total order and cannot
be skipped or repeated across a page boundary. A short page is the final page; a full page always
carries a `next`. A malformed `after` is a `400`, not an ignored filter — silently serving page 1
would look like a paginator that loops forever. Backed by `idx_sessions_created_at_id` and
`idx_sessions_subject` (`migrations/20260902000005_sessions_listing_indexes.sql`).

**An unrecognised `status` is rejected**, never widened to `all`. Widening a filter on a typo is how
a sensitive list leaks.

## `revokeSession`

```
revokeSession({ id: string, reason?: string }) -> { revoked: boolean }
```

`revoked` reports whether **this call** changed state, not whether the session is now revoked — a
second call on an already-revoked session succeeds with `revoked: false`, the same shape
`revokeSubjectSessions` uses when it answers `revokedCount: 0`. `reason` is accepted for the audit
trail and is not persisted anywhere today (there is no session-revocation audit table, unlike the
budget ledger); stated rather than quietly dropped.

The write is one transaction with two statements, the same pair `revoke_sessions_and_cascade` and
`revoke_for_logout` use, keyed on the session id instead of on `subject`: flip `sessions.status` to
`revoked`, then revoke every still-active `exchange_refresh_tokens` row chained under that session.
The second statement is not optional — a revoked session whose chain is still active leaves a
working refresh token for a session that is gone, which is the hole ADR-0020 Decision 9's cascade
requirement closes.

## Where authorization happens

Both procedures are gated at the **self-service** permission in `rpc_authorize.rs`
(`session:read-own` / `session:revoke-own`), which every default role holds. That is the floor to
call them; the widening to other people's sessions is decided per row, and the two place it
differently for a structural reason.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller (console)
    participant G as rpc_authorize<br/>(coarse RBAC gate)
    participant P as cratestack policy<br/>(Session @@allow "read")
    participant D as Postgres
    participant R as StoreRepo<br/>(session_listing.rs)

    Note over C,G: querySessions — scoping is the SCHEMA's job
    C->>G: POST /rpc/procedure.querySessions {status, subject, after, limit}
    alt lacks session:read-own
        G-->>C: 403 permission_denied
    else
        G->>P: dispatch, auth ctx carries permSessionRead / permSessionReadOwn
        P->>D: SELECT ... FROM sessions WHERE <filters><br/>AND (permSessionRead OR subject = auth.id)
        Note right of P: the policy is folded INTO the WHERE clause,<br/>so an own-scope caller asking for<br/>subject=<someone else> intersects to zero rows
        D-->>P: page (limit rows, created_at DESC, id DESC)
        P->>R: session_listing_facts([ids just released])
        R->>D: subject -> accounts.user_id, EXISTS(chain scope ~ offline_access)
        D-->>R: subjectUserId, offline
        R-->>C: 200 {rows: SessionRow[], next}
    end

    Note over C,D: revokeSession — the own-vs-other check CANNOT be in the schema
    C->>G: POST /rpc/procedure.revokeSession {id, reason?}
    alt lacks session:revoke-own
        G-->>C: 403 permission_denied
    else
        G->>R: find_session_owner(id)
        R->>D: SELECT subject, status FROM sessions WHERE id = $1
        alt no such row
            R-->>C: 404 not found
        else subject != caller AND lacks session:revoke
            R-->>C: 403 forbidden
        else
            R->>D: BEGIN; UPDATE sessions SET status='revoked' WHERE id AND active;<br/>UPDATE exchange_refresh_tokens SET status='revoked' WHERE session_id AND active; COMMIT
            D-->>R: rows_affected
            R-->>C: 200 {revoked: rows_affected > 0}
        end
    end
```

Why the asymmetry: `Session` has an `@@allow("read", ...)` clause and deliberately no
`@@allow("update", ...)`. Adding an update policy would light up the generic `model.Session.update`
verb — a way to flip a revoked session back to `active` — and a procedure-level `@allow` clause can
only see `auth()`, never the row a caller-supplied id names. So the read's scoping is
unbypassable-by-construction, and the revoke's is an explicit, tested handler check.

Every generic `model.Session.*` verb stays denied unconditionally: none of them appears in
`MAPPED_OP_ID_PERMISSIONS`, and an op-id that map does not list is refused before dispatch, on both
the unary and `/rpc/batch` paths.

## The session lifecycle these two procedures observe and drive

```mermaid
stateDiagram-v2
    [*] --> active: token-exchange / device / authorization-code grant<br/>(oauth2_op/store.rs::create_session)

    active --> revoked: revokeSession(id)<br/>revokeOwnSessions() · revokeSubjectSessions(accountId)<br/>revoke_for_logout (/oauth2/end_session)
    active --> expired: expires_at passes<br/>(computed at read time — NOTHING writes this)

    revoked --> revoked: revokeSession(id) again<br/>idempotent, returns revoked=false

    expired --> revoked: revokeSession(id)<br/>still allowed; the row was never<br/>"expired" in the database, only "active"

    revoked --> [*]: retained; no reaper yet (ADR-0020 Follow-up 7)
    expired --> [*]: retained; no reaper yet

    note right of expired
        Not a stored value. `sessions.status` only ever
        holds "active" or "revoked"; `expired` is
        (status = 'active' AND expires_at <= now()).
        querySessions selects on that rule and reports
        it with the same clock, so a page can never
        contain a row that contradicts its own filter.
    end note

    note left of revoked
        There is no edge back to `active`, from any
        procedure or generic verb: `Session` carries no
        @@allow("update", ...) and `model.Session.update`
        is denied unconditionally. Revocation is terminal.
    end note
```

The two states nothing can reach are the point of the diagram: there is no transition **into**
`active` other than session creation, and none **out of** `revoked`. `offline` is not a state — it
is a property of the refresh chain hanging off a session, which is why revoking a session has to
revoke that chain in the same transaction rather than leaving a live token behind an ended session.

## Verification

DB-backed, `crates/lightbridge-authz-rest/tests/rpc_it_tests.rs` (feature `it-tests`):
`query_sessions_as_admin_returns_other_subjects_rows`,
`query_sessions_own_scope_cannot_reach_another_subject_with_any_filter`,
`query_sessions_computes_expired_status_and_selects_on_it`,
`query_sessions_pages_deterministically_including_across_a_created_at_tie`,
`query_sessions_derives_offline_from_the_refresh_chain_scope`,
`query_sessions_resolves_the_subjects_owning_user`,
`revoke_session_closes_one_session_and_its_chain_idempotently`,
`revoke_session_refuses_another_subjects_session_without_session_revoke`. Gate coverage (no DB) in
`rpc_router_tests.rs`; pure helpers in `session_query_tests.rs`.
