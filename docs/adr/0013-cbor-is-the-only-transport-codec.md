# ADR-0013: CBOR is the only transport codec for this platform's own RPC/CRUD surface

- Status: Accepted
- Date: 2026-08-17
- Decision owners: @stephane-segning
- Reverses (partially): ADR-0003's "CBOR in production, JSON in dev/CI" section — not the
  environment split as actually shipped (see Context: what ADR-0003 described was never what got
  built), but the underlying premise that this router should ever accept more than one wire format.

## Context

Two prod-only bugs, both invisible to a green CI, motivated this decision:

1. **`createProject` 500 from a CBOR `undefined`-vs-`null` codec drift.** `cborg`, the frontend's
   CBOR encoder (`converse-frontends/packages/authz-rpc/src/codec.ts`), encodes a JS `undefined`
   property value as the CBOR `undefined` simple value (`0xf7`) rather than omitting the key.
   `minicbor-serde`, the server's CBOR decoder, has no mapping from `undefined` into `Option<T>`,
   so any RPC input with an `undefined`-valued optional field failed to decode with a generic
   `invalid_argument` error. This reproduced on the CBOR path only. It has since been fixed —
   `crates/lightbridge-authz-rest/src/codec.rs`'s `LenientCborCodec` normalizes wire-level
   `undefined` to `null` before decoding, with both an isolated unit-test suite
   (`crates/lightbridge-authz-rest/tests/codec_undefined_regression_tests.rs`) and a live-router
   regression test
   (`cbor_project_create_accepts_the_frontends_undefined_allowed_models`,
   `crates/lightbridge-authz-rest/tests/rpc_it_tests.rs`). That fix is not undone by this ADR —
   `LenientCborCodec` remains the codec this ADR makes the *only* one.
2. **A live white-screen crash in the frontend's `OneTimeSecretCard`**
   (`TypeError: t?.trim is not a function`, prod-only), still under investigation as of this ADR.
   It lives in `converse-frontends`, outside this repository, and this ADR does not fix it —
   it is cited here only as a second, independent instance of the same failure class this
   decision closes off: a value arriving in a shape the CBOR path produces that the JSON path
   would not have.

Both bugs share one root cause: **more than one wire format existed for the same RPC surface, and
nothing forced the tested path to be the shipped path.**

**Correction to this ADR's original brief.** The brief that triggered this work assumed a
`server.api.codec` config key — set to `cbor` in production and `json` in dev/CI via
`config/default.yaml`/`.docker/authz/container.yaml`/`ai-helm-values` — that this ADR would need
to narrow to a single value, with a corresponding risk of breaking prod config parsing on the next
rollout. **No such key exists anywhere in this codebase.** `ApiServer`
(`crates/lightbridge-authz-core/src/config/mod.rs`) carries no `codec` field, `config/default.yaml`
and `.docker/authz/container.yaml` carry no `codec` key, and no Helm chart template references one.
ADR-0003's "CBOR in production, JSON in dev/CI" section *described* an environment-driven split as
the decision, but explicitly left the implementation mechanism open — "whether that is implemented
as two differently-constructed router instances... or one `CodecSet`-based router with an
environment-driven default/allowlist is an implementation detail for the cutover task to resolve."
What actually got built, and has stood since (`crates/lightbridge-authz-rest/src/lib.rs`, both
`build_api_router` and `build_budget_router`), is the second option minus the environment-driven
part: **one hardcoded `CodecSet<LenientCborCodec, JsonCodec>`, identical in every environment**,
dispatching on each request's literal `Content-Type` header. Prod's real client (the TS `cborg`
encoder) only ever sent CBOR; dev/CI *could* send either. There was never a config value to flip
and therefore nothing for this ADR to remove from `ai-helm-values` or any other prod config — this
was a pure code change, not a config-and-code change, and no coordinated `ai-helm-values` PR is
needed before or after this lands.

**The dual-codec router still let the tested path diverge from the shipped path — just not the
way ADR-0003 originally framed it.** Because the same router accepted both formats everywhere,
nothing about environment or config forced a test to exercise CBOR. In practice almost none did:
of this crate's RPC integration tests, the overwhelming majority (61 of ~90 `Wire`-parameterized
calls in `rpc_it_tests.rs` alone, before this ADR) used the JSON wire for convenience — `serde_json`
round-trips are easier to read and debug — leaving only a handful of dedicated tests exercising the
CBOR path at all. A future CBOR-only bug in a field or code path none of those dedicated tests
happened to cover would have shipped exactly the way the `createProject` bug did: invisible to a
green CI, because CI's own tests mostly weren't using the format prod's real client uses. Removing
JSON as an *option* — not just as a default — is what makes that structurally impossible: every
test that exercises the RPC surface now exercises the one and only format the router accepts.

## Decision

### 1. CBOR is the only wire format `authz-api`'s and `authz-budget`'s RPC routers accept

`crates/lightbridge-authz-rest/src/lib.rs`:

- `build_api_router` (the CRUD/RPC surface `authz-api` serves): `schema::axum::rpc_router(...)`'s
  codec argument changes from `CodecSet::new(LenientCborCodec::default(), JsonCodec)` to
  `LenientCborCodec::default()` alone.
- `build_budget_router` (the budget-domain RPC surface `authz-budget` serves, ADR-0010): the same
  change, same codec.

No `CodecSet` wrapper is needed to satisfy `rpc_router`'s transport bound with a single codec —
`cratestack-axum` (0.7.16, this workspace's pin) provides a blanket
`impl<C: CoolCodec> HttpTransport for C`, so any single `CoolCodec` implementor — here,
`LenientCborCodec` — already satisfies the bound directly. `LenientCborCodec` itself is unchanged:
it still exists specifically to normalize the `undefined`-vs-`null` drift (Context, bug 1) on top of
the raw `cratestack_codec_cbor::CborCodec`. `cratestack-codec-json` is dropped from
`crates/lightbridge-authz-rest`'s `[dependencies]` entirely — it is retained only as a
`[dev-dependencies]` entry, for the one legitimate remaining use: encoding a request that the test
suite expects the router to *reject* (Decision 4).

A request with any other `Content-Type` — including `application/json` — now gets
`415 Unsupported Media Type` before reaching dispatch (`cratestack_core::CoolError::UnsupportedMediaType`
→ `StatusCode::UNSUPPORTED_MEDIA_TYPE`), the same as it always would have for, say,
`application/xml`. A request asking for a non-CBOR `Accept` gets `406 Not Acceptable` instead, and
is checked *first* — `cratestack-axum`'s header validation validates `Accept` before
`Content-Type` — so a naive all-JSON request (both headers set to `application/json`, exactly what
`common::Wire::Json` produces) is actually refused with `406`, not `415`; see Decision 4 for both.
This is not a new error path; it is the existing "no encoder configured for this
Content-Type" behavior, now reached by one previously-accepted value.

### 2. Exact in-scope surface

Both routers this ADR touches are `cratestack::schema::axum::rpc_router` instances — the only two
call sites of `rpc_router` in this codebase (`crates/lightbridge-authz-rest/src/lib.rs:1696`,
`:2228`). This is the entirety of "this platform's own RPC/CRUD transport": the cratestack-generated
surface the frontend's generated client (`converse-frontends`) talks to.

### 3. Excluded surfaces, with the reason each is excluded

None of the following touch cratestack's codec machinery at all — verified by grepping for
`CodecSet`/`cratestack_codec_*`/`JsonCodec`/`CborCodec` across `crates/lightbridge-authz-rest/src/handlers/`,
`crates/lightbridge-authz-rest/src/routers/`, `crates/lightbridge-authz-usage/src/`, and
`app/lightbridge-authz/src/mcp.rs`: zero hits in all four. Each is excluded for a different, external
reason, not merely "not yet migrated":

- **`authz-opa`/Authorino endpoints** (`/v1/opa/validate`, `/v1/authorino/validate`,
  `/v1/authorino/validate/introspect`) — the wire format is dictated by Authorino, an external auth
  component this service does not control. These handlers (`crates/lightbridge-authz-rest/src/handlers/*`)
  are plain hand-written Axum/`serde_json` handlers and always have been; nothing here changes.
- **`lightbridge-authz-usage` OTLP ingest** (`/v1/otel/traces`, `/v1/otel/metrics`) — OTLP/HTTP is a
  spec'd protocol (protobuf-over-JSON per the OTLP spec's JSON encoding). Cannot be CBOR.
- **`lightbridge-mcp`** — MCP streamable HTTP (`rmcp`, `transport-streamable-http-server` feature,
  root `Cargo.toml`) is a spec'd protocol: JSON-RPC 2.0 requests/responses over
  `Content-Type: application/json` (with `text/event-stream` for the streaming leg). This is a
  different SDK and wire contract entirely, unrelated to cratestack. Confirmed no cratestack codec
  import anywhere in `app/lightbridge-authz/src/mcp.rs`.
- **Discovery/JWKS** (`/.well-known/openid-configuration`, `/.well-known/jwks.json`) **and the
  OAuth2 `/oauth2/token`/`/oauth2/revoke` endpoints**, on both `authz-api`
  (`build_api_router`'s calls to `well_known_router`/`token_exchange_router`) and the newer
  `authz-idp` (`build_idp_router`, ADR-0012) — RFC-mandated `application/json` (RFC 8414 §3.2 for
  discovery, RFC 7517 for JWKS, RFC 6749/8693 for the token endpoints). These routers
  (`crates/lightbridge-authz-rest/src/signing.rs`, `crates/lightbridge-authz-rest/src/token_exchange.rs`)
  use plain `axum::Json`, never cratestack's `rpc_router`/`HttpTransport`, and were never part of
  the dual-codec `CodecSet` this ADR removes. Changing their format would break every OIDC/OAuth2
  client (Keycloak, Authorino, any generic OIDC-discovery consumer) that expects RFC-standard JSON.

### 4. Test suite: CBOR-only, with one dedicated negative test proving the cutover

`crates/lightbridge-authz-rest/tests/`:

- `common/mod.rs`'s `Wire` enum keeps both variants, but their meaning changes: `Wire::Cbor` is now
  the only format any real request should use, and every call site across `rpc_it_tests.rs`,
  `rpc_router_tests.rs`, `budget_router_tests.rs`, and `budget_rpc_it_tests.rs` that previously
  defaulted to `Wire::Json` for readability now uses `Wire::Cbor`. `Wire::Json` is retained
  narrowly, as a negative-path probe: `rpc_it_tests.rs::json_content_type_is_rejected` proves two
  distinct rejections — `Wire::Json` sets both `Content-Type` and `Accept` to `application/json`,
  and cratestack-axum validates `Accept` first, so that combination is refused with
  `406 Not Acceptable` before the request codec is even consulted; a second, hand-built request
  (valid `Accept: application/cbor`, invalid `Content-Type: application/json`) isolates the
  request-codec half and gets `415 Unsupported Media Type`. Either assertion alone would catch a
  regression that accidentally re-widened the router back to a `CodecSet` on just one side
  (encoder or decoder); having both means neither can quietly reopen without a failing test —
  every other test in the suite would stay green even if JSON quietly started working again, since
  none of them send it.
- `rpc_it_tests.rs`'s `batch_rpc_frames_succeed_and_fail_independently` (a bare router built
  directly with a raw `CodecSet::new(CborCodec, JsonCodec)`, not via `build_api_router`) and
  `batch_rpc_frames_enforce_permission_per_frame` (against the real assembled router) both
  round-tripped their `/rpc/batch` request/response bodies through `serde_json` directly, with a
  literal `application/json` `Content-Type` — `/rpc/batch` dispatches through the same
  `HttpTransport`/codec machinery as any other op (`cratestack-axum`'s `rpc/batch.rs` calls
  `decode_rpc_body(codec, headers, &body_bytes)`), so it was never actually codec-agnostic; both
  now encode/decode via `CborCodec` and `application/cbor`.
- `json_body` (the shared response-decoding helper `create_account`/`create_project`/
  `create_api_key` and ~30 assertions call) switched from `serde_json::from_slice` to
  `Wire::Cbor.decode`, since every response it decodes is CBOR-encoded now.

### 5. `.docker/it/*.py` integration-test runners gain a hand-rolled CBOR codec

`authorino_it.py` and `servers_it.py` are plain `python:3.12-slim` containers
(`compose.it.yaml`) with no package-install step, and both call `authz-api`'s `/rpc/*` surface
directly (`createAccount`, `model.Project.create`, `createApiKey`). Rather than adding a `pip
install` step — a network dependency and version-drift risk this repo's own house rules already
flag for release/CI pipelines — `.docker/it/cbor_min.py` hand-rolls exactly the CBOR (RFC 8949)
subset these two scripts' request/response shapes need: maps with string keys, arrays, strings,
booleans, null, and integers, both encode and decode. It is mounted read-only into both containers
(`compose.it.yaml`) and validated against RFC 8949 Appendix A's test vectors. Each script gained a
`request_rpc` helper (mirroring the existing `request_json`) that only the three `/rpc/*` call
sites use; every other call in both scripts (health probes, Keycloak, OPA's form-encoded
introspect, the usage query API, MCP) is untouched, since none of it goes through cratestack's
codec. One 401-before-dispatch probe in each script (`model.Account.list`/`/rpc/batch` with no
bearer) deliberately keeps a JSON-shaped body — the RBAC gate rejects it before the codec is ever
consulted (it is the outermost layer, see `build_api_router`'s doc comment), so which format the
probe body happens to be in is immaterial to what it tests.

### 6. No frontend (`converse-frontends`) change is required

The TS client's RPC codec (`converse-frontends/packages/authz-rpc/src/codec.ts`) already emits CBOR
exclusively via `cborg` — that is the only reason bug 1 in Context reproduced in prod at all: the
frontend was never sending JSON to begin with, only CBOR, and the `undefined`-vs-`null` drift is a
property of the frontend's *existing* CBOR encoder. Removing the JSON secondary codec removes a
capability the frontend never used, not one it depends on.

## Consequences

### Positive

- Removes the entire bug class Context describes: a CBOR-only defect can no longer hide behind a
  green CI that mostly tested JSON, because CBOR is now the only format any test — Rust or Python —
  is capable of sending to this surface.
- Dev/CI and prod are now provably identical on this axis, with no config or environment branch to
  drift apart in the first place — there was never a "flip a value back" risk to design around,
  because the divergence was in test-authoring convention, not configuration.
- One fewer dependency shipped in `authz-api`'s/`authz-budget`'s production binaries
  (`cratestack-codec-json` moves to `[dev-dependencies]` only).
- `json_content_type_is_rejected` gives the cutover itself a regression test, not just a one-time
  code change — a future accidental re-widening back to a `CodecSet` fails a test instead of
  silently reopening the gap.

### Negative

- `.docker/it/cbor_min.py` is new, hand-maintained parsing/encoding logic outside the Rust
  workspace, in a language with no compiler or type system to catch a future encoding mistake —
  mitigated by pinning its coverage to exactly the RFC 8949 test vectors it needs and keeping it
  intentionally narrow (no tags, no bignums, no byte-string decoding beyond passthrough) rather than
  a general-purpose library reimplementation.
- Any future legitimate need for a second wire format on this surface (unlikely, but not
  structurally impossible — e.g. a future public/partner API with different client constraints)
  would need its own ADR to reopen this decision, not a quiet config flip, since there is no longer
  a mechanism to add one without code review of exactly that change.

### Neutral / follow-ups

- `docs/adr/0003-cratestack-crud-migration.md`'s "CBOR in production, JSON in dev/CI" section is
  historical record of a decision this ADR reverses — left unedited, not rewritten, per this repo's
  ADR convention of a superseding record rather than an edited one.
- `CLAUDE.md`'s `server.api.codec` config-key reference is corrected as part of this change (it
  described a key that, per Context, never existed) — see the accompanying stanza update.

## Alternatives considered

- **Flip the default from CBOR to JSON instead of removing JSON** — rejected outright; exactly
  backwards from the goal. Prod already runs CBOR via its real client; defaulting *tests* to JSON
  is the status quo this ADR exists to end, not preserve under a different label.
- **Keep both codecs, add a lint/convention requiring new tests to use `Wire::Cbor`** — rejected.
  A convention is not enforced the way a removed capability is; this repo's own delivery doctrine is
  a hard cutover over a soft one, and "requires everyone to remember" is exactly the kind of gap
  that produced the two bugs in Context in the first place.
- **Add a `server.api.codec` config key now, defaulting to `cbor` everywhere, as a documented
  single-value enum** — rejected as unnecessary ceremony. There is nothing left to configure once
  there is only one valid value; a config key with one legal value is a key that exists only to be
  misremembered as configurable.

## Related

- ADR-0003 (cratestack CRUD migration) — introduced the dual-codec `CodecSet` mechanism and the
  "CBOR in production, JSON in dev/CI" framing this ADR reverses; see Context for exactly what
  ADR-0003 specified versus what was actually built.
- ADR-0010 (budget domain uses procedures, not cratestack models) — `build_budget_router` shares
  the same `rpc_router`/codec plumbing `build_api_router` does, which is why this ADR touches both.
- ADR-0012 (device authorization grant via `authz-idp`) — `authz-idp`'s `build_idp_router`, an
  excluded surface (Decision 3), is the newer of the two RFC-mandated-JSON routers this ADR leaves
  untouched.
