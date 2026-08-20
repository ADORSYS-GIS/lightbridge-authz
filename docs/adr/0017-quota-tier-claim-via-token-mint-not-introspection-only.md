# ADR-0017: `quota_tier` is also stamped at token-mint time for the human/OIDC plane, carving out one claim from ADR-0011 Decision 7

- Status: Accepted
- Date: 2026-08-20
- Decision owners: Stephane Segning Lambou
- Supersedes (partially): ADR-0011's Decision 7 ("The id_token is not a second home for
  authorization data ... `project_quota`, `role`, and `quota_tier` ride on the introspection
  response ... Role/quota data stays out of **both** JWTs"). This ADR narrows that statement to
  `project_quota`/`role` only. Decision 7's general principle — this service asserts nothing beyond
  what upstream told us, and does not invent a second home for data that already has one — is
  **unaffected and remains in force**; see Decision 1 and "Alternatives considered" below for
  exactly why `quota_tier` earns the one carve-out and `project_quota`/`role` do not.

## Context

Issue #385: `ai-helm-values/environments/prod/values/security-policies.yaml` derives the
`x-quota-tier` gateway header on the human/OIDC plane with

```
has(auth.identity.quota_tier) ? string(auth.identity.quota_tier) : ""
```

No code path in `lightbridge-authz` has ever put a `quota_tier` claim on a human-plane token —
ADR-0011 Decision 7 deliberately kept it introspection-only, and the human/OIDC plane never calls
introspection (`docs/governance-model-and-enforcement.md` §4.7: "there is no `api_key_id`", the
condition introspection's own CEL predicate gates on). So `has(auth.identity.quota_tier)` evaluates
`false` for every human request, unconditionally, and `x-quota-tier` has been an accidental,
permanent `""` since the CEL first shipped — not a deliberate "tier rules don't apply here yet"
signal. Not currently exploitable (an empty `x-quota-tier` falls through to the safe plan-level
fallback, `docs/governance-model-and-enforcement.md` §4.8), but a governance gap: a rule authored
against this CEL, believing the claim already exists, would silently never fire, and nobody would
notice because the fallback is itself safe. The issue's Expected Behavior gave two directions;
**this ADR takes the first**: stamp a real claim, rather than weakening the CEL/docs to admit the
gap is permanent.

**ADR-0014 already set the precedent for exactly this bug class, one axis over.** `budget_tier`
had the identical shape — a CEL expression (`has(auth.identity.budget_tier)`) shipped assuming a
claim that no code minted — and ADR-0014's fix was to stamp it at token-exchange/refresh mint time,
resolved live from its source of truth (the budget ledger), rather than reintroducing a Keycloak
write-back dependency or building per-request introspection for a plane that structurally lacks it
(ADR-0014's own "Alternatives considered" rejects both, for reasons that apply identically here —
see this ADR's own Alternatives section). `TokenExchangeOpStore` — the same store, same file,
`crates/lightbridge-authz-rest/src/oauth2_op/store.rs` — is already the token-issuing authority for
the human/OIDC plane (ADR-0011) and already resolves tenant context (`account_id`/`project_id`) on
every exchange and refresh via `StoreRepo::resolve_context`. Resolving `quota_tier` in the same call
adds no new dependency: `project_members` is a table this store's own `resolve_context` query
already joins against (`EXISTS (SELECT 1 FROM project_members pm WHERE ...)`), on the same Postgres
pool, in the same request.

**Why ADR-0011 Decision 7 grouped `quota_tier` with `project_quota`/`role` in the first place, and
why that grouping no longer holds for `quota_tier` specifically:** Decision 7's stated reason for
keeping all three off the token was `docs/governance-model-and-enforcement.md`'s "Why introspection
and not claims" — "a quota or roster change takes effect within 30 seconds [via introspection's
30s cache], rather than waiting for the key to be rotated. Claims freeze at mint time." That
argument presupposes introspection is actually reachable as the faster, live alternative. It is,
for the API-key plane. It is **not**, and never has been, for the human/OIDC plane — introspection
does not run there at all (§4.7). So the propagation-latency argument that justifies keeping
`project_quota`/`role` off the human-plane token (there is a real live alternative, and claims would
be strictly worse) does not apply to `quota_tier` on that same plane (there is no live alternative
at all — the claim is the only mechanism this plane could ever have). `project_quota`/`role` keep
the introspection-only treatment because, for them, a live path genuinely exists elsewhere (the
API-key plane) and adding claims would only add a second, staler source of the same fact for no
platform that lacks the live path already accepts silently missing data instead. `quota_tier` is
different in exactly one respect: the human plane has no live path at all today, so "off both JWTs"
does not trade against a faster mechanism — it trades against no mechanism, i.e. the permanent gap
this issue reports.

## Decision

### 1. `quota_tier` is stamped as an access-token `extra` claim at token-exchange/refresh mint time, resolved live from `project_members`

`TokenExchangeOpStore::resolve_quota_tier` (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs`)
calls the new `StoreRepo::project_member_quota_tier(project_id, subject)`
(`crates/lightbridge-authz-api-key/src/repo.rs`) — `SELECT quota_tier FROM project_members WHERE
project_id = $1 AND account_id = $2` — keyed on the **acting subject**, not the project's owning
account, mirroring exactly how the API-key plane's `api_key_validation` view already joins
`project_members` on `owner_account_id` rather than the project owner
(`migrations/20260731000001_api_keys_owner_account.sql`). Both `handle_token_exchange` and
`handle_refresh_token` call it identically and re-resolve on every refresh rather than copying the
previous token's claim forward — the same "re-resolve, don't carry over" shape ADR-0014 established
for `budget_tier` on the same two call sites, for the same reason: a lead's tier edit should reach
the client at its next natural refresh, not persist stale until re-login.

The claim is inserted into the same `access_extra: HashMap<String, Value>` map `access_token_extra`
already builds, immediately before `TokenManager::issue_user_token_with_extra` signs the token —
placed alongside, not inside, `access_token_extra` itself, the same way ADR-0014 added
`budget_tier`: that function is shared with the plain self-signed API-key JWT path
(`ApiKeyJwtSigner::sign`), and `quota_tier` must not reach that path — the API-key plane's
`quota_tier` already works, via introspection, and is explicitly out of scope for this ADR (issue
#385's own "Out of Scope"). `signing.rs`'s `claims_supported` discovery-document list gains
`quota_tier` alongside the `budget_tier` entry ADR-0014 already added, for the same "advertise what
we actually serve" reason.

### 2. Three distinct resolution outcomes, and the wire MUST NOT collapse two of them into the same value

`project_members.quota_tier` being legitimately `NULL` is not new: the `api_key_validation` view's
own migration comment already documents it for the API-key plane — "the project's owning account
normally holds NO `project_members` row ... an owner's tier is legitimately NULL. NULL means 'no
per-member ceiling'." The human plane inherits the identical semantics, and this ADR is explicit
about keeping three outcomes distinct, because collapsing the third into the second is exactly the
failure mode issue #385 warns against ("an unresolvable or missing tier must not silently grant a
more permissive envelope than intended"):

1. **Resolved, tier present** — `project_member_quota_tier` returns `Ok(Some(tier))`. Stamped
   verbatim.
2. **Resolved, tier legitimately absent** — `Ok(None)`: either no `project_members` row at all (the
   common case for a project's owning account, or a person who was never added to the roster), or a
   row whose `quota_tier` column is `NULL`. This is a **known, resolved answer** — "no per-member
   ceiling, bounded by the pooled `projects.project_quota` alone" — not a failure. The claim is
   **omitted** from the token entirely. On the wire this is indistinguishable from "the claim was
   never implemented" (`has(auth.identity.quota_tier)` is `false` either way) — which is
   deliberate and safe: it is the exact same absence the existing CEL already treats as "no rule
   applies, fall through to plan-level limits" (`docs/governance-model-and-enforcement.md` §4.8),
   and that fallback is the documented-safe behavior this ADR must not disturb for every account
   that genuinely has no per-member tier (i.e., every account today — see §5's "tier and envelope
   rules are not configured").
3. **Could not resolve** — `project_member_quota_tier` returns `Err(_)` (e.g. the database is
   unreachable, or the specific query fails independently of `resolve_context`'s own success).
   This is **unknown**, not "no ceiling", and per this repository's fail-closed doctrine unknown
   must route to the strictest branch available. **The token-exchange/refresh grant is refused
   outright** (`oauth_err("server_error", ...)`) — no token is minted, so no `quota_tier` value of
   any kind (real, absent, or a sentinel) ever reaches the wire for that request. This is the
   distinguishing mechanism between outcomes 2 and 3: outcome 2 always produces a token (with the
   claim omitted); outcome 3 never produces a token at all. A CEL evaluated against a token that
   was never issued cannot observe "no ceiling" for that request, so there is no path by which a
   database outage is representable as a quota bypass.

This is a deliberate divergence from `resolve_budget_tier`'s shape (Decision 3 explains why) and is
the crux this ADR exists to get right — see `StoreRepo::project_member_quota_tier`'s and
`TokenExchangeOpStore::resolve_quota_tier`'s doc comments for the same argument made at the code
site, and `crates/lightbridge-authz-rest/tests/token_exchange_tests.rs` for the prove-fail-first
tests asserting refusal (not a permissive default) on a `project_members` lookup failure.

### 3. Deliberately NOT the same fail-closed shape as `budget_tier` (ADR-0014) — refuse, don't float to a floor

ADR-0014's `resolve_budget_tier` downgrades any lookup failure to
`PolicyEngine::fail_closed_floor_micros()` rather than failing the mint, because `budget_tier` has a
well-ordered ladder (`BudgetTier`, `B15` through `B1000`) with a defined, policy-configurable "most
conservative rung" to fall back to. `quota_tier` has no such structure: `QuotaTiers` is an
operator-defined, **unordered** catalogue of opaque tier ids (`crates/lightbridge-authz-core/src/config/mod.rs`)
with no notion of "the strictest configured tier" this service could reach for. Inventing an
ordering (e.g. "alphabetically first tier id") to manufacture a floor would be arbitrary and
actively misleading — it would imply a severity relationship between tier ids that does not exist
in the data model. Stamping a non-matching sentinel string (e.g. `"unresolved"`) was also considered
and rejected: with no gateway rule configured today (§5), a sentinel that matches no `Exact`
selector falls through to the exact same plan-level fallback as an omitted claim — it would not
actually be stricter than outcome 2 above, only harder to read, and would require coordinated
`ai-helm-values` CEL changes (recognizing and specially handling the sentinel) that are out of this
ADR's scope and not yet justified by any configured rule. Refusing the mint is the only option that
is unconditionally correct today, requires no gateway-side change to be safe, and costs nothing
extra beyond `resolve_context`'s own database dependency, which the exchange/refresh grant already
has and already refuses on failure (`Err(_) => oauth_err("server_error", "context resolution
failed")` a few lines above every call site of `resolve_quota_tier`) — this only extends the same,
already-established refusal rule to one more query against the same table.

## Consequences

**Positive**

- Closes the gap issue #385 reports: `x-quota-tier` on the human plane is no longer an accidental,
  permanent `""` — it reflects a real resolution once a gateway rule is eventually configured
  (§5, unchanged scope), the same way ADR-0014 made `x-budget-tier` real ahead of its own
  gateway-side rule authoring (`ai-helm#877`).
- No new outbound dependency and no new failure mode: the query runs against the same Postgres pool
  `resolve_context` already depends on, in the same request.
- The three-way outcome split (Decision 2) is a stricter, more carefully argued fail-closed
  treatment than ADR-0014's own `budget_tier` claim — because unlike `budget_tier`, `quota_tier` has
  no safe intermediate "floor" to fall back to, refusing the mint is the only choice that cannot
  become a bypass, and this ADR states that explicitly rather than reusing ADR-0014's shape by
  rote.

**Negative**

- A `project_members` query failure that is somehow independent of `resolve_context`'s own success
  (a narrow window: the same table, but a distinct query) now refuses login/refresh for **every**
  human-plane caller, not only those with a configured per-member tier — a wider availability
  blast radius than `budget_tier`'s fail-to-floor treatment. Accepted because no safe non-refusing
  alternative exists (Decision 3) and because this table is already a hard dependency of
  `resolve_context` in the same call, so the marginal new failure surface is narrow in practice.
- `quota_tier` is now the one claim carved out of ADR-0011 Decision 7's "role/quota data stays off
  both JWTs" — a future reader must not assume the carve-out generalizes to `project_quota`/`role`;
  Decision 1's Context section states explicitly why it does not (there is a live introspection path
  for those two, on the plane where the argument for keeping them off the token actually applies).
- Adds one more query to the token-exchange/refresh hot path (mint-time only, not per-request —
  bounded by the same `access_ttl_seconds`/`refresh_ttl_seconds` cadence every other claim here is
  already bounded by).

**Neutral / follow-ups**

- This ADR does not configure any human-plane per-member tier rule at the gateway — `x-quota-tier`
  is a real claim on real tokens as of this ADR, but §5's "tier and envelope rules are not
  configured" is unchanged; nothing at the gateway reads it yet, exactly as `budget_tier` sat unread
  between ADR-0014 and `ai-helm#877`. Checked directly against `ai-helm-values` (private repo) as
  part of this change: the existing `has(auth.identity.quota_tier) ? string(auth.identity.quota_tier)
  : ""` CEL requires no edit to start working once this claim exists — `has()` now evaluates `true`
  for a human-plane token that resolved a tier, `false` for one where the tier was legitimately
  absent (outcome 2), and the request never reaches the CEL at all when resolution failed (outcome
  3, refused upstream). No `ai-helm-values` PR is opened by this change.
- `AGENTS.md`/`CLAUDE.md`'s "Identity context resolution" section is corrected in the same change as
  this ADR to stop conflating the legacy `lightbridge-keycloak-spi` + protocol-mapper path (which
  seals only `account_id`/`project_id`, unchanged) with the native RFC 8693 token-exchange path
  (`TokenExchangeOpStore`, which now seals `budget_tier` and `quota_tier` too) — the two are
  separate mechanisms and the previous wording read as one.
- `docs/governance-model-and-enforcement.md` §4.7, its "Why introspection and not claims" section,
  and its §6 quick-reference table are updated alongside this ADR to state the `quota_tier` carve-out
  plainly, so a future reader of that document does not have to rediscover it from this ADR alone.

## Alternatives considered

- **Leave `quota_tier` introspection-only and correct the CEL/docs instead (issue #385's second
  option).** Rejected per this repository's standing doctrine (fix the live path, do not document a
  known-inert one as permanent) and because it forecloses ever configuring a human-plane per-member
  tier rule without a second migration later.
- **Add per-request introspection to the human/OIDC plane, mirroring the API-key plane exactly.**
  Rejected for the same reasons ADR-0014 rejected it for `budget_tier`: this was already evaluated
  and shelved once (`ai-helm` ADR-0110's `0086-authorino-project-context-metadata-step`) because a
  slow dependency in the `ext_authz` path risks becoming fail-open under load, and building it here
  would be considerably more work than a claim this service can already stamp on a token it mints
  itself.
- **Write `quota_tier` to Keycloak as a user/group attribute, read back via a protocol mapper.**
  Rejected for the same reason ADR-0014 rejected the equivalent plan for `budget_tier`: Keycloak no
  longer issues the token Authorino validates for the human plane (ADR-0011) — there is no
  Keycloak-issued token left in this path for such an attribute to reach via a protocol mapper.
- **On lookup failure, fall back to a policy-configurable floor tier, mirroring `budget_tier`
  exactly.** Rejected — see Decision 3. `QuotaTiers` has no ordering to derive a "floor" from, so
  any floor would be an arbitrary invented ranking over operator-defined opaque ids, not a genuine
  safety property.
- **On lookup failure, stamp a distinguishable non-matching sentinel value instead of refusing the
  mint.** Rejected — see Decision 3. With no gateway rule configured today, a sentinel is
  observably identical in effect to omitting the claim (both fall through to the same safe
  plan-level limits), so it would not actually close the "could look like a bypass later" gap this
  ADR exists to close, only obscure it behind an extra layer that still needs a coordinated
  `ai-helm-values` change to mean anything.

## Related

- Supersedes (partially): ADR-0011 (`docs/adr/0011-authz-issues-a-full-oidc-token-object.md`)
  Decision 7 — narrowed to `project_quota`/`role` only; see this ADR's header note and Decision 1's
  Context for exactly what changes and what does not.
- Precedent: ADR-0014 (`docs/adr/0014-budget-tier-claim-via-token-mint-not-keycloak-writeback.md`)
  — the same bug class on the adjacent `budget_tier` axis, the same call sites
  (`TokenExchangeOpStore::handle_token_exchange`/`handle_refresh_token`), and the source of the
  "re-resolve live on every refresh, do not copy the old claim forward" shape this ADR reuses.
  Diverges from it deliberately on the fail-closed mechanism — see Decision 3.
- `docs/governance-model-and-enforcement.md` — "Why introspection and not claims" (the argument this
  ADR narrows), §4.7 (human-plane walkthrough, updated), §5 ("tier and envelope rules are not
  configured", unaffected), §6 (quick-reference table, updated).
- Issue #385 — the report this ADR resolves.
- `ai-helm-values/environments/prod/values/security-policies.yaml` (private repo) — the
  `x-quota-tier` CEL this ADR's claim now feeds; verified to need no edit (Neutral/follow-ups).
