# ADR-0014: The `budget_tier` claim is stamped at token-mint time from the ledger, not written to Keycloak as a user attribute

- Status: Accepted
- Date: 2026-08-18
- Decision owners: Stephane Segning Lambou
- Supersedes (partially): ADR-0008's delivery-mechanism paragraph ("the tier reaches the gateway
  as a Keycloak claim -- this service writes a user attribute when a grant lands, a protocol
  mapper turns it into a claim"). ADR-0008's ladder model, reset-not-topup semantics, and
  discrete-tiers decision are **unaffected and remain in force** -- see Decision 1 for exactly
  what changes and what does not.

## Context

Issue #196 (Phase 6b, epic #188) asks for the write-back half of ADR-0008's design: when a budget
refill grants a new tier, write it as a Keycloak user attribute so a protocol mapper can turn it
into the `x-budget-tier` claim Authorino stamps at the gateway. That plan was written on
2026-07-31 (ADR-0008) against the architecture as it existed then: the human/OIDC plane's access
token was issued by Keycloak directly, so a claim on that token could only originate from
Keycloak.

**That premise no longer holds.** ADR-0011 (2026-08-14, two weeks after ADR-0008) made
`lightbridge-authz` itself the token-issuing authority for the human plane: `authz-idp`'s native
RFC 8693 token-exchange (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs`,
`TokenExchangeOpStore::handle_token_exchange`/`handle_refresh_token`) mints the access token a
client actually presents to the gateway, via `authkestra_engine::token::TokenManager`. Keycloak's
role is reduced to being the upstream IdP for the *subject_token* input to that exchange -- it
never issues, and never touches, the token Authorino inspects. ADR-0011 confirms this explicitly
(`docs/adr/0011-authz-issues-a-full-oidc-token-object.md:282-288`): Authorino's `AuthConfig`
verifies the signature via `issuerUrl` discovery, resolving to whichever issuer signed the
*presented* token -- this service's own `/.well-known/openid-configuration`, for a token-exchange
grant. There is, as of ADR-0011, no Keycloak-issued token left in this path for a Keycloak
attribute to reach via a protocol mapper.

**The obvious alternative -- resolve the tier the same way `project_members.quota_tier` already
reaches the gateway, via introspection -- was evaluated and rejected, because that mechanism does
not exist for the plane this story needs it on.** `docs/governance-model-and-enforcement.md`'s
"Why introspection and not claims" section and its walkthrough §4.7 ("A human on the Keycloak
plane") both establish that Authorino's introspection call (`POST
/v1/authorino/validate/introspect`, cached 30s per `jti`) fires **only** when a request carries
`api_key_id` -- the machine/API-key plane. The human/OIDC plane's first escape hatch is exactly
"no `api_key_id`", so it never reaches introspection at all; `x-project-id`/`x-account-id` there
come from claims sealed at token-exchange time, and `x-quota-tier`/`x-project-quota` are, as of
today, **not populated for humans either** -- confirmed independently by ADR-0011 Decision 7
(`docs/adr/0011-authz-issues-a-full-oidc-token-object.md:408-412`, restated in its own
"Neutral / follow-ups" as a stale-`AGENTS.md`-doc fix still outstanding at
`docs/adr/0011-authz-issues-a-full-oidc-token-object.md:540-544`) and by
`ai-helm-values/environments/prod/values/security-policies.yaml`'s own CEL, which reads
`auth.identity.quota_tier` (a claim, `""` on absence) for this plane, not a metadata/introspection
lookup. So "mirror the existing quota_tier path" is not actually available without first building
introspection for the human plane -- a considerably larger and, per `ai-helm` ADR-0110's own
"Alternatives considered", already-once-rejected design (the shelved
`0086-authorino-project-context-metadata-step`, superseded in favor of a claims-based approach for
exactly this reason).

Both the rejected Keycloak-write plan and the also-rejected introspection-mirror plan share one
root problem for this specific axis: neither is where the tier's own source of truth (the budget
ledger, `budget_grants`/`budget_balances`, ADR-0009) lives. The service that already resolves
`account_id`/`project_id` at token-mint time from its own database can resolve `budget_tier` the
same way, in the same call, with no new dependency.

## Decision

### 1. `budget_tier` is stamped as an access-token `extra` claim at token-exchange/refresh mint time, resolved live from the budget ledger

`TokenExchangeOpStore::resolve_budget_tier` (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs`)
computes `Period::current(now)` and calls `BudgetRepo::current_tier(account_id, period)`
(`crates/lightbridge-authz-budget/src/repo.rs`, moved there from a private method on
`RefillService` so this caller can share it without constructing a full refill-orchestration
stack). The result is inserted into the same `extra: HashMap<String, Value>` map
`access_token_extra` already builds for `account_id`/`project_id`, immediately before
`TokenManager::issue_user_token_with_extra` signs the token. Both call sites --
`handle_token_exchange` and `handle_refresh_token` -- call it identically, because ADR-0011
already re-mints both grants through the same signing calls (verified, not assumed: see
`refresh_re_resolves_the_budget_tier_live_rather_than_copying_the_old_claim` in
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`, which seeds a grant *between* the
original exchange and a subsequent refresh and asserts the refreshed token carries the new tier,
not the one it started with).

**What this does NOT change from ADR-0008:** the ladder itself (`b-15` through `b-1000`,
`crates/lightbridge-authz-budget/src/tier.rs`), the append-only rung ordering, and the
reset-not-topup semantics (a refill replaces the period's ceiling, it does not add to it) are all
untouched -- `BudgetRepo::current_tier` is the exact same resolution `RefillService` already used
to decide the next rung, only now also read by the token-mint path. **What changes is only *how
the resolved tier reaches the token* -- an outbound Keycloak admin-API write, superseded by an
intra-database read on the same call that already resolves tenant context.**

`budget_tier` is scoped to the OIDC token-exchange/refresh grants only, exactly matching ADR-0008's
"Refills are OIDC users only" boundary. It is **not** added to `access_token_extra` itself (the
function shared with the plain self-signed API-key JWT path, `ApiKeyJwtSigner::sign`) -- inserted
only at the two token-exchange call sites, so the API-key plane's tokens are unaffected, matching
"Internal/API-key clients ... keep plan-level budgets."

### 2. No new outbound dependency; a new intra-database read instead

`authz-idp` (`start_idp_server`, `crates/lightbridge-authz-rest/src/lib.rs`) now also constructs a
`lightbridge_authz_budget::repo::BudgetRepo` from the **same** `pool: Arc<dyn DbPoolTrait>` it
already uses for `StoreRepo`/signing-key bootstrap -- not a call to the separate `authz-budget`
microservice, not a network hop, not a new credential or client to manage. `authz-idp` and
`authz-budget` already share one Postgres (`AGENTS.md`: "authz-api, authz-opa ... share the same
Postgres database"; the budget domain's own service split, `docs/architecture/budget.md`, moved
RPC *procedures* to a separate process, never the underlying data). This is the concrete form of
"avoids a new outbound dependency" promised in the design report that preceded this ADR: there is
no Keycloak admin client, no admin credential, no new network egress, and no new failure mode
beyond "the same Postgres this service already depends on for everything else is unavailable."

### 3. Fail-closed at two layers, deliberately redundant

`BudgetRepo::current_tier` already resolves to `BudgetTier::B15` (the lowest rung) for "no
qualifying grant yet this period" and "grant amount doesn't match a known rung" -- pre-existing
behavior inherited unchanged from `RefillService`'s prior private implementation. It does **not**
swallow a genuine storage failure (`BudgetError::StorageFailed`) into that default; the error still
propagates, so a caller that wants to distinguish "new account" from "ledger unavailable" (an
operator alert, say) still can (`current_tier_propagates_a_genuine_storage_failure`,
`crates/lightbridge-authz-budget/tests/budget_repo_query_tests.rs`).

`TokenExchangeOpStore::resolve_budget_tier` is the layer that closes that gap for the token-mint
path specifically: any `Err` from `current_tier` -- for any reason, including a genuine database
outage -- is caught, logged, and downgraded to `BudgetTier::B15`. The claim is **never** omitted
and the token exchange/refresh **never** fails because of this lookup. This is deliberate and
matches the exact requirement `docs/runbooks/budget-tier-rekey-cutover.md` (§"Before you deploy")
already states for the eventual gateway cutover: *"An account with no claim must land on a sane
rung, not on no matching rule -- that is the difference between 'starts at their base budget' and
'is unlimited'."* Proven, not just asserted: with `budget_repo` pointed at an unreachable pool
(the same `connect_lazy`-to-`127.0.0.1:1` pattern this test suite already uses elsewhere for
"database down" scenarios), both `budget_tier_claim_survives_a_budget_ledger_outage_on_exchange`
and `budget_tier_claim_survives_a_budget_ledger_outage_on_refresh` assert the exchange/refresh
still returns `200 OK` with `budget_tier: "b-15"` on the decoded access token
(`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`). The fallback's B15 constant was
deliberately mutated to `B1000` (the most permissive rung -- a simulated fail-*open* bug) to watch
both tests fail for exactly that reason before being restored; see the PR for the failure
transcript.

### 4. Propagation latency is bounded by the access-token TTL, not undefined

A refill's effect on enforcement (once Phase 6a below exists) reaches a given client within, at
most, `token_exchange.access_ttl_seconds` (`config/default.yaml`, default `900` -- 15 minutes),
because the client's next natural token refresh re-runs `resolve_budget_tier`. This is a real
improvement over the state `docs/budget-refill-ui-contract.md:176-208` currently documents
("nothing downstream of the ledger is watching it") and over ADR-0008's own "a refill takes effect
at the next token refresh, not instantly" -- now a bounded, configurable number rather than an
open-ended promise, and one that does not depend on Keycloak-side propagation timing at all. This
is only usable because refresh tokens are actually available to reach that "next refresh" without
a full re-login -- the `docs/adr-0011-all-clients-offline-access` work landing `offline_access` for
every client is the concrete enabler.

## Consequences

**Positive**

- Removes a dependency this service does not otherwise have anywhere: no Keycloak admin-API
  client, no admin credential to provision/rotate, no new outbound network egress, no new failure
  mode beyond the Postgres dependency every other code path here already has.
- No two-source-of-truth problem. There is exactly one place `budget_tier` is derived from --
  `budget_grants`/`budget_balances` -- read fresh at every mint, never written elsewhere. An
  out-of-band edit to a Keycloak attribute (the divergence risk ADR-0008's mechanism carried) is
  structurally impossible because no such attribute exists.
- Bounded, configurable propagation latency (Decision 4), instead of an undefined "next token
  refresh" that depended on a Keycloak-side write actually landing first.
- Reuses, rather than duplicates, the exact resolution logic `RefillService` already used and had
  already tested -- `BudgetRepo::current_tier`'s fail-closed-to-`B15` behavior is inherited, not
  reimplemented.

**Negative**

- `authz-idp` (and, per ADR-0012, whichever service eventually hosts the OIDC token-exchange
  surface) now has a real dependency on the budget domain's tables, which it did not have before.
  Confined to a read-only query against `budget_grants`; no write path is added here.
- `budget_tier` inherits the exact same "starting-tier gap" ADR-0008 already flagged and this PR
  does not solve: there is no `billing_plan` -> `BudgetTier` mapping anywhere in this codebase, so
  every account with no grant history this period defaults to `B15` regardless of plan. Safe (it
  never claims more than the cheapest plan would justify) but not the intended long-run behavior
  for e.g. an enterprise account. Unchanged scope from ADR-0008; not solved by this ADR.
- The claim only reaches a client on its next token mint (exchange or refresh), not the instant a
  grant lands -- bounded by Decision 4's TTL, but still not literally instant. An operator wanting
  true instant effect would need per-request introspection on the human plane, the option Decision
  "Context" above explains was already rejected once (`ai-helm` ADR-0110) and is not reopened here.

**Neutral / follow-ups**

- Issue #196 (Phase 6b, "grants write the Keycloak `x-budget-tier` attribute") is superseded by
  this ADR's Decision 1 and should be updated or closed in favor of tracking the work this ADR
  actually describes (claim-stamping at token-mint time) -- its acceptance criteria as written
  ("the account's Keycloak user attribute is set", "a retry of a failed write-back") describe a
  mechanism this ADR replaces.
- `ai-helm#877` (Phase 6a, "re-key monthly budget to the append-only `x-budget-tier` ladder") is
  **already filed and open**, boundary-scheduled for 2026-09-01 UTC -- no new tracking issue is
  needed for the gateway-side rule work. Its Expected Behavior section, however, currently reads
  "every account stamped onto its plan's base rung via the **Keycloak attribute → protocol mapper
  → claim** → Authorino CEL path" and its Technical Context notes reserve `ADR-0117` (an
  `ai-helm`-side ADR number) for that mechanism. Both need a one-line correction pointing at this
  ADR's mechanism (`has(auth.identity.budget_tier)` read directly off the token, mirroring how
  `x-quota-tier` already reads `auth.identity.quota_tier`) instead -- the append-only rule
  authoring, fail-closed CEL default, and boundary-scheduling requirements #877 already documents
  are all unaffected and remain exactly as written.
- This ADR does not implement Phase 6a (the gateway-side `BackendTrafficPolicy` rules and the
  retirement of the legacy per-plan monthly-budget rule) or wire the resulting `x-budget-tier`
  header into any enforcement rule -- `x-budget-tier` is a real claim on real tokens as of this
  ADR, but nothing at the gateway reads it yet, exactly as `x-quota-tier`/`x-project-quota` already
  sit unread per `docs/governance-model-and-enforcement.md` §5. That work is `ai-helm#877`,
  boundary-scheduled per the runbook, deliberately not bundled with this change.
- `crates/lightbridge-authz-rest/src/signing.rs`'s `claims_supported` discovery-document list now
  advertises `budget_tier` alongside `project_id`/`account_id`, unconditionally (matching how
  `nonce`/`auth_time`/`at_hash` are already advertised regardless of whether token-exchange is
  actually enabled on a given deployment) -- a pre-existing minor imprecision in that list, not
  newly introduced here.

## Alternatives considered

- **Write the tier to Keycloak as a user attribute (ADR-0008's original plan, issue #196's literal
  ask).** Rejected: its premise -- that Keycloak issues the token Authorino validates for the
  human plane -- was invalidated by ADR-0011 before this story was ever picked up. Implementing it
  as written would add a real outbound dependency (admin API, credential, egress, a new failure
  mode) to write a claim that this service can now stamp on a token it mints itself, in the same
  call that already resolves tenant context.
- **Resolve `budget_tier` at request time via introspection, mirroring `project_members.quota_tier`.**
  Rejected: introspection does not run on the human/OIDC plane at all today (Context, above) --
  building it would mean adding a live per-request metadata call to Authorino's `AuthConfig`
  specifically for this plane, the design `ai-helm` ADR-0110 already evaluated and rejected once
  (the shelved `0086-authorino-project-context-metadata-step`) in favor of a claims-based approach,
  for reasons (added latency in the `ext_authz` path, a slow dependency becoming fail-open) that
  apply identically here.
- **Do nothing until Phase 6a's gateway rules exist, then decide the delivery mechanism.**
  Rejected: the claim is harmless to stamp before any rule reads it (an unread claim, like
  `x-quota-tier` today, changes nothing observable), and stamping it first lets `ai-helm#877` land
  its rule authoring against a header that is already real on live tokens, rather than serializing
  the two pieces of work.

## Related

- Supersedes (partially): ADR-0008 (`docs/adr/0008-refills-are-discrete-budget-tiers.md`) --
  delivery mechanism only; ladder/reset-not-topup decisions reaffirmed.
- Builds on: ADR-0009 (budget grants are an immutable ledger) -- `BudgetRepo::current_tier` reads
  this ledger directly; ADR-0011 (`docs/adr/0011-authz-issues-a-full-oidc-token-object.md`) --
  establishes that `authz-idp`/the token-exchange path mints the token this ADR stamps a claim
  onto, and its Decision 7 is the prior art for "role/quota data stays out of both JWTs" that this
  ADR deliberately narrows (only `budget_tier`, only on the OIDC grants).
- `docs/governance-model-and-enforcement.md` -- the introspection/claims split (§"Why introspection
  and not claims", §4.7, §5's quick-reference table) this ADR's Context relies on.
- `docs/runbooks/budget-tier-rekey-cutover.md` -- states the fail-closed requirement (§"Before you
  deploy") this ADR's Decision 3 satisfies, and owns the still-open gateway-side cutover (Phase
  6a).
- `docs/budget-refill-ui-contract.md` -- documents the present-tense "no gateway effect" state this
  ADR begins to close (the claim now exists; nothing reads it yet -- see Neutral/follow-ups).
- Issue #196 (Phase 6b) -- the story this ADR's Decision 1 supersedes the literal mechanism of.
- `ai-helm` ADR-0084 (rate-limit plan order is append-only) and ADR-0110 (project quota-tier rules
  use an append-only list) -- the append-only contract Phase 6a (`ai-helm#877`) must satisfy when
  it eventually adds rules keyed on the `x-budget-tier` claim this ADR makes real.
