# ADR-0025: lightbridge owns its subjects — accounts stop being aliases for a raw upstream `sub`

- Status: Accepted (Stages 1-3 implemented; Stages 4-6 designed here, NOT YET IMPLEMENTED)
- Date: 2026-08-25
- Decision owners: Stephane Segning Lambou
- Supersedes: ADR-0006's "`accounts.id` IS the caller's JWT `sub`" / "`createAccount` inserts the
  subject" (see "Supersession" below — the rest of ADR-0006 survives)
- Completes: ADR-0024 Follow-up 2 ("a person's `accounts.id` values across issuers are still
  unrelated strings with no shared identity claim on the wire")
- Amends: ADR-0011 Context and Decision 7 ("sub copied from upstream, never re-minted" — the
  second half is now false; the upstream-validation posture survives verbatim)
- Reconciles: ADR-0039 (CUID2 is the house id format) — see "ADR-0039 reconciliation" below
- Related: ADR-0006 (this ADR's own "## Related" section gets a one-line forward pointer to here)

## Context

ADR-0006 built this service on one property: **`accounts.id` IS the caller's JWT `sub`.** Every
downstream authorization check — `resolve_context`'s `projects.account_id = $2`,
`find_default_project_id`'s `account_id = $1`, `project_member_quota_tier`'s per-member lookup,
`revoke_sessions_and_cascade`'s session ownership, cratestack's generated `auth().id ==
account.id` policies — is written in terms of an **account id**, but every one of them has, since
day one, been handed a **raw bearer subject** and trusted it to already BE the account id, with
nothing in the type system distinguishing the two.

ADR-0024 (2026-08-24, corrected 2026-08-25) already cracked this property open once: `accounts.id
== subject` stopped being true in general the moment a person could authenticate through more than
one issuer, because a `sub` is only unique *within* an issuer. ADR-0024's fix was structural on the
**identity** side — `federated_identities`, keyed `(issuer, subject)`, is the only way to resolve
"which account does this remote identity belong to," and a second issuer presenting a colliding
`sub` value gets refused (`Error::Conflict`), never silently merged. ADR-0024 explicitly deferred
the other half as its own Follow-up 2: *nothing yet actually calls
`resolve_account_for_federated_subject`-shaped translation at the ingress boundary* — every
handler still reads `info.sub`/`claims.sub` off a validated token and hands it straight to a
repository method whose parameter is conceptually an account id. The federation table existed;
nothing routed through it yet.

This ADR closes that gap: it is the ingress-side completion of ADR-0024's identity model, plus the
mechanical consequence for every codepath below it that now must be typed and threaded correctly.

### The one mechanism

Everything below the ingress boundary already speaks ACCOUNT ID — `resolve_context`
(`crates/lightbridge-authz-api-key/src/repo.rs`), `find_default_project_id`,
`project_member_quota_tier`, `revoke_sessions_and_cascade`, and every one of the ~37
`subject: &str`-typed repository methods. It worked, by accident, only because `accounts.id ==
sub` held for every account that existed before ADR-0024. The change this ADR makes is **one
translation at every ingress**: `(issuer, remote_sub) -> federated_identities -> account_id`,
computed once, handed down as a typed value from there on.

### Two ids that must never be conflated

`crates/lightbridge-authz-rest/src/authorize.rs:202-211` already documents the swap bug this ADR
exists to make impossible by construction:

- **ACTING account id** — the person actually performing the request. Goes on the minted JWT
  `sub`, `resolve_context`'s `$2` parameter, `sessions.subject`, `budget_account_id` for
  self-service refill, cratestack's `auth().id`.
- **CONTEXT account id** — the project's OWNING account, which may differ from the actor (a lead
  who is not the owner may still mint keys and manage the roster). Goes on the `account_id` JWT
  claim, `sessions.account_id`, `resolve_budget_tier`'s input, introspection's `account_id` field.

These were already two different concepts before this ADR (see `docs/rbac.md`'s ownership vs.
membership rules and the sessions-actor fix in #492/#494); this ADR's contribution is making the
ACTING half of that pair type-checked (`lightbridge_authz_core::identity::AccountId`) instead of a
bare `&str` indistinguishable from any other string.

## Decision

### One-seam translation, not translate-everywhere

A single repository method,
`StoreRepo::resolve_account_for_federated_subject(issuer, subject, grandfather_issuer) ->
Result<String>`, is the ONLY function in this codebase allowed to turn a raw external subject into
an account id. Every ingress that receives a bearer token — the RPC/CRUD surface
(`auth_provider::CratestackAuthProvider`), the MCP surface (`mcp::LightbridgeMcpHandler`), the
legacy `POST /idp/v1/resolve-context` endpoint the Keycloak SPI adapter calls, and the native RFC
8693 token-exchange grant (`TokenExchangeOpStore::handle_token_exchange`) — calls through this one
seam (via the `auth_provider::SubjectResolver` trait, see "The self-signed short-circuit" below)
rather than each re-implementing "look up federated_identities."

Everything reached from an already-resolved value (a session row's `subject` column, an
introspected API key's `owner_account_id`, an already-minted token's own `sub` claim on its next
refresh) is NOT re-translated — it is wrapped via `AccountId::from_resolved(already_trusted_value)`
and passed on. `AccountId`'s own doc comment
(`crates/lightbridge-authz-core/src/identity.rs`) states this precisely: the construction
discipline is "call the one function" (the same shape ADR-0039 already uses for `cuid2()`), not a
type-system-enforced capability token — `core` sits beneath the crate that owns the resolver, so a
compile-time-only guarantee is not achievable without inverting that layering.

### The self-signed short-circuit (why the API-key plane never breaks)

`BearerTokenService` (`crates/lightbridge-authz-bearer`) is ONE shared instance per component,
constructed once at startup from `oauth2.jwks_url`. Under `oauth2.type: self` (this repo's own
dev/prod deployments), every bearer token authz-api/authz-budget/lightbridge-mcp ever validate was
minted BY THIS SERVICE — never a raw externally-issued token. Re-running such a token's `sub`
back through `resolve_account_for_federated_subject` would refuse it outright: no
`federated_identities` row is ever written for `(this service's own signing issuer, sub)`, and
that issuer is never `oauth2.federation.issuer` (the Keycloak realm the translation seam
grandfathers against).

`FederatedSubjectResolver` (`crates/lightbridge-authz-rest/src/auth_provider.rs`) is built with an
optional `own_issuer` (`oauth2.signing.issuer`, present only under `type: self`). When a
presented token's `iss` equals `own_issuer`, the resolver trusts `sub` directly — no database call
— because Stage 3 (below) guarantees that `sub` was minted from an already-resolved account id in
the first place. Only a genuinely external `iss` (relevant under `oauth2.type: external`, or any
raw Keycloak token unexpectedly reaching this surface) goes through the real database-backed
resolution. This is what keeps "never break the API-key self-signed-JWT plane" true by
construction rather than by discipline.

### Bearer `iss` enforcement: extract-only, scoped as a follow-up

`TokenInfo`/`Claims` (`lightbridge-authz-bearer`) now carry `iss`, extracted on every validated
token. Deliberately NOT enforced inside `BearerTokenService::validate_bearer_token` itself: that
service is the single shared instance described above, validating both self-signed and
(depending on deployment) externally-issued tokens through the identical `oauth2.jwks_url`/
`ACCEPTED_ALGORITHMS` path, with no signal today distinguishing "which plane is this call for."
Enforcing `iss == oauth2.federation.issuer` at that layer would refuse every self-signed
deployment's own tokens outright (their `iss` is `oauth2.signing.issuer`, never
`oauth2.federation.issuer`). Scoping enforcement correctly needs a caller-side signal this trait
does not carry — tracked as a follow-up, not attempted here per this PR's own scope discipline
(`docs/adr/` change log; no separate tracking issue filed in this PR).

### Self-healing adoption over backfill-or-fallback

Two alternatives were rejected:

- **A backfill migration** stamping every existing `accounts` row with a synthetic
  `federated_identities` row up front. Rejected: it requires knowing every account's issuer ahead
  of time (this deployment has exactly one today, but that is a deployment fact, not a schema
  fact), and it does the work for accounts that may never log in again, for no benefit over doing
  it lazily.
- **A read-side fallback** — "if no `federated_identities` row exists, fall back to
  `accounts.id == subject`" evaluated at every read. Rejected explicitly: this re-opens ADR-0024's
  own cross-issuer merge bug on every ingress that takes this path, since a second issuer
  presenting a colliding `sub` would be silently treated as the same account, with no
  `federated_identities` row ever standing in the way. `AccountId`'s own doc comment calls this
  out as "re-opens ADR-0024's cross-issuer merge" for exactly this reason.

Instead, `resolve_account_for_federated_subject` self-heals: an existing
`federated_identities` row resolves directly (no write); absent that, a subject presented by the
ONE configured `grandfather_issuer` (`oauth2.federation.issuer`) that matches a pre-existing
`accounts.id == subject` row is adopted — a real `federated_identities` row is inserted, under
`SELECT ... FOR UPDATE` on the `accounts` row so two concurrent first-time resolutions of the same
subject serialize into one adoption rather than racing into a duplicate or a spurious conflict.
This is TEMPORARY and issuer-pinned: it exists only until the ADR-0025 residue query (every
`accounts` row with no adopting `federated_identities` row) reaches zero, at which point the
grandfather branch is deleted outright — it is not a permanent second way to link an identity.

A subject presented by any OTHER issuer, or matching no `accounts` row at all, is refused with the
SAME `Error::Forbidden` message in both cases — deliberately indistinguishable, so no ingress ever
becomes an account-existence oracle (mirroring `resolve_context`'s own pre-existing
non-leaking-404 contract, and `/idp/v1/resolve-context`'s Basic-auth-protected posture).

### Stages, and the point of no return

1. **Config + resolver** (this PR, commit 1-2): `oauth2.federation.issuer` becomes mandatory,
   loudly refused at startup, for authz-api/authz-idp/authz-opa/authz-budget/lightbridge-mcp.
   `resolve_account_for_federated_subject` exists; nothing calls it yet.
2. **Translate at every ingress** (this PR, commit 3): every bearer-token-consuming surface routes
   through the resolver seam. The ~37 repository methods below the ingress boundary are retyped
   from `subject: &str` to `account_id: &AccountId`.
3. **Mint our subject** (this PR, commit 4): `identity_for` — the function backing both the
   self-signed API-key path and the RFC 8693 exchange path — mints the token's `sub` claim from
   the resolved acting account id, never the raw upstream claim.
4. **NOT YET IMPLEMENTED — CEL/policy-layer edits.** Any Envoy/Authorino CEL expression that
   assumes `x-account-id` (or an equivalent claim) is byte-identical to the presented bearer's raw
   `sub` needs auditing once a genuinely non-grandfathered (Stage 5+) account can exist. Out of
   scope for this PR; the wire is byte-identical for every account that exists today, so nothing
   downstream needs to change yet.
5. **NOT YET IMPLEMENTED — `createAccount` mints a CUID2.** The actual "point of no return":
   `accounts.id` stops being `= subject` for BRAND NEW accounts, becoming a minted CUID2 instead
   (ADR-0039 compliant), with the creating subject's `federated_identities` row pointing at it from
   the start — closing the very door ADR-0006 opened (`createAccount` no longer inserts the
   subject as the id). Every account that exists BEFORE this stage ships remains grandfathered
   forever; this stage only changes the shape of accounts created after it lands. Requires its own
   RFC-weight review: it changes what a caller can assume about `account_id`'s shape (a stored
   `sub` is opaque and IdP-shaped; a CUID2 is always 24 lowercase alphanumeric characters starting
   with a letter — never validate this format per AGENTS.md's own id-opacity rule, but the two
   populations coexisting is a real fact worth naming).
6. **NOT YET IMPLEMENTED — backfill.** Once (5) ships, a scoped, owner-approved migration could
   choose to also re-key long-lived grandfathered accounts onto minted CUID2 ids. Deliberately the
   LAST stage, and the one most likely to never happen at all — every property this ADR relies on
   (wire-invariance, no forced re-auth) holds indefinitely without it.

This PR implements Stages 1-3 only. Stages 4-6 are designed here so the eventual PRs implementing
them do not have to re-litigate these decisions, but no code for them exists yet.

### SPI contract survives unchanged

`lightbridge-keycloak-spi`'s `POST /idp/v1/resolve-context` body shape
(`{subject, project_id}`) is untouched — the new `issuer` field is `Option<String>`, defaulting to
`oauth2.federation.issuer` when absent, so the existing adapter (which never sends it) keeps
working with zero changes on its side. A future adapter update that DOES send `issuer` explicitly
is supported without a breaking change.

## Wire-invariance: the property this whole PR is graded on

For every account that exists today, `resolve_account_for_federated_subject`'s grandfather branch
resolves to the SAME value the raw subject always was — `account_id == subject`, byte for byte.
Every minted claim that changed source in this PR (`auth().id`, the JWT `sub` claim,
`sessions.subject`, `exchange_refresh_tokens.subject`) is therefore byte-identical to what it would
have been before this PR, for every existing account. This is not asserted by inspection alone —
`crates/lightbridge-authz-rest/tests/signing_tests.rs`'s
`grandfathered_account_mints_a_byte_identical_sub_to_the_pre_stage_3_signer` is the dedicated test
for exactly this property, asserted against the fixture's own `owner.subject` value directly
(never a hardcoded literal), so it fails if the invariant is ever violated by a future change, not
only if this PR's own fixtures happen to agree.

## Owner OQ answers (recorded 2026-08-25)

- **Frontends**: verified safe — every frontend reads `createAccount`'s own response for the
  account id rather than assuming it equals the login subject, so translating the acting account
  id post-login is transparent to them.
- **Internal-plane divergence** (any internal service that currently assumes `account_id == sub`)
  is accepted until LibreChat/Coder integrate against this surface directly.
- **Beta-user subject breakage**: accepted. A beta user whose subject was never grandfathered
  correctly (should not occur under Stages 1-3, since every account that exists today IS
  grandfathered by definition) would need a manual `federated_identities` row; no such case is
  known to exist today.
- **api-key plane**: never rate-limits, and is capped at 20 keys per project (#493) — unaffected by
  and irrelevant to this ADR.
- **#492 (session revocation targets the actor)**: fixed separately, on its own branch, merged
  first (`d36381a`, this branch rebased onto it). This PR's own `revoke_sessions_and_cascade`
  touch is a mechanical parameter rename only (`subject: &str` -> `account_id: &AccountId`) — the
  SQL #492 already fixed is untouched.
- **Second-issuer-presents-a-fresh-identity**: accepted as a real limitation until a second issuer
  is actually configured in `oauth2.federation` — today's single-issuer deployment makes this a
  latent, not live, gap; the `federated_identities_issuer_subject_uidx`/`_account_uidx` structural
  guards (ADR-0024) are what make a second issuer's arrival safe to configure later, not something
  this ADR needs to solve today.

## ADR-0039 reconciliation

ADR-0039 bans MINTING a new id in any format other than `cuid2()`; it does not ban STORING an id
this service does not mint (an external `sub`, verbatim — AGENTS.md's own "Identifier Format"
section already states this explicitly for `accounts.id`). This ADR does not change that today:
`accounts.id` stays exactly what it always was for every account created before AND during Stages
1-3. Stage 5 (not yet implemented) is where `accounts.id` actually moves to "minted CUID2" for
NEW accounts, per Decision 6 above. Grandfathered ids remain stored verbatim forever, and the
resulting heterogeneity (some ids are opaque IdP-shaped strings, some are CUID2) is safe precisely
because this codebase already bans shape-checking an id anywhere (AGENTS.md: "Never validate an
id's shape") — the exact discipline that made cratestack's `Cuid` schema-scalar regression
(rejecting any id not starting with `'c'`) a bug to fix, not a spec to enforce.

## Supersession

ADR-0006's "`accounts.id` IS the caller's JWT `sub`" and "`createAccount` inserts the subject" are
superseded by this ADR's Decision (the translation seam) for every READ/AUTHORIZATION path, and
will be superseded for the WRITE path (`createAccount` itself) once Stage 5 ships. The rest of
ADR-0006 — project-scoped roster rules, the removal of account-level membership, billing identity
living on `projects` — is entirely unaffected and survives verbatim. ADR-0006 gets a one-line
`## Related` pointer to this ADR.

## Consequences

- Every repository method below the translation seam is now typed with
  `lightbridge_authz_core::identity::AccountId` instead of a bare `&str`, closing the exact class
  of bug `authorize.rs:202-211` already documents by name (a raw upstream subject reaching a
  parameter that means "account id").
- `oauth2.federation.issuer` is a new, mandatory config block for every serving component. Prod
  values already carry it in all five blocks (`ai-helm-values#306`, merged and synced
  2026-08-25) — the sequencing gate this PR would otherwise need is already satisfied.
- `TokenInfo`/`Claims` carry `iss` now; no behavior depends on it being present except the new
  resolver seam itself.
- `KeyOwner` (signing) carries `account_id` alongside `subject`; every minted token's `sub` now
  reads from the former.
- No wire format changed for any account that existed before this PR shipped. A future account
  created after Stage 5 ships (not yet implemented) will, for the first time, have an `accounts.id`
  that is NOT the literal value of any `sub` claim it was ever presented with — this ADR is what
  makes that eventual change safe to make without a second audit of every downstream consumer.
