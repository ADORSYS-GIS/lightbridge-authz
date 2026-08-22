# ADR-0019: `authz-idp` brokers the standard authorization-code flow (`/authorize`) alongside the device grant, so most clients can retire token-exchange; `redirect_uris` becomes a real registry

- Status: Accepted
- Date: 2026-08-22
- Decision owners: Stephane Segning Lambou
- Supersedes (partially): ADR-0012 Decision 3's `AuthorizationCodeStore` half ("remains a
  permanent no-op stub") and Decision 4 in full (`redirect_uris` deliberately empty, reaffirming
  ADR-0011 Decision 5). ADR-0012 Decision 3's `DeviceCodeStore` half, and every other decision in
  ADR-0012 and ADR-0011, are **unaffected** — see Decision 1 below for exactly what is and is not
  reopened. ADR-0011 Decision 5 (`redirect_uris: []`) is superseded in the same, narrow sense: it
  stops being universally true, but stays true for every client that does not register for the
  authorization-code grant.

## Context

**The decision, made by the repo owner in-session on 2026-08-22 — implement it, do not re-open
it:**

> *"I think we need an auth endpoint to start standard flow or device-code flow, then redirect to
> SSO (Keycloak) so that we shall remove token-exchange from most of our clients."*

Source of truth for this ADR: issue #337 (the device-grant epic) plus that instruction. No separate
issue number exists for the instruction itself; it is cited here as the in-session directive it
was.

### What `authz-idp` actually is today, verified live, not assumed

ADR-0012's "Phase 1 — new microservice" is **done**. `authz-idp` is deployed and serving:

```
https://auth.ai.camer.digital/.well-known/openid-configuration
  grant_types_supported:         [token-exchange, refresh_token]
  device_authorization_endpoint: absent
  authorization_endpoint:        absent
  response_types_supported:      []
  token_endpoint:                /oauth2/token   ← live
```

`AGENTS.md`'s service list already documents `authz-idp` as exposing discovery, JWKS,
`/oauth2/token`, and `/oauth2/revoke`, with every route public because the presented
token/assertion is itself the credential — and as transitional, since `authz-api` still serves the
identical surface until the public issuer is repointed. Issue #337 (opened against ADR-0012) still
frames Phase 1 as future work ("stand up a new binary under `app/`... move `/oauth2/token`...").
That framing is stale: the service exists, is routed, and is live. **This ADR re-scopes from the
current state, not from #337's original plan** — its epic breakdown is superseded by this ADR's own
ticket list (see the linked issues in "Related").

**The device grant is stubbed, not implemented**, despite ADR-0012 Accepted status:
`crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs` has no-op `store_device_code`/
`get_device_code`/`get_by_user_code`/`update_device_code`/`consume_device_code` on
`NoDeviceCodeStore`; `discovery_document` (`signing.rs`) hardcodes `device_code_ttl_secs: 0`; and
`oauth2_op/client_store.rs:76` already maps
`urn:ietf:params:oauth:grant-type:device_code → GrantType::DeviceCode` with nothing behind it yet.
authkestra-op (workspace-pinned `=0.5.1`, lockstep with the rest of the `authkestra-*` family)
supplies the device-flow handlers and store trait — this remains wiring plus a verification page,
not a protocol implementation, exactly as ADR-0012's own "Key Assumptions" already stated.

### ADR-0012's two decisions this ADR directly contradicts, quoted verbatim

**Decision 3** (`docs/adr/0012-device-authorization-grant-brokered-via-new-idp-service.md`):

> `DeviceCodeStore` is superseded for real; `AuthorizationCodeStore` remains a **permanent no-op
> stub**... `NoAuthorizationCodeStore` stays exactly as it is: `store_code` always errors,
> `consume_code` always returns `None`. No client this service registers is ever given the
> `authorization_code` grant type.

**Decision 4**:

> Decision 5 of ADR-0011 (`redirect_uris` deliberately empty) stays standing, unchanged — and the
> device grant is a positive argument for keeping it that way... choosing RFC 8628 over
> authorization-code eliminates an entire class of surface this service would otherwise have to
> build and defend — per-client redirect-URI registries, open-redirect validation, and
> authorization-code substitution attacks — none of which have an RFC 8628 equivalent.

Both were correct calls against the constraint they were solving for at the time: issue #336 asked
specifically whether `/authorize` should exist, and the answer was no, on the evidence that every
known client population was headless CLIs for which RFC 8628 is strictly the right flow (opencode's
own chart README: the plugin's default `authorization_code` flow "binds a localhost callback port
and breaks headless use"). **That evidence is still true for CLIs and is not being relitigated
here.** What changed is the client population this service now needs to serve: the owner's
instruction above adds a second population — browser clients (the self-service dashboard,
`lightbridge-ss`) — that a device grant does not fit and a headless-CLI argument was never meant to
cover. `/authorize` was rejected as the wrong flow for CLIs, not as universally wrong; extending it
to browser clients is a different question ADR-0012 never asked.

This code comment encodes the stub as permanent, and gets corrected by this ADR rather than left
to rot:

```
// crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs:1-7
//! Permanent no-op `AuthorizationCodeStore`/`DeviceCodeStore` implementations (ADR-0011, Decision
//! 3). Both flows require *running* a user-facing authentication step... and this service owns no
//! users and runs no login flow anywhere (ADR-0011 Context). That is the architecturally correct
//! terminus, not an expedient shortcut: there is no future version of this service that
//! implements these two traits for real, because doing so would mean authenticating a user, which
//! it structurally cannot.
```

The "owns no users" premise is unaffected by this ADR (Decision 4 below) — the comment's error is
narrower: it treated "runs a login flow" and "authenticates a user" as things `/authorize` would
require this service to do itself. It does not. `/authorize`, like the device grant already
decided in ADR-0012, still terminates in a redirect to Keycloak's own hosted login; this service
still authenticates no one. The stub's premise conflated "this service will host an authorization
endpoint" with "this service will run a login page" — ADR-0012 Decision 2 already drew that exact
distinction for the device grant (broker, not full IdP) and this ADR extends the same distinction
to `/authorize`.

**⚠️ Regression test that will need a deliberate edit, and is the signal this ADR exists to
address, not scope creep to route around:**
`discovery_never_advertises_response_types_or_modes`
(`crates/lightbridge-authz-rest/tests/signing_tests.rs:466`) asserts, across both the
token-exchange-enabled and -disabled states, that `response_types_supported`/
`response_modes_supported` stay empty and `authorization_endpoint` is absent — with a doc comment
explaining it was added *because* `response_types_supported` once flipped to
`["token", "id_token", "id_token token"]` in production purely as a side effect of an unrelated
flag. That test was written precisely to catch an authorization endpoint being advertised by
accident. This ADR advertises one on purpose. The test must be rewritten, not deleted or loosened —
it should assert the *correct*, non-empty values once `/authorize` ships (Decision 4 below), so it
keeps doing the job it was built for: catching a discovery document that drifts from what this
service actually serves.

### Why this matters beyond ergonomics: the live incident this connects to, and what it does not fix

Issue #419, open today, is a production denial: `Procedures::request_budget_refill` refuses every
human caller because `lightbridge_caller_kind` is hardcoded `"api_key"` on **every** token this
service mints, including human-plane tokens — `signing.rs`'s shared `access_token_extra()` has no
parameter to vary it, and the native RFC 8693 token-exchange path
(`oauth2_op/store.rs::handle_token_exchange`/`handle_refresh_token`) calls that same helper
unconditionally. A session CUID2 gets stuffed into the `api_key_id` claim on every human-plane
token exactly the way an API key's id would be.

That single mislabeled claim is load-bearing well beyond #419: `docs/governance-model-and-enforcement.md`
documents `api_key_id`'s presence as **the** plane discriminator, used independently in at least
three places — Envoy filter #7's own routing (`F7 -->|"has api_key_id?"| PLANE`, choosing
introspection vs. claims), the model-allowlist CEL predicate (whose first fail-open escape hatch is
literally "no `api_key_id`"), and rule family 4's `quota_tier` gate. Every one of these was written
assuming `api_key_id`'s presence means "this is an API-key caller" — a fact that has not been true
since PR #95 wired the same signer into the human plane three weeks before the claim was
introduced. **A client that obtains its token through a real OIDC flow — device grant or
authorization-code — never goes through this impersonating code path at all**: it authenticates
against Keycloak directly, through this service's broker, and the token this ADR's flows mint does
not need to borrow the API-key claim shape to carry tenant context, because `/authorize`'s own
Decision 2 gives it a real registered-client identity instead.

**Stated plainly: this ADR does not fix #419.** Existing token-exchange-issued tokens keep
circulating, correctly or not, until they expire — this ADR does not revoke or reissue anything.
The `lightbridge_caller_kind`/`api_key_id` claim-naming bug is independently wrong and needs its own
fix regardless of this ADR (#419 tracks it). What this ADR does is strategic, not remedial: it gives
most clients a path off the token-exchange grant entirely, so the *class* of bug #419 represents —
a token minted through a machine-to-machine exchange grant wearing an API-key's claim shape because
that was the only signing path available — has fewer and fewer callers routing through it over
time. The dashboard moving to `/authorize` (Decision 3) removes its single largest caller from that
path.

## Decision

### 1. `/authorize` and a real `AuthorizationCodeStore` are in scope, superseding ADR-0012 Decision 3's `AuthorizationCodeStore` half only

`authz-idp` adds `GET /authorize` (authorization-code flow, PKCE mandatory — Decision 2) alongside
the already-decided device grant (ADR-0012, still landing — see the linked epic tickets). Both
terminate in the same place: a redirect to Keycloak's own hosted login, exactly as ADR-0012
Decision 2 already established for the device grant's verification page. This service still
authenticates no one and still owns no `users` table — Decision 4 restates this explicitly because
it is the one part of ADR-0011/ADR-0012 this ADR leaves completely untouched.

**What remains of Decision 3, precisely:** the device half is unaffected — `DeviceCodeStore` was
already decided "superseded for real" by ADR-0012 and stays exactly as that ADR left it (currently
mid-implementation per the linked epic; see Related). Only the sentence "`AuthorizationCodeStore`
remains a permanent no-op stub" is reversed. `NoAuthorizationCodeStore`
(`crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs`) is replaced by a real,
persistence-backed implementation with the same shape ADR-0012 Decision 7 specified for
`device_authorizations`: single-use, CAS-consumed, TTL'd, ids minted via `cuid::cuid2()`, stored
`TEXT`, opaque, never shape-validated. The authorization code itself is a short-lived (recommend
≤60s, configurable), single-use bearer value — not an id in ADR-0039's sense — mirroring how
`device_code`/`user_code` sit on the secret/display side of that same distinction in ADR-0012's
Decision 7.

### 2. A `redirect_uris` registry is now required, superseding ADR-0012 Decision 4 and ADR-0011 Decision 5 — the security trade, argued honestly

ADR-0012 Decision 4 listed exactly what the empty-`redirect_uris` posture bought, and this ADR does
not pretend that risk disappears — it states what replaces each mitigation:

| What ADR-0012 avoided by having no `redirect_uris` | What replaces it now that a browser redirect genuinely exists |
|---|---|
| A per-client redirect-URI registry to maintain | `OauthClient.redirect_uris: Vec<String>` (currently hardcoded `Vec::new()` in `oauth2_op/client_store.rs`'s `to_registration`) stops being force-emptied for clients registered with the `authorization_code` grant type. It is **exact-string-match only** — no wildcards, no prefix/suffix matching, no scheme-relative matching, no `*` in any registered entry. A request whose `redirect_uri` is not byte-identical to a registered entry is rejected before Keycloak is ever reached. |
| Open-redirect vector (an attacker-supplied `redirect_uri` used as a phishing/token-leak relay) | Closed by the same exact-match rule: this service only ever redirects a user-agent to a URI it (an operator, via GitOps config) explicitly registered, never to a value a request parameter alone can select unchecked. |
| Authorization-code substitution across clients (a code minted for client A redeemed by client B) | The stored `AuthorizationCode` (Decision 1) binds `client_id` **and** the exact `redirect_uri` presented at `/authorize` time; `consume_code` at the token endpoint re-validates both against the presented values, per RFC 6749 §4.1.3 ("ensure that the `redirect_uri` parameter is present if the `redirect_uri` parameter was included in the initial authorization request... and if included ensure that their values are identical"). A code minted for one client/redirect pair is rejected for any other. |
| PKCE enforcement risk (a code intercepted by a malicious app on a shared device) | **Mandatory for every public client** — `require_pkce: true` (the field already exists on `authkestra_op::ClientRegistration`, currently unused because no client sets it), `S256` only, never `plain`. `governance-auth`'s own device-flow implementation already proves this pattern out in this org (`lightbridge-governance/app/governance-auth/tests/device_flow.rs`), and Decision 1's authorization-code path holds the same bar. Confidential clients (still `private_key_jwt`-only, ADR-0011 Decision 6 unaffected) may additionally use PKCE but are not exempted from redirect-URI exact-match. |
| No dynamic client registration surface | Unaffected and reaffirmed: clients are still sourced from GitOps'd YAML config only (ADR-0011 Decision 5's "sourced from config, not a database" clause is the one part of that decision this ADR keeps standing), never a runtime registration endpoint. This is a deliberate, narrower surface than a "full OIDC provider" would offer — the registry grows only through a reviewable config diff, the same GitOps property ADR-0012's Context argued for over ad-hoc Keycloak realm edits. |

**The honest net position**: this ADR trades "no redirect-URI surface exists" for "a
tightly-constrained redirect-URI surface exists, gated by exact-match, PKCE, and code-binding."
That is strictly more attack surface than ADR-0012's zero, not a wash — the mitigations bound it,
they do not eliminate it. The justification for accepting that trade is the owner's stated goal
(retire token-exchange for most clients) combined with there being no way to serve a browser client
without *some* redirect step; RFC 8628 has no browser-redirect equivalent for a client that is
itself the user-agent.

`ClientRegistration.redirect_uris` and `require_pkce` (both already present on the upstream
`authkestra_op` type, just unused by every client registered so far) are the only fields this
decision newly activates — no new upstream dependency, no schema change to `authkestra-op` itself.

### 3. Client-to-flow assignment

- **Device grant (RFC 8628) — headless CLIs.** opencode and any future CLI in the same shape.
  Unchanged from ADR-0012 Decision 1; this ADR adds nothing here beyond restating that the
  headless-CLI argument that motivated ADR-0012 is unaffected. The opencode chart's own README
  (`ai-helm/charts/librechat-opencode-wellknown/README.md`) already documents why: the plugin's
  default `authorization_code` flow "binds a localhost callback port and breaks headless use."
- **Authorization-code + PKCE (`/authorize`) — browser clients.** `lightbridge-ss`, the self-service
  dashboard, is the concrete first mover: it is already a `public` client
  (`oauth2.clients` config, ADR-0011 Decision 5) requesting `openid profile email offline_access`
  via token-exchange today, presenting a `subject_token` it must obtain some other way first. It
  becomes a real `authorization_code` client with `require_pkce: true` and a registered
  `redirect_uris` entry (its own callback route). Any future browser-hosted client (a support
  console, an admin UI) follows the same shape.
- **Stays on token-exchange, deliberately, and why**: `lightbridge-mcp` — a `confidential`,
  `private_key_jwt`-authenticated **server-side** client (ADR-0011 Decision 5) that receives an
  already-obtained bearer credential from its own caller and exchanges it for a scoped downstream
  token. It is not a human logging in and never runs a browser redirect; RFC 8693 is precisely the
  grant designed for "I already hold a token, give me a different one for a different audience,"
  which is exactly `lightbridge-mcp`'s situation. Any future purely server-to-server integration
  with the same shape (already holds a credential, needs a re-scoped one, never touches a browser)
  stays on token-exchange for the same reason. **"Most clients" in the owner's instruction reads as
  "every client whose credential today originates from a human interactively authenticating" —
  `lightbridge-ss` and future CLIs — not literally every client of `/oauth2/token`.**

### 4. `sub` is still never minted — brokering does not change subject ownership

Unchanged from ADR-0006 and restated, unaltered, from ADR-0012 Decision 5: `accounts.id` is the
caller's JWT `sub`, sourced from Keycloak and never rewritten or regenerated into this service's own
CUID2 format (ADR-0039). Both new flows terminate in the same Keycloak-hosted login the device grant
already redirects to; the `sub` on a token minted after a completed `/authorize` exchange is copied
verbatim from that Keycloak session, exactly as the device grant and the existing token-exchange
grant already do. This ADR adds no login flow of its own, adds no user store, and does not change
who authenticates the user — only which standard grant a given client uses to obtain a credential
asserting that authentication happened.

### 5. Discovery document gains a real `authorization_endpoint`, gated correctly

`discovery_document` (`signing.rs`) currently unconditionally empties
`response_types_supported`/`response_modes_supported` and drops `authorization_endpoint` — by
design, per its own doc comment's "Authorization endpoint — never advertised, in either state."
That is no longer true once `/authorize` exists. Following the same three-independent-gates
discipline that comment already establishes (the exact discipline that prevented the earlier
`response_types_supported` production bug it documents): `authorization_endpoint`,
`response_types_supported` (at minimum `["code"]`), and `response_modes_supported` (at minimum
`["query"]`) become a **fourth**, independently-gated capability — true only when the
authorization-code grant is actually mounted, following the same "gate on what is actually mounted,
not on an unrelated flag" rule the existing comment insists on. `device_authorization_endpoint` and
the device grant type join `grant_types_supported` on the same principle once ADR-0012's own
implementation lands (tracked by the linked epic, not this ADR).

## Consequences

### Positive

- Answers the owner's instruction directly: `authz-idp` becomes able to serve both a headless-CLI
  population (device grant) and a browser population (`/authorize`) from one broker, closing the
  gap that made token-exchange the only path for a client like `lightbridge-ss` that never actually
  holds a `subject_token` from anywhere else.
- Is the **strategic** fix for the `api_key_id`-as-plane-discriminator class of bug #419 belongs to:
  every client that moves off token-exchange onto a real OIDC flow stops needing to borrow the
  API-key claim shape to get a token minted at all. It shrinks the population exposed to that bug
  class over time.
- `AuthorizationCodeStore` moving from a permanent stub to a real, tested implementation removes a
  discovery-document inconsistency (`authorization_endpoint` genuinely absent when no code is
  possible) that was previously covered by the "this can never be reached" argument — an argument
  that no longer holds once a real caller population exists.

### Negative

- **Explicitly does not fix #419.** Existing token-exchange-issued human-plane tokens keep the
  `lightbridge_caller_kind`/`api_key_id` impersonation until they naturally expire; the claim-naming
  bug needs its own fix, independent of this ADR and not gated by it.
- **Reopens exactly the surface ADR-0012 was pleased to avoid** (Decision 2): a `redirect_uris`
  registry, open-redirect risk (bounded, not eliminated, by exact-match), and authorization-code
  substitution risk (bounded by client+redirect binding at consume time). This is a real increase in
  attack surface accepted for a stated reason (owner's goal), not a free win.
- A second grant-specific store (`AuthorizationCodeStore`, mirroring `DeviceCodeStore`'s shape) is
  new, security-sensitive, CAS-consumed logic needing the same fail-first testing discipline
  ADR-0011's refresh-token work and ADR-0012's `device_authorizations` design already used — real
  implementation and review cost, not a config flip.
- `discovery_never_advertises_response_types_or_modes` must be deliberately rewritten (Context)
  rather than left green by accident — a one-time but non-trivial test-authoring cost, since the
  test's whole point was catching exactly this kind of change happening silently.
- The dashboard's own client-side integration (whatever currently drives its `subject_token`
  acquisition to feed token-exchange) needs a real migration to an authorization-code + PKCE
  redirect flow — a client-side code change, not just a server-side capability flip.

### Neutral / follow-ups

- The exact `/authorize`/token-endpoint request/response shapes, the authorization-code TTL value,
  and whether `authorization_code` storage reuses the `device_authorizations` table's shape or gets
  its own table are implementation decisions for the linked tickets, not decided here.
- Whether any client beyond `lightbridge-ss` needs a browser flow is not decided here — this ADR
  establishes the mechanism and the first mover, not an exhaustive client migration list.
- `AGENTS.md`/`CLAUDE.md`'s "Identity context resolution" section and
  `docs/governance-model-and-enforcement.md` will need updates once client cutover actually happens
  (tracked by the linked epic tickets, not part of this ADR).

## Alternatives considered

- **Keep token-exchange everywhere and fix only the claim naming (#419).** Rejected as the *sole*
  fix — it repairs the immediate incident but leaves the dashboard permanently dependent on
  obtaining a `subject_token` some other way first, which was never actually solved; it does not
  give the owner what was asked (retiring token-exchange for most clients), only a correctly-labeled
  version of the status quo. #419 remains a real, separate ticket regardless of this ADR (Context).
- **Device-grant-only, ADR-0012's current position, unchanged.** Rejected — it solves headless CLIs
  correctly (and this ADR keeps that answer) but has no browser-redirect story at all; RFC 8628 was
  never meant to serve a client that is itself the user-agent presenting a browser to a human.
- **Use Keycloak directly for every client and drop the broker entirely.** Rejected on the same
  grounds ADR-0012's Context already established and this ADR does not relitigate: it reintroduces
  per-client hand-registered Keycloak clients in a realm `ai-helm-values` already flags as an
  unmanaged external dependency, splits the trust domain (`auth.verif.fyi` vs. the product domain),
  and gives up the one thing brokering buys — tenant context (`account_id`/`project_id`) sealed at
  issuance without a second exchange step.
- **A wildcard or prefix-matched `redirect_uris` scheme, to ease client onboarding.** Rejected —
  this is the single most common real-world open-redirect vector in OAuth deployments; exact-match
  costs an extra line in a GitOps config diff per client and buys back the entire class of bug.

## Related

- Supersedes (partially): ADR-0012 (`docs/adr/0012-device-authorization-grant-brokered-via-new-idp-service.md`)
  Decision 3's `AuthorizationCodeStore` half, and Decision 4 in full. Every other ADR-0012 decision,
  including the device-grant half of Decision 3, is unaffected — see Decision 1 above.
- Supersedes (partially): ADR-0011 (`docs/adr/0011-authz-issues-a-full-oidc-token-object.md`)
  Decision 5's `redirect_uris: []` clause — narrowed to "empty for every client not registered for
  the `authorization_code` grant type," not universally empty. Decision 5's "clients are sourced
  from config, not a database" clause is unaffected and explicitly reaffirmed (Decision 2 above).
  Decision 6 (`private_key_jwt`-only for confidential clients, no client secrets) is unaffected.
- Precedent: ADR-0012's own `device_authorizations` design (Decision 7) — the CAS-consume,
  cuid2-id, opaque-secret shape this ADR's `AuthorizationCodeStore` reuses.
- Issue #337 — the epic this ADR re-scopes; see the linked tickets in this ADR's implementing PR for
  the current, code-verified breakdown, which supersedes #337's own (now-stale) phase list.
- Issue #419 — the live incident this ADR is the strategic, not remedial, response to; explicitly
  not fixed by this ADR (Context, Consequences).
- `docs/governance-model-and-enforcement.md` — documents `api_key_id`'s role as gateway plane
  discriminator, the mechanism #419 breaks and this ADR reduces exposure to over time.
- `AGENTS.md` — service list (`authz-idp` entry) and "Identity context resolution" section, both to
  be updated as client cutover lands.
