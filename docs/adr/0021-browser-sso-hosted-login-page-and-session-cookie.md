# ADR-0021: Browser SSO at `authz-idp` via a same-origin hosted login page and a revocable browser-session cookie bound to ADR-0020's `sessions` table

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Stephane Segning Lambou

## Context

**The owner's instruction, in-session, is the source of truth this ADR implements:**

> *"ensure authz can do SSO. It's being a blocker for all late major integrations. We'll do hosted
> page using cookies and forward to Keycloak."*

This is a **blocking design document**, exactly in ADR-0020's sense: it decides the shape, not the
code. No implementation lands in this PR, only the decision and a follow-up ticket breakdown
sequenced against the epic's existing tickets (see "Follow-ups").

### What ADR-0019 already decided, and the one thing it explicitly does not contain

`docs/adr/0019-authz-idp-brokers-authorization-code-alongside-device-grant.md` (Accepted,
2026-08-22) already designed `GET /authorize`, a real `AuthorizationCodeStore`, a `redirect_uris`
registry with exact-match validation, and mandatory PKCE for public clients. It supersedes ADR-0012
Decision 3's `AuthorizationCodeStore` half and Decision 4 in full. **None of this ADR re-decides any
of that** — `/authorize`'s existence, its PKCE requirement, its exact-match `redirect_uris`
registry, and the code/client/redirect-URI binding at redemption time all stand exactly as
ADR-0019 left them.

What ADR-0019 does not contain, verified by rereading it in full: **no cookie, no browser session,
no concept of "the browser is already authenticated" anywhere in the document.** Its only use of
the word "SSO" is quoting the owner's original instruction in its own Context section. Every
`/authorize` hit ADR-0019 designs terminates in the same place: "a redirect to Keycloak's own
hosted login" (Decision 1), unconditionally, every single time. That is a broker, not SSO — a
browser client gets a real authorization-code+PKCE flow instead of the token-exchange workaround,
but a user who authorizes two different client apps back-to-back still authenticates against
Keycloak twice, with no memory between them. **This is the precise gap this ADR closes**: a
same-origin hosted login page plus a session cookie that lets a second, third, or Nth `/authorize`
call skip the Keycloak round-trip entirely, for a bounded time, after the first one.

### Verified current state (against `origin/main`, not this worktree)

- `NoAuthorizationCodeStore`/`NoDeviceCodeStore`
  (`crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs:1-119`) are still no-op stubs today
  — `store_code` always `Err(OpError::InvalidCode)`, `consume_code` always `Ok(None)`, every
  `DeviceCodeStore` method errors or returns `None`. Neither ADR-0019 nor ADR-0012's device grant
  has landed any real implementation yet.
- `discovery_document` (`crates/lightbridge-authz-rest/src/signing.rs:495-582`) still
  unconditionally empties `response_types_supported`/`response_modes_supported`
  (`signing.rs:516,536`) and removes `authorization_endpoint` from the serialized document
  (`signing.rs:576`), regardless of `oauth2.token_exchange.enabled`. `grant_types_supported`
  (`signing.rs:504-511`) only ever contains `token-exchange`/`refresh_token`.
  `device_authorization_endpoint` is not a field this function sets at all. Live discovery at
  `auth.ai.camer.digital` (AGENTS.md) matches this code exactly.
- `access_token_extra` (`crates/lightbridge-authz-rest/src/signing.rs:224-267`) still mints `sid`
  inline at line 245 — `extra.insert("sid".to_string(), Value::String(cuid2()));` — with no
  persisted row behind it. ADR-0020's `sessions` table does not exist in any migration yet; none of
  ADR-0020's own Follow-ups have landed.
- Open tickets under epic #337, re-verified via `gh issue view` against the live repo, not assumed
  from the epic's stale checklist: **#423** (real `DeviceCodeStore`), **#424** (RP leg to Keycloak +
  device-grant verification page, blocked on #423), **#425** (`/authorize` +
  `AuthorizationCodeStore` + `redirect_uris` + PKCE, blocked on #424), **#426** (discovery
  advertises the new endpoints, blocked on #423-#425), **#427** (client cutover, blocked on #426).
  **None of these tickets mention a cookie, a browser session, or a hosted login page anywhere in
  their text.** #424 explicitly frames the RP leg as shared infrastructure for two callers — "the
  device-grant verification page (this ticket) and `/authorize`'s browser redirect (the next
  ticket, per ADR-0019)" — written before this ADR existed, so it anticipated `/authorize` always
  redirecting to Keycloak, never a cookie-satisfied shortcut. This ADR changes that assumption for
  #424/#425 (see "Follow-ups").
- Root `Cargo.toml`'s `authkestra-*` block pins `authkestra-resource`/`authkestra-op`/
  `authkestra-engine` at exactly `=0.5.1` in lockstep (`Cargo.toml:117-119`). `authkestra-oidc` is
  not a dependency anywhere in this workspace (`grep -rn authkestra-oidc` returns nothing).
  `tower-http` is pinned with only the `cors` feature (`Cargo.toml:155`) — no `fs` feature, so no
  static-file-serving capability exists in this workspace today. No cookie-handling crate
  (`axum-extra` with a `cookie` feature, `tower-cookies`, or similar) is a dependency anywhere.

### Relationship to ADR-0020: extend the seam it already built, do not invent a parallel one

`docs/adr/0020-sessions-are-a-first-class-revocable-table.md` (Accepted, 2026-08-23, merged PR
#435) gives this service, for the first time, a durable, revocable `sessions` table plus
`session:read-own`/`session:read`/`session:revoke-own`/`session:revoke` authority and
`listMySessions`/`revokeOwnSession`/`revokeSubjectSessions`-shaped procedures. Its own scope,
stated explicitly in its Decision 1, is **every access token** — a session row exists so that a
bearer JWT with a `sid` claim can be looked up and revoked. A browser SSO cookie is a genuinely
different kind of credential: it never appears as a bearer token anywhere, it exists purely to
answer one question at `/authorize` time — "has this browser already completed a real Keycloak
login recently enough to skip doing it again?" — and it is not scoped to any one downstream OAuth
client, by design (that is the entire point of SSO: one login, many client authorizations).

**Decision 3 below is the answer to the task's explicit instruction not to invent a second,
parallel session concept**: the browser cookie's value is an id of a row in the *same* `sessions`
table ADR-0020 built, not a new table, new claim name, or bespoke cookie-signing scheme. Getting
this right is what keeps "log out everywhere" (ADR-0020's existing bulk procedures) and "log out of
this browser" in agreement, rather than two commands that can silently disagree about what "this
session" means.

### Sequencing against ADR-0020's own Follow-ups 1/2/4

ADR-0020's Consequences/Negative section states plainly: *"Decisions 1, 2, and 4 are one coherent
unit... The implementation ticket must land Decisions 1/2/4 together."* That table, that minting
correction, and that introspection check do not exist in `origin/main` yet (verified above). This
ADR's own new schema (Decision 3's `kind` column) and new code (Decision 1's hosted page, Decision
5's RP leg reuse) all sit on top of a `sessions` table that must exist first. **This ADR's
implementation cannot start before ADR-0020 Follow-up 1 (the migration + cratestack model) lands**,
and the `kind` column this ADR adds (Decision 3) should be folded into that same migration rather
than shipped as a second `ALTER TABLE` immediately behind it — the table does not exist in
production yet, so there is no live-data cost to getting the full column set right in one
migration. This ADR's cookie-issuance code additionally depends on ADR-0020 Follow-up 2's minting
correction being live (a real, resolvable session id must be creatable before a browser flow can
create one the same way), though it does not depend on ADR-0020 Follow-up 4 (the introspection
check) at all — introspection consults sessions referenced by a bearer token's `sid` claim, which a
browser cookie's session row never is.

## Decision

### 1. The hosted page is a same-origin Vite React static build, served by `authz-idp` itself; Rust owns every protocol step

> **Update (2026-08-31, follow-up to #591):** the page's **source home moved out of this
> repository** to `converse-frontends`' `apps/authz-ui`; `web/hosted-login/` is deleted and this
> repo builds no JavaScript. **Nothing this Decision argues has changed.** The two load-bearing
> properties are unaffected: the bundle is still served **same-origin** by `authz-idp`'s own Axum
> server (so the `__Host-` cookie prefix of Decision 4 remains available), and there is still
> **one authentication boundary in Rust** — the page remains pure presentation, makes no
> authentication decision, and every redirect, `Set-Cookie` and ID-token verification still happens
> in this codebase. What changed is only *who compiles the HTML*: the bundle arrives as a
> digest-pinned, assets-only OCI artifact rather than from an `npm ci` in this repo's `Dockerfile`.
> "Explicitly rejected: a separately deployed Next.js frontend" still stands and is **not** what
> this is — a separately *built* artifact served from this origin is the opposite of a separately
> *deployed* origin. See **ADR-0029** for the artifact contract, the pin policy and the
> version-skew rule.

The login/consent UI is a Vite React project, built to static assets, and served from
`https://auth.ai.camer.digital` — the same origin as the issuer, by `authz-idp`'s own Axum server,
not a separately deployed frontend. This is not the default choice for a UI team and is adopted
here for two concrete, load-bearing reasons, not convenience:

- **Same-origin is what makes the `__Host-` cookie prefix available at all** (Decision 4). The
  `__Host-` prefix forbids a `Domain` attribute and requires `Secure` + `Path=/` — the strictest
  cookie scoping the platform offers, binding the cookie to exactly one origin with no subdomain
  leakage possible even by misconfiguration. A separately deployed frontend (a different origin,
  even a subdomain of the same parent domain) cannot share this cookie without either giving up the
  `__Host-` prefix (falling back to a `Domain`-scoped cookie, which is strictly weaker: it becomes
  readable/settable by any subdomain of that `Domain`) or routing every UI request back through
  `auth.ai.camer.digital` anyway, at which point the separate deployment buys nothing but an extra
  network hop and a second set of secrets.
- **One authentication boundary in the fail-closed Rust codebase, not two.** This repo's own review
  priority #1 (`AGENTS.md`, "Code Style Guidelines") is "does the unavailable branch become the
  permissive branch" — the single highest-yield question on every review here, because this service
  is the authentication boundary for every protected service on the platform. Splitting the cookie
  logic and the OIDC RP-leg/callback logic across two runtimes (a Next.js frontend owning cookies or
  the Keycloak callback, and this Rust service owning the rest) means that class of bug can now hide
  in a second codebase this repo's clippy lint gates, `rustfmt`, `deny.toml` supply-chain policy,
  and testing discipline (`AGENTS.md`, "Testing rules that have caught real bugs here") do not cover
  at all. The page is pure UI — it renders what the server tells it to render and never makes an
  authentication decision itself; every redirect, every cookie `Set-Cookie`, every ID-token
  verification happens in Rust.

**Explicitly rejected, with reasons** (see "Alternatives considered" for the full argument):
a separately deployed Next.js frontend, and a Next.js app that owns the RP leg to Keycloak while
this service owns only the OAuth broker surface.

### 2. A full local session with a short TTL — `/authorize` is satisfied outright by a valid cookie; Keycloak is contacted on first login and after TTL expiry only

Once a browser holds a valid session cookie, `GET /authorize` for *any* registered client does not
redirect to Keycloak at all — it mints an authorization code directly and redirects back to the
requesting client's `redirect_uri`, exactly as if the user had just finished a Keycloak login.
Keycloak is contacted in exactly two cases: the browser presents no cookie (first login), or the
cookie references a session row that is `revoked`/`expired`/not found.

**Proposed default TTL: 8 hours (28,800 seconds), absolute from creation, not sliding.** Reasoning:

- This repo does not control the Keycloak realm's own SSO session settings — `ai-helm-values`
  flags the `camer-digital` realm as an explicitly external dependency (AGENTS.md quotes this for
  the JWKS URL; the same caveat applies to whatever idle/max session timeouts that realm is
  configured with). The TTL proposed here is chosen to bound this service's own exposure
  independent of Keycloak's configuration, not calibrated against an assumed Keycloak default this
  repo cannot verify without deploying and observing a system it does not own.
- It sits deliberately between this service's two existing TTL precedents, for a reason specific to
  what this cookie controls. `oauth2.token_exchange.access_ttl_seconds` defaults to 900s/15 minutes
  (`config/mod.rs:891-894`) — too short for SSO's actual purpose, which is letting one login cover
  several client-app authorizations across a working session, not one request.
  `refresh_absolute_ttl_seconds` defaults to 90 days (`config/mod.rs`, per ADR-0020 Context point
  6) — that TTL bounds a *renewable* credential the user is actively using; this cookie instead
  bounds how long this service goes **without re-checking the strongest signal it has** (a live
  Keycloak authentication). Letting that gap run for weeks or months would mean an offboarded
  user's browser stays capable of silently minting new authorization codes for that entire window
  with zero re-verification against the identity provider that is the actual source of truth for
  "is this person still allowed to log in."
- **The tradeoff, stated as directly as the task requires**: an upstream-offboarded user (disabled
  in Keycloak, or removed from `project_members`) whose browser already holds a valid session
  cookie keeps a working browser session — able to skip Keycloak and keep authorizing client apps —
  until either the cookie's 8-hour TTL elapses or an operator explicitly revokes it. **This is
  exactly why the TTL is short, and exactly why explicit revocation must exist as the fast path,
  not a nice-to-have**: TTL is the automatic backstop for the case where nobody remembers to call
  revocation; `revokeSubjectSessions`/`revokeSession` (ADR-0020, extended by Decision 3 below to
  also cover browser-kind rows) is the immediate path for the case where an operator does. Framed
  the other way: the 8-hour number bounds "how bad is it if revocation is forgotten," not "how long
  does an offboarded user keep access" — an explicit `revokeSubjectSessions` call kills a browser
  session (and every downstream token session it spawned — Decision 3) immediately, regardless of
  where the browser is in its TTL window, the same bounded-not-instant guarantee ADR-0020 Decision
  5 already established for token sessions (Authorino's 30s introspection cache; here, the
  equivalent bound is simply "the next `/authorize` call after revocation," since there is no cache
  layer sitting in front of this table's `SELECT` at all).
- Configurable, not hardcoded: a new config field (implementation ticket's choice of name, e.g.
  `oauth2.browser_session_ttl_seconds`, following the existing `access_ttl_seconds`/
  `refresh_ttl_seconds` naming convention in `config/mod.rs`), live from day one at the 8-hour
  default — this is an operational tuning knob every deployment can adjust, not a feature flag
  gating whether the behavior exists at all (`AGENTS.md`'s "no dormant flags" convention).

First login through Keycloak, cookie issuance, and a later `/authorize` for a *different* client
served entirely locally — `(new)` marks code this ADR's implementation tickets add; everything else
already exists on the path today:

```mermaid
sequenceDiagram
    participant Browser
    participant AuthzIdp as authz-idp /authorize<br/>(ADR-0019 Decision 1 + this ADR, new)
    participant RPLeg as RP leg<br/>(#424, hand-written per Decision 5, new)
    participant Keycloak
    participant Sessions as sessions table<br/>(ADR-0020 Follow-up 1;<br/>kind column, this ADR, new)

    Note over Browser,Sessions: --- first login: lightbridge-ss sends the browser here ---
    Browser->>AuthzIdp: GET /authorize?client_id=lightbridge-ss&redirect_uri=...&state=S1&code_challenge=...<br/>(cross-site top-level nav, no cookie yet)
    AuthzIdp->>Sessions: SELECT status, expires_at WHERE id = <no cookie> [new]
    Sessions-->>AuthzIdp: not found
    AuthzIdp->>RPLeg: no valid browser session -> start Keycloak redirect
    RPLeg->>RPLeg: generate state2/nonce/PKCE,<br/>encrypt via OAuth2State::encrypt [new]
    RPLeg-->>Browser: 302 to Keycloak /auth?...state2...
    Browser->>Keycloak: GET (user authenticates)
    Keycloak-->>Browser: 302 to RP-leg callback ?code=...&state=state2
    Browser->>RPLeg: GET /idp/callback [new]
    RPLeg->>Keycloak: POST token endpoint (exchange code)<br/>[fail-closed: unreachable/error -> refuse, Decision 6]
    Keycloak-->>RPLeg: id_token, access_token
    RPLeg->>RPLeg: validate_jwt_generic w/ RS256-only,<br/>issuer, audience, kid check<br/>(mirrors lightbridge-authz-bearer/src/lib.rs:146,200,232-240,252,265)<br/>[fail-closed on any failure, Decision 6]
    RPLeg->>Sessions: INSERT session (id=cuid2(), kind='browser',<br/>client_id=NULL, expires_at=now()+8h) [new]
    Sessions-->>RPLeg: committed
    RPLeg-->>Browser: Set-Cookie: __Host-authz_session=<session.id><br/>(Secure, HttpOnly, SameSite=Lax, Path=/, no Domain)<br/>302 back into the original /authorize (resume S1)
    AuthzIdp->>AuthzIdp: mint AuthorizationCode bound to<br/>client_id + redirect_uri (#425, new)
    AuthzIdp-->>Browser: 302 lightbridge-ss redirect_uri?code=...&state=S1

    Note over Browser,Sessions: --- later: same browser, a DIFFERENT client app ---
    Browser->>AuthzIdp: GET /authorize?client_id=other-app&...&state=S2<br/>(Cookie: __Host-authz_session=<session.id>)
    AuthzIdp->>Sessions: SELECT status, expires_at WHERE id = <session.id> [new]
    Sessions-->>AuthzIdp: status = active, not expired
    AuthzIdp->>AuthzIdp: mint AuthorizationCode for other-app<br/>(Keycloak never contacted)
    AuthzIdp-->>Browser: 302 other-app redirect_uri?code=...&state=S2
```

### 3. Bind the browser session to ADR-0020's `sessions` table — a new `kind` column, not a parallel concept

The cookie's value is the bare, opaque `id` of a row in ADR-0020's `sessions` table — the exact
same table `sid` will reference once ADR-0020 Follow-up 2 lands, minted via
`lightbridge_authz_core::cuid::cuid2()` (`crates/lightbridge-authz-core/src/lib.rs:28`, ADR-0039)
the same way every other session row is. **This is the one piece of schema ADR-0020 did not and
could not anticipate**, because ADR-0020's own scope was "every access token needs a revocable
identity" — a browser cookie is never presented as a bearer token anywhere and is not scoped to one
OAuth client, so it needs a discriminator ADR-0020's original column set has no room for:

**New column: `sessions.kind` — `'token'` (ADR-0020's original scope, one row per OAuth
grant/refresh chain, always has a `client_id`) or `'browser'` (this ADR, one row per completed
Keycloak login in one browser, `client_id` always `NULL`).** Concretely, what a browser-originated
row carries that a token-originated one does not:

| Field | `kind = 'token'` (ADR-0020) | `kind = 'browser'` (this ADR) |
|---|---|---|
| `client_id` | always set — the registered OAuth client this grant was issued to | always `NULL` — a browser session is not scoped to any one client; that is the entire point of SSO |
| Created by | `handle_token_exchange`/the future `/oauth2/token` `authorization_code` redemption (#425) | the RP-leg callback (#424), on a *verified* Keycloak authentication — never by `/authorize` itself, never speculatively |
| Referenced by | a minted access token's `sid` claim (ADR-0020 Decision 2) | a `__Host-` cookie value only — never appears inside any JWT |
| Cardinality per login | one row per grant/refresh chain — a user authorizing 3 client apps in one browser session produces 3 separate `kind='token'` rows | one row per Keycloak login — that single row is what lets all 3 of those client authorizations skip Keycloak |
| `user_agent` purpose (ADR-0020 Decision 7) | secondary — "which app/device holds this token" | primary — this is literally what "log out that one browser" means to a human reading a session list |

Multiplicity follows directly from this: one `kind='browser'` row can outlive and sit
"upstream" of several `kind='token'` rows created while it was valid, each independently listed
(`listMySessions`) and independently revocable (`revokeOwnSession`) — revoking one downstream token
session (e.g., "log out this one app") never touches the browser session that spawned it, and vice
versa unless the bulk cascade (below) is used.

**Bulk revocation must cover both kinds, or "log out everywhere" lies.** ADR-0020 Decision 9
already specifies that `revokeOwnSessions`/`revokeSubjectSessions` cascade to revoke the
`exchange_refresh_tokens` rows chained under each revoked `kind='token'` session. This ADR extends
that same cascade requirement: both bulk procedures must also flip every `kind='browser'` row for
the subject to `revoked`. Without this, an admin calling `revokeSubjectSessions` on an offboarded
user would correctly kill every issued token but leave that user's browser cookie silently valid
until its 8-hour TTL — exactly the gap Decision 2's tradeoff section warns about, reopened by an
incomplete cascade. `session:revoke-own`/`session:revoke` need no new permission for this — the
existing gate already covers "every session for this subject," it is the *query* underneath each
procedure that must stop being `kind`-blind.

A `kind='browser'` row's lifecycle, following ADR-0020 Decision 6's own three-state shape exactly
(`active`/`revoked`/`expired`, no reachable reverse transition), with the transitions specific to
this ADR marked `(new)`:

```mermaid
stateDiagram-v2
    [*] --> active: created only after a VERIFIED Keycloak\ncallback (RP leg, #424, new) -- never\nbefore, per the session-fixation rule\n(Decision 8); row itself lives in ADR-0020's\nsessions table (Follow-up 1, new column: kind)
    active --> active: a later /authorize hit with a valid\ncookie reuses the SAME row -- no re-mint,\nno TTL extension (fixed, non-sliding TTL,\nDecision 2) [new]
    active --> revoked: revokeOwnSession(sessionId) / revokeSession\n(existing, ADR-0020) OR revokeOwnSessions /\nrevokeSubjectSessions (existing, bulk,\nrpc_authorize.rs:361-362 -- cascade to\nkind='browser' rows is this ADR's addition) [new query]
    active --> expired: now() > expires_at\n(computed at read time, same pattern\nADR-0020 Decision 6 uses for kind='token' rows)
    revoked --> [*]: terminal -- log out this browser;\nnext /authorize forces a fresh Keycloak login
    expired --> [*]: terminal -- 8h TTL elapsed;\nnext /authorize forces a fresh Keycloak login
```

**Unreachable by design, stated explicitly per this repo's own "draw the state machine, don't just
describe it" rule** (the same discipline ADR-0020 Decision 6 already applied): `revoked -> active`
and `expired -> active` do not exist as transitions anywhere in this design — there is no
"reactivate my browser session" capability, matching ADR-0020's own stance that reopening a revoked
session would need its own ADR. A session-lookup **error** (DB unreachable, Decision 6) is
deliberately **not** a node in this diagram at all: it is not a persisted state a row can be in, it
is a transient read failure at `/authorize` time that this ADR resolves by treating the *call* as
if no session were found — the row itself, if it exists, stays `active` in the database, unchanged,
and the next successful lookup finds it exactly as it was.

### 4. Cookie attributes, each justified

| Attribute | Value | Why |
|---|---|---|
| Name prefix | `__Host-` (e.g. `__Host-authz_session`) | The strictest cookie-scoping mechanism the platform offers; forbids `Domain`, requires `Secure` + `Path=/`, and is enforced by the browser itself — a misconfigured server cannot accidentally widen this cookie's scope, only Decision 1's same-origin architecture makes it available at all |
| `Secure` | set (implied and enforced by `__Host-`) | Never transmitted over plain HTTP; this service is TLS-only end to end already (AGENTS.md, "run with TLS") |
| `HttpOnly` | set | The React app never needs to read this cookie's value — it relies on the browser auto-attaching it to same-origin requests. There is no client-side code path that legitimately reads a raw session id, so denying script access closes an entire XSS-exfiltration vector for free |
| `SameSite` | `Lax` — deliberately, not `Strict` | `/authorize` is reached by a **cross-site, top-level GET navigation** initiated by the requesting client app (e.g. `lightbridge-ss` on a different origin navigating the whole page to `https://auth.ai.camer.digital/authorize?...`). `SameSite=Strict` cookies are withheld on exactly this kind of cross-site top-level request in modern browsers — choosing `Strict` here would not error, it would **silently** make every `/authorize` call behave as if no cookie exists, forcing a full Keycloak redirect every single time and defeating the entire feature without any visible failure. `SameSite=Lax` is the correct choice specifically because it still attaches the cookie on safe (GET), top-level, cross-site navigation while still withholding it from cross-site subresource requests and unsafe methods (POST) — the standard SSO cookie posture |
| `Path` | `/` | Required by `__Host-`; also correct on its own merits — the cookie must be visible to `/authorize`, the RP-leg callback route, and any future session-management UI route, all of which live at this origin's root |
| `Domain` | absent (forbidden by `__Host-`) | The cookie is scoped to exactly `auth.ai.camer.digital`, not any parent or sibling domain — no subdomain of the product domain can read or set it |
| Value | the bare `sessions.id` (an opaque CUID2, ADR-0039) | Not a JWT, not a signed/encrypted blob. Every `/authorize` call already requires a DB round-trip to check `status`/`expires_at` fail-closed (Decision 6), so a stateless self-contained cookie buys no latency win and would reintroduce exactly the "cannot revoke mid-lifetime" problem ADR-0020 exists to solve — for the access-token case already. Doing that again for the browser cookie would be a regression, not a design choice (see "Alternatives considered") |
| `Max-Age` / `Expires` | Decision 2's TTL (8h default), mirrored from `sessions.expires_at` | The **server-side row's `expires_at` is the authoritative boundary**, re-checked on every `/authorize` hit (Decision 6) — the cookie's own expiry is a convenience for the browser to stop sending a definitely-dead cookie, not the security boundary itself, matching ADR-0020 Decision 6's "expired... computed at read time" pattern applied here to a second table row kind |

### 5. The RP leg to Keycloak: DECIDED — hand-write it, do not adopt `authkestra-oidc`

No outbound OIDC-client HTTP call to Keycloak exists anywhere in this workspace; every existing
interaction with the identity layer is inbound (JWKS fetch, JWT presentation). #424's own text
framed this as an open choice between adopting `authkestra-oidc` (pinned `=0.5.1` to match the
family's lockstep) or hand-writing the RP leg, and asked for the pinned version's actual capability
to be verified before committing, "this repo has been burned before by assuming a capability claim
without re-verifying against the exact pinned version." **That verification has now been done, as
a concurrent spike, by tracing the real source of `authkestra-oidc` 0.5.1 (not its documentation),
and its result settles this decision — it is recorded here as accepted, not left open for #424 to
re-litigate.**

**Decision: hand-write the RP leg, on top of primitives this workspace already depends on directly.
Do not add `authkestra-oidc`.**

`authkestra-oidc` 0.5.1 is not rejected for version drift — it matches the workspace's existing
lockstep pin exactly, so adopting it would not by itself create a new pin to track. It is rejected
because its one entry point for this exact job, `OidcProvider::exchange_code_for_identity`,
hardcodes `jsonwebtoken::Validation::default()` when verifying the ID token it receives back from
the identity provider, and that default is unsafe for this use case in three independent, stacking
ways:

- `algorithms: [HS256]` only — every RS256-signed Keycloak token (what this deployment's JWKS
  already serves, per `lightbridge-authz-bearer`'s own `ACCEPTED_ALGORITHMS: [Algorithm; 1] =
  [Algorithm::RS256]`, `crates/lightbridge-authz-bearer/src/lib.rs:146`) would be rejected outright
  by this default, not merely unverified.
- `iss: None` — **the issuer is never checked at all.** This is not a missing convenience feature;
  it is a fail-open gap in exactly the dimension this repo's review priority #1 exists to catch — a
  library silently skipping a check whose absence is indistinguishable from success.
- `aud: None` with `validate_aud: true` — `jsonwebtoken`'s own match arm for this combination
  (`(TryParse::Parsed(_), None) => Err(InvalidAudience)`) means any token that *carries* an `aud`
  claim, which every real Keycloak-issued ID token does, is unconditionally rejected. Not
  insecure-permissive here, but broken: this alone would make `authkestra-oidc` unable to complete
  a real login against Keycloak at its current pinned version.

There is no builder or setter on `OidcProvider` that allows overriding this `Validation` — using it
safely would require forking the crate, not configuring it. A second, independent defect compounds
this — but in the fail-**closed**, not fail-open, direction, corrected here after re-tracing the
real published source: `OidcProvider::exchange_code_for_identity` *does* correctly validate the
nonce it receives as a parameter against `claims.nonce` from the verified ID token
(`authkestra-oidc` 0.5.1 `src/provider.rs:277-282`); the defect is that when it then builds the
returned `Identity`, it inserts only `"picture"` into `attributes` (`src/provider.rs:287`) —
`"nonce"` is never written there. `authkestra-engine`'s `OAuth2Flow::finalize_login` performs a
*second*, redundant nonce check by reading `identity.attributes.get("nonce")` back out
(`authkestra-engine` 0.5.1 `src/flow/oauth2.rs:192-197`), which is therefore always `None`,
while `OAuth2Flow::initiate_login` generates a nonce unconditionally for every flow with no
opt-out (`src/flow/oauth2.rs:128`), so the value on the other side of that comparison is always
`Some(...)`. `Some(...) != None` is always true, so the composition returns
`Err("Nonce mismatch")` on *every* login through it — nonce validation (Decision 7's second
CSRF-relevant control) is redundant and totally broken here, blocking all logins through this
composition, not a silent no-op that would let a forged or replayed nonce through undetected. The
distinction matters for a security ADR specifically: describing a fail-closed defect as fail-open
points a future reader in exactly the wrong direction.

**What hand-writing costs, concretely: nothing new in the dependency graph.** Every primitive an RP
leg needs is already a direct workspace dependency at the same `=0.5.1` pin, just not yet composed
for this purpose:

- `authkestra_engine::auth::discovery::ProviderMetadata::discover` — OIDC discovery against
  Keycloak's own `.well-known/openid-configuration`, so this service does not hardcode Keycloak's
  endpoint shape.
- `authkestra_engine::auth::pkce::Pkce` — correct PKCE `code_verifier`/`code_challenge` generation,
  reusable for the RP leg's own outbound leg to Keycloak (a separate PKCE pair from whatever the
  original client presented to `/authorize`, exactly as ADR-0012 Decision 1's device-flow
  verification page already keeps this service's outbound leg and the inbound client leg
  independent).
- `authkestra_engine::auth::state::OAuth2State::{encrypt,decrypt}` — AES-256-GCM-protected
  transport for the pending flow's own `state`/`nonce`/PKCE verifier (Decision 7/8) — `aes-gcm`
  already resolves in the lockfile as a transitive dependency of this same crate, so this is not a
  new supply-chain addition either.
- `authkestra_resource::jwt::{JwksCache, ValidationConfig, validate_jwt_generic}` — a genuinely
  configurable validator, unlike `authkestra-oidc`'s hardcoded default: `.issuer()`, `.audience()`,
  `.algorithms()` builder methods that actually take effect.

**The load-bearing precedent: `lightbridge-authz-bearer` already uses that last primitive correctly,
in production, for a structurally identical problem — verifying an externally-issued RS256 JWT
against a JWKS this service does not control.** `crates/lightbridge-authz-bearer/src/lib.rs:200`
builds a `ValidationConfig` explicitly; line 146 fixes the algorithm allowlist to RS256 only; lines
232-240 add an explicit `kid`-presence check the upstream library does not enforce on its own
(`authkestra_resource`'s key lookup falls back to the JWKS's first key when `kid` is absent, which
this service's own code deliberately refuses to allow); line 252 sets an explicit multi-audience
match the crate's own single-value `.audience()` cannot express directly; line 265 calls
`validate_jwt_generic` with that hardened configuration. **The RP leg's own ID-token verification
should copy this exact pattern, not invent a second one.** Running two different JWT-verification
postures in one authentication service — a hardened, explicit one for inbound bearer tokens and a
second, ad hoc one for the outbound RP leg — would itself be a defect worth flagging in any review
of the implementation ticket, independent of whether either individually passes review.

`reqwest` (`Cargo.toml:158`, `version = "0.13"`, features `["json", "form"]`) is already a direct
dependency of `lightbridge-authz-rest`, so the RP leg's outbound HTTP calls to Keycloak's token
endpoint need no new HTTP-client dependency either. `deny.toml` carries no `[bans]` section, so
nothing there constrains or blesses this choice either way.

**Stated honestly, not overclaimed**: this decision rests on a static trace through
`authkestra-oidc`/`jsonwebtoken` 11.0.0's real vendored source, not an observed failure against a
live Keycloak — no end-to-end login was actually run against either path as part of reaching this
decision. The read that `authkestra-oidc` is a low-adoption crate rests only on public download
counts, not a deeper claim about its maintenance. Both caveats are real; neither changes the
conclusion, since the three defects above are structural (present in the pinned version's own
source, not a runtime-dependent edge case), but a reviewer of the implementation ticket should still
expect the first real end-to-end Keycloak login test to be the actual proof, not this analysis
alone.

### 6. Fail-closed, per dependency — including one place the direction of "closed" is not the obvious one

This repo's review priority #1 (AGENTS.md) applies at full force to every new dependency this
design introduces. Four distinct failure modes, each stated explicitly because getting any of them
backwards is the exact class of bug that priority exists to catch:

- **Browser-session lookup at `/authorize` time (DB unreachable, timeout, malformed row) — fails
  toward *requiring* Keycloak, not toward trusting the cookie.** This is the one place in this
  design where "unknown routes to the strictest branch" does **not** mean "propagate an error and
  refuse the whole request," and the reason is worth stating precisely so it is not miscopied from
  ADR-0020's introspection pattern: ADR-0020's session check answers *"should this bearer token be
  treated as currently granting access to a protected resource"* — answering yes on an unknown
  state is a security bypass, so it must hard-fail. This design's session check instead answers
  *"may this `/authorize` call skip the stronger, explicit form of authentication (a real Keycloak
  login) as a convenience"* — answering **no** on an unknown state (i.e., falling through to a full
  Keycloak redirect) is not a bypass, it is the strictest available answer to *that* question,
  because it forces the stronger credential rather than trusting a possibly-invalid shortcut. A
  lookup error must never be read as "cookie is valid, skip Keycloak" — the only two acceptable
  outcomes for a lookup error are "treat as no valid session" (fail toward more authentication) or
  "hard-refuse the whole `/authorize` call" (an availability choice, not a security one); this ADR
  picks the former as the better user experience, but a reviewer must confirm the code never takes
  the third, dangerous option.
- **Keycloak unreachable during the RP-leg redirect/callback (the actual login attempt) — refuses,
  never silently authenticates.** No cookie is issued, no `kind='browser'` row is created, the user
  sees an error. This is the same principle #424 already states for the device grant ("a Keycloak
  outage mid-pairing must leave the device code `pending`/`expired`, never silently `approved`")
  applied to this flow.
- **ID-token verification failure (bad signature, wrong `iss`/`aud`, expired, nonce mismatch) —
  refuses.** No cookie, no session row. This is standard OIDC RP correctness, restated here because
  it is new code this workspace has never had to write before (Decision 5) and incomplete
  verification is indistinguishable from a working login until it is exploited.
- **`resolve_context` failure** (`crates/lightbridge-authz-api-key/src/repo.rs:661`,
  `crates/lightbridge-authz-rest/src/handlers/idp.rs:25`) — reused as-is, not reimplemented. Its
  existing uniform-404 contract ("a non-member or unknown project is a uniform 404 — deliberately
  indistinguishable," AGENTS.md) already fails closed by refusing to distinguish "wrong project"
  from "no such project"; nothing about this ADR changes or reopens that contract, it is simply
  called from a new place (the hosted-page flow, wherever it needs to resolve which project context
  the session applies to).
- **Session-row write failure after a verified Keycloak login** — refuses. If the `INSERT` creating
  the `kind='browser'` row fails, no `Set-Cookie` is emitted referencing a row that does not durably
  exist; the whole `/authorize` attempt fails rather than handing the browser a cookie value nothing
  backs.

### 7. CSRF at `/authorize` becomes a live concern the moment a session cookie exists — and PKCE does not cover it

ADR-0019's broker had no ambient credential a victim's browser could be tricked into presenting —
every `/authorize` hit necessarily forced a fresh, explicit Keycloak login, which functioned as an
implicit "the user is actually here right now" check. Once a session cookie exists, that stops
being true: an attacker's page can force the victim's browser into a top-level navigation to
`https://auth.ai.camer.digital/authorize?client_id=<a_real_registered_client>&redirect_uri=<that
client's real, registered redirect_uri>&state=<attacker's choice>&code_challenge=...` and, riding
the victim's `SameSite=Lax` cookie (Decision 4), silently obtain an authorization code without the
victim ever seeing a login screen — a classic login-CSRF / confused-deputy attack (RFC 6749
§10.12).

**Two separate mitigations for two separate hops, not one mechanism covering both:**

- **Client-to-`authz-idp` hop**: the client-supplied `state` parameter, generated and stored by the
  requesting client app *before* it redirects the browser here, and validated by that client app
  against its own record when the callback returns. This is unaffected by this ADR — it is
  ADR-0019's existing assumption, and it is what makes the attack above non-damaging in practice:
  the resulting code/callback lands in the victim's browser at the *legitimate* client's
  `redirect_uri` carrying the *attacker's* `state`, and a correctly-implemented client rejects a
  callback whose `state` does not match one it generated. Mandatory PKCE (ADR-0019 Decision 2)
  additionally prevents the code from being *redeemed* by anyone other than whoever holds the
  original `code_verifier` — but PKCE and `state` defend against different things and must not be
  conflated: PKCE stops code theft/substitution between parties who both want to redeem it; `state`
  stops a forged *browser-initiated* authorization request from being mistaken for a real one by
  the client that receives it.
- **`authz-idp`-to-Keycloak hop (only reached on a first login / expired session)**: the RP leg
  (Decision 5) must generate and server-side-store its own `state`/`nonce` for the pending Keycloak
  redirect, independent of whatever `state` the original client sent, and verify it on the callback
  before ever creating a session row or cookie — otherwise a forged or replayed Keycloak callback
  could be used to complete an authentication event the browser never actually initiated. This is a
  new requirement for #424's RP-leg implementation, not something ADR-0019 or #424's current ticket
  text already covers, since neither anticipated a cookie-issuing caller.

### 8. Session fixation: the cookie is issued (and rotated) only after successful authentication, never before

The server must never accept a client-supplied session-cookie value and "adopt" it after login
completes — the `kind='browser'` row's `id` is always freshly minted server-side (`cuid2()`) at the
moment the RP-leg callback verifies successfully (Decision 5/6), and the `Set-Cookie` carrying that
value is emitted for the first time at that same moment. If the pending Keycloak redirect itself
needs any client-side state (the `state`/`nonce` pair from Decision 7, or PKCE parameters), that
lives in a **separate, narrowly-scoped, short-lived cookie or server-side store distinct from the
real session cookie** — never a pre-set placeholder value for the eventual session cookie that the
callback later "confirms." This is what makes the guarantee in Decision 6 ("no unknown-state
bypass") actually hold: an attacker who can set cookies in the victim's browser (a different attack
surface than CSRF, e.g. a subdomain takeover if one existed, or a network attacker on non-HTTPS —
mitigated here by `Secure`/`__Host-`/TLS-only regardless) still cannot pre-seed a session id the
server will later treat as authenticated, because the server never trusts a client-supplied value
as a live session id — it only ever trusts an id it minted itself, at the moment it verified a real
login.

### 9. What this does not do

- **No `users` table.** `authz-idp` still authenticates nobody itself and still owns no user store
  — this is unchanged from ADR-0012 Context and restated, unaltered, by ADR-0019 Decision 4: *"This
  service still authenticates no one and still owns no `users` table."* This ADR's `sessions` rows
  record that a Keycloak authentication happened and when it expires; they are not a local identity
  store, carry no password/credential material, and the `sub` on any token eventually minted off
  the back of a browser session is still copied verbatim from Keycloak, never minted here (ADR-0006,
  ADR-0039).
- **Does not change `/authorize`'s security posture beyond adding a shortcut.** Exact-match
  `redirect_uris`, mandatory PKCE, and code/client/redirect binding at redemption (ADR-0019
  Decision 2) apply identically whether `/authorize` reached its "mint a code" step via a fresh
  Keycloak login or via a valid session cookie — the cookie only changes *whether Keycloak is
  contacted first*, not any downstream validation.
- **Does not implement instant revocation.** Exactly like ADR-0020 Decision 5's bounded-not-instant
  guarantee for access tokens, revoking a browser session takes effect the next time it is looked up
  — here, simply the next `/authorize` call, since there is no cache layer analogous to Authorino's
  30s introspection cache sitting in front of this particular check. Any user-facing "sign out"
  copy must say so, not promise instant effect.

### 10. Static asset serving: `tower-http`'s file-serving layer, mounted under `/ui`, with asset-hash-aware caching and a strict CSP

> **Update (2026-08-23, follow-up to #442):** the original text of this Decision mounted the
> static build as the idp router's root-level `.fallback_service(..)` — safe only because a real
> route always beats a fallback, never because the two could not otherwise collide. In production
> that produced a split personality: `GET /` returned the API-welcome-JSON `root_handler` every
> server in this workspace shares (a real route wins), while `GET /index.html`/`GET /login` served
> the SPA. The fix, decided by the repo owner: build the frontend with Vite `base: "/ui/"` and
> serve it exclusively under an `/ui` path prefix, never at the router root. `GET /` stays
> API-only, unconditionally. The bullets below describe the corrected shape; the safety property
> is now **path-scoping**, not **mount-order** — static assets and protocol routes occupy disjoint
> path spaces, so they cannot collide at all, regardless of merge order.

> **Update (2026-08-31, follow-up to #591):** the serving side of this Decision is unchanged —
> `static_assets.rs`, the `/assets/`-prefixed `immutable` vs `no-cache` split, the
> `default-src 'self'; frame-ancestors 'none'` CSP, and the `.nest_service("/ui", ..)` path-scoping
> all still hold, and their tests (`static_assets_tests.rs`, `idp_server_tests.rs`'s
> `static_fallback_never_shadows_an_existing_protocol_route` and the `ui_*` family) pass unmodified,
> because every one of them builds its own fixture directory and never read `web/hosted-login/dist`
> in the first place. What changed is the *provenance* of the directory `static_dir` points at: the
> Vite build now happens in `converse-frontends` (`apps/authz-ui`) and arrives as a digest-pinned
> OCI artifact. Two assertions this Decision depends on moved with it and did **not** disappear:
> the content-hash assertion (without which the `immutable` half of the caching posture is wrong)
> and the service-worker-scope verifier (the SW-level twin of
> `static_fallback_never_shadows_an_existing_protocol_route`) both now run inside the producing
> repo's build, and the pin-checking action here re-asserts the content-hash property against the
> pulled artifact. See **ADR-0029**.

`tower-http` is already a direct dependency but pinned with only the `cors` feature
(`Cargo.toml:155`) — no static-file-serving feature is enabled anywhere in this workspace today.
This ADR decides the serving layer and posture, leaving only the frontend project scaffold itself
to the implementation ticket (Follow-up 7):

- **Layer**: `tower-http`'s `fs` feature (`ServeDir`/`ServeFile`), the same crate family already in
  the dependency graph for CORS — no new crate, only a feature-flag addition. Mounted into
  `build_idp_router` (`crates/lightbridge-authz-rest/src/lib.rs`) via `.nest_service("/ui", ..)`,
  scoped entirely under the `/ui` path prefix rather than mounted as a root-level fallback. Every
  protocol route (`.well-known/*`, `/oauth2/*`, `/authorize`, the RP-leg callback, the probe
  router, including `GET /`) lives outside `/ui` and the static build can only ever answer a
  request that already starts with `/ui` — the two path spaces are disjoint by construction, so a
  future protocol route and a future static asset can never collide no matter what order they are
  merged in. `GET /ui` and `GET /ui/` both serve `index.html`; `GET /ui/<anything-else>` falls
  back to `index.html` too (client-side routing); a path outside `/ui` that matches no protocol
  route gets a normal `404`, not the SPA.
- **Caching**: Vite's default production build emits content-hashed filenames for JS/CSS
  (`assets/index-<hash>.js`), so those files are safe to cache as `Cache-Control:
  public, max-age=31536000, immutable` — a hash change is a different URL, not a cache-invalidation
  problem. `index.html` itself is the one file that must never be cached this way (`Cache-Control:
  no-cache`, forcing revalidation on every load) since it is the only file whose content changes
  without its own URL changing — it is what references the current hashed bundle.
- **CSP**: a strict `Content-Security-Policy` on the hosted page specifically —
  `default-src 'self'`, `frame-ancestors 'none'`, no inline scripts (Vite's production build does
  not require inline `<script>` by default). `frame-ancestors 'none'` mirrors the exact clickjacking
  posture #424 already requires for the device-grant verification page ("Clickjacking/framing
  protection... `X-Frame-Options`/`frame-ancestors`") — a login-adjacent page must never be
  embeddable by another origin, for the same phishing-pairing reason #424 states, applied here to a
  page that additionally sets an authentication cookie on success, which raises the stakes of a
  framing attack rather than lowering them.

## Consequences

### Positive

- Delivers the owner's actual ask: a second, third, or Nth client authorization in one browser no
  longer forces a repeat Keycloak login, closing the integration blocker cited as the motivation.
- Reuses, rather than duplicates, every piece of authority ADR-0020 already built —
  `session:revoke-own`/`session:revoke`, `revokeOwnSessions`/`revokeSubjectSessions`, the `sessions`
  table itself. The net-new schema surface is one discriminator column (`kind`) and one nullable
  relaxation (`client_id` optional for browser rows), not a second table or a second authority
  model.
- Gives `/authorize`'s Keycloak redirect a single, shared, reusable implementation across both this
  ADR's hosted page and #424's device-grant verification page — one RP leg, one place ID-token
  verification correctness lives, not two.
- The `__Host-` cookie plus same-origin architecture together give this specific cookie the
  strictest scoping this platform can offer without any additional infrastructure.

### Negative

- **Reopens a CSRF-shaped surface at `/authorize` that ADR-0019's stateless broker never had**
  (Decision 7). This is a real, new class of attack surface accepted for a stated reason (the
  owner's SSO requirement), not a free win — and it requires the RP-leg implementation (#424) to
  add a `state`/`nonce` mechanism for its own Keycloak-facing hop that its current ticket text does
  not describe.
- **A short-TTL cookie is still a real, if bounded, offboarding blind spot** (Decision 2) — an
  operator who forgets to call `revokeSubjectSessions` after disabling a Keycloak account leaves
  that user's browser silently capable of skipping Keycloak for up to the TTL window. The mitigation
  is procedural (explicit revocation as the fast path) as much as technical (a short TTL as the
  backstop); this ADR does not and cannot make forgetting revocation harmless, only bounded.
- **One new dependency this workspace has never carried**: a static-asset build/serve pipeline
  (Vite build output, `tower-http`'s `fs` feature or equivalent, not currently enabled — Decision 1
  and Follow-up 7) plus, most likely, a cookie-handling crate (`axum-extra`'s `cookie` feature or
  similar, Follow-up 8) — neither exists in `Cargo.toml` today. The RP leg itself (Decision 5) adds
  no new dependency — `authkestra_engine`'s discovery/PKCE/state primitives, `authkestra_resource`'s
  configurable JWT validator, and `reqwest` are all already direct dependencies at their current
  pinned versions.
- **Two JWT-verification postures would coexist in this service if the RP leg's implementation does
  not deliberately copy `lightbridge-authz-bearer`'s existing hardened pattern** (Decision 5) — a
  real review risk to flag explicitly on the implementation ticket, not a hypothetical one, since
  the two verification jobs (inbound bearer tokens vs. the RP leg's inbound ID tokens from
  Keycloak) are structurally the same problem and should not independently reinvent the algorithm
  allowlist / `kid`-presence / multi-audience handling this codebase has already gotten right once.
- **Bulk revocation must be updated, not just extended** (Decision 3): `revokeOwnSessions`/
  `revokeSubjectSessions`'s underlying query changes from "every session for this subject" to
  "every session, of either `kind`, for this subject" — a real code change to already-shipped
  (ADR-0020) logic, with its own regression-test obligation (an admin `revokeSubjectSessions` call
  must be proven, not assumed, to also kill a browser-kind row in the same test suite that already
  exercises the token-kind case).
- **A brand-new failure mode this service has never had to reason about**: session fixation
  (Decision 8) and the "which direction does fail-closed point" subtlety (Decision 6) are both new
  categories of mistake a reviewer must check for, distinct from every existing fail-closed pattern
  in this codebase, which all point the same direction ("unknown → refuse access"). This one has a
  case where "unknown → refuse the *shortcut*, not access itself" is the correct answer, and it is
  exactly the kind of nuance that gets silently miscopied from a more familiar pattern.

### Neutral / follow-ups

- The exact `/authorize`/callback route paths, the pending-flow `state`/`nonce` storage mechanism,
  and whether the config field is named `oauth2.browser_session_ttl_seconds` or something else are
  implementation-ticket decisions, not decided here.
- Which pages the Vite app actually renders beyond the infrastructure this ADR decides (same-origin
  static serving, caching, CSP) — an error page, a post-login landing page, a future session-list
  UI — is left to the implementation ticket. ADR-0020 Follow-up 5 already scopes a session-list UI
  for `lightbridge-ss`; whether any part of that also belongs on this hosted page is not decided
  here.

## Alternatives considered

- **A separately deployed Next.js frontend for the hosted login page.** Rejected — it cannot carry
  the `__Host-` cookie prefix without either giving up its strict scoping (falling back to a
  `Domain`-scoped cookie shared across a wider surface) or proxying every request back through
  `auth.ai.camer.digital` anyway, at which point the separate deployment adds a network hop and a
  second set of secrets for no benefit. It also does not change which origin issues the cookie —
  only which origin renders the HTML around it — so it buys nothing on the one property (cookie
  scoping) that motivated same-origin in the first place.
- **A Next.js app owning the RP leg to Keycloak, with this Rust service owning only the OAuth broker
  surface.** Rejected — it splits the authentication boundary across two runtimes and two
  languages, meaning this repo's review priority #1 ("does the unavailable branch become the
  permissive branch") now has to be independently re-verified in a second codebase this repo's own
  lint/test/`deny.toml` discipline does not reach. The RP leg is exactly the kind of
  security-sensitive, fail-closed-critical code (Decision 6) this repo's own conventions exist to
  protect, and moving it out of Rust removes that protection rather than relocating it.
- **A stateless, self-contained (JWT/signed) session cookie instead of an opaque id referencing a
  DB row.** Rejected — every `/authorize` hit already requires a DB round-trip to check the session
  row's `status`/`expires_at` fail-closed (Decision 6), so a self-contained cookie buys no latency
  win, and it would reintroduce exactly the "cannot revoke mid-lifetime" problem ADR-0020 exists to
  close for access tokens — regressing the very property this ADR relies on ADR-0020 having already
  fixed.
- **`SameSite=Strict` instead of `Lax`.** Rejected, explicitly and with the mechanism stated
  (Decision 4): `/authorize` is reached via cross-site top-level navigation from the requesting
  client app, and `Strict` cookies are withheld on exactly that request shape in modern browsers.
  Choosing `Strict` would not error — it would silently make the cookie invisible to every
  `/authorize` call, forcing a Keycloak redirect every time and defeating SSO without any visible
  symptom, exactly the kind of silent breakage the task explicitly warned about.
- **A sliding (activity-extended) TTL instead of a fixed, absolute one.** Rejected for this first
  cut — a sliding window means an actively-used browser session could in principle never expire on
  its own, which directly undermines Decision 2's stated goal (a hard backstop for forgotten
  revocation). A fixed, absolute TTL guarantees every browser session self-expires the same business
  day regardless of activity, which is the property that makes the "how bad is it if revocation is
  forgotten" argument in Decision 2 actually hold.
- **Overloading ADR-0020's existing session-row shape (always `client_id`-scoped) instead of adding
  a `kind` discriminator.** Rejected — a browser session is not scoped to one client by design (the
  entire premise of SSO), so forcing every browser row to carry a `client_id` would mean either
  picking an arbitrary client to attribute it to (meaningless) or making the column nullable for a
  reason unrelated to why ADR-0020 made anything else nullable, silently changing what "no
  `client_id`" means for existing token-kind rows. An explicit `kind` column keeps both row shapes
  self-describing and keeps `listMySessions`/UI code able to render them differently without
  inferring kind from an absence.

## Follow-ups

Sequenced against epic #337's existing tickets — each row states what's already covered and what
this ADR adds to it, so nothing here duplicates an existing ticket's scope:

1. **#423 (`DeviceCodeStore`) — unaffected.** No change to this ticket's scope from this ADR.
2. **#424 (RP leg + device-grant verification page) — scope grows and its central open question is
   now closed, both need an explicit update before implementation starts.** The
   `authkestra-oidc`-vs-hand-write question #424's own text posed is **decided by this ADR**
   (Decision 5): hand-write the RP leg on top of `authkestra_engine::auth::discovery`/`pkce`/
   `state` and `authkestra_resource::jwt`'s configurable validator (all already direct dependencies
   at `=0.5.1`), copying `lightbridge-authz-bearer`'s existing hardened JWT-validation pattern
   (`crates/lightbridge-authz-bearer/src/lib.rs:146,200,232-240,252,265`) for the ID-token check —
   do not spend further implementation time evaluating `authkestra-oidc`. Beyond that, this ADR
   still adds: (a) the RP leg must be built as a shared primitive with two callers, not one — the
   device-grant verification page's existing scope, plus this ADR's hosted-page callback; (b) the
   RP leg's own `state`/`nonce` mechanism for its Keycloak-facing hop (Decision 7), via
   `OAuth2State::encrypt`/`decrypt`, not currently described in #424's text; (c) on successful
   verification, the hosted-page caller path additionally creates a `kind='browser'` session row
   and issues the `__Host-` cookie (Decisions 3/4/6/8) — the device-grant caller path does not do
   this, it continues to only flip the `device_authorizations` row to `approved` as #424 already
   specifies.
3. **#425 (`/authorize` + `AuthorizationCodeStore` + `redirect_uris` + PKCE) — scope gains a new
   precondition check.** This ADR adds: before redirecting to the RP leg at all, `/authorize` must
   look up the `__Host-` cookie's referenced `kind='browser'` session row and, if `active` and not
   expired, skip the Keycloak redirect entirely and proceed straight to minting the authorization
   code (Decision 2). #425's current ticket text assumes every `/authorize` call redirects to
   Keycloak unconditionally; this is the change that assumption needs before implementation.
4. **#426 (discovery document) — unaffected directly.** No new discovery field is introduced by
   this ADR; `authorization_endpoint`/`response_types_supported` advertisement continues to depend
   only on `/authorize` being mounted (#425), independent of whether the cookie-skip path exists
   behind it.
5. **#427 (client cutover) — unaffected in scope, strengthened in outcome.** Once #425/this ADR's
   pieces ship, `lightbridge-ss`'s cutover (5b) additionally benefits from SSO across repeat visits,
   which is not a new task for this ticket but is worth noting in its own verification evidence once
   implemented.
6. **New ticket: sessions-table `kind` column + browser-session creation/lookup, folded into ADR-0020
   Follow-up 1's migration if that has not yet landed** (Decision 3). Adds `kind`, relaxes
   `client_id` to nullable for `kind='browser'` rows, and updates `revokeOwnSessions`/
   `revokeSubjectSessions`'s underlying query to cover both kinds — with a regression test proving
   the bulk cascade actually reaches a browser-kind row, not just asserted by code review.
   **Hard dependency: ADR-0020 Follow-up 1 (migration + `Session` model) must land first**; this
   ticket is additive schema on the same table, ideally the same migration if timed right.
7. **New ticket: hosted login page — Vite React static build + static-asset serving in
   `authz-idp`** (Decision 1/10). Scaffolds the frontend project, adds a build step to CI, adds
   `tower-http`'s `fs` feature to `Cargo.toml`, and wires the `ServeDir`-style fallback router with
   the caching and CSP posture Decision 10 already specifies — this ticket implements that
   decision, it does not re-decide the layer or posture.
8. **New ticket: cookie-issuing crate selection.** Add `axum-extra`'s `cookie` feature (or
   equivalent) to `Cargo.toml`, evaluated against the same house-rule caution CLAUDE.md already
   states for dependency-capability claims (verify against the exact version pinned, don't assume).
9. **Non-blocking: file the `authkestra-oidc` fix upstream with `marcjazz`** (Decision 5). The gap
   is narrow and the fix is plausible: thread a `ValidationConfig`-style builder through
   `OidcProvider::exchange_code_for_identity` instead of the hardcoded `Validation::default()`, and
   populate `identity.attributes["nonce"]` so `OAuth2Flow`'s existing nonce re-check actually has
   something to check. Filing this does not gate any of this ADR's other follow-ups — the hand-write
   decision (Decision 5) stands regardless of whether or when an upstream fix lands, and this
   service does not block on it either way.
