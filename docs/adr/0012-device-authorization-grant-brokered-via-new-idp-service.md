# ADR-0012: authz brokers the OAuth 2.0 Device Authorization Grant (RFC 8628) to Keycloak, from a new microservice that takes over the OIDC surface

> **Superseded in part by ADR-0019** (`docs/adr/0019-authz-idp-brokers-authorization-code-alongside-device-grant.md`,
> 2026-08-22): Decision 3's `AuthorizationCodeStore` half ("remains a permanent no-op stub") and
> Decision 4 in full (`redirect_uris` deliberately empty) no longer hold — `/authorize` and a real
> `redirect_uris` registry are now in scope, to serve browser clients the device grant was never
> meant to cover. Decision 3's `DeviceCodeStore` half and every other decision below are
> unaffected. See ADR-0019 for the full argument, including why the `redirect_uris` trade this ADR
> avoided is now accepted deliberately, not by accident.

- Status: Accepted
- Date: 2026-08-16
- Decision owners: @stephane-segning
- Supersedes (partially): ADR-0011's Context sentence on "no login/authentication flow", and
  ADR-0011 Decision 3's `DeviceCodeStore` half only. ADR-0011 Decision 5 (`redirect_uris`
  deliberately empty) and Decision 3's `AuthorizationCodeStore` half are **reaffirmed, unchanged**
  — see Decision 2/3 below.

## Context

Issue #336 filed the actual trigger for this ADR: a proposal to add the `/authorize`
authorization-code flow, which would make this service a full OIDC provider — a proposal that
**directly contradicts** ADR-0011's Context sentence, quoted there verbatim:

> **this system owns no users.** User identity is delegated entirely to the IdP (Keycloak) — there
> is no user store, no user table, and no login/authentication flow anywhere in this codebase, and
> this ADR does not add one.

and the code comment that encodes the same constraint,
`crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs:1-7`:

> Permanent no-op `AuthorizationCodeStore`/`DeviceCodeStore` implementations (ADR-0011, Decision
> 3). Both flows require *running* a user-facing authentication step — a login page for
> authorization-code, a device-pairing prompt for the device flow — and this service owns no users
> and runs no login flow anywhere (ADR-0011 Context). That is the architecturally correct
> terminus, not an expedient shortcut: there is no future version of this service that implements
> these two traits for real, because doing so would mean authenticating a user, which it
> structurally cannot.

Issue #336 asked for a superseding ADR before any implementation, with the user-store question
answered explicitly, and — separately, resolved in this ADR's Decision 1 below — for the specific
flow choice to be argued, not merely asserted.

**This ADR is not the "full OIDC provider" issue #336 flagged as the risk.** It deliberately does
not add `/authorize`. It adds RFC 8628 (Device Authorization Grant) instead, for reasons grounded
in this org's own already-measured evidence, not preference:

**opencode is already running the device grant against Keycloak directly, and the org has already
concluded `/authorize` is the wrong shape for headless CLIs.** Verified in
`/Users/selast/dev/gis/ai-helm/charts/librechat-opencode-wellknown/values.yaml`
(`wellKnown.config.provider.<id>.options.oauth2`): `issuer:
https://auth.verif.fyi/realms/camer-digital`, `clientId: opencode-cli`, `authFlow: device_code`.
That chart's own README (`charts/librechat-opencode-wellknown/README.md:73`) states the reason
from measurement, not guesswork:

> **Set `authFlow: device_code`** (plugin default is `authorization_code` which binds a localhost
> callback port and breaks headless use).

That is exactly the failure mode RFC 8628 exists to avoid, and the org already hit it and worked
around it once, per-client, outside this service. This ADR's Decision 1 generalizes that
already-adopted answer instead of building the flow the org already rejected.

**A sibling service in the same organization already implements this correctly.**
`lightbridge-governance`'s `governance-auth` binary implements RFC 8628 with PKCE end to end —
`/Users/selast/dev/gis/lightbridge-governance/app/governance-auth/tests/device_flow.rs`,
`login_via_device_code_sends_pkce_and_caches_a_session` (lines 6-10, 24, 51-73), which asserts a
`code_challenge`/`code_challenge_method=S256` is sent on the device-authorization request and
fails with a clear message if it is missing. That both proves the pattern out and sets the PKCE
bar this ADR's Decision 4 must clear. `governance-auth` itself, however, authenticates directly
against Keycloak (`https://auth.ai.camer.digital/realms/platform` /
`https://auth.verif.fyi/realms/camer-digital` depending on environment — see
`app/governance-auth/src/config.rs:34` and
`docs/runbooks/onboard-a-developer-ai-client.md:21-23`) — it is not, today, a client of this
service's token-exchange grant. **Correction to this ADR's original brief**: no reference to a
`governance-auth-cli` client of *lightbridge-authz*'s `/oauth2/token` exists anywhere in this
repository; `governance-auth-cli` is a Keycloak-registered client `governance-auth` talks to
directly. Decision 8 below is scoped accordingly.

**Every new CLI today needs its own hand-registered Keycloak client, in a realm this org's own
GitOps repo already flags as unmanaged.** `ai-helm-values/environments/prod/values/lightbridge-app.yaml:109-112`:

> ⚠️ EXTERNAL DEPENDENCY: the camer-digital realm (auth.verif.fyi, the jwks_url above) MUST emit
> these roles in a top-level `lightbridge_api_roles` claim (realm-role protocol mapper)... Not
> managed in ai-helm-values — wire it in the realm.

That specific comment is about the `lightbridge_api_roles` claim mapper, not client registration in
general — cited precisely rather than generalized, but it establishes the same underlying fact
this ADR relies on: realm configuration lives outside this org's reviewable GitOps path, is a
manual step per integration, and is already a known pain point severe enough to be called out
in-line in production values.

**Users authenticate at `auth.verif.fyi` while using the product at `ai.camer.digital`** — two
different domains a CLI user has to trust and be redirected through today, one per Keycloak client
registered directly against the realm.

**Codex CLI and GitHub Copilot need a long-lived, non-refreshing credential — the reason this has
to ship as an issued token, not just a login UX improvement.**
`lightbridge-governance/docs/integrations/ai-client-support-matrix.md`, matrix rows "Telemetry
auth, refreshing" / "Telemetry auth, static" (lines 23-24): both Codex CLI and GitHub Copilot are
❌ for refreshing telemetry auth and rely on a static credential only (Copilot: "env var only — no
setting exists"). Every existing local mechanism that could provision such a credential
(self-signed API-key JWT via `createApiKey`) already exists in this service **today**, independent
of this ADR — see Alternative (c) below for why this ADR does not simply lean on that path alone.

**Routing risk this ADR must not create**: `ai-helm-values/environments/prod/values/security-policies.yaml:101-113`
documents that `https://auth.ai.camer.digital` is **already** a live, trusted OIDC issuer —
Authorino's `lightbridge-apikey` identity source discovers this service's own self-signed
API-key-JWT discovery document and JWKS at that exact hostname today, over a real cert-manager TLS
cert, on a scoped ingress path (`/.well-known/*`) that already routes to `authz-api`:

> authz mints RS256 API-key JWTs signed by its own DB-backed key; `iss` = the PUBLIC issuer below
> (= `oauth2.signing.issuer` in `lightbridge-app.yaml`). Authorino OIDC-discovers at
> `<issuerUrl>/.well-known/openid-configuration` and fetches the JWKS from the `jwks_uri` it
> advertises — both served by authz via the scoped `auth.ai.camer.digital` ingress (path
> /.well-known → authz), over a real cert-manager TLS cert.

Moving discovery/JWKS ownership to a new service (Decision 1) must not let this resolve to nothing,
even transiently — see Consequences.

**`accounts.id` is the caller's JWT `sub`.** ADR-0006 established this as a structural fact, not
an implementation detail: `createAccount` "no longer generates a `cuid2` — it inserts the caller's
subject as the id" (`docs/adr/0006-project-membership-supersedes-account-roles.md:156-157`), and
`account_id` is "derivable from the token without touching the database" (same file, line 162-163).
Issue #336 asked this question be answered explicitly for a brokered flow — Decision 5 does so.

## Decision

### 1. Implement RFC 8628 (Device Authorization Grant); lightbridge becomes the token issuer for CLI clients, brokering authentication to Keycloak behind a verification page it hosts

lightbridge-authz becomes an OP (OAuth 2.0 Authorization Server / OpenID Provider) to CLI clients —
`device_authorization_endpoint`, `token_endpoint` (device_code grant), and a browser-facing
verification page (`GET /device/verify` or equivalent) that a user opens once, is redirected to
Keycloak to authenticate (Keycloak's own hosted login UI — this service still runs no login UI of
its own), and is redirected back to complete the pairing. Concurrently, lightbridge-authz becomes
an RP (Relying Party) to Keycloak for that single verification-page redirect. `/authorize` for
arbitrary third-party clients is explicitly **not** added — see Decision 2/3.

This is the generalization Decision 1's Context section grounds: opencode already proved the
device grant is the right flow for headless/CLI clients against this org's Keycloak realm; this
ADR moves the *issuer* from a per-client hand-registered Keycloak client to one shared, reviewable
service, closing the "every new CLI needs its own Keycloak client in an unmanaged realm" gap.

### 2. This service becomes an OIDC broker, not a full identity provider — ADR-0011's Context sentence is superseded, precisely

ADR-0011's Context stated, as a hard constraint:

> this system owns no users... there is no user store, no user table, and no login/authentication
> flow anywhere in this codebase, and this ADR does not add one.

That sentence is **superseded, precisely, as follows**:

- **"no user store, no user table" remains true, unchanged.** This ADR adds no `users` table, no
  password/credential storage, no user-profile model. The device-code table (Decision 7) stores
  pairing session state, not user identity — it references the upstream `sub` after the fact, it
  never mints one.
- **"no login/authentication flow anywhere in this codebase" is reversed, narrowly.** This service
  now runs one flow: RFC 8628's device-pairing flow, terminating in a redirect to Keycloak's own
  hosted login. It never renders a username/password form, never validates a credential, never
  issues a session cookie that asserts "this browser is authenticated" independent of Keycloak.
  Keycloak performs the actual authentication event; this service performs *pairing and
  brokering* — matching an upstream authentication to a CLI's polling device code.

Per #336's explicit ask, the replacement concept is named precisely: this service becomes an
**OIDC broker** to CLI clients — it terminates a standard grant (RFC 8628) on one side and
delegates the actual authentication event to Keycloak on the other, the same broker/proxy
relationship a corporate SSO gateway has to an upstream IdP. It is not a full OIDC *provider* in
the sense of owning identity — Decision 5 keeps `sub` exactly as upstream-issued, same as ADR-0011
already does for the token-exchange grant.

### 3. `DeviceCodeStore` is superseded for real; `AuthorizationCodeStore` remains a permanent no-op stub

ADR-0011 Decision 3 grouped `AuthorizationCodeStore` and `DeviceCodeStore` together and reasoned:

> That reframes the stub from an expedient shortcut into the architecturally correct terminus:
> there is no future version of this service that implements these two traits for real, because
> doing so would mean this service authenticating a user, which it structurally cannot.

**That reasoning held at the time because it conflated two different things `authkestra-op`
happens to bundle into one supertrait: running a login UI, and brokering to one.** Both traits
require *a* user-facing step to have happened before the store is ever consulted — the store
itself never authenticates anyone in either flow. What changed is not the store's contract; it is
this service's willingness to *host the redirect that gets the user to Keycloak's login*, which
Decision 1 now does. Once that redirect exists, `DeviceCodeStore`'s six methods
(`crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs:38-72`) stop being unreachable and
need a real, persisted implementation (Decision 7).

**`AuthorizationCodeStore` is not affected by that change, and its no-op status is reaffirmed as
permanent, on exactly ADR-0011's original grounds.** The distinction is not "code flow bad, device
flow good" in the abstract — it is that this ADR deliberately does not build `/authorize` as a
route any third-party client can initiate against arbitrary `redirect_uri`s. `/authorize` is a
categorically larger surface than device-code pairing: it requires a registered
`redirect_uri`-per-client (reopening exactly the surface Decision 4/ADR-0011 Decision 5 keep
closed — see below), an in-browser consent/redirect dance with all of authorization-code's
open-redirect and code-substitution risk, and PKCE enforcement on a code an attacker-controlled
browser tab, not this service, ultimately redirects. Device-code pairing has none of that: there
is no client-supplied `redirect_uri` anywhere in RFC 8628, the "browser leg" is entirely between
this service's own verification page and Keycloak (never a third-party redirect target), and the
CLI never touches a browser redirect at all — it only polls. `NoAuthorizationCodeStore`
(`noop_stores.rs:21-33`) stays exactly as it is: `store_code` always errors,
`consume_code` always returns `None`. No client this service registers is ever given the
`authorization_code` grant type (`oauth2_op::client_store` maps only `token-exchange`,
`refresh_token`, and now `device_code`/`urn:ietf:params:oauth:grant-type:device_code`).

### 4. Decision 5 of ADR-0011 (`redirect_uris` deliberately empty) stays standing, unchanged — and the device grant is a positive argument for keeping it that way

ADR-0011 Decision 5:

> `ClientRegistration` also carries `redirect_uris: Vec<String>`... for the authorization-code
> flow's browser-redirect step. It is inert for every client we register... Left empty (`[]`)
> deliberately for every client here, not omitted by oversight, so nobody later mistakes this
> client list for a login-app registry.

This ADR does not touch that field. Every client this service registers for the device grant
(Decision 1) supplies **no** `redirect_uri` — RFC 8628 has no such parameter anywhere in the
device-authorization or polling requests. This is a genuine argument *for* preferring the device
grant over `/authorize`, not an incidental side effect: choosing RFC 8628 over authorization-code
eliminates an entire class of surface this service would otherwise have to build and defend —
per-client redirect-URI registries, open-redirect validation, and authorization-code substitution
attacks — none of which have an RFC 8628 equivalent. **The only browser redirect this ADR
introduces is between this service's own verification page and Keycloak's hosted login** — a
single, hardcoded, non-client-supplied redirect this service controls end to end, not a
per-registered-client value an attacker could ever influence.

### 5. `sub` is still never minted — brokering does not change subject ownership

Issue #336 asked this be answered explicitly. It is unchanged from ADR-0011 and from the house
rule both cite (`AGENTS.md`'s Identifier Format section, ADR-0039): any OIDC claim sourced from an
external IdP — `sub` included — is "read, never rewritten, never regenerated into our own format."
The device-authorization flow does not change who authenticates the user (Keycloak, via its own
hosted login, reached through this service's verification-page redirect) — it only changes *how a
CLI obtains a credential asserting that authentication happened*. The token this service issues at
the end of a completed device-code pairing carries `sub` copied verbatim from the Keycloak session
established during that redirect, exactly as `mint_from_refresh`/the token-exchange grant already
do for `subject_token.sub` today. `accounts.id` being the Keycloak `sub` (ADR-0006) is what lets
this service resolve `account_id`/`project_id` context for the issued token without inventing an
identity of its own — the same resolution path `POST /idp/v1/resolve-context` already performs for
the human/browser plane (`crates/lightbridge-authz-rest/src/handlers/idp.rs`).

### 6. `nonce` and `auth_time` — what changes and what does not

ADR-0011 Decision 7 refused to synthesize a `nonce`:

> We run no authorization request in a token exchange — there is nothing for `nonce` to reflect —
> so... Correct treatment: propagate `nonce` from the presented `subject_token` when it already
> carries one, otherwise pass `None`... We never synthesize a `nonce` of our own.

**A device-authorization request is a real authorization request**, unlike a token exchange — RFC
8628 device-authorization requests can carry client-supplied parameters the way an authorization
request does. Where a CLI client supplies its own `nonce` on the device-authorization request, this
service now has something real for it to reflect and propagates it verbatim into the issued
`id_token`, mirroring `openid_connect`'s ordinary authorization-code semantics. Where no `nonce` is
supplied — RFC 8628 does not require one — the claim is omitted, never synthesized, unchanged from
ADR-0011's rule.

`auth_time` follows the same shape ADR-0011 established, now with a real event to report instead of
none: this service still authenticates no one itself, but the verification-page redirect
terminates in a real Keycloak authentication, and that session's `auth_time` (read off the
Keycloak-issued token obtained during the verification redirect, the same way `decode_email`
already reads `email`/`email_verified` off a presented upstream token today) is copied onto the
issued token — never defaulted to "now" if, for whatever reason, upstream did not supply one.

### 7. Storage boundaries — a new, ADR-0038-exception device-code table

The `DeviceCodeStore` implementation (Decision 3) needs its own table — call it
`device_authorizations`. Fields, at minimum: `id` (primary key), `device_code` (the value the CLI
polls with), `user_code` (the short value the user types at the verification page), `client_id`,
`scope`, `status` (`pending` / `approved` / `denied` / `expired`), `subject` (the resolved Keycloak
`sub`, set only on approval — never present on a still-pending row), `expires_at`, `interval_secs`,
`last_polled_at`.

Per ADR-0039 (Identifier Format), `id` is minted through the one chokepoint,
`lightbridge_authz_core::cuid::cuid2()` — never a second `Uuid::new_v4`/`gen_random_uuid()` call
site. `device_code` and `user_code` are opaque strings, stored `TEXT`, never shape-validated, never
sorted or paginated by. **`user_code` is deliberately not a `cuid2()`-minted id in ADR-0039's sense
— it is a display/pairing code, not a row identifier.** RFC 8628 §6.1 recommends restricting its
character set for human-transcription accuracy (short, easily-typed, case-insensitive), which is a
usability property distinct from the "every id this service mints is a cuid2" rule; `id` remains
the row's real identifier and stays cuid2-shaped. This mirrors the same distinction ADR-0011
already draws between an id (`cuid2`-shaped, opaque) and a bearer secret (`lgbr_rt_`-prefixed
opaque token, ADR-0011 Decision 6) — `device_code`/`user_code` sit on the secret/display side, not
the id side.

Under ADR-0038, this needs justifying as an exception on the exact grounds `CLAUDE.md` already uses
for `exchange_refresh_tokens`:

> `exchange_refresh_tokens`: CAS rotation via `SELECT ... FOR UPDATE`
> (`rotate_exchange_refresh_token` in `crates/lightbridge-authz-api-key/src/repo.rs`).

`device_authorizations` needs the identical shape: `consume_device_code` must atomically transition
an `approved` row to consumed-and-gone (or an equivalent terminal state) exactly once, under
concurrent polling from the same CLI and a possible retry — a `SELECT ... FOR UPDATE`/CAS pattern,
not an ordinary cratestack CRUD model. Added to `CLAUDE.md`'s "genuinely not migratable" list
alongside `signing_keys`, `project_members`, and `exchange_refresh_tokens`, in the same form:

- `device_authorizations`: CAS rotation via `SELECT ... FOR UPDATE`, mirroring
  `rotate_exchange_refresh_token`'s single-use-consume pattern — a device code must be
  atomically claimed exactly once across concurrent poll requests.

### 8. What is unaffected

- **RFC 8693 token exchange keeps working exactly as ADR-0011 shipped it.** The clients
  registered under ADR-0011 Decision 5 (`lightbridge-ss`, `lightbridge-mcp`) continue exchanging a
  `subject_token` for an access/refresh/id token pair through `/oauth2/token`'s existing grant
  arm, unaffected by adding a second grant type alongside it.
- **Correction to this ADR's original framing**: no evidence exists in this repository that
  `governance-auth-cli` is a client of lightbridge-authz's token-exchange grant.
  `governance-auth` (see Context) authenticates directly against Keycloak
  (`auth.verif.fyi/realms/camer-digital` / `auth.ai.camer.digital/realms/platform`), not through
  this service. It is therefore unaffected by this ADR for a different reason than "the grant
  keeps working" — it never routed through this service to begin with, and this ADR does not
  change that. Whether `governance-auth` should migrate onto this service's new device grant is an
  open question, not decided here (see Follow-ups).
- **`lightbridge-keycloak-spi` is untouched.** It intercepts *Keycloak's own* token-exchange grant
  at project-switch time (`AGENTS.md`, "Identity context resolution" section) — a different
  protocol leg than either this service's RFC 8693 grant or the new RFC 8628 grant this ADR adds.

## Consequences

### Positive

- Closes the actual gap issue #336 was filed against: the authorization-code proposal is answered
  with a superseding decision, as asked, and the flow it would have added is replaced with the one
  the org's own prior measurement (opencode) already showed is correct for headless/CLI clients.
- One reviewable, GitOps-adjacent Keycloak client registration per CLI category instead of a
  hand-registered Keycloak client per integration in a realm `ai-helm-values` already flags as
  externally managed.
- Users get one issuer to trust for the CLI plane (this service) instead of authenticating against
  `auth.verif.fyi` directly per client while using the product at `ai.camer.digital`.
- Gives Codex CLI and GitHub Copilot a real path to a long-lived, non-refreshing credential
  (Decision 1, via the same self-signed-JWT issuance machinery ADR-0011/the existing `createApiKey`
  path already established), provisioned through a standard, auditable device-pairing flow instead
  of an out-of-band manual key mint.
- `AuthorizationCodeStore` staying a permanent no-op stub means the largest security surface of a
  full OIDC provider (arbitrary client `redirect_uri`s, in-browser consent/redirect risk) is never
  built, keeping ADR-0011 Decision 5's `redirect_uris: []` invariant intact estate-wide.

### Negative

- **A genuinely new browser-facing surface.** This service has never rendered a page a human looks
  at; the verification page is a new, security-sensitive UI (must resist clickjacking, must render
  the user code and client name clearly enough to prevent a phishing pairing, must handle
  already-used/expired/malformed user codes without leaking pairing-session existence).
- **A new outbound HTTP dependency on Keycloak that does not exist in this service today.** Every
  other Keycloak interaction this service has is inbound (JWKS fetch for validation, JWT
  presentation by a caller). The verification-page redirect makes this service, for the first
  time, an RP that depends on Keycloak's own login endpoint being reachable from a user's browser
  and this service's own callback handling being correct — a new failure mode this service's own
  review priority ("does the unavailable branch become the permissive branch?") must be re-proven
  against: a Keycloak outage mid-pairing must leave the device code `pending`/`expired`, never
  silently `approved`.
- **Routing risk, stated explicitly**: `https://auth.ai.camer.digital` is a live, trusted issuer in
  `security-policies.yaml` for this service's own self-signed API-key JWTs today (Context). Moving
  discovery/JWKS ownership to the new microservice (Decision 1) must be executed so that hostname's
  `/.well-known/openid-configuration` and `jwks_uri` never stop resolving, even during the cutover
  — a break here fails closed for every API-key JWT in flight, which is strictly worse than
  shipping this ADR's feature late.
- `DeviceCodeStore`'s six methods, previously a few lines of permanent no-op stub
  (`noop_stores.rs:38-72`), become real, tested, security-sensitive logic — polling-rate handling,
  `slow_down`/`expired_token`/`access_denied` error semantics, and the CAS-consume pattern
  (Decision 7) all need the same fail-first testing discipline ADR-0011's own refresh-token work
  used.
- A new microservice is a new deployable, a new Helm chart/subchart, a new set of health probes,
  and a new TLS/ingress surface to operate — real ongoing operational cost, not a one-time build
  cost.

### Neutral / follow-ups

- The new microservice's name, chart, and exact route surface (`/device/authorize`,
  `/device/verify` or equivalent) are implementation decisions, not made in this ADR.
- Whether `governance-auth` migrates from its direct Keycloak client onto this service's new device
  grant is an open question this ADR does not resolve (Decision 8).
- `AGENTS.md`'s service list needs a new entry once the microservice is named and built — tracked
  as implementation follow-up, not part of this ADR.
- The verification page's exact UX (code-entry vs. pre-filled `verification_uri_complete` link,
  session/cookie handling for an already-logged-in Keycloak browser) is implementation detail, not
  decided here.

## Alternatives considered

- **A full `/authorize` browser authorization-code broker** (issue #336's original proposal) —
  rejected. Reopens the exact `redirect_uri`-per-client registry ADR-0011 Decision 5 deliberately
  closed, adds open-redirect and code-substitution surface RFC 8628 has no equivalent of, and the
  org's own measured evidence (opencode's chart README) already shows this is the wrong flow for
  the actual client population (headless CLIs), not merely an unnecessary one.
- **Keep RFC 8693 token exchange for every CLI, add nothing** — rejected. Token exchange requires a
  client to already hold a `subject_token` obtained some other way; it does not solve "a brand-new
  CLI on a fresh machine has no credential yet." It remains the right mechanism for clients that
  already have one (Decision 8), but does not substitute for an initial-login flow.
- **`governance-auth` calls `createApiKey` after its existing Keycloak device login and writes the
  long-lived self-signed JWT** — the honest strongest alternative. This would unblock Codex/Copilot
  static-credential provisioning with **zero new server-side surface**: no new microservice, no new
  browser page, no new outbound Keycloak dependency, reusing a `createApiKey` path that already
  exists and is already tested. Rejected as the *general* answer, not because it is wrong, for two
  reasons: (1) it only solves provisioning for clients `governance-auth` itself fronts — it does
  not give opencode, or any future CLI that isn't wrapped by `governance-auth`, a path off
  per-client hand-registered Keycloak clients, which is the actual gap in Context; (2) it leaves
  "who is the token issuer for CLI clients" answered differently per client (Keycloak directly for
  some, an authz-minted key for others) rather than consolidating onto one broker, which is what
  #336 asked this ADR to decide deliberately rather than let accumulate by accretion. This
  alternative is not discarded — it remains the right shape for `governance-auth`'s *own* telemetry
  static-credential need specifically, and nothing here prevents `governance-auth` from adopting it
  independently of this ADR's device-grant work.
- **Do nothing; every new CLI keeps registering its own Keycloak client** — rejected. This is the
  status quo the Context section already shows accumulating cost (unmanaged realm config, split
  trust domains, no path to a static credential for Codex/Copilot), and issue #336 was filed
  specifically because the alternative under consideration (full `/authorize`) was the wrong fix
  for it, not because the status quo itself was acceptable.

## Related

- Amended by ADR-0023 (`docs/adr/0023-the-authz-idp-surface-is-mandatory-not-composable.md`):
  `oauth2.relying_party` and `oauth2.token_exchange` are no longer optional for `authz-idp` — every
  flow route this ADR and ADR-0019 describe is mounted unconditionally.
- ADR-0006 (project membership supersedes account roles) — establishes `accounts.id` as the
  caller's JWT `sub`, which Decision 5 depends on.
- ADR-0011 (authz issues a derived OIDC token object via token-exchange) — the token-exchange grant
  and client registry (Decision 5, `redirect_uris: []`) this ADR adds a second grant type
  alongside, without modifying either.
- Issue #336 — the governing ask this ADR answers.
- `docs/governance-model-and-enforcement.md` — the introspection/claims split this ADR's issued
  tokens must remain consistent with (role/quota data stays out of both JWTs, per ADR-0011
  Decision 7).
