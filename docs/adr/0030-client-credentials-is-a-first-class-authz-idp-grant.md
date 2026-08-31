# ADR-0030: `client_credentials` (M2M) is a first-class `authz-idp` grant, intercepted before upstream dispatch, `private_key_jwt`-only

- Status: Accepted
- Date: 2026-08-31
- Decision owners: Stephane Segning Lambou

**Numbering note:** originally drafted as ADR-0029, renumbered to ADR-0030 before merge — PR #599
(branch `claude/authz-ui-migration-plan-a1d837`) claims 0029 for the login-UI-is-a-pinned-external-
artifact ADR, and CI on neither branch can see a cross-branch ADR-number collision (the same class
of problem as the 2026-08-30 migration-prefix incident this repo's own migration docs already
describe). Every in-repo reference (this file's own filename, the ADR-0011 Correction, the ADR-0023
Amendment, `docs/rbac.md`, `docs/auth-reference.md`, config comments, test doc comments) was updated
to match.

## Context

`authkestra-op` 0.6.3 (the version this repo already pins, see the root `Cargo.toml`'s lockstep
history) already implements RFC 6749 §4.4 `client_credentials` end to end via its own adopted
dispatch table (`handle_token`, adopted whole rather than reimplemented — ADR-0011 Decision 3) — a
live `"client_credentials" => handle_client_credentials(...)` match arm exists inside
`authkestra-op` itself, not a copy vendored into this repo, and `handle_client_credentials` itself
stamps `cnf`/RFC 8705 certificate binding, validates `allowed_audiences`, and intersects requested
scope against `client.scopes`. Before this ADR it was
simply unreachable: `ConfigClientStore::to_registration` (`oauth2_op/client_store.rs`) only ever
mapped `oauth2.clients[].grant_types` strings into `authkestra_op::client::GrantType` values, and no
`OauthClient` in this repo's own config schema had ever listed `"client_credentials"` there. Adding
the grant type to a client's `grant_types` list would flip that match arm live with zero further
code changes — which is exactly the two problems this ADR exists to head off before anyone tries it:

**Problem 1 — the upstream mint has the wrong claim shape for this platform.** `handle_client_credentials`
calls `tokens.issue_client_token_with_extra(&client_id, ...)`, which mints `sub = client_id` verbatim
(a bare client identifier, not namespaced) and lets `authkestra-engine`'s `take_jti` fall back to a
UUIDv4 `jti` whenever `extra["jti"]` is absent — a straight ADR-0039 violation (every id this service
mints is a CUID2, through the one `lightbridge_authz_core::cuid::cuid2()` chokepoint; see AGENTS.md's
"Identifier Format" section). It also stamps no `lightbridge_caller_kind` claim at all, the signal
`lightbridge_authz_bearer::TokenInfo::is_api_key_derived`/RBAC resolution reads to tell a machine
token apart from a human one.

**Problem 2 — a config-only enable is a live footgun, not a hypothetical one.** `oauth2_op/client_store.rs`'s
`to_registration` mapped `OauthClientType::Public` to `TokenEndpointAuthMethod::NoAuth` — and
`authkestra_op::handlers::token::authenticate_client` accepts `(Some(NoAuth), NoCredential) => Ok(())`
unconditionally, for ANY grant type the client is authorized for, not only the ones NoAuth makes
sense for (RFC 8628 device code, where PKCE-equivalent binding is genuinely absent by design). Before
this ADR, an operator could set `type: public` + `grant_types: [client_credentials]` on a config
entry and it would parse, register, and mint a machine token to anyone who merely knew the
`client_id` — no credential proving who was asking. Nothing in the config schema, the client store,
or the startup path caught this combination. This is the single most important defect this ADR
closes; see Decision 4.

**D8 (repo-owner ruling, this planning cycle): SA tokens are rejected outright for authz-idp
surfaces; the edge collector's OIDC leg is the trust boundary; in-cluster legs are trusted directly;
`client_credentials` is for out-of-cluster machine callers.** Concretely: a Kubernetes ServiceAccount
token is never accepted as a credential anywhere on this service's surface — it is not an OIDC/OAuth2
credential this deployment's trust model recognizes, and accepting one would smuggle
cluster-internal RBAC into a boundary this service does not control. The AI-governance edge
collector's own OIDC client-credentials leg to `authz-idp` is the intended door for that specific
caller. A workload running IN the same cluster as `authz-idp` that needs to call this service's own
surfaces is trusted via its network position/mTLS posture already established elsewhere in this
estate (see `docs/governance-model-and-enforcement.md`), not via a minted OAuth2 token — issuing one
for a same-cluster caller would be solving a problem that caller does not have. `client_credentials`
on `authz-idp` is therefore scoped, deliberately, to OUT-OF-CLUSTER machine callers: an external
usage exporter, a partner integration, anything that cannot present a same-cluster network identity
and genuinely needs a bearer credential it can hold and rotate on its own schedule.

## Decision

### 1. Intercept the grant before it ever reaches `handle_token` — never fix upstream's mint in place

`token_exchange::client_credentials_token_endpoint` (`crates/lightbridge-authz-rest/src/token_exchange.rs`)
checks `raw.grant_type == CLIENT_CREDENTIALS_GRANT` at the very top of `token_endpoint`, mirroring the
pre-existing `DEVICE_CODE_GRANT` intercept immediately above it (`token_exchange.rs:219-225` before
this ADR) — both grants are dispatched to a hand-written handler and NEVER reach
`authkestra_op::handlers::token::handle_token` at all. This is a repeat of a pattern this repo already
established, not a new one: ADR-0011 Decision 3's own "Correction" documents that the token-exchange
and refresh grants are likewise full from-scratch reimplementations against the `OpStore` seam, not
thin delegations — this ADR extends the same non-delegation posture to a THIRD grant, but via a
pre-dispatch intercept rather than an `OpStore` trait override, because `client_credentials` has no
`OpStore` seam to override in the first place (unlike `handle_token_exchange`/`handle_refresh_token`,
`handle_client_credentials` is called directly from `handle_token`'s match arm with no trait
indirection at all in `authkestra-op` 0.6.3).

Client authentication for the intercepted grant reuses `token_exchange.rs`'s own
`extract_presented_credential`/`resolve_presented_client_id`/`authenticate_presented_client` — the
SAME machinery `/oauth2/revoke` and `/oauth2/introspect` already use, not upstream's
`extract_credential`/`resolve_client_id`/`authenticate_client`. This is deliberate and load-bearing,
not a style preference: upstream's own `authenticate_client` propagates ANY `OpError` from
`record_client_assertion_jti` (including `OpError::Storage`, the Redis-down case) through a single
`?`, and the caller collapses every resulting error into `invalid_client`/401 uniformly
(`authkestra-op` 0.6.3 `handlers/token.rs`, the branch immediately after the `authenticate_client`
call). This repo's own mirrored `authenticate_presented_client` distinguishes the two: a genuine
authentication failure is `invalid_client`/401, but a Redis storage failure while spending the
assertion's `jti` is `server_error`/500 — Redis-down must never look identical to "the client isn't
who it claims to be," and must never become a mint either way. Reusing revoke/introspect's own
machinery for `client_credentials` gets this distinction for free instead of re-deriving it; had this
ADR instead pointed the new intercept at upstream's `authenticate_client`, Redis-down would silently
collapse into `invalid_client`, indistinguishable from a forged assertion — proven as a fail-first
regression test, `client_credentials_redis_unreachable_is_server_error_never_a_mint`
(`token_exchange_tests.rs`). Actually run, not merely asserted: upstream's own
`extract_credential`/`resolve_client_id`/`authenticate_client` trio is `pub(crate)` to
`authkestra-op` and cannot be routed through from this crate at all, so the achievable, smallest
mutation that exercises the same claim is temporarily changing
`authenticate_presented_client`'s own `Err(_) =>` arm from `server_error`/500 to
`Err(invalid_client())` — reran the test, it went red for the predicted reason (`401 invalid_client`
instead of `500 server_error`), reverted immediately after.

### 2. `private_key_jwt` only — no client secrets, ever, no new exception

ADR-0011 Decision 6 already banned `client_secret_basic`/`client_secret_post` for every client this
service registers, for every grant. This ADR does not reopen that: a `client_credentials` client
authenticates via `private_key_jwt` (RFC 7523 §2.2) exactly like a `confidential`
token-exchange/authorization-code client already does, using the SAME fail-closed Redis-backed `jti`
replay tracking (`RedisClientAssertionStore`) already covering every other `private_key_jwt` client
today. No new authentication method, no new replay-tracking mechanism, no exception carved out for
machine clients specifically.

### 3. New config type, `Service` — a naming decision, not a new authentication path

`OauthClientType` gains a third variant, `Service`, alongside `Public`/`Confidential`
(`lightbridge_authz_core::config::mod`). `oauth2_op::client_store::to_registration` maps `Service` to
`TokenEndpointAuthMethod::PrivateKeyJwt` — byte-identical to `Confidential`. This is purely a
config-review-legibility decision: `Confidential` predates `client_credentials` entirely and
originally meant only "a browser/native RP leg that happens to hold a keypair" (an
`authorization_code` client with `require_pkce`, or a token-exchange client); giving machine clients
their own type name means a reviewer scanning `oauth2.clients` can tell "this registration is a
machine caller" apart from "this registration is a browser/native app" at a glance, without reading
`grant_types` to infer it. `Service` and `Confidential` are not distinguished anywhere in the
authentication code path — merging them back into one variant later would be a config-schema
rename, not a behavior change.

**Alternatives rejected for client authentication:**

- **Client secrets (`client_secret_basic`/`client_secret_post`) for machine clients specifically** —
  rejected on the same grounds ADR-0011 Decision 6 already rejected them for every other client:
  a client bound to a weaker method is only as strong as that method, and this service's threat
  model already excludes shared secrets entirely. Carving out an exception for `client_credentials`
  alone would reintroduce exactly the downgrade path Decision 6 closed, for the one grant whose
  entire purpose is proving machine identity without a human in the loop.
- **Device-code-style enrolment for machine clients** (mint a keypair via a pairing flow, mirroring
  RFC 8628) — rejected: device-code enrolment exists to bind a *user's* browser session to a
  code-entry device with no keyboard of its own; a machine client has neither a user nor a browser to
  pair through, and forcing one through that flow would require inventing a fake human step for a
  caller that is, by construction, not a human. `private_key_jwt` needs no such fiction: the
  operator generates a keypair once, publishes the public half into `oauth2.clients[].jwks`, and the
  private half never leaves the calling system.

### 4. Startup guard: the config-only footgun (Problem 2) is refused, not merely discouraged

`validate_client_credentials_and_service_clients` (`crates/lightbridge-authz-rest/src/lib.rs`), called
from `build_token_exchange_state` — `start_idp_server`'s sole production caller of that function, so
this check runs unconditionally at every `authz-idp` startup exactly like the pre-existing
`validate_authorization_code_clients` beside it:

1. **A `public` client listing `client_credentials` refuses to start.** This startup guard is the
   SOLE control against Problem 2, not a second line of defense behind the Decision 1 intercept.
   `client_credentials_token_endpoint`'s own `authenticate_presented_client`
   (`token_exchange.rs:903`) has, as its first match arm, `(Some(TokenEndpointAuthMethod::NoAuth),
   PresentedCredential::NoCredential) => Ok(())` — the exact same "no credential authenticates
   fine for a public client" rule every other grant relies on. A `public` client that somehow
   reached this endpoint with `client_credentials` in its `grant_types` would authenticate with
   `Ok(())` and then pass the `allows_grant_type(&GrantType::ClientCredentials)` check, minting a
   token with no credential proving who asked — the intercept reproduces Problem 2 verbatim; it
   does not close it. This startup check is therefore the only thing standing between a `type:
   public` + `client_credentials` config entry and a live footgun. Decisive, fail-first-proven:
   deleting the `client_type == OauthClientType::Public` branch turns
   `build_token_exchange_state_rejects_a_public_client_credentials_client` red immediately.
2. **A `Confidential`/`Service` client whose `jwks` does not contain at least one parseable JWK
   refuses to start.** This closes a SEPARATE, pre-existing latent disagreement this ADR happened to
   surface while auditing the client-registration path: `ConfigClientStore::to_registration` would
   map ANY `confidential`-typed client to `PrivateKeyJwt` regardless of whether its `jwks` actually
   parsed to anything usable, while `signing::ClientAuthenticationMetadata::from_oauth2` (which
   drives `token_endpoint_auth_methods_supported` in discovery) silently dropped an unparseable one
   from the advertised algorithm list — the client store and the discovery document disagreeing
   about whether the client could ever actually authenticate, with nothing catching it. The startup
   guard calls a new predicate, `signing::client_has_a_parseable_jwk`; `from_oauth2` keeps its own
   inline filter chain rather than calling that same function (it needs to walk every key to
   collect signing algorithms, not just answer "is there at least one"), so the two are not one
   shared piece of code — but both bottom out in the same `parse_public_jwk` call, so a JWK either
   one accepts/rejects is judged identically, closing the disagreement above without requiring the
   two to literally share a function.
   `ConfigClientStore::has_confidential_client`/`TokenExchangeOpStore::has_confidential_client` — the
   aggregate "is there at least one" query this per-client check replaces — are removed: neither
   could have driven a check this specific, and both were otherwise exercised only by their own unit
   tests.

   **`client_has_a_parseable_jwk` additionally enforces a 2048-bit RSA modulus floor.** `authkestra
   -op`'s `parse_public_jwk` validates shape only — a well-formed but arbitrarily short RSA key
   (e.g. 512 bits) parses cleanly — so without this floor, a weak key would pass a gate whose own
   error text promises the client "could never actually authenticate," when in fact it could,
   just not safely. 2048 bits matches this repo's own generated keys (`generate_rs256_key`) and
   NIST SP 800-131A's floor for RSA signing keys; EC/OKP keys are unaffected (every curve this
   service's `client_assertion_algorithms` recognizes is already at or above an equivalent
   strength). Fail-first-proven: a `Service` client registering only a fabricated 1024-bit RSA JWK
   is refused at startup (`build_token_exchange_state_rejects_a_1024_bit_rsa_service_client`);
   reverting `client_has_a_parseable_jwk` to skip the strength check turns it red.
3. **A `client_credentials` client may not register `redirect_uris`.** RFC 6749 §4.4 is a
   non-browser, non-redirect grant by construction; a client combining the two is either a config
   mistake or two client roles smuggled into one registration.

### 5. Minted claim shape — `service_token_extra`, a sibling of `access_token_extra`, not an extension of it

A new function, `signing::service_token_extra(client_id, scope)`, builds the `extra` claim map for
this grant. Deliberately NOT an added branch on `access_token_extra`: a `client_credentials` token
carries no `KeyOwner` (no human ever authenticated), no `sid`, no `api_key_id`, and no tenant context
at all, so threading it through `access_token_extra`'s existing many-`Option`-parameter signature
would either force fake values through it or grow that function's arity further for a shape that has
almost nothing in common with a human-derived access token.

Minted via `TokenManager::issue_client_token_with_extra(&format!("svc:{client_id}"), ttl, scope,
Some(aud), extra)`:

- **`sub = "svc:<client_id>"`** — never the bare `client_id`. This is the one claim this ADR
  deliberately does NOT mirror from upstream's own mint. `auth_provider::FederatedSubjectResolver`'s
  own-issuer short-circuit trusts a self-signed token's `sub` as an already-resolved account id
  verbatim (ADR-0025 Stage 3) with no database round-trip — the `svc:` prefix is the namespace guard
  that keeps a machine client's identifier from ever colliding with a real account id of the same
  literal string, since `accounts.id` is always either a Keycloak `sub` or a minted CUID2 (AGENTS.md,
  "Identifier Format") and never carries a `svc:` prefix.
- **`azp = <client_id>`** (the bare, unprefixed client identifier) — names the authenticated client,
  consistent with every other grant's `azp` convention.
- **`typ = "Bearer"`** — so `/oauth2/introspect`'s existing `typ == "Bearer"` gate recognizes this
  token the same way it recognizes a token-exchange access token, with no new introspection branch.
- **`jti = "lgbr:<cuid2()>"`** — this repo's own ADR-0039 CUID2 convention, via the same
  `extra["jti"]` override mechanism `access_token_extra` already uses. This is the direct fix for
  Problem 1's `jti` half.
- **`lightbridge_caller_kind = "service"`** (`lightbridge_authz_bearer::SERVICE_CALLER_KIND`, a new
  constant sibling to the existing `API_KEY_CALLER_KIND`) — the RBAC-visible signal this is a machine
  token. Notably NOT load-bearing for the fail-closed RBAC property itself (Decision 6) — that
  property holds because no `roles` claim is stamped at all, independent of this constant's value.
  It exists for observability/audit callers that need to tell "no signal" apart from "this genuinely
  is a service token."
- **`aud`** — the requested `audience` parameter when it is listed in the client's
  `allowed_audiences`, otherwise the client's own `client_id` (mirroring upstream's own no-audience
  default for this grant, kept for consistency with existing integrator expectations rather than
  changed to something new). This is the ONE grant where a granted `aud` may legitimately differ
  from `azp`/the authenticated client — ADR-0011 Decision 5 otherwise ties the two together for
  every other grant this service mints; RFC 8707 resource indicators are exactly this grant's
  reason to diverge.
- **`scope`** — the requested scope, intersected against `client.scopes` ONLY (Decision 7), passed as
  `TokenManager`'s own top-level `scope` parameter (never duplicated into `extra`, to avoid the exact
  duplicate-flattened-key hazard `access_token_extra`'s own `jti` doc comment describes for `jti`
  before `authkestra-engine` 0.5.0).

**Deliberately absent, by omission rather than an empty-string default:** `account_id`, `project_id`,
`api_key_id`, `sid`, `identity`, `budget_tier`, `quota_tier`, `allowed_models`. There is no account,
no project, no API key, and no session behind a machine client — inventing placeholder values for any
of these would be a claim about tenancy this token does not actually have.

**No `refresh_token`, no `id_token`.** RFC 6749 §4.4.3 explicitly forbids a refresh token on this
grant; `TokenResponseBody`'s existing `skip_serializing_if` omits it (and `id_token`) the same way it
already omits them for every grant that doesn't produce one. There is no human identity for an
`id_token` to describe.

### 6. RBAC: machine tokens hold zero permissions, by omission, not by a new deny rule

No `roles` claim (or whatever `rbac.roles_claim` names) is ever stamped onto a `client_credentials`
token. `lightbridge_authz_bearer::BearerTokenService::validate_bearer_token` reads that claim via
`roles_from_claim`, which returns an empty `Vec` for an absent claim, and `permissions_for_roles(&[])`
resolves to an empty `PermissionSet` — the SAME code path every other zero-role caller already goes
through, not a new special case added for this grant. `TokenInfo::has_permission` is therefore `false`
for every `Permission` this service defines, which `auth_provider::build_context` bakes directly into
every `perm*` field on the `CratestackContext` cratestack's generated `@allow`/`@@allow` clauses read
— so a machine token fails every one of them, on every RPC op-id, with no per-op-id enumeration
required anywhere in this ADR's implementation.

This is proven directly against the real `BearerTokenService::validate_bearer_token` code path (not a
mock of it) in `crates/lightbridge-authz-bearer/tests/token_validation_tests.rs`'s
`client_credentials_style_token_has_no_roles_and_zero_permissions_for_every_permission` — a token
carrying `service_token_extra`'s exact claim shape is fed through real JWKS fetch + signature
verification + claims extraction, and every `Permission::ALL` member is asserted denied.

**Local-compose-only gap, not a platform posture, and not closed by this ADR:** in `ai-helm-values`
production config (`environments/prod/values/lightbridge-app.yaml`), the `api`, `mcp`, and `budget`
components all set `oauth2.jwks_url` to `https://auth.ai.camer.digital/.well-known/jwks.json` --
`authz-idp`'s own JWKS -- while Keycloak's JWKS is configured only inside the `idp` component
itself, which is exactly right: `authz-idp` brokers the Keycloak login leg, every other component
validates against `authz-idp`. The owner's rule ("all authz services MUST validate against
authz-idp") already holds in production, so a `client_credentials` access token DOES reach
`authz-api`/`authz-budget`'s bearer validation there, and the zero-permissions property this
Decision establishes is what actually stops it -- not a signature failure.

The gap is local only: `.docker/authz/container.yaml`'s `oauth2.jwks_url` (and
`config/default.yaml`'s non-container equivalent) still point directly at Keycloak, never migrated
to `authz-idp` when ADR-0023 made it the full IdP. `docs/local-testing.md`'s "two independent trust
roots today" description is accurate for that LOCAL compose topology only. In that topology alone,
a `client_credentials` access token is rejected at signature validation before any permission is
ever checked -- which is why this ADR's own live IT coverage (`idp_it.py`) does not attempt a live
RPC call with one (see that suite's own doc comment). Migrating the local stack's `jwks_url` to
`authz-idp` is a separate, tracked follow-up (see Neutral/follow-ups) -- deliberately not done by
this ADR, since it would also require re-pointing every IT suite that currently mints Keycloak
tokens directly against local `authz-api`/`authz-budget`.

### 7. Scope check is against `client.scopes` only — a deliberate, separate namespace

`client_credentials_scopes` (`token_exchange.rs`) validates a requested scope against the
AUTHENTICATED CLIENT's own `client.scopes` list — never against
`oauth2.token_exchange.allowed_scopes`, the server-wide ceiling every OTHER grant additionally
intersects against (`oauth2_op::grant_scopes`). This is intentional, not an oversight: machine scopes
(e.g. `read:usage`) describe capabilities on resources a machine client talks to, an entirely
different namespace from the human-plane `openid`/`profile`/`email`/`offline_access` scopes that
ceiling exists to bound. Conflating the two would either pollute the human-plane allow-list with
machine-only scope names, or force every machine scope to also be blessed as a human-requestable one.
An absent `scope` parameter grants every scope the client is configured for (RFC 6749 §3.3 leaves the
no-scope default up to the server; there is no narrower default-scope concept for a machine client to
fall back to, unlike the human-plane exchange grant's `offline_access`-excluded default).

### 8. Discovery advertises `client_credentials` unconditionally (ADR-0023's rule, applied again)

`signing::discovery_document` pushes `client_credentials` into `grant_types_supported` inside the
SAME unconditional block as `TOKEN_EXCHANGE_GRANT`/`REFRESH_TOKEN_GRANT` — never gated on whether any
`oauth2.clients` entry is actually configured with it, and never behind its own route-mount flag the
way `DEVICE_CODE_GRANT`/`authorization_code` are (both of those have their OWN routes to gate on;
`client_credentials` does not — it lives entirely inside the always-mounted `/oauth2/token` handler).
This is ADR-0023's rule verbatim, applied to a grant instead of a route: "mounted unconditionally
means advertised unconditionally," and #473's lesson — "optional" and "half-broken" must never be the
same state for a capability this document claims — applies exactly as it did to `authorization_code`/
`device_code` in that ADR. One line added to ADR-0023 itself records this (see Related).

## Consequences

### Positive

- Closes a live, previously-unguarded footgun (`type: public` + `client_credentials`) before any
  deployment could ever reach it, with a decisive, fail-first-proven regression test.
- Fixes both ADR-0039 violations upstream's own mint would have produced (`jti` UUIDv4, unnamespaced
  `sub`) without forking or patching `authkestra-op` — the intercept pattern this ADR uses is the
  SAME one this repo already uses for the device-code grant, not a new mechanism.
- Zero new authentication surface: `private_key_jwt` + Redis-backed replay tracking is exactly the
  machinery three other grants already exercise and this repo already tests for failure modes
  (wrong key, replay, Redis down).
- The `client_has_a_parseable_jwk` unification (Decision 4.2) closes a real, independently-discovered
  discovery-vs-store disagreement for `Confidential` clients too, not only `Service` ones — a
  side-benefit of auditing the client-registration path for this feature.
- RBAC fail-closed for machine tokens falls out of the existing "no roles claim → empty
  `PermissionSet`" mechanism with no new deny rule to maintain or audit separately.

### Negative

- A `client_credentials` client's public key lives in plaintext config exactly like every other
  `private_key_jwt` client's does (ADR-0011 Decision 6's existing consequence, inherited unchanged):
  rotation is a config change and redeploy, and the artifact must be kept in sync with the client's
  actual key.
- `client_credentials_ttl_seconds` doubles as the revocation window: this grant has no refresh token
  and no other server-side revocation record, so an already-issued token remains usable until it
  naturally expires even after its `jwks` entry is removed from config and the deployment redeployed.
  Operators needing faster revocation than the TTL allows have no other lever today.
- The LOCAL-compose-only `jwks_url`-points-at-Keycloak gap (Decision 6) means this grant is not
  exercisable against `authz-api`'s own RPC surface in that one topology -- real, not hypothetical,
  for local `just up`/IT runs specifically, and NOT something this ADR resolves. Production is
  unaffected: `ai-helm-values` already points `authz-api`/`authz-budget` at `authz-idp`'s JWKS, so
  there this grant's zero-permissions property is what actually gates the RPC surface, exactly as
  designed.
- `OauthClientType::Service` and `OauthClientType::Confidential` are behaviorally identical
  (Decision 3) — a reviewer must remember this is a naming/legibility distinction, not an
  authentication-strength one, or risk assuming a `Service` client is somehow more (or less)
  restricted than a `Confidential` one.
- **This is a real, breaking startup-behavior change for existing deployments, not purely additive.**
  A pre-existing `confidential` client whose `jwks` is absent or does not parse (Decision 4.2) used
  to start `authz-idp` cleanly — it just silently couldn't authenticate, per the discovery-vs-store
  disagreement Decision 4.2 describes. After this ADR, that same configuration refuses to start
  `authz-idp` at all. This is not hypothetical: fixing this PR's own `idp_server_tests.rs` fixtures
  (`authorization_code_client`, which previously built `confidential`/`service` clients with
  `jwks: None`) to keep passing required generating them a real keypair, which is exactly the shape
  of change a values-repo overlay carrying a `confidential` client with no real key would also need
  before upgrading. **Pre-upgrade check:** grep every values overlay for `type: confidential` (or
  `type: service`) entries and confirm each has a `jwks.keys` array containing at least one
  RSA/EC/OKP key `parse_public_jwk` can actually use (≥2048-bit RSA modulus, per Decision 4.2's own
  floor) — a client that fails this check today was already unable to authenticate, but will now
  take the whole `authz-idp` process down with it at the next deploy instead of merely failing its
  own requests.

### Neutral / follow-ups

- **Local-stack `jwks_url` migration** (Decision 6's known LOCAL gap -- not a production gap) is
  explicitly deferred, not decided here. Production already validates against `authz-idp`
  (`ai-helm-values`); only `.docker/authz/container.yaml`/`config/default.yaml` still point at
  Keycloak directly, kept that way because every local IT suite currently mints raw Keycloak tokens
  and would need converting alongside the `jwks_url` change. Migrating the local stack to match
  production's already-correct posture is its own tracked follow-up, with its own IT-suite
  migration story -- not a quiet side effect of this ADR.
- **Production collector-audience selection** (whether an out-of-cluster AI-governance edge collector
  targets `governance-auth-cli` or a distinct second receiver client, gov#144) is a values-repo
  deployment decision, not a code decision this ADR makes. The `it-machine` IT fixture's
  `allowed_audiences: [lightbridge-api-key]` is a TEST value chosen to exercise the RFC 8707
  audience-divergence path (Decision 5), not a recommendation for what a real deployment's collector
  client should request.
- `client_credentials_ttl_seconds` (`oauth2.token_exchange.client_credentials_ttl_seconds`, default
  900s) is a new, independent config field rather than reusing `access_ttl_seconds` — kept separate
  because the two are allowed to diverge (see Negative, "revocation window").
- **Amendment (2026-08-31, PR #604): the `it-machine` keypair is generated fresh at IT-stack-up
  time, never checked into the repo.** A real RSA private key committed to git trips Gitleaks/
  Trivy exactly like a real credential would, even as test-only material scoped to
  `compose.it.yaml`'s `it-idp` runner, and this repo deliberately carries no scanner allowlist to
  carve an exception into. `.docker/it/generate_it_machine_fixtures.py` (a new one-shot compose
  service, `it-machine-keygen`, mirroring `authz-tls`'s own "generate into a shared location at
  compose-up time" shape) generates the keypair and renders an IT-only `authz-idp` config
  (`container.it.yaml`, `container.yaml` read unmodified plus the `it-machine` client entry) that
  `compose.it.yaml` mounts in place of the checked-in `container.yaml`, for the IT run only. The
  checked-in `container.yaml` itself never carries an `it-machine` entry at all, closing the
  earlier review note that the registration was live in the ordinary `just up` stack.
- **The `jti` replay-prevention namespace (`RedisClientAssertionStore`) is global, not per-client.**
  Every client assertion, from every registered client, is spent under the same fixed Redis key
  prefix (`format!("{prefix}{jti}")`, `CLIENT_ASSERTION_JTI_KEY_PREFIX`) — this grant adds a third
  consumer of that shared namespace (alongside `/oauth2/revoke` and `/oauth2/introspect`), not a new
  one of its own.
- **A verified client assertion is fungible across `/oauth2/token`, `/oauth2/revoke`, and
  `/oauth2/introspect`** — `verify_client_assertion` accepts `aud ∈ {token endpoint, issuer}` with
  no further binding to which endpoint or grant the caller intends, and `authenticate_presented_client`
  is the identical function all three routes call. This grant means a captured-but-not-yet-spent
  assertion's set of interchangeable uses now includes minting a fresh `client_credentials` access
  token, not only revoking or introspecting an existing one — the `jti` single-use guarantee still
  caps it at exactly one of those three outcomes, never more than one, but which one is the
  presenter's choice.
- **`allowed_audiences` is not a privilege boundary.** It restricts which `aud` value a
  `client_credentials` token may request (RFC 8707), but does not itself grant or gate any
  permission — what makes a self-signed token acceptable to a bearer-validating resource server is
  its signature/issuer, and `oauth2.signing.audience` is the value that participates in that check
  when configured, not `allowed_audiences`. The actual containment for a machine token is the empty
  `PermissionSet` (Decision 6), not anything about which audiences it is allowed to request.
- **Discovery advertises `client_credentials` unconditionally (Decision 8), but `scopes_supported`
  never lists a machine scope.** This is deliberate, not an oversight: `scopes_supported` reflects
  `oauth2.token_exchange.allowed_scopes`, the human-plane ceiling Decision 7 explicitly does NOT
  apply to this grant — a machine scope like `read:usage` lives entirely in `client.scopes`, a
  per-client, not server-wide, list with no discovery-document representation.

## Alternatives considered

- **Fix upstream `handle_client_credentials`'s claim shape in place (fork/patch `authkestra-op`)** —
  rejected on the same grounds ADR-0011's own "Alternatives considered" already rejected forking
  `authkestra-op` for the token-exchange/refresh grants: creates a divergent fork of the most
  security-sensitive dependency this service takes, and this repo already has a working, tested
  pattern (pre-dispatch intercept) for exactly this situation.
- **Reuse `access_token_extra` with new optional parameters for the machine-token case** — rejected:
  see Decision 5's own reasoning; the two shapes have almost nothing in common, and growing an
  already-large parameter list to cover a case that needs almost none of the existing ones is worse
  than a small sibling function.
- **Gate `client_credentials` behind its own boolean config flag, mirroring `token_exchange.enabled`**
  — rejected: ADR-0023 already settled this question for `authz-idp` as a whole ("let's not make
  something from the IdP optional anymore. It's a full IDP now.") — the grant is handled entirely
  inside the already-unconditionally-mounted `/oauth2/token` route, so a separate enable flag would
  reintroduce exactly the "optional surface, easy to half-configure" shape ADR-0023 eliminated
  elsewhere. Whether the grant is ever actually reachable is instead controlled the way every other
  grant already is: by whether any `oauth2.clients` entry lists it.

## Related

- ADR-0011 (authz issues a derived OIDC token object via token-exchange) — Decision 5's client
  concept, Decision 6's `private_key_jwt`-only rule (both inherited unchanged here), and Decision 3's
  "adopt dispatch, reimplement grant bodies" precedent this ADR's Decision 1 extends to a third
  grant.
- ADR-0023 (the `authz-idp` surface is mandatory, not composable) — the "mounted unconditionally means
  advertised unconditionally" rule Decision 8 applies to `client_credentials`; amended with a one-line
  note recording that this grant joins the unconditional surface.
- ADR-0039 (CUID2 is the house id format, webank-context) — the `jti` violation Problem 1 identifies
  and Decision 5 fixes.
- `docs/local-testing.md` — documents the LOCAL-compose-only trust-root divergence this ADR's
  Decision 6 cites as a known, pre-existing, unresolved gap; also states the production posture
  (authz-idp is the sole trust root for resource servers there) this ADR's own claims rely on.
- `docs/rbac.md` / `docs/auth-reference.md` — updated alongside this ADR to record the `service`
  caller kind and "machine clients hold no permissions."
- #534 (the tracking issue this ADR closes AC1 for).
