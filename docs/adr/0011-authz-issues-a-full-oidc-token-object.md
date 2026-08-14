# ADR-0011: authz issues a derived OIDC token object via token-exchange, minted and dispatched through authkestra

- Status: Proposed
- Date: 2026-08-14
- Decision owners: @stephane-segning

## Context

**Hard constraint, stated first because it reframes everything below: this system owns no
users.** User identity is delegated entirely to the IdP (Keycloak) — there is no user store, no
user table, and no login/authentication flow anywhere in this codebase, and this ADR does not add
one. We never authenticate a user. Consequently, the `id_token` this feature adds is not an
assertion of an authentication event this service performed; it is a *derived* OIDC identity —
project-scoped, minted at token-exchange time from an upstream Keycloak authentication that
already happened. This is not a new rule invented for this ADR: `accounts.id` is already
documented as the caller's JWT `sub`, an id this service does not mint and stores exactly as
issued, and the same house rule states plainly that any OIDC claim sourced from an external IdP —
`jti`, `sub`, `aud`, `iss` — is "read, never rewritten, never regenerated into our own format"
(`AGENTS.md:392-395`). This ADR extends that rule, unchanged, to every further claim it introduces:
`sub` is copied from the upstream `subject_token`, never re-minted; `auth_time`/`nonce`/
`email`/`email_verified` are upstream snapshots or clean omissions, never invented. Decision 8
works through each claim.

`crates/lightbridge-authz-rest/src/signing.rs:275-276` already advertises
`"id_token_signing_alg_values_supported": ["RS256"]` in `/.well-known/openid-configuration`
alongside `"response_types_supported": ["token"]` — a document that promises ID-token signing
capability nothing in this service can produce. A repo-wide `grep -ri id_token` (excluding
`target/`) returns exactly that one hit plus two unrelated matches in
`rpc_router_tests.rs`/`token_exchange.rs` that are substring hits on `invalid_token`. The
discovery document over-promises today, before this feature exists; that inconsistency is the
sharpest evidence that the gap needs closing, not a hypothetical one.

PR #95 (closing #94) shipped the native RFC 8693 grant at `POST /oauth2/token`
(`crates/lightbridge-authz-rest/src/token_exchange.rs`): an access token plus an optional opaque,
rotating refresh token (gated behind `offline_access`, fixed to require it explicitly requested by
PR #98 — `ca1eca2`), gated on `oauth2.token_exchange.enabled`, requiring `oauth2.type: self` (PR
#114, `2eb840e`). `id_token` was explicitly out of scope there. `TokenResponse`
(`token_exchange.rs:66-77`) has no `id_token` field today, and no code path anywhere issues one.

Claims currently sealed on the exchanged access token are `ApiKeyClaims`
(`crates/lightbridge-authz-rest/src/signing.rs:114-143`): `iss`, `sub`, `jti`, `iat`, `exp`, `typ`,
`aud`, `azp`, `lightbridge_caller_kind`, `sid`, `scope`, `api_key_id`, `project_id`, `account_id`,
optional `email`/`email_verified`, optional `allowed_models`. Consistent with the no-user-store
constraint above, `email`/`email_verified` are already upstream snapshots, not facts this service
establishes: `decode_email` (`token_exchange.rs:421-441`) reads them straight off the presented
`subject_token`'s payload, best-effort, and its own doc comment says exactly this — it "snapshots
`email`/`email_verified` from the presented upstream token."

The refresh path has a real bug, not a design choice: `mint_from_refresh`
(`token_exchange.rs:301-355`) constructs `KeyOwner { subject: session.subject.clone(), email: None,
email_verified: None }` (lines 311-315) — every refreshed token is strictly thinner than the token
it replaces, silently dropping `email`/`email_verified` on every rotation. This ADR fixes it as a
byproduct of re-minting through a shared path.

ADR-0004 adopted `authkestra-resource` (crate `authkestra_resource`, module `jwt`) for the
resource-server / JWT-validation role only, and explicitly scoped the authorization-server /
token-exchange role as out of scope, noting authkestra had no facility for it at the time and that
"a from-scratch authorization-server implementation is being built separately... and will be
integrated later, once available." That component — `authkestra-op` — is now available: upstream
`marcjazz/authkestra` tagged `authkestra-op-v0.4.0` / `authkestra-engine-v0.4.0` (verified against
the actual tagged source at `/Users/selast/dev/authkestra`, a local clone of that project, verified
by reading each cited file at its git tag via `git show <tag>:<path>` rather than trusting a
working-tree checkout, which can sit on an unrelated branch). The commit load-bearing for this ADR
is cited by hash below because it is recent enough that GitHub's own PR numbering does not yet
reflect it cleanly in this repo's issue tracker: `2dd30eb` ("op: make refresh_token overridable via
OpStore, issue id_token on openid scope", PR #191, closing upstream issue #189 — confirmed the
commit that actually merged into the `authkestra-op-v0.4.0` tag via `git merge-base --is-ancestor`;
its feature branch started life as a smaller commit, `d605b00`, which never reached the tag
directly and is cited nowhere below) and the `token/mod.rs` additions that introduced
`issue_user_token_with_extra`/`issue_id_token_with_extra`. `marcjazz` is a colleague who maintains
authkestra; this repository's decision owner is a *collaborator* on that project — with commit
access and an established working relationship, evidenced by `2dd30eb` itself being authored by
that same decision owner — but does not maintain it and does not control its release schedule.
authkestra is therefore a genuine external dependency: upstream changes are not unilaterally
schedulable from this side, and this ADR's headline feature ships only when marcjazz merges and
releases the change this ADR needs (see Decision 3's critical path and Negative consequences). The
escalation path is nonetheless concrete, not hypothetical: when something is *proved* broken or
missing from this side, the established mechanism is to file an upstream issue — and, per the
`2dd30eb`/PR #191 precedent, potentially contribute the fix as a PR — rather than fork or work
around it. That is materially better than a cold third-party dependency, but it is coordination,
not control.

## Decision

### 1. The token-exchange grant returns a full OIDC token object

`access_token` is always returned. `id_token` is returned when the granted scope set includes
`openid`. `refresh_token` is returned when it includes `offline_access` — unchanged from the rule
PR #98 already enforces (`token_exchange.rs:181`, `granted_scopes.iter().any(|s| s ==
OFFLINE_ACCESS_SCOPE)`). The refresh grant re-mints all three symmetrically through the same
minting path as the exchange grant, which fixes the `mint_from_refresh` email-dropping bug in
Context by construction — there is no longer a second, thinner code path.

### 2. Minting moves to `authkestra_engine::token::TokenManager`; key rotation is unchanged

Hand-rolled `jsonwebtoken::encode` in `signing.rs` is replaced by `TokenManager::issue_user_token_with_extra`
and `TokenManager::issue_id_token_with_extra` (authkestra `crates/authkestra-engine/src/token/mod.rs:197-227`,
`:250-286`, verified against the `authkestra-engine-v0.4.0` tag). Both take `extra: HashMap<String, serde_json::Value>`, `#[serde(flatten)]`-merged into
`Claims` (`token/mod.rs:7-28`) — the seam that carries `api_key_id`/`project_id`/`account_id`/
`allowed_models` alongside the standard claims, mirroring today's `ApiKeyClaims` shape.

`TokenManager::new_asymmetric(private_key_pem: &[u8], issuer: Option<String>, kid: Option<String>)`
(`token/mod.rs:57-104`) takes caller-supplied key material and returns `Result<Self, AuthError>`.
There is no `SigningKeyStore`/`KeyProvider` trait in authkestra — rotation orchestration stays
entirely ours. The DB-backed `signing_keys` table, `ensure_active_signing_key`
(`crates/lightbridge-authz-api-key/src/repo.rs:1586`) and its `pg_advisory_xact_lock` are retained
**unchanged**; a `TokenManager` is constructed from whichever key that function returns as active.

`TokenManager::public_jwk()` returns a single `Option<Jwk>` (`token/mod.rs:166-168`), but
`JwksResponse::new(keys: impl IntoIterator<Item = Jwk>)` (authkestra
`crates/authkestra-op/src/handlers/jwks.rs:25-29`) accepts any iterable — its own doc comment
(`jwks.rs:15-17`) notes it "accepts anything implementing `IntoIterator<Item = Jwk>`, so a single
`Option<Jwk>`... still works unchanged" — so publishing active+stale keys together during a
rotation window (what `list_verification_jwks` already does) is unaffected.

### 3. We adopt `authkestra-op`'s `OpStore`/`handle_token` dispatch, not a hand-rolled one

This repository already hand-rolls, badly and partially, several things `authkestra-op` provides
as a maintained surface: client concept (none today — see Decision 5), refresh-token rotation
(`rotate_exchange_refresh_token`, `crates/lightbridge-authz-api-key/src/repo.rs:701`, a `SELECT ...
FOR UPDATE` CAS), JWKS publication, and the discovery document. Adopting `authkestra-op::handle_token`
(`authkestra crates/authkestra-op/src/handlers/token.rs:96-189`) deletes that duplication rather
than adding to it.

We implement `OpStore` (`store.rs:13-100`, a supertrait requiring `ClientStore` + `RefreshTokenStore`
+ `AuthorizationCodeStore` + `DeviceCodeStore`, 13 required methods total — 1 + 4 + 2 + 6):

- **`ClientStore::find_client`** (1 method, `client.rs:173-178`) — backed by the config-defined
  client list from Decision 5, not a database.
- **`RefreshTokenStore`** (4 methods: `store_token`/`get_token`/`revoke_token`/`consume_token`,
  `refresh.rs:23-38`) — backed by the *existing* `exchange_refresh_tokens` table and
  `rotate_exchange_refresh_token`'s CAS rotation, wired as the trait's storage seam instead of
  being called directly from a hand-rolled handler.
- **`AuthorizationCodeStore`** (2 methods, `code.rs:60-69`) and **`DeviceCodeStore`** (6 methods,
  `device.rs:47-63`) — no-op stubs, and permanently so, not "unused today, maybe later." Both flows
  require *running* a user-facing authentication step (a login page for authorization-code, a
  device-pairing prompt for device flow) — exactly what the no-user-store constraint (Context)
  forbids this service from ever doing. That reframes the stub from an expedient shortcut into the
  architecturally correct terminus: there is no future version of this service that implements
  these two traits for real, because doing so would mean this service authenticating a user, which
  it structurally cannot. `authkestra-op`'s own test suite shows the shape (`DummyOpStore`,
  `builder.rs:159-215`), but it is a private, non-`pub` struct inside `#[cfg(test)] mod tests`
  (`builder.rs:147-148`) — not compiled into the published crate and not something we can import; we
  write our own equivalent no-op impls, using it as a reference, not a reusable library type. A
  blanket impl over `authkestra_engine::store::{KvStore, AtomicConsume}` is the alternative shape all
  four traits offer via generic impls — `ClientStore`/`RefreshTokenStore` (`client.rs:180-194`,
  `refresh.rs:40-46`) as well as `AuthorizationCodeStore`/`DeviceCodeStore` themselves
  (`code.rs:76-102`, `device.rs:73-154`, the latter needing `IndexedKvStore` for its two-key
  lookup) — for stores that don't need custom behavior. Reaching for that shape here would still mean
  hand-writing a no-op `KvStore`/`IndexedKvStore` backend ourselves; it relocates the same no-op work
  rather than avoiding it, so implementing the two `OpStore` sub-traits directly, as stated above, is
  no more work than the alternative. 8 of the 13 required methods are therefore permanent, principled
  stubs, entirely hand-written either way — the real cost of adopting the supertrait wholesale for a
  server that, by architecture, will only ever speak two of its five grant types; see Consequences.

Client authentication (`find_client` + `authenticate_client`, unconditional, ahead of the
grant-type match — `handle_token`, `token.rs:104-149`) is no longer an obstacle: clients are real
under Decision 5, so authenticating them is desired, not friction to route around.

**What remains genuinely blocking, stated plainly as this ADR's critical path — two separate
upstream gaps, not one:**

**(1) No `extra`/`id_token` seam on the exchange grant.** `handle_token_exchange` (`token.rs:971`
onward) calls plain `tokens.issue_user_token(identity, expires_in, final_scope_str, new_aud)` with
no `extra` map (`token.rs:1129-1130`), hardcodes `id_token: None` on its response (`token.rs:1150`),
and rejects any `requested_token_type` other than `access_token` (`token.rs:1018-1029`,
`"Unsupported requested_token_type. Only access_token is supported."`). It does accept
`subject_token_type: id_token` on the way in (`token.rs:1007-1016`), just not on the way out.
Unlike `refresh_token` — which `2dd30eb` (PR #191, closing upstream issue #189) gave a defaulted,
overridable `OpStore::handle_refresh_token` seam mirroring the pre-existing `handle_custom_grant`
seam (`store.rs:76` onward, dispatched through at `token.rs:168-169`) — the token-exchange match arm
in `handle_token` (`token.rs:175-176`) still calls `handle_token_exchange` directly, with no
trait-level override point.

**(2) The audience-binding check is a hard type error against this repo's actual tokens, not a
policy mismatch to configure around — this is worse than "our token has no reason to carry our
`client_id`," the framing an earlier draft of this section used.** `handle_token_exchange` requires
`claims.aud.as_deref() == Some(client_id.as_str())` (`token.rs:1055`) — unconditional, single-value,
exact-string equality; an adjacent code comment claims the check accepts "azp or aud," but the
implementation never reads `azp` (upstream's comment/code mismatch, not ours to fix).
`authkestra_engine::token::Claims.aud` is typed `Option<String>` (`token/mod.rs:12`) — one value,
never a list. This repo's own Keycloak realm already stamps **two** simultaneous audiences on every
access token: two active `oidc-audience-mapper` protocol mappers,
`lightbridge-token-issuer-audience` and `lightbridge-api-key-audience`, both with
`access.token.claim: true` (`.docker/keycloak_config/realm.json:112-133`). `jsonwebtoken::decode`
deserializes the token payload into the caller's `Claims` type *before* any audience-matching logic
runs at all (`jsonwebtoken` 11.0 `decoding.rs:287`, `let claims = decoded_claims.deserialize()?;`,
one line ahead of the `validate(...)` call that would otherwise do audience matching) — a JSON array
against a `String`-typed field is a hard deserialization error, not a soft mismatch. So
`tokens.validate_token(subject_token_str, None)` (`token.rs:1042`) fails closed on **every**
Keycloak-issued token this realm mints today, before the audience-equality check at `token.rs:1055`
is ever reached. `ClientRegistration.allowed_audiences` does not relax this — that field gates the
*newly minted* token's requested audience (`token.rs:1069`), a different check on a different value.
Nor is this configurable away: adding our `client_id` as a third mapper only adds a third array
element to the same type mismatch, and collapsing the realm to a single audience risks breaking
whatever already consumes the other one. The upstream fix is `Claims.aud` gaining multi-value
support, mirroring the pattern `authkestra_resource::jwt::ValidationConfigBuilder::audiences`
already documents on the resource-validation side — "a token is accepted if its `aud` claim matches
ANY of the configured audiences" (`authkestra-resource` `jwt.rs:181-187`) — applied to the issuance
side this ADR depends on.

**Both are required dependencies of this work, not optional enhancements.** Per this repo's own
delivery rules, the answer is a hard cutover once both land: no temporary local fork of
`authkestra-op`, no parallel in-house dispatch kept "until upstream catches up," no
staged/back-compat path, and no config-side workaround for (2) — there isn't one. Both are listed
again under Neutral / follow-ups, itemized there as the specific upstream issues this needs filed,
each with the proof it needs, as the literal blockers on Decision 1.

### 4. Dependency baseline is mandatory, already mostly satisfied

- **`jsonwebtoken`**: already pinned to `11.0` in the root `Cargo.toml` (`jsonwebtoken = { version =
  "11.0", features = ["rust_crypto"] }`, line 51) — this **is** the latest stable line, and both
  `authkestra-op` and `authkestra-engine` 0.4.0 declare the identical `jsonwebtoken = { version =
  "11", features = ["rust_crypto"] }` (verified against their `Cargo.toml`s at the
  `authkestra-op-v0.4.0`/`authkestra-engine-v0.4.0` tags). No upgrade to perform, no conflict to
  manage.
- **`authkestra-resource`** moves `0.3.2` (declared; `0.3.4` in the recent dependabot history, see
  git log) → `0.4.0`. This is forced, not chosen: every crate in the authkestra workspace shares one
  `[workspace.package] version` via `version.workspace = true` (verified against every
  `crates/*/Cargo.toml` in that repo), so pulling in `authkestra-op`/`authkestra-engine` at `0.4.0`
  drags `authkestra-resource` along. Verified this is a non-event for the risk the root
  `Cargo.toml`'s lockstep comment (lines 30-59) guards: `git diff authkestra-resource-v0.3.4
  authkestra-resource-v0.4.0 -- crates/authkestra-resource/` shows exactly one 2-line, additive
  test-fixture change (`crv: None, x: None` on a `Jwk` literal in `tests/jwt_test.rs`) — the crate's
  own source, and therefore `ValidationConfig`/`JwksCache`/`validate_jwt_generic`, the three APIs
  `crates/lightbridge-authz-bearer/src/lib.rs` consumes, are unchanged.
- **`authkestra-op` and `authkestra-engine`** are new direct dependencies at `0.4.0` — nothing in
  this workspace has imported them before.
- **cratestack lockstep repair to `0.7.16` is an already-committed prerequisite, its own PR, not a
  question this ADR is deciding.** Verified by actually running the check: root `Cargo.toml:132-141`
  declares `cratestack-core`/`cratestack-axum`/`cratestack-redis = "0.7.1"` and `cratestack-codec-json
  = "0.7.6"` directly, while `cratestack = { package = "cratestack-pg", version = "0.5.1" }` (line
  139) pulls in its *own* `cratestack-core 0.5.2`/`cratestack-axum 0.5.1` internally — two
  semver-incompatible copies of each resolve simultaneously (`cargo tree -p cratestack-axum
  --duplicates` reports `cratestack-axum@0.5.1` and `cratestack-axum@0.7.5`). `cargo check -p
  lightbridge-authz-rest` fails today with exactly the error this repo's own prior art predicted:
  `error[E0277]: the trait bound `CodecSet<LenientCborCodec, JsonCodec>: HttpTransport` is not
  satisfied` at `crates/lightbridge-authz-rest/src/lib.rs:1174`, plus a second mismatch
  (`cratestack::ratelimit::RateLimitStore` vs `cratestack_axum::ratelimit::RateLimitStore`) at
  `lib.rs:1404`, both rooted at `crates/lightbridge-authz-api/src/lib.rs:27`'s
  `include_server_schema!` bound — "there are multiple different versions of crate `cratestack_axum`
  in the dependency graph." `cratestack-pg-0.7.16` already exists in-family (confirmed present
  alongside `cratestack-core-0.7.16` in the local registry cache) and is the fix: bump line 139 to
  match the family's `0.7.x` line. This repair unblocks `cargo check` for the whole workspace and is
  a precondition for building anything in this ADR, but it is not itself a decision this ADR is
  making — it is already agreed, tracked separately.

### 5. Clients are a real, config-defined list — audiences vary per client

There is no client concept in this codebase today. `aud` and `azp` are both stamped from one static
value, `oauth2.signing.audience` (`JwtSigning.audience: Option<String>`,
`crates/lightbridge-authz-core/src/config/mod.rs:448-450`; stamped at `signing.rs:223-224`,
`aud: self.audience.as_deref(), azp: self.audience.as_deref()`) — identical on every token
regardless of caller. The only existing `client_id` in this codebase is `Oauth2Issuance.client_id`
(`config/mod.rs:469-484`), a required `String` used under `oauth2.type: external` when *this*
service is the client presenting to Keycloak — the inverse relationship. There is no `Client` model
in `crates/lightbridge-authz-api/schema/authz.cstack` (only `Account`/`Project`/`ApiKey`/
`ProjectMember`) and no client table in `migrations/`.

This decision replaces the single static constant with a real, config-sourced client list — `aud`
becomes the `client_id` of the requesting client, so audiences genuinely vary. This is safe to
change: Authorino's documented `AuthConfig` (`docs/authorino-usage.md:196-232`) verifies the
signature via `issuerUrl` discovery only, with no `aud` predicate anywhere in that block; this
service's own `aud` enforcement is opt-in — `validate_aud` is set only when `oauth2.audience` is
non-empty (`crates/lightbridge-authz-bearer/src/lib.rs:246-258`); and the shipped charts disable it
(`charts/lightbridge-authz/values.yaml:161`, `charts/lightbridge-mcp/values.yaml:107`, both
`audience: []`).

Clients are sourced from **YAML config**, not a database table, not a cratestack model, no
migration — added to `crates/lightbridge-authz-core/src/config/mod.rs` alongside `Oauth2`
(`:395`) / `JwtSigning` (`:445`) / `Oauth2TokenExchange` (`:487`). The backing type mirrors
`authkestra-op`'s own `ClientRegistration` (`client.rs:91-131`, 9 fields — `client_id`,
`client_secret_hash`, `redirect_uris`, `grant_types`, `scopes`, `require_pkce`,
`allowed_audiences`, `token_endpoint_auth_method`, `jwks`):

```yaml
oauth2:
  clients:
    - client_id: lightbridge-ss
      type: public          # no client_secret_hash, require_pkce: true
      scopes: [openid, profile, email]   # no offline_access — see Decision 6
      grant_types: [urn:ietf:params:oauth:grant-type:token-exchange]
      allowed_audiences: [lightbridge-ss]
    - client_id: lightbridge-mcp
      type: confidential     # token_endpoint_auth_method: private_key_jwt
      jwks: { keys: [ { kty: RSA, kid: "...", n: "...", e: "..." } ] }
      scopes: [openid, profile, email, offline_access]   # confidential, so allowed — Decision 6
      grant_types: [urn:ietf:params:oauth:grant-type:token-exchange, refresh_token]
      allowed_audiences: [lightbridge-mcp]
```

`ClientRegistration` also carries `redirect_uris: Vec<String>` (`client.rs:100`), for the
authorization-code flow's browser-redirect step. It is inert for every client we register: these
are machine clients (a frontend service, an MCP server) presenting a `subject_token` they already
hold, not browsers a user logs into — and per the no-user-store constraint (Context), this service
never runs the authorization-code flow that field exists for. Left empty (`[]`) deliberately for
every client here, not omitted by oversight, so nobody later mistakes this client list for a
login-app registry.

Because clients come from config, adding or rotating a client is a config change and redeploy, not
an API call. This is a deliberate limitation, not an oversight: `ClientRegistration`'s
`allowed_audiences: Vec<String>` field already exists upstream (`client.rs:113-116`) — it is what
makes "audiences are clients" a native concept here rather than something bolted on. The revisit
trigger is self-service client registration: the moment that is needed, it needs a real table, and
*that* is where a cratestack model earns its place in this feature (the only other place, besides
the already-committed lockstep repair in Decision 4, where cratestack enters this ADR at all — see
Decision 9).

### 6. Public clients never get `offline_access` — refresh tokens are confidential-client-only

The example client list above deliberately does not grant `lightbridge-ss` (public) the
`offline_access` scope. This has to be a stated decision, not a silent omission, because the
alternative is a real gap: a public client authenticates via `(Some(NoAuth), NoCredential) =>
Ok(())` (`token.rs:385`) — zero proof of anything beyond knowing the (deliberately public)
`client_id` — and RFC 8693 token-exchange has no PKCE equivalent to fall back on. PKCE binds an
`authorization_code` request to whoever started it; there is no authorization request in a token
exchange for a proof-of-possession value to bind to. So a public client granted `offline_access`
would let anyone who knows `client_id: lightbridge-ss` and holds *any* valid `subject_token` walk
away with a long-lived, rotating refresh token, no barrier beyond what the exchange already
requires for a short-lived access token.

Per this repo's own first review priority — the unavailable/unauthenticated branch must never
become the permissive one — this is a rule, not a runtime gate that could silently pass:
**`offline_access` is granted only to confidential clients, authenticated via `private_key_jwt`
(Decision 7); no public client registration in this service's config may carry it**, and scope
intersection (Decision 1) must enforce that regardless of what an operator mistakenly writes into a
public client's `scopes` list in config.

Honest consequence: a browser SPA like `lightbridge-ss` never receives a refresh token and must
re-run the token exchange against its upstream Keycloak session every time the access token
expires. That is a real UX/traffic cost, accepted deliberately in exchange for never handing a
long-lived credential to a client type with no proof-of-possession. This decision was made on the
decision owner's behalf while drafting this ADR and should be confirmed, not assumed.

### 7. Confidential clients authenticate with `private_key_jwt` only — no client secrets, ever

Two client types: **public** (`TokenEndpointAuthMethod::NoAuth`, `client.rs:70-85`, serializes as
`"none"`; `authenticate_client` accepts `(Some(NoAuth), NoCredential) => Ok(())` at `token.rs:385`)
and **confidential**, which authenticate exclusively via `private_key_jwt` (RFC 7523 §2.2,
`TokenEndpointAuthMethod::PrivateKeyJwt`, `token.rs:337-360`). We never set
`token_endpoint_auth_method` to `ClientSecretBasic`/`ClientSecretPost` for any client we register,
and never store or accept a `client_secret_hash` — `ClientRegistration.client_secret_hash: Option<String>`
stays `None` for every client this service registers. `verify_secret` (`client.rs:148-165`) uses
real argon2 and unconditionally returns `false` when the hash is `None`, so omitting secrets can
never accidentally authenticate a client that has none.

A confidential client's public key is a **static inline JWK Set** on `ClientRegistration.jwks:
Option<serde_json::Value>` (`client.rs:122-133`) — there is deliberately **no `jwks_uri`**
counterpart. `client_assertion.rs:1-22`'s module doc explains why: a `jwks_uri` would make the OP an
HTTP client (outbound fetch, cache, a refresh task, SSRF exposure, and a new failure mode where
client auth depends on a third party being reachable), and the crate has no HTTP-client dependency
at all. Consequence for the config shape in Decision 5: each confidential client's public JWK is
written directly into our YAML, and rotating a client's key is a config change/redeploy — the same
operational shape as adding a client.

Security properties, verified against source: `assertion_algorithms` (`client_assertion.rs:177-203`)
derives the permitted signature algorithms from the registered key's **type** (RSA/EC/OKP), never
from the assertion's JWT header — forecloses the classic alg-confusion attack (an attacker cannot
request `HS256` verified against a public RSA/EC key, because the returned algorithm set never
contains an `HS*` variant). `verify_client_assertion` (`client_assertion.rs:328-425`) checks
signature, `exp`/`nbf`, `aud` against `{token endpoint, issuer}`, and `iss == sub == client_id`.

`OidcDiscovery::with_private_key_jwt()` (`discovery.rs:82-88`, doc comment at `:69-81`) is opt-in — `from_config`'s default
`token_endpoint_auth_methods_supported` is `["client_secret_basic", "client_secret_post", "none"]`
(`discovery.rs:52-56`) — so we must call it explicitly, and we must **not** advertise
`client_secret_basic`/`client_secret_post`, the two methods we refuse outright. `claims_supported`
and `scopes_supported` similarly need to be set explicitly to our real claim shape rather than
`from_config`'s generic defaults (which omit `email_verified`, `nonce`, and everything else we add
via `extra`).

**Hard implementation requirement, not optional polish: assertion replay prevention is fail-closed
and currently unimplemented here.** `OpStore::record_client_assertion_jti`'s default body
(`store.rs:32-38`) delegates to `NoClientAssertionStore::record_jti`
(`client_assertion.rs:100-111`), which does not silently no-op — it logs and returns
`Err(OpError::ReplayProtectionUnavailable)`, refusing *every* `private_key_jwt` attempt. Upstream
test `no_store_refuses_rather_than_permitting_replay` (`client_assertion.rs:770-777`) pins exactly
this behavior. Consequences:

1. Confidential clients are non-functional until we implement `ClientAssertionStore::record_jti`
   (one method: `async fn record_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool,
   OpError>`, returning `false` on a replayed `jti`), wired via
   `CompositeOpStore::with_client_assertion_store` (impl block `store.rs:141-164`, method itself
   `:152`).
2. It needs TTL-keyed storage. Redis is already in this stack for rate limiting (`just it-tests`
   brings it up) and fits jti-with-expiry better than a Postgres table — recommend Redis. A Redis
   outage then refuses confidential-client authentication rather than admitting it, which is
   exactly this repo's own first review priority ("does the unavailable branch become the
   permissive branch? ... unwrap_or(false) on an authorization check is how an outage becomes a
   bypass") — here it correctly does not, and our implementation must preserve that under test.

This removes shared-secret distribution and the argon2 client-secret-hashing path from the threat
model entirely for these clients — a compromised config file leaks only public keys, never a
credential. The honest operational cost: every confidential client needs keypair management and a
way to publish/rotate its public key into config, which is strictly more work than rotating a
shared secret.

### 8. The id_token is not a second home for authorization data — and asserts nothing beyond what upstream told us

`docs/governance-model-and-enforcement.md:272-282` already made this call deliberately for the
existing access-token/introspection split: `project_quota`, `role`, and `quota_tier` ride on the
introspection response — cached 30s by Authorino — specifically because "claims freeze at mint
time" and a roster/quota change should propagate faster than a token's lifetime. Adding an
`id_token` must not erode that. Under the no-user-store constraint (Context) it cannot erode it
further either: this service owns no users, so it has no user attribute of its own to add — only
what the upstream `subject_token` already asserted, plus the project scoping it resolved.

Claim by claim, against `issue_id_token_with_extra` (`token/mod.rs:250-286`):

- `iss`, `sub`, `aud`, `exp`, `iat` are set directly by the function itself. `sub` in particular is
  the upstream Keycloak subject, carried through unchanged via `Identity.external_id` — never
  re-minted, per the same house rule already cited in Context (`AGENTS.md:392-395`).
- `nonce` is **not** something the function invents on our behalf — it is an `Option<String>`
  parameter the caller supplies, merged into `extra` only when `Some`, and the function's own doc
  comment is explicit about why: it "reflects what the client sent in the authorization request."
  We run no authorization request in a token exchange — there is nothing for `nonce` to reflect —
  so the earlier framing here ("all set directly") was wrong to lump `nonce` in with `iss`/`sub`/
  `aud`/`exp`/`iat`. Correct treatment: propagate `nonce` from the presented `subject_token` when it
  already carries one, otherwise pass `None` and the claim is omitted entirely. We never synthesize
  a `nonce` of our own.
- `auth_time` is, like `at_hash`/`azp`, outside `Claims` (`token/mod.rs:7-28`) and the function's own
  logic — it can only reach the token through our `extra` map. Because we never authenticate anyone
  (Context), we have no authentication instant to report. It is **copied from the upstream
  `subject_token`'s own `auth_time` when present, and omitted — never defaulted to "now" — when the
  upstream token doesn't carry one.**
- `email`/`email_verified` follow the identical rule and already have a working implementation:
  `decode_email` (`token_exchange.rs:421-441`) snapshots them from the presented `subject_token`,
  best-effort, and is already wired into the exchange path (`token_exchange.rs:183`) — see Context.
- `at_hash` is the one claim here that genuinely is ours to compute, not upstream's to supply: it
  binds this `id_token` to the `access_token` minted in the same response, and both are ours, so we
  compute it over our own output.
- `azp` identifies which registered client (Decision 5) the tokens were issued to — also genuinely
  ours, since client identity is resolved by this service's own client authentication, not by
  anything upstream asserted.

Tenant context (`account_id`/`project_id`) stays on the access token exactly as `ApiKeyClaims`
carries it today. Role/quota data stays out of **both** JWTs — introspection remains the only
source, matching how Authorino already distinguishes the two identity planes by `api_key_id`
presence (`docs/governance-model-and-enforcement.md:177-179`).

### 9. cratestack's role here is minimal, and stated honestly

`id_token`s are not persisted, so this feature adds no tables and needs no new cratestack models.
cratestack enters this ADR exactly twice: (a) the lockstep repair to `0.7.16` in Decision 4, which
is a prerequisite repair already committed, not a design choice made here; and (b) the revisit
trigger in Decision 5 — if self-service client registration is ever built, that is where a
cratestack model would earn its place, because it would then be genuine persisted, queried domain
data. No cratestack work is manufactured beyond those two, real, narrow points.

### 10. The discovery document is corrected

`response_types_supported` (`signing.rs:276`) gains id_token-bearing values reflecting the grants we
actually serve, and `scopes_supported`/`claims_supported` are published rather than omitted.
`well_known_router`'s hand-built `serde_json::json!` document is replaced by
`authkestra_op::handlers::discovery::OidcDiscovery` (`.with_private_key_jwt()` per Decision 7) and
`handlers::jwks::JwksResponse` as the document types, so the shapes stay spec-correct — worth taking
from authkestra even though `handle_token_exchange` itself is not (yet) reachable through the
`OpStore` seam per Decision 3.

## Consequences

### Positive

- Deletes three hand-rolled, partially-correct subsystems (client concept, refresh-token grant
  dispatch, discovery/JWKS document construction) in favor of a maintained, tested upstream surface,
  the same trade this repo already made once for JWT *validation* in ADR-0004 — this ADR extends
  authkestra from the validation plane to the issuance plane.
- The `mint_from_refresh` email-dropping bug (Context) is fixed as a structural consequence of
  re-minting through the same path as the exchange grant, not a separate patch.
- Real, hard-to-fake client authentication (`private_key_jwt`, proof-of-possession) becomes
  available with zero shared-secret storage anywhere in this service for confidential clients.
- `aud`/`azp` finally mean something real per caller instead of one static string every token
  shares.

### Negative

- Adopting `TokenManager` rewrites the signing path — the most security-sensitive code in this
  service. Per this repo's own testing rules, every existing failure-mode test (Redis down, JWKS
  unreachable, expired/replayed refresh tokens) must be re-proven against the new signer and
  dispatch path, not assumed to carry over.
- `OpStore` costs 13 required methods to implement 2 grant types; 8 of those (the
  `AuthorizationCodeStore`/`DeviceCodeStore` slots) are permanent no-op stubs. That is real,
  reviewable surface carried for a supertrait we use a third of.
- This ADR's headline feature (id_token + custom claims on token-exchange) is blocked on **two**
  separate upstream `authkestra-op` changes that do not exist yet (Decision 3): the missing
  `extra`/`id_token` seam, and `Claims.aud` needing multi-value support before this repo's own
  Keycloak tokens can even pass `validate_token`. Until both land, this service cannot ship
  Decision 1 through the adopted dispatch path — and per house style there is deliberately no
  fallback/local-fork path to ship it sooner.
- `at_hash`/`auth_time`/`azp` on the `id_token` are hand-supplied via `extra`, so their spec
  conformance is entirely this codebase's responsibility to test — authkestra provides no help
  here.
- Confidential clients require ongoing keypair lifecycle management (generation, secure
  distribution of the private half to the client, publishing/rotating the public half in our
  config) — strictly more operational work than a shared secret, in exchange for removing the
  secret-leak threat model.
- Every confidential client's public key lives in plaintext config (not a secret, but still an
  artifact that must be kept in sync with the client's actual key and cannot be rotated without a
  redeploy).
- Public clients (Decision 6) never get a refresh token, by rule. A browser SPA like
  `lightbridge-ss` must re-run the token exchange against its upstream Keycloak session on every
  access-token expiry — extra request volume and a real UX cost, accepted in exchange for never
  handing a long-lived credential to a client type with no proof-of-possession.

### Neutral / follow-ups

- **Critical path, tracked here explicitly, as three specific upstream issues to file — this
  repo's decision owner has authkestra collaborator access, not maintainer/release authority (see
  Context), so filing is the real escalation mechanism, not a formality:**
  (a) a token-exchange `OpStore` override seam mirroring `handle_refresh_token`, the shape
  `2dd30eb` (PR #191, closing upstream issue #189) already gave the `refresh_token` grant — the
  literal blocker on stamping `extra` claims and issuing an `id_token`, and the precedent to mirror
  in the filed issue;
  (b) `handle_token_exchange` rejects any `requested_token_type` other than `access_token`
  (`token.rs:1018-1029`) — needs its own issue, since (a) makes `extra` claims stampable but does
  not by itself unblock `id_token` on the way out;
  (c) `Claims.aud` (`token/mod.rs:12`) needs multi-value support — proof is the type-error analysis
  in Decision 3(2): this repo's Keycloak realm already stamps two audiences on every access token
  (`.docker/keycloak_config/realm.json:112-133`), and a single-valued `Option<String>` cannot
  deserialize that, so `validate_token` fails closed on every real token issued today, not merely on
  an edge case. None of the three is guaranteed a release date on this side — see Negative
  consequences.
- `ClientAssertionStore::record_jti` (Decision 7) must be implemented and wired via
  `CompositeOpStore::with_client_assertion_store` before any confidential client can authenticate at
  all — tracked as a hard implementation requirement, not follow-up polish.
- `AGENTS.md:452` claims project context including `role`/`quota_tier`/`project_quota` is "sealed
  into the JWT" for the human plane. That contradicts both the code (`ApiKeyClaims` has no such
  fields) and the more authoritative `docs/governance-model-and-enforcement.md:272-282`. Flagged as
  a stale-doc fix to be made separately — not corrected as part of this ADR.
- `authkestra-op`'s exchange handler already accepts `subject_token_type: id_token`
  (`token.rs:1007-1016`); our own current hand-rolled dispatch only accepts `access_token`
  (`token_exchange.rs:119-127`). Whether to accept an upstream-issued id_token as a `subject_token`
  is an open question, not a decision made here.

## Alternatives considered

- **Extend the hand-rolled `signing.rs` with an `id_token` and adopt no new dependency** — rejected:
  re-implements OIDC document/claim shapes the estate already has a maintained crate for, and
  ADR-0004 already committed this service to authkestra for the token plane.
- **Keep hand-rolling dispatch in-house instead of adopting `authkestra-op`** — rejected: this
  service already hand-rolls, badly and partially, exactly what `OpStore`/`handle_token` provide
  (client auth, refresh rotation, discovery/JWKS); continuing to duplicate a maintained surface has
  no offsetting benefit once clients are a real concept.
- **Fork `authkestra-op` locally to add the token-exchange `extra`/id_token seam ourselves** —
  rejected: creates a divergent fork of the most security-sensitive dependency this service takes,
  contradicts the hard-cutover house rule (no dormant/parallel paths), and duplicates work this
  repo's decision owner is positioned to contribute upstream as a collaborator — as already happened
  for the refresh-token seam (`2dd30eb`, PR #191, authored by that same person) — even though merge
  and release remain `marcjazz`'s call as maintainer, not something forking here would shortcut.
- **Route tenant-claim exchange through a custom grant URN via `OpStore::handle_custom_grant`** —
  rejected: abandons the standard RFC 8693 URN PR #95 already shipped, which external callers
  reasonably expect; `handle_custom_grant` exists for grant types with no native match arm, not as a
  workaround for one that already has an inflexible native handler.
- **Introduce a DB-backed client registry now (table + migration + cratestack model)** — rejected as
  speculative: nothing needs self-service client registration today; a config-defined list satisfies
  every known client, and the revisit trigger (Decision 5) is concrete and easy to detect.
- **Accept `client_secret_basic`/`client_secret_post` for confidential clients** — rejected: a
  client bound to a weaker method is only as strong as that method regardless of what stronger
  method it could also use (per `authkestra-op`'s own `TokenEndpointAuthMethod` doc comment,
  `client.rs:63-72`), so this service simply never registers a client with a secret-based method,
  keeping shared secrets out of the threat model entirely.
- **Have Keycloak issue the id_token, keep authz access-token-only** — rejected: the entire point of
  the project-scoped exchange is that project context is sealed at exchange time; a Keycloak-issued
  id_token predates that resolution and cannot carry it (ADR-0001 lineage).

## Related

- ADR-0001 (resolve-context by subject + project) — the lineage this exchange's project-context
  sealing descends from.
- ADR-0003 (cratestack CRUD migration) — the `include_server_schema!` bound whose duplicate-version
  break (Decision 4) this ADR's prerequisite repair fixes.
- ADR-0004 (adopt authkestra as the resource-server JWT validator) — this ADR extends authkestra
  from the validation plane to the issuance plane, and closes the authorization-server gap ADR-0004
  explicitly left open.
- ADR-0006 (project membership supersedes account roles) — why `project_id`/`account_id` resolution
  works the way it does at exchange time.
- Issue #94 / PR #95 (native RFC 8693 token-exchange), PR #98 (offline_access fix), PR #114
  (`oauth2.type` required enum) — the surface this ADR extends.
- The cratestack lockstep prerequisite (Decision 4) — its own PR, tracked separately from this ADR.
