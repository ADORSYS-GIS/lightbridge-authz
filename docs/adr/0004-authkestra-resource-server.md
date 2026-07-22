# ADR-0004: Adopt authkestra as the resource-server JWT validator

- Status: Accepted
- Date: 2026-07-21
- Decision owners: Lightbridge Authz maintainers

## Context

Bearer-token validation today is hand-written in `crates/lightbridge-authz-bearer` (JWKS fetch/cache,
`jsonwebtoken` validation, claim extraction) and shared by `authz-api` and `lightbridge-mcp`.
`authz-opa` is Basic-auth protected and unaffected. `oauth2.jwks_url`/`oauth2.audience` in
`lightbridge_authz_core::config::Oauth2` already carry the JWKS endpoint and an optional expected
`aud` list; `oauth2.rbac.roles_claim` (default `lightbridge_api_roles`, see `docs/rbac.md`) selects
which claim RBAC reads for permission mapping. A claim-name drift in this exact path (the emitted
claim didn't match `roles_claim`) broke local-dev RBAC recently and was fixed in `a615ce0` — this
class of regression is the primary risk this ADR has to guard against, not a hypothetical.

[authkestra](https://www.authkestra.com) (GitHub `marcjazz/authkestra`) is a modular Rust
authentication framework. **Correction to this ADR's original research**: the module this ADR
describes as `authkestra-resource` does not exist as a published crate — it lives only in the
`marcjazz/authkestra` git repository, unreleased. The real published equivalent is
**`authkestra-guard` `0.1.0`** (module `authkestra_guard::jwt`), confirmed by the implementation task
reading actual crates.io source before writing code against it: `ValidationConfig::builder()`,
`JwksCache::new(jwks_url, refresh_interval)`, `validate_jwt_generic::<T>()`. Two real divergences from
this ADR's original assumptions, also confirmed from source: `ValidationConfig.audience` is a single
`Option<String>`, not the `Vec<String>` this codebase's `oauth2.audience` already supports (so
multi-value audience matching stays hand-written, via `jsonwebtoken`'s own `set_audience`, exactly as
before this migration); and `Jwks::find_key(None)` falls back to the JWKS's *first* key when a token
omits `kid` rather than rejecting it, which this service pre-empts with its own explicit `kid`
presence check. The Axum `Jwt<T>` extractor (`authkestra-axum`, "guard" feature) requires the
router's state to implement `FromRef` for the JWKS cache and validation config, which would mean
changing `AppState` in a crate out of this task's scope — so the migration calls `authkestra_guard`'s
free functions directly from inside the existing `BearerTokenService`, rather than adopting the
extractor. It is a third-party crate (not maintained by anyone on this team), at `0.1.0`, very low
download count — earlier and higher-risk than `cratestack-pg` (0.4.9, and at least authored by a
maintainer of this repo).

authkestra's README has no mention of RFC 8693 token exchange or authorization-server issuance — it
is built for the OAuth2-*client* role (integrating upstream providers like GitHub/Google/Discord) plus
the resource-server validation role. It does not cover what this service already does in
`crates/lightbridge-authz-rest/src/token_exchange.rs` / `signing.rs` (native RFC 8693 exchange,
self-signed JWT issuance) — that capability has no equivalent here.

## Decision

Adopt `authkestra`'s resource-server validation (published as `authkestra-guard`, see the corrected
Context above) to replace `crates/lightbridge-authz-bearer`'s hand-written JWKS fetch/cache, for both
`authz-api` and `lightbridge-mcp` (both currently depend on the same `lightbridge-authz-bearer` crate,
so both move automatically since neither references the JWKS implementation directly — only the
crate's public trait, `BearerTokenServiceTrait`).

### Explicitly out of scope: the authorization-server / token-exchange role

This service's existing role as a full OAuth2 authorization server for its own downstream clients
(RFC 8693 token exchange only, no standard `authorization_code`/`client_credentials` flows) is
**not** touched by this ADR. `token_exchange.rs` and `signing.rs` are unaffected — authkestra has no
facility for this role, and a from-scratch authorization-server implementation is being built
separately (not by this team) and will be integrated later, once available. Until then, the existing
hand-written token-exchange path continues to serve this role unchanged.

### Claims mapping is the primary risk

`authkestra-resource`'s `Jwt<T>` extractor requires a typed claims struct chosen at the call site,
not a passthrough of arbitrary claims. The replacement must carry the `lightbridge_api_roles` (or
whatever `oauth2.rbac.roles_claim` is configured to) claim, the subject, and any other claim the
existing RBAC permission-check middleware (`docs/rbac.md`) or `resolve_context`/token-exchange flows
read, through to the same call sites unchanged. Given the recent `a615ce0` incident was exactly this
class of bug (claim name drift breaking RBAC), the implementation must be verified against the real
Keycloak `dev` realm token shape (`.docker/keycloak_config/realm.json`), not assumed, and the existing
RBAC test suite must pass unmodified in its assertions (only its plumbing may change).

### Audience enforcement

`oauth2.audience: Option<Vec<String>>` already exists in config and is documented as enforced "if
set." authkestra's `ValidationConfig.audience` must be wired from this same field so behavior is
unchanged when `audience` is unset (no enforcement, matching today) and equivalent when it is set.

### Hard cutover

`lightbridge-authz-bearer`'s hand-written JWKS fetch/cache and JWT validation are deleted, not kept
as a fallback. `authz-api` and `lightbridge-mcp` both move to `authkestra-resource` in the same
change — no dual-path.

### Same PR as the cratestack CRUD migration (ADR-0003)

This lands in the same branch/PR as ADR-0003's cratestack migration, per explicit instruction,
despite touching a different concern (the authentication boundary for every protected service, not
just `authz-api`'s CRUD surface) and carrying materially higher pre-1.0/third-party risk than
`cratestack-pg`. `authz-api`'s cratestack `AuthProvider` (ADR-0003) wraps whatever this ADR lands as
the resource-server validator, not the old `lightbridge-authz-bearer` — sequenced so the cratestack
cutover (ADR-0003 task 5) is not built against code this ADR deletes.

## Consequences

### Positive

- Removes hand-written JWKS fetch/cache code, one less security-critical subsystem to maintain
  in-house.
- Incidentally fixed a real algorithm-confusion footgun found while porting: the pre-migration code
  built `jsonwebtoken::Validation::new(header.alg)` from the attacker-controlled JWT header, rather
  than a fixed server-side allowlist. The replacement fixes the accepted algorithm to `RS256`
  (matching both `authkestra_guard`'s own default and what Keycloak actually issues) independent of
  what the presented token's header claims. Not the point of this ADR, but a genuine improvement
  surfaced by doing the migration.

### Negative

- Introduces a `0.1.2`, ~84-download, third-party dependency into the authentication boundary for
  every protected service in this repository — the highest-risk dependency this codebase has taken
  on to date, by version maturity and by blast radius (auth for everything, not one CRUD surface).
- Real regression risk on the RBAC claims path given the very recent `a615ce0` incident was exactly
  this class of bug; this ADR does not eliminate that risk, it re-introduces the exact surface where
  it already happened once.
- The authorization-server/token-exchange role stays permanently hand-written for an indefinite
  period (until the separate, external effort lands), so this ADR does not reduce that maintenance
  burden — it only touches the resource-server half of the picture.
- Bundled into the same PR as ADR-0003 rather than shipped and verified independently, so a
  regression in either concern (CRUD codegen or auth boundary) blocks/complicates reverting the
  other.

## Alternatives considered

### Keep `lightbridge-authz-bearer`, wait for authkestra to mature

Rejected per explicit instruction to proceed now.

### Ship as a separate PR after the cratestack migration lands

Recommended by the assistant during planning as the lower-risk sequencing (smaller diffs, independent
revert units, doesn't couple two unrelated architectural bets). Explicitly rejected in favor of the
same-PR approach.

### Also adopt authkestra for the authorization-server/token-exchange role

Not possible — authkestra does not implement this role today. Revisit once the separate,
externally-developed authorization-server component referenced in Context is available.
