# ADR-0023: the `authz-idp` surface is mandatory, not composable — `oauth2.relying_party` and `oauth2.token_exchange` are both required, and `build_idp_router` mounts every flow route unconditionally

- Status: Accepted
- Date: 2026-08-24
- Decision owners: Stephane Segning Lambou
- Reverses: PR #473 (`468084a`, "gate `oauth2.relying_party` requirement on the RP-leg actually
  mounting"), which itself was a fix for PR #463 (`9e0ef4d`, "add Keycloak RP device verification
  flow") having made `oauth2.relying_party` an unconditional startup requirement. #473's OTHER
  change — threading a pre-validated `Arc<KeycloakRelyingParty>` into `build_idp_router` instead of
  reconstructing it there — is kept and strengthened by this ADR, not reversed; only the `Option`
  wrapper (and the mount-conditional branching it enabled) goes away.

## Context

**The decision, from the repo owner, verbatim — implement it, do not re-open it:**

> *"Let's not make something from the IdP optional anymore. It's a full IDP now."*

`authz-idp` (ADR-0012 Phase 1, ADR-0019, ADR-0021) is the sole owner of the OIDC broker surface for
this platform: discovery, JWKS, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/device_authorization`,
the browser `/authorize` flow, and the Keycloak relying-party leg (`/device/verify`,
`/idp/callback`). `auth.ai.camer.digital` — the live, trusted issuer every in-circulation API-key
JWT carries as `iss` — points at it directly. There is no fallback server behind it any more
(`build_api_router`'s own doc comment records `authz-api` giving up this surface entirely).

### The live defect PR #473 left behind, verified against production on 2026-08-24

PR #463 made `oauth2.relying_party` an unconditional requirement for `authz-idp` to start at all —
breaking every deployment that only wanted the discovery/JWKS/token-exchange surface. PR #473 fixed
that regression the wrong way: instead of making `relying_party` genuinely optional-but-complete
(mount nothing RP-related when absent, and don't advertise anything RP-related either), it made the
RP-leg **mount-conditional** while leaving `device_authorization_endpoint` gated only on
`token_exchange`, which has no dependency on `relying_party` at all. The result, live in production
before this ADR:

- Discovery (`/.well-known/openid-configuration`) advertised `device_code` in
  `grant_types_supported` and a `device_authorization_endpoint`, because those are gated solely on
  `oauth2.token_exchange` being enabled.
- `/device/verify` — the hosted page a device-flow client's user is told to visit — 404'd, because
  `relying_party::router` was never merged when `oauth2.relying_party` happened to be absent from
  that deployment's config.
- `/idp/callback` and `/authorize` were in the same state: absent from the router, present (or
  silently omitted with no diagnostic) depending on a config field most operators had no reason to
  believe gated anything beyond "does the RP login page exist."

"Optional" and "half-broken" were the same state for this field: any config that didn't set
`oauth2.relying_party` produced a server that advertised a capability it structurally could not
serve. There is no config shape under the #473 gate that is both valid AND fully self-consistent
with what discovery promises, other than "always configure it" — which is just this ADR's
conclusion reached the slow way, by a production operator hitting the gap instead of the config
schema saying so up front.

By 2026-08-24 ~20:00 UTC, the prerequisite this ADR's PR needs (prod `ai-helm-values` carrying both
`oauth2.relying_party` and `oauth2.token_exchange.enabled: true`) was independently already merged,
synced, and verified live: pods healthy, discovery spec-complete. This ADR's code change makes that
already-true production state a startup-time guarantee instead of an operational accident.

## Decision

### 0. Fate of each piece that used to be optional

| Piece | Verdict |
|---|---|
| `oauth2.relying_party` (previously gated in `build_idp_router`, and briefly unconditional in `start_idp_server` under #463) | **Mandatory** for `authz-idp`. Checked once, in `start_idp_server`, before `build_idp_router` is ever called. Absence is a hard startup failure — never a silent skip. |
| `oauth2.token_exchange` (previously `Ok(None)`-tolerant at every caller) | **Mandatory** for `authz-idp`. `build_token_exchange_state` keeps its `Result<Option<...>>` contract (other callers/tests still exercise the `None` path directly), but its one production caller, `start_idp_server`, now treats `None` as fatal. |
| The router-level `oauth2.is_self_signed()` re-gate inside `build_idp_router` | **Removed** as redundant. `start_idp_server` already hard-requires `oauth2.type: self` before `build_idp_router` is ever reached (`start_idp_server_rejects_external_oauth2`); the gate lived in two places for one invariant. |
| `DiscoveryCapabilities` (#467, `signing.rs`) | **Kept**, with a new always-on constructor, `full_idp()`. `build_api_router` uses none of this machinery — zero risk of `authz-api` advertising anything it shouldn't. |
| `/ui` static mount | Unchanged. |

### 1. `DiscoveryCapabilities::full_idp()` — a named constant for the assembled route table, not a config read

```rust
pub const fn full_idp() -> Self {
    Self::token_surface()
        .with_device_authorization()
        .with_authorization_code()
}
```

`DiscoveryCapabilities` exists (#467) specifically so the discovery document is a statement about
the router `build_idp_router` actually assembled, never about configuration intent — that
discipline is what caught the original `response_types_supported` production bug it was built to
prevent. `authz-idp`'s production call site now always passes `full_idp()`, because every flow
route this ADR makes mandatory is mounted unconditionally. Kept as a named constructor rather than
collapsing `DiscoveryCapabilities` away entirely: `well_known_router` stays generic over other
possible callers that mount less, and the type is still the thing that keeps the document honest
about what got merged, not what got configured.

### 2. `build_idp_router` takes owned, pre-validated parameters — no more `Option<...>` branching

```rust
pub fn build_idp_router(
    oauth2: &Oauth2,
    signing: &JwtSigning,
    signing_repo: Arc<StoreRepo>,
    token_exchange: token_exchange::TokenExchangeState,
    readiness_pool: Arc<dyn DbPoolTrait>,
    static_dir: impl AsRef<std::path::Path>,
    relying_party: Arc<relying_party::KeycloakRelyingParty>,
) -> Router
```

Every parameter here is a pre-validated product of `start_idp_server`'s checks. `well_known_router`,
`authorize::router`, `token_exchange_router`, and `relying_party::router` are all merged
unconditionally, in the same byte-for-byte merge order as before (well-known → authorize →
token-exchange → relying-party → `/ui`). #473's OTHER decision — threading a pre-validated `Arc`
instead of reconstructing `KeycloakRelyingParty` inside this function — is kept and strengthened:
only the `Option` wrapper around it (and the branching that came with it) is removed.

### 3. `start_idp_server`'s check order, and why redis comes before relying_party

Kept order: ① `oauth2.type: self` → ② `oauth2.signing` present → ③ `redis.url` present → ④
`oauth2.relying_party` present and valid → ⑤ `oauth2.token_exchange` present, enabled, and
`openid` ∈ `allowed_scopes`.

③ stays before ④ deliberately: the Redis-backed rate-limit store built from `redis.url` is an input
to `KeycloakRelyingParty::new`, and AGENTS.md's own "Redis is a mandatory dependency" rule requires
the redis failure to be the one an operator sees when both are missing — reordering would silently
make a missing-redis deployment fail on a relying-party error instead, which is the wrong
diagnostic to surface first.

**`oauth2.relying_party` enforcement is presence PLUS the existing offline validation — not
presence-only**, unlike the Redis rule. `KeycloakRelyingParty::new` is fully synchronous and offline
(it validates shape: timeout, TTL, base64url-encoded 32-byte state key, exact fixed callback
URL/path — it never dials Keycloak), so validating it at startup costs no startup-ordering
dependency on a third party. This deliberately does **not** fetch Keycloak discovery at startup —
that would be exactly the mistake the Redis rule's own "presence-only, not a PING" reasoning warns
against, aimed at an external IdP instead of an in-cluster Redis.

**`oauth2.token_exchange` enforcement**: `build_token_exchange_state(...)?.ok_or_else(|| ...)?` —
the function's `Ok(None)` contract for "disabled" is unchanged, but its sole production caller now
converts that `None` into a hard `Error::Server`.

**`openid` ∈ `allowed_scopes` (Q2)**: OIDC Discovery 1.0 §3 requires an OpenID Provider's
`scopes_supported` to include `openid`. `authz-idp` always mounts `/authorize` and always
advertises `authorization_endpoint` now, so it is always an OpenID Provider, never a bare OAuth2
authorization server — a deployment whose `allowed_scopes` omits `openid` is refused at startup
rather than allowed to serve a spec-noncompliant discovery document. Verified live: prod already
serves `openid` in `scopes_supported`.

### 4. Presence-vs-validated, contrasted with the Redis rule

| | Redis (`AGENTS.md`) | `relying_party` (this ADR) |
|---|---|---|
| Presence required | Yes | Yes |
| Live reachability checked at startup | No (lazy client, no `PING`) | No (no Keycloak discovery fetch) |
| Shape/config validated at startup | N/A (a URL string, parsed lazily) | Yes — `KeycloakRelyingParty::new` runs its full offline validation synchronously |

Both share the same "do not add a startup-ordering dependency on a live third party" discipline;
they differ because `relying_party`'s config has real internal structure (a base64url 32-byte key,
an exact-match callback URL) worth catching before a socket is ever bound, where Redis's config is
just a connection string with nothing to validate offline beyond "is it well-formed."

## Consequences

### Positive

- Closes the live discovery/route-mounting inconsistency described in Context — permanently, not
  until the next `#473`-shaped "fix" reintroduces mount-conditional gating. There is no longer a
  config shape that starts successfully while serving a half-broken surface.
- `build_idp_router_mounts_authorize_device_verify_and_callback_unconditionally`
  (`crates/lightbridge-authz-rest/tests/idp_server_tests.rs`) is new coverage that would have caught
  the #473 regression directly — asserting `/authorize`, `/device/verify`, and `/idp/callback` are
  all reachable off the shared offline fixture, with a doc comment saying so.
- Discovery now correctly advertises `authorization_endpoint`, `response_types_supported: ["code"]`,
  `response_modes_supported: ["query"]`, and `code_challenge_methods_supported: ["S256"]`
  unconditionally — closing the same interop gap #471 fixed for the router side, now closed for the
  discovery-document side too.
- Simpler code: `build_idp_router` loses three `Option`-branches and the redundant router-level
  `is_self_signed`/`signing` re-gate; there is exactly one enforcement point for each mandatory
  piece, in `start_idp_server`.

### Negative

- **Breaking change.** Every `authz-idp` deployment must supply a complete `oauth2.relying_party`
  block and an enabled `oauth2.token_exchange` block (with `openid` in `allowed_scopes`), or the
  process refuses to start. There is no compatibility window — this is a hard cutover, consistent
  with this codebase's stated delivery style (no gradual/parallel path unless explicitly requested).
- A future deployment that genuinely wants only the token-exchange/discovery surface with no
  browser SSO has no way to opt out short of supplying a syntactically valid but effectively unused
  `relying_party` block (e.g. pointing at a realm nobody will ever complete a login against). This
  ADR treats that as acceptable because no such deployment currently exists or is planned — the
  owner's directive is unconditional ("not... optional anymore").
- Chart defaults (`charts/lightbridge-authz/values.yaml`) must now ship placeholder
  `relying_party`/`token_exchange` blocks for the `idp` alias so a fresh install doesn't immediately
  crash-loop; real deployments still override from their values repo (mirrors the existing
  `config/default.yaml` placeholder-key precedent).

### Neutral / follow-ups

- `DiscoveryCapabilities`'s other named constructors (`token_surface`, `with_device_authorization`,
  `with_authorization_code`) stay in place — `well_known_router` remains a generic function other
  future callers could still use with a narrower capability set. This ADR does not change that
  function's own contract, only what `authz-idp`'s one production caller passes it.
- The `token_exchange_enabled` field is dropped from `start_idp_server`'s startup `tracing::info!`
  log line — it was always `true` by the time that line executes now, so logging it was dead
  signal. Operator-visible log change, not a behavior change.

## Alternatives considered

- **Keep #473's mount-conditional gate, and instead fix only the `device_authorization_endpoint`
  gating to also depend on `relying_party`.** Rejected — it patches the one manifestation of the
  bug caught so far without addressing the root cause the owner's directive names directly: an IdP
  with an optional identity leg is not a full IdP. The next unaudited discovery field would
  reproduce the same class of gap.
- **Make `relying_party` presence-only (no offline validation), matching the Redis rule exactly.**
  Rejected — `relying_party`'s config has real internal structure worth validating before a socket
  binds (a malformed `state_encryption_key` is a config authoring mistake, not a third-party
  outage), and the existing `KeycloakRelyingParty::new` validation was already this strict before
  #463/#473; loosening it would be a separate, unrelated regression.
- **A feature flag to opt out of the RP-leg for deployments that want token-exchange only.**
  Rejected per this repo's own delivery-style convention: a feature flag here would be exactly the
  "dormant behind a default-off flag" pattern that convention exists to prevent, and the owner's
  directive is explicit that nothing about the IdP should stay optional.

## Related

- Reverses: PR #473 (`468084a`) — see title and Context above for the full chain (#463 → #473 →
  this ADR).
- Amends: ADR-0012 (`docs/adr/0012-device-authorization-grant-brokered-via-new-idp-service.md`) —
  see that ADR's "Related" section for the pointer back to this one.
- Amends: ADR-0019 (`docs/adr/0019-authz-idp-brokers-authorization-code-alongside-device-grant.md`)
  — see that ADR's "Related" section for the pointer back to this one.
- `AGENTS.md`/`CLAUDE.md` — "Redis is a mandatory dependency for authz-api / authz-idp /
  authz-budget" section is the house-rule shape this ADR's `relying_party`/`token_exchange`
  enforcement mirrors; a new section documents the mandatory-idp-surface rule in the same voice.
- `docs/architecture/services.md` — the `authz-idp` route table, rewritten to describe the full,
  always-mounted surface.
- `docs/auth-reference.md` — the `oauth2.relying_party`/`oauth2.token_exchange` config reference,
  updated to state both are required, not conditionally gated.
- #471 — the router-side PKCE/interop fix this ADR extends to the discovery-document side
  (`response_modes_supported`, `code_challenge_methods_supported`).
