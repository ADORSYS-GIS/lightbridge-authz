# Token-exchange integration guide

Audience: an engineering team standing up an RFC 8693 token exchange against `lightbridge-authz`'s
native `/oauth2/token` endpoint (ADR-0011 phase 2) — trading a Keycloak access token for a
project-scoped, short-lived JWT this service signs itself.

This is a task-oriented walkthrough, not a reference dictionary: field-by-field config-key/claim/
discovery-field/permission lookups (Ctrl-F a name, get a `file:line`) live in
[`docs/auth-reference.md`](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md) —
linked throughout below rather than restated. Design rationale (why a full OIDC token object, why
the client registry looks the way it does, why nonce/auth_time are propagate-or-omit) lives in
[ADR-0011](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/adr/0011-authz-issues-a-full-oidc-token-object.md).

Everything in this doc was verified against code on `main` as of this writing (commit `9f095e0`).
Every failure mode below is one the exchange handler can actually produce, cross-checked against
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`.

## Read this first: Keycloak client requirements

This is the part that costs hours if skipped. Getting a subject token from Keycloak and POSTing it
to `/oauth2/token` is not enough — **the Keycloak client that issued your `subject_token` must be
configured with the right `aud` claim, or the exchange fails with one of two different errors
depending on which of two independent checks you missed.**

The two checks run in this order, against the same subject token's `aud` claim, but they check for
different values and fail differently:

| # | Check | What it needs | Where | On failure |
|---|-------|----------------|-------|------------|
| a | **Bearer validation** | `subject_token.aud` must contain this deployment's configured `oauth2.audience` (e.g. `lightbridge-api-key`) | `crates/lightbridge-authz-bearer/src/lib.rs:246-259` | `401 invalid_token` |
| b | **Exchange client binding** | `subject_token.aud` must also contain the literal `client_id` you send in the exchange request | `crates/lightbridge-authz-rest/src/oauth2_op/store.rs:187-192` | `400 invalid_grant` |

**(a) Bearer validation.** `BearerTokenService::validate_bearer_token` only checks audience when
`oauth2.audience` is non-empty (`if let Some(expected_audiences) = &self.config.audience { if
!expected_audiences.is_empty() { validation.set_audience(expected_audiences); validation.validate_aud
= true; } }`, `crates/lightbridge-authz-bearer/src/lib.rs:246-253`). Underneath, `jsonwebtoken`
11.0's `Validation::validate_aud` uses `is_subset`, which only requires a **non-empty intersection**
between the configured audiences and the token's `aud` — not an exact match
(`jsonwebtoken-11.0.0/src/validation.rs:242-247, 336-339`). So one matching value anywhere in
`subject_token.aud` is enough. This deployment's Helm chart ships `oauth2.audience: []` (no
validation) by default and documents `["lightbridge-api-key"]` as the production override
(`charts/lightbridge-authz/values.yaml:140,157`) — check your actual deployment's config for the
live value, since it's not fixed by the code.

**(b) Exchange client binding.** Independently of (a), `TokenExchangeOpStore::handle_token_exchange`
requires the `client_id` you send in the exchange request to also appear in `subject_token.aud`:

```rust
// crates/lightbridge-authz-rest/src/oauth2_op/store.rs:187-192
if !token_info.aud.iter().any(|a| a == &client_id) {
    return Err(oauth_err(
        "invalid_grant",
        "Client is not authorized to exchange this token",
    ));
}
```

This is a **different** audience value from (a) unless you deliberately make them the same string.
A subject token whose `aud` contains `lightbridge-api-key` but not your registered exchange
`client_id` (e.g. `lightbridge-ss`) passes check (a) and fails check (b).

### Two ways to satisfy both, and the trade-off

**Option 1 — two audience mappers on the Keycloak client (recommended).** Add one mapper for the
bearer-validation audience, and a second one whose value is your client's own registered
`client_id`. This is the working template already in `.docker/keycloak_config/realm.json`
(lines 123-133), quoted verbatim:

```json
{
  "name": "lightbridge-api-key-audience",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "consentRequired": false,
  "config": {
    "included.custom.audience": "lightbridge-api-key",
    "id.token.claim": "false",
    "access.token.claim": "true"
  }
}
```

That satisfies check (a). Add a **second** `oidc-audience-mapper` alongside it, same shape, with
`included.custom.audience` set to your own registered `client_id` (e.g. `lightbridge-ss`) to satisfy
check (b). This is what the per-client entry in `oauth2.clients` (ADR-0011 Decision 5) exists for —
each exchange client keeps a distinct identity in `aud`/`azp` on the tokens it mints
(`aud_is_the_requesting_client_id_and_varies_between_clients`,
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:592-639`).

**Option 2 — name your client `lightbridge-api-key`.** One audience mapper, one value, satisfies
both checks at once (client_id == the bearer-validation audience). No second mapper needed — but
every exchange client would need the *same* `client_id`, which collapses the per-client `aud`/`azp`
distinction ADR-0011 Decision 5 relies on (audit trail, per-client scope/grant-type restrictions).
Only reach for this if you genuinely have one exchange client, not several.

## A working request

```
POST https://<issuer>/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
client_id=lightbridge-ss
subject_token=<keycloak access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
project_id=<your project id>
scope=openid profile email offline_access
```

| Field | Required | Notes |
|---|---|---|
| `grant_type` | yes | must be exactly `urn:ietf:params:oauth:grant-type:token-exchange` |
| `client_id` | yes (public clients) | must be registered in `oauth2.clients`; must appear in `subject_token.aud` — see above. Confidential clients authenticate via `client_assertion`/`client_assertion_type` instead (RFC 7523, ADR-0011 Decision 6) and may omit `client_id` in the body if it's recoverable from the assertion |
| `subject_token` | yes | the Keycloak access token being exchanged |
| `subject_token_type` | optional | if present, must be exactly `urn:ietf:params:oauth:token-type:access_token` — any other value (e.g. `saml2`) is rejected (`unsupported_subject_token_type_is_invalid_request`) |
| `project_id` | **yes today** | see below — PR #309 will make this optional |
| `scope` | optional | space-separated; see "Scope semantics" |
| `requested_token_type` | optional | only `access_token` is supported if present at all |

**`project_id` is currently required.**
[PR #309](https://github.com/ADORSYS-GIS/lightbridge-authz/pull/309) (open, not yet merged as of
this writing) adds a fallback: an absent `project_id` will resolve to the subject's own
auto-provisioned default project (`StoreRepo::find_default_project_id`), and an account with **zero**
projects will get the same uniform `403 access_denied` as a non-member/unknown project — the
fallback is deliberately indistinguishable from every other "you can't have this project" case, for
the same non-enumeration reason `resolve_context` already applies (see the error table below). Until
#309 merges, omitting `project_id` entirely fails with `400 invalid_request` / `"project_id is
required"` (`missing_project_id_is_invalid_request`,
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:960-974`).

The RFC 8693 `audience`/`resource` request parameter is accepted on the wire but **not read** by
this deployment's exchange handler — `TokenExchangeOpStore::handle_token_exchange`
(`crates/lightbridge-authz-rest/src/oauth2_op/store.rs:116-308`) never inspects `req.audience`
anywhere in its body. The minted token's `aud`/`azp` are always exactly the requesting `client_id`;
there is no multi-resource audience request here today, regardless of what a client's configured
`allowed_audiences` suggests (that field only matters to `authkestra-op`'s own default exchange
handler, which this deployment's hand-written override bypasses entirely — see the header comment
on `store.rs`).

## What you get

```json
{
  "access_token": "<jwt>",
  "id_token": "<jwt>",
  "refresh_token": "<opaque>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email offline_access"
}
```

`id_token` is present only when `openid` was granted; `refresh_token` only when `offline_access` was
granted. `issued_token_type` is always present and always the access-token URN (this endpoint never
issues any other primary token type — `crates/lightbridge-authz-rest/src/oauth2_op/mod.rs:25-28`).

The full claim-by-claim table for both tokens (source, minted-vs-propagated, exact `file:line`) is
[`docs/auth-reference.md` §3](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md#3-token-claims--source) —
not repeated here. What matters for integrating against it:

- This service owns no users (ADR-0011, Context): `sub` on both tokens is the upstream Keycloak
  subject, copied verbatim, never re-minted. `auth_time`/`nonce` on the `id_token` are propagated
  only when present on the *subject token itself*, never invented or defaulted to "now".
- `role`, `quota_tier`, and `project_quota` are **never** present on either token — verified here by
  `tenant_claims_on_access_token_role_and_quota_absent_from_both`
  (`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:672-717`). Those claims live on the
  introspection response instead (`docs/auth-reference.md` §3), not on any JWT this endpoint issues.
- The access token's `api_key_id` claim is a CUID2 minted fresh on **every** exchange/refresh — it
  is not a real `api_keys.id`; no key row exists behind a token-exchange-derived token, so don't use
  it to look one up. `sid` is likewise an independent, freshly-minted value per token, not a stable
  session id across a refresh.
- `allowed_models` on the access token is the **project's** `allowed_models`, present only if
  non-empty (absence means "all models allowed", same convention as `api_keys.allowed_models`).

## Error → cause → fix

| HTTP | `error` | `error_description` | Cause | Fix |
|---|---|---|---|---|
| 401 | `invalid_token` | `subject_token validation failed` | Check (a) above (audience mismatch), OR a JWKS/issuer mismatch. The API log line names the underlying `jsonwebtoken` error, so `InvalidAudience` vs a signature/issuer error tells them apart — see "How to debug" | Fix the Keycloak client's audience mapper (a), or confirm `oauth2.jwks_url`/issuer match the IdP that signed the token |
| 401 | `invalid_token` | `subject_token is not active` | Bearer validation succeeded but the token reports inactive (`bearer_validation_error_is_unauthorized`-style path) | Get a fresh subject token |
| 400 | `invalid_grant` | `Client is not authorized to exchange this token` | Check (b) above — `client_id` not in `subject_token.aud` | Add/fix the second audience mapper (Option 1), or use Option 2 |
| 400 | `invalid_grant` | `refresh_token is invalid, expired, or already used` | One message, several causes, all indistinguishable on the wire (by design): the token was already consumed (single-use) or is expired or unknown; it was issued to a different `client_id`; its **chain** is past the 90-day absolute cap; or re-validation failed — the subject lost project membership, or the resolved project/account is suspended or the project no longer exists. See "Refresh" below for the re-validation and absolute-cap details | Use the most recent refresh token; if the session is legitimately older than the absolute cap or the subject's access changed, re-exchange from a fresh subject token instead of retrying the same refresh token |
| 403 | `access_denied` | `subject is not a member of the requested project` | The subject neither owns nor is a member of `project_id`. Deliberately identical to "project does not exist" — this endpoint never leaks which projects exist | Confirm the subject's actual project membership; do not use this response to probe for valid project ids |
| 401 | `invalid_client` | `Client authentication failed` | `client_id` missing, unregistered in `oauth2.clients`, or (confidential clients) `client_assertion` missing/invalid/replayed | Register the client, or fix the client assertion |
| 400 | `unauthorized_client` | `Client is not authorized to use token_exchange grant type` (or `refresh_token`) | The registered client's `grant_types` doesn't include the grant you're using | Add the grant type to the client's config entry |
| 400 | `invalid_request` | `subject_token is required` | Missing `subject_token` field | Add it |
| 400 | `invalid_request` | `subject_token_type must be urn:ietf:params:oauth:token-type:access_token` | Sent a `subject_token_type` other than the access-token URN | Omit it or set it to the correct URN |
| 400 | `invalid_request` | `Unsupported requested_token_type. Only access_token is supported.` | Sent a `requested_token_type` other than the access-token URN | Omit it or set it to the correct URN |
| 400 | `invalid_request` | `project_id is required` | See "`project_id` is currently required" above | Send `project_id` (until #309 merges) |
| 500 | `server_error` | varies | Signing key unavailable, DB unreachable, or refresh-token persistence failed | Not a caller-side fix; check API health/DB connectivity |

`unsupported_grant_type` exists in the handler's source but is not reachable through this
deployment in practice: the `/oauth2/token` route itself is only mounted when
`oauth2.token_exchange.enabled` is true, and the same flag gates the check that would otherwise
produce this error — so by the time a request reaches that check, it's already guaranteed to be
true. `invalid_scope` and `invalid_target` are defined by RFC 6749/8693 but this crate's exchange/
refresh overrides never emit either.

Status-code mapping source: `crates/lightbridge-authz-rest/src/token_exchange.rs:218-225`.

**How to debug:** the real reason for a `401 invalid_token` is logged at `ERROR` in
`lightbridge-authz-bearer` even though the response body is deliberately generic:

```
kubectl logs deploy/lightbridge-api-main | grep -i "JWT validation failed"
```

An audience mismatch (check (a)) logs as:

```
JWT validation failed: JWT error: InvalidAudience
```

(`authkestra_resource`'s `ValidationError::Jwt` wraps `jsonwebtoken::errors::Error` with `"JWT
error: {0}"`, and that error's `Display` for `InvalidAudience` is literally `InvalidAudience` — the
two together produce that exact string.) A missing `aud` claim entirely, or an issuer/signature
problem, logs a different, more specific message from the same call site
(`crates/lightbridge-authz-bearer/src/lib.rs:265-298`) — read the log line, don't guess from the
generic 401 body alone.

## Scope semantics

Counter-intuitive, so stated explicitly: **the subject token's own `scope` claim is not read at
all** — `TokenInfo` (the type `validate_bearer_token` returns) has no `scope` field
(`crates/lightbridge-authz-bearer/src/lib.rs:28-48`). Granted scopes come entirely from:

```
requested (or, if empty, the server allow-list minus offline_access)
  ∩ oauth2.token_exchange.allowed_scopes
  ∩ the registered client's own `scopes`
```

(`grant_scopes`, `crates/lightbridge-authz-rest/src/oauth2_op/mod.rs:50-76`.) So a subject token
whose own `scope` claim is only `profile email` can still yield `openid` + `offline_access` on the
exchanged token, as long as the request asks for them and both the server allow-list and the client
registration permit them. Conversely, requesting a scope the client isn't registered for silently
drops it from the grant rather than erroring
(`exchange_with_unrecognized_scope_omits_scope_from_response`).

`offline_access` must be explicitly requested (OIDC Core §5.4) — an empty/absent `scope` parameter
grants the allow-list *minus* `offline_access` specifically, so a scope-less exchange never silently
mints a refresh token.

## Refresh

```
POST https://<issuer>/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
client_id=lightbridge-ss
refresh_token=<the refresh_token from the previous response>
```

Same endpoint, same client authentication rules as the original exchange. The refresh token is
**single-use with rotation**: each successful refresh consumes the presented token and returns a new
one in its place (`refresh_rotates_and_rejects_replay`,
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:1133-1186`); replaying an
already-consumed refresh token fails with `400 invalid_grant`. A refresh token presented by a
different `client_id` than the one it was issued to is likewise burned, not honored
(`refresh_token_issued_to_client_a_is_rejected_when_presented_by_client_b`). The re-minted access/
id_token carry the *original* grant's scope verbatim — a refresh request cannot widen or narrow
scope; there is no `scope` parameter on this grant to do so.

The field-by-field dictionary for `chain_id`/`chain_expires_at`/`exchange_refresh_tokens.status` is
[`docs/auth-reference.md` §4](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md#4-refresh-token-chain--lifecycle) —
what follows here is the task-oriented version of the same material.

### Every refresh re-validates — it is not just a token-row lookup

`handle_refresh_token` (`crates/lightbridge-authz-rest/src/oauth2_op/store.rs:422-616`) re-runs, on
**every** refresh, the same checks the original exchange used:

1. **Membership/ownership** — `resolve_context(subject, project_id)`, the same query
   `/idp/v1/resolve-context` uses (ADR-0006: owns the project OR holds a `project_members` row). A
   subject removed from the project's roster between refreshes loses the ability to refresh
   immediately, even though the presented refresh token is individually still unexpired
   (`refresh_after_member_removed_from_project_is_invalid_grant`,
   `crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:1821-1854`).
2. **Project status** — the resolved project must be `Active`
   (`refresh_after_project_suspended_is_invalid_grant`, `token_exchange_tests.rs:1900-1936`).
3. **Account status** — the resolved account must be `Active`
   (`refresh_after_account_suspended_is_invalid_grant`, `token_exchange_tests.rs:1938-1976`).

Any failure in any of these three refuses the refresh with a plain `invalid_grant` — never a
permissive fallback. **A deleted or otherwise-unresolvable project now fails closed, and did not
always.** Before this hardening, a refresh whose project could not be resolved fell through to
`allowed_models = None`, which this codebase reads as *"no restriction"* — a genuine fail-open bug
that would have handed back an unrestricted access token against a project that no longer exists.
It is now a hard refusal, locked by a regression test named for exactly that:
`refresh_after_project_deleted_is_invalid_grant_not_fail_open`
(`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:1861-1899`).

### The refresh chain has a 90-day absolute cap — rotating does not reset it

**This is the behavioral change to plan around.** Before this hardening, a session that refreshed
at least once before every individual token's expiry stayed alive indefinitely — each rotation only
ever reset that token's own `expires_at`, never a session-level ceiling. Refreshing monthly, forever,
kept the session alive forever.

Every refresh-token row now belongs to a **chain**: `chain_id`/`chain_expires_at`. `chain_id` is
minted once, at the offline-scope exchange grant that gives the chain its first token, and every
subsequent rotation **inherits it unchanged** rather than getting a fresh one. `chain_expires_at` is
likewise set once, at chain birth, to `now + oauth2.token_exchange.refresh_absolute_ttl_seconds`
(default `7_776_000` seconds / 90 days — see
[`docs/auth-reference.md`](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md)
for the config row), and inherited unchanged by every rotation after that — never extended, never
reset, regardless of how recently the chain was last refreshed.

A chain that has crossed its `chain_expires_at` refuses the very next refresh outright, even if the
presented token's own individual `expires_at` has not passed
(`refresh_after_absolute_cap_is_invalid_grant`,
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:1705-1755`); the inheritance itself is
asserted across two consecutive rotations, not just one, so a bug that only shows up on the second
inheritance cannot hide behind a single-rotation check
(`chain_id_and_absolute_cap_survive_multiple_rotations`, `token_exchange_tests.rs:1763-1813`). A
client whose user needs a session to outlive 90 days has to re-exchange from a fresh Keycloak
subject token — there is no way to extend or reset a chain's cap from within the refresh grant
itself.

### Replaying an already-rotated token revokes its entire chain

Presenting a refresh token that has already been rotated away (superseded by a later token in the
same chain) is treated as the strongest signal this codebase has that the token was stolen (RFC
6819 §5.2.2.3): the **entire chain** is revoked, including the current, otherwise-still-valid
successor token — not just the replayed one
(`replaying_a_rotated_refresh_token_revokes_the_whole_chain`,
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:1978-2026`).

An **unknown** token (never issued), or a token that is merely expired or already explicitly
revoked, is a plain `400 invalid_grant` with **no** cascade — it never touches any other chain
(`unknown_refresh_token_is_invalid_grant_without_cascading`, `token_exchange_tests.rs:2032-2065`).
Explicit revocation (`/oauth2/revoke`, below) and this automatic cascade compose safely: replaying a
token that was *explicitly* revoked is never mistaken for the cascade's own "already rotated"
trigger (`replaying_an_explicitly_revoked_token_does_not_trigger_the_reuse_cascade`,
`token_exchange_tests.rs:2508-2547`).

### The honest limit: refresh does not call Keycloak

None of the re-validation above talks to the upstream IdP. `handle_refresh_token` re-checks only
this service's own `resolve_context` plus project/account status — **a user disabled directly in
Keycloak, but still active on this service's own roster, is not detected by a refresh.** That
session is bounded only by the 90-day absolute cap above and by an explicit revoke (`/oauth2/revoke`
below, or the `revokeOwnSessions`/`revokeSubjectSessions` RPC procedures —
[`docs/auth-reference.md` §5](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md#5-permissions--procedures)
has both). If a user being disabled in the IdP needs to take effect immediately rather than waiting
out the cap, pair that with an explicit `revokeSubjectSessions` call — do not rely on refresh
re-validation to catch it.

## Revocation

```
POST https://<issuer>/oauth2/revoke
Content-Type: application/x-www-form-urlencoded

token=<the refresh_token to kill>
client_id=lightbridge-ss
```

RFC 7009. Same client-authentication rules as `/oauth2/token` and `/oauth2/refresh` above (public
`client_id` alone, or `client_assertion`/`client_assertion_type` for a confidential client) — a
confidential client revoking its own token needs a **fresh** assertion `jti`, distinct from
whichever one it last used to obtain a token; a replayed `jti` is refused the same way it is at
`/oauth2/token`.

A successful call is `200 OK` with an empty body. **The counter-intuitive part (RFC 7009 §2.2):**
an unknown token, an already-revoked token, or a token issued to a *different* client than the one
authenticating the request is **also** `200 OK` — never an error. This is deliberate: it denies an
attacker an oracle for probing whether a given token string is currently valid, or which client it
belongs to. The only error this endpoint ever returns is client-authentication failure itself
(unknown `client_id`, missing/invalid assertion) — `401 invalid_client` — which happens entirely
before the token is even looked up. A request missing the `token` field altogether is
`400 invalid_request` (a malformed *request*, not a malformed *token value*).

Revocation flips the token's row from `active` to `revoked`; the very next presentation to
`grant_type=refresh_token` fails with `400 invalid_grant`, same as an already-consumed
(rotated-away) refresh token — the two are indistinguishable on the wire, by design (see the
Refresh section above). There is no access-token revocation: access tokens are stateless
self-signed JWTs with no server-side record, so this endpoint only ever touches
`exchange_refresh_tokens` rows regardless of `token_type_hint`.

Tests: `crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`, the "RFC 7009" section near
the end of the file.

## Discovery

`GET https://<issuer>/.well-known/openid-configuration` is public, unauthenticated, wide-open CORS.
Full field-by-field derivation is
[`docs/auth-reference.md` §2](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md#2-discovery-document-fields--derivation).
Two things it will **not** tell you, by design, not omission, worth knowing before you write a
client that parses it:

- `response_types_supported` is an empty array **in both the enabled and disabled state**, and
  `authorization_endpoint` is absent from the document entirely (not null — the key itself is
  removed post-serialization), also in both states. This service runs no `/authorize` route and
  never redirects a user-agent; token exchange is a direct machine-to-machine POST/response, not a
  redirect-based flow. Per OIDC Discovery 1.0 §3, the "must support code/id_token/id_token token"
  requirement only binds a *Dynamic* OpenID Provider (one that advertises `registration_endpoint`)
  — this deployment registers clients from static config only (ADR-0011 Decision 5) and has no such
  endpoint, so the empty array is spec-compliant. Locked by a regression test specifically because
  an earlier version of this code *did* flip `response_types_supported` to
  `["token","id_token","id_token token"]` purely because `token_exchange.enabled` went from `false`
  to `true`
  (`discovery_never_advertises_response_types_or_modes`,
  `crates/lightbridge-authz-rest/tests/signing_tests.rs:465-514`).
- `grant_types_supported`, `token_endpoint`, and `scopes_supported` are the three fields actually
  gated on `oauth2.token_exchange.enabled`, empty/absent when it's off — don't infer token-exchange
  availability from the presence of `issuer`/`jwks_uri` alone; check those three instead.
- **`/oauth2/revoke` is not in this document at all** — `revocation_endpoint` isn't a field
  `OidcDiscovery` (from `authkestra-op` 0.5.0) has room for, even though the endpoint above is real
  and live. This is a known upstream gap (`marcjazz/authkestra#220`, RFC 8414 §2), not a bug in this
  service — a client integrating revocation needs the hardcoded path (`{issuer}/oauth2/revoke`), the
  same way `token_endpoint`'s literal `{issuer}/oauth2/token` shape is already assumed above.

Source: `discovery_document`, `crates/lightbridge-authz-rest/src/signing.rs:401-529`.

## See also

- [ADR-0011](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/adr/0011-authz-issues-a-full-oidc-token-object.md) —
  design rationale for the token shape, the client registry, and the claim-propagation rules cited
  throughout this doc.
- [`docs/auth-reference.md`](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/auth-reference.md) —
  the field-by-field reference dictionary this guide deliberately does not duplicate.
