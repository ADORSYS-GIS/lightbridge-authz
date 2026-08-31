# OAuth/OIDC standards gap and delivery roadmap

**Status:** implementation inventory and roadmap, verified against this repository on 2026-08-24.
It is the canonical statement of what `authz-idp` implements today and what is still required
before it can be described as a browser-facing Authorization Server / OpenID Provider. Accepted
ADRs remain the decision record; this page records delivery status and protocol conformance.

## Baseline and scope

The conformance baseline is OAuth 2.0 plus the security guidance in
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), with
[RFC 10017](https://www.rfc-editor.org/rfc/rfc10017) for browser-based applications and the
relevant extension RFCs below.
OAuth 2.1 is **not** a released baseline: as of 2026-08-24 it is
[draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/15/).
The project may target its final requirements, but must not claim OAuth 2.1 conformance until it
is an RFC and the implementation has been checked against that RFC.

This roadmap implements the direction in
[ADR-0019](adr/0019-authz-idp-brokers-authorization-code-alongside-device-grant.md) (browser
authorization code) and
[ADR-0021](adr/0021-browser-sso-hosted-login-page-and-session-cookie.md) (brokered Keycloak SSO
and a browser session). It does not reopen their security decisions.

## What is implemented now

`authz-idp` is the sole public owner of this repository's self-issued OIDC surface; `authz-api`
no longer serves these paths. Its router is
[`build_idp_router`](../crates/lightbridge-authz-rest/src/lib.rs). Since
[ADR-0023](adr/0023-the-authz-idp-surface-is-mandatory-not-composable.md), `authz-idp` is a full
IdP: `oauth2.relying_party` and an enabled `oauth2.token_exchange` (with `openid` in
`allowed_scopes`) are both required for the process to start at all, and every route below is
mounted **unconditionally** on every deployment that does start — there is no reduced-surface
configuration left to describe. `start_idp_server` refuses to start otherwise:

| Surface | Current state |
| --- | --- |
| `GET /.well-known/openid-configuration`, `GET /.well-known/oauth-authorization-server`, `GET /.well-known/jwks.json` | Implemented and unconditional (ADR-0023). OIDC discovery and RFC 8414 authorization-server metadata always advertise the token-exchange/refresh/device/authorization-code surface, the authorization endpoint, `code` response type, `query` response mode, `S256` PKCE method, and revocation endpoint. For an issuer with a path, OIDC discovery follows the issuer path (`/issuer/.well-known/openid-configuration`) while RFC 8414 inserts `.well-known` before it (`/.well-known/oauth-authorization-server/issuer`); protocol endpoints remain at their mounted root paths. |
| `GET /authorize`, `POST /oauth2/token` | Implemented and unconditional. `/authorize` validates a reviewed static client registry, byte-exact redirect URI and S256 PKCE before either using a valid browser session or starting the Keycloak RP leg. Authorization codes are persisted, short-lived and CAS-consumed. `/oauth2/token` serves authorization-code, RFC 8628 device-code, RFC 8693 token-exchange, and refresh grants; its responses carry no-store cache controls and its browser CORS policy is derived from registered public authorization-code callbacks. |
| `POST /oauth2/revoke` | Implemented and unconditional, under RFC 7009, and always advertised as `revocation_endpoint`. |
| Device verification + Keycloak RP leg | Implemented and unconditional. `GET`/`POST /device/verify`, `POST /device/verify/continue`, `GET /device/verify/context`, and `GET /idp/callback` are mounted by [`relying_party.rs`](../crates/lightbridge-authz-rest/src/relying_party.rs). **Since lightbridge-authz#607, this leg renders no HTML itself** — `GET /device/verify` `303`s into the SPA's `/ui/device` route (prefilling a sanitised `?user_code=`), `POST /device/verify` looks up the code and `303`s onward (`/ui/device/confirm` on success, `/ui/device/invalid` uniformly for unknown/expired/consumed, `/ui/error` on a store outage), and `GET /device/verify/context` — bound to the `__Host-authz_device_confirm` cookie `/device/verify` set — serves the confirmation data (`user_code`, `client_id`) as JSON for the SPA to render. Confirming redirects to Keycloak only from `POST /device/verify/continue`, with PKCE, an encrypted cookie-bound RP state, and nonce. The callback performs discovery, bounded code redemption, and RS256/`kid`/issuer/audience/required-`iat`/nonce validation (with `azp` bound to this client for multi-audience tokens) before its CAS approval of the persisted device row and a final `303` to `/ui/device/success`; failure leaves it pending. Browser sessions resolve the verified Keycloak subject and requested project through the store and are used by `/authorize` for the SSO shortcut. |
| Hosted static assets | A same-origin SPA build is served under `/ui` ([`static_assets.rs`](../crates/lightbridge-authz-rest/src/static_assets.rs)), sourced from `converse-frontends`' `apps/authz-ui` and consumed as a digest-pinned OCI artifact (ADR-0029), not built in this repo. **Since lightbridge-authz#598, `/ui` is a route ALLOWLIST, not a whole-subtree fallback:** only the paths listed in the artifact's own `dist/routes.json` resolve to `index.html`; every other `/ui/*` path is a plain `404`. It serves files only — it does not authenticate, set cookies, or implement `/authorize`. |

The existing exchange is useful for an already-authenticated, server-side caller. It is not an
authorization-code flow and must not be presented as one. Likewise, an accepted ADR is intent,
not evidence that its routes or grant are live.

## Browser Authorization Code + PKCE implementation record

The following must-have path is implemented for a standards-based browser client, using
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), and OpenID Connect
[Core](https://openid.net/specs/openid-connect-core-1_0.html):

1. Build the shared Keycloak RP leg: authorization request, encrypted/bound `state`, nonce,
   callback, issuer/signature/audience/nonce validation, and fail-closed error handling. The
   broker never authenticates a user itself; it accepts a verified Keycloak result.
2. Implement the ADR-0021 browser session after that verified callback: a short-lived,
   revocable persisted browser session and correctly scoped `__Host-` cookie. Unknown, expired,
   revoked, or unavailable session state must disable the SSO shortcut and return to Keycloak,
   never create a session or issue a code.
3. Implement `GET /authorize` with registered-client lookup, exact byte-for-byte
   `redirect_uri` matching, requested-scope validation, `state` round-trip, and a redirect only
   after all validation succeeds. Do not accept wildcard, prefix, or inferred redirect URIs.
4. Replace `NoAuthorizationCodeStore` with a persisted, short-lived, opaque, single-use,
   CAS-consumed code bound to `client_id`, exact `redirect_uri`, granted scope, authenticated
   subject/context, and PKCE challenge/method. Expired, replayed, cross-client, or
   cross-redirect redemption must fail without disclosing which check failed.
5. Enable `authorization_code` only for clients that have the registry fields above. For public
   clients, require PKCE `S256` and reject `plain` or an absent verifier/challenge. Keep the
   ADR-0011 private-key-JWT policy for confidential clients; it does not replace redirect binding.
6. Redeem the code at `POST /oauth2/token`, issue the intended access token and, for `openid`, an
   ID Token with correct nonce semantics. Then advertise only the routes and response/grant types
   that are actually mounted.

The browser client is a redirect/RP client; token exchange remains appropriate for the distinct
server-to-server case that already holds a subject token. See ADR-0019 for that client split.

## Device-flow implementation record

[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) support is complete beyond the database store:

- a device-authorization endpoint authenticates/validates the client, creates a pending
  device code, and returns `device_code`, `user_code`, `verification_uri`,
  `verification_uri_complete`, `expires_in`, and polling `interval`;
- a browser verification route/page accepts the user code, uses the shared Keycloak RP leg,
  and atomically approves or denies the pending row for the verified subject;
- token-endpoint dispatch for the device-code grant includes RFC 8628 `authorization_pending`,
  `slow_down`, expiry, denial, and one-time consumption behavior; and
- discovery metadata advertises `device_authorization_endpoint` and the device grant only
  once those endpoints are reachable.

The exact endpoint spelling is an implementation choice retained by ADR-0012; clients must not
be told an endpoint exists until it is mounted and advertised.

## Current protocol defects to fix before adding clients

These are concrete, independently testable defects in the current live token boundary. Fixing
them first prevents the later authorization-code/device work from inheriting an incorrect HTTP
contract.

- **Token response cache controls — resolved:** successful token responses and token error
  responses now carry `Cache-Control: no-store` and `Pragma: no-cache`, applied at the token-route
  boundary so extractor errors and future browser/device grants receive the same treatment.
- **RFC 8693 required parameter and errors — resolved:** `subject_token_type` is required in
  [`handle_token_exchange`](../crates/lightbridge-authz-rest/src/oauth2_op/store.rs) and an empty
  value is rejected. RFC 8693 makes it REQUIRED, and this server accepts exactly the supported
  access-token type. An invalid or unacceptable subject token now uses RFC 8693's
  `invalid_request`/400 shape, separately from RFC 6749 client-authentication failures.
- **`issued_token_type` — resolved:** the HTTP wrapper emits it only for successful RFC 8693 token
  exchange. Refresh and future code/device responses follow their own grant response profile.
- **Browser token-endpoint CORS — resolved:** the token endpoint derives an exact origin allowlist
  (scheme, host, and port) from registered public authorization-code callbacks, mounts matching
  methods/headers and preflight handling, and sets `Vary: Origin`. It does not infer an origin from
  the issuer or allow a wildcard.
- **SPA fallback protocol-namespace leak — resolved:** unknown `/oauth2/*` and
  `/.well-known/*` paths, plus allocated root protocol endpoints (`/authorize`, `/userinfo`,
  `/device_authorization`, and `/idp/callback`), are reserved ahead of the SPA fallback and return
  `404`; they can no longer return `index.html` with `200`. Superseded further by
  lightbridge-authz#598: `/ui` stopped being a whole-subtree fallback at all and became a route
  allowlist (see the "Hosted static assets" row above), so this class of leak is now structurally
  closed rather than defended by an enumerated denylist. The browser-facing device-verification
  flow (`/device/verify`) hands off into that allowlisted SPA routing via `303`, not by rendering a
  page itself — see the "Device verification + Keycloak RP leg" row above.

## Discovery and authorization-server metadata gaps

The current documents advertise authorization and device endpoints only when their routes are
mounted. UserInfo, introspection, and logout remain absent. When a new surface ships, update the
metadata according to
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) and
[OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), in lockstep
with router tests:

- keep `authorization_endpoint`, `response_types_supported` (at least `code`),
  `response_modes_supported`, `grant_types_supported`, and `code_challenge_methods_supported`
  (`S256`) tied to their matching mounted routes;
- keep `device_authorization_endpoint` tied to a working RFC 8628 endpoint;
- add the standard introspection, UserInfo, and logout metadata only with their corresponding
  endpoints; and
- keep `issuer`, endpoint URLs, signing algorithms, client-auth methods, scopes, and CORS behavior
  internally consistent. Discovery must be a capability statement, never a roadmap.

## Token profile and lifecycle cleanup

Human-plane tokens currently reuse the API-key signing extras: a persisted session id is put in
`api_key_id` and `lightbridge_caller_kind` is stamped as `api_key` (see
[`access_token_extra`](../crates/lightbridge-authz-rest/src/signing.rs) and its exchange callers).
That breaks the documented plane discriminator and must be fixed independently of client cutover.
Define separate, tested claim profiles for API-key, human authorization-code/device, and
token-exchange tokens.

At the same time, separate three concepts that are currently conflated:

- OAuth client identity (`client_id`, and `azp` where applicable);
- the resource server / target resource (`resource` from
  [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) or a deliberately constrained RFC 8693
  `audience` policy); and
- the JWT access-token `aud` claim, which must name the resource(s) that will validate it, not
  merely whichever client requested it.

Today the exchange handler accepts `audience` in the HTTP form but mints the access-token audience
from `client_id`; it needs an explicit resource/audience model before resource servers can rely on
`aud`. A later, optional compatibility target is the JWT access-token profile in
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068); adopt it only after the resource and claim
contracts are settled, rather than relabeling the current tokens as RFC 9068 compliant.

## Standard lifecycle endpoints still to add

[`/oauth2/revoke`](https://www.rfc-editor.org/rfc/rfc7009) is useful but only revokes persisted
refresh-token state; a self-contained access JWT cannot be made invalid by deleting a refresh row.
Complete the interoperable lifecycle surface as follows:

- add a client-authenticated, standards-shaped introspection endpoint per
  [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), distinct from the internal
  Basic-auth Authorino API-key validation endpoint. It must report `active: false` for expired,
  revoked, unknown, and cascade-revoked credentials without becoming an oracle;
- define revocation cascades across refresh-token chain, server-side session, browser session,
  authorization codes, and device authorizations. Access-token revocation needs either short TTL
  plus introspection/deny-list enforcement at resource servers, or a clearly documented bounded
  window; do not imply immediate JWT invalidation where none exists;
- add a UserInfo endpoint only if the OIDC scope/claim contract has a server-side source and it
  can validate the presented access token and subject consistently; and
- add [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) only with
  browser-session clearing, persisted-session revocation, and post-logout redirect validation.
  Publish `end_session_endpoint` only then.

## Optional hardening, after the core flows

- [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) issuer identification in authorization
  responses, particularly if this deployment can be reached through multiple issuers;
- pushed authorization requests, [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126), if clients
  need a protected front-channel request or large/sensitive request parameters;
- sender-constrained tokens with [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449) or
  [OAuth mTLS (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705) where the resource-server
  topology can verify the proof; and
- JWKS/key-rotation, redirect, CSRF, token replay, negative-path, and interoperability testing
  across a real browser, a public client, a confidential client, and a resource server.

These are valuable defenses, not blockers for a correct Authorization Code + PKCE baseline.

## Explicit non-goals

This roadmap does not add the implicit grant, Resource Owner Password Credentials grant, or a
dynamic client-registration endpoint. Static, reviewed/GitOps client registration remains the
chosen operating model. Those omissions are compatible with OAuth 2.0 plus RFC 9700 and do not
block a standard authorization-code, device, introspection, revocation, or logout deployment.
`client_credentials` is likewise outside this browser/device roadmap and should be added only for
a concrete machine-to-machine use case with a defined client identity, audience, and authorization
policy.

## Ordered delivery and definition of done

1. Correct the existing token HTTP contract: cache headers, RFC 8693 parameter/error behavior,
   grant-specific response fields, token CORS, and reserved protocol namespaces.
2. Implement and test the shared Keycloak RP callback and browser-session/cookie lifecycle.
3. Implement Authorization Code + PKCE, client redirect registry, and truthful discovery.
4. Complete the RFC 8628 endpoint/verification/polling flow using the existing device store.
5. Separate claim profiles and introduce an explicit client/resource/audience model.
6. Add standard introspection, lifecycle cascade semantics, and the deliberately scoped
   UserInfo/logout endpoints.
7. Add optional sender constraints/PAR/issuer-response hardening where deployment needs justify
   them.

The server is ready to claim Authorization Code + PKCE/OIDC support only when the
[OpenID Foundation conformance suite](https://openid.net/certification/about-conformance-suite/)
and repository integration tests prove: registered exact redirect matching; `S256` PKCE success
and every negative case; one-time/expired/cross-client code refusal; Keycloak callback
state/nonce/issuer validation; correct browser-cookie/session revocation behavior; truthful OIDC
and RFC 8414 discovery; token response cache headers and CORS; correct RFC 8693 requests/errors;
device polling states; and standard introspection/revocation behavior. Passing a happy-path
browser login alone is not conformance.

## Related repository references

- [Architecture service inventory](architecture/services.md#authz-idp)
- [Authentication and token reference](auth-reference.md)
- [Auth flows](architecture/auth-flows.md)
- [ADR-0011: full OIDC token object](adr/0011-authz-issues-a-full-oidc-token-object.md)
- [ADR-0012: device authorization broker](adr/0012-device-authorization-grant-brokered-via-new-idp-service.md)
- [ADR-0019: authorization-code broker](adr/0019-authz-idp-brokers-authorization-code-alongside-device-grant.md)
- [ADR-0021: browser SSO session](adr/0021-browser-sso-hosted-login-page-and-session-cookie.md)
