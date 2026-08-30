# Auth/token reference dictionary

A lookup layer over the auth/token surface of `authz-api`, `authz-idp`, `authz-opa`,
`lightbridge-mcp`, and `lightbridge-authz-usage`. Ctrl-F a config key, a claim, a discovery field,
or a permission string and get a `file:line` citation, not prose. This does **not** replace
`docs/rbac.md` (the RBAC model in full) or the ADRs (the *why*) — it points at them instead of
restating them.

For the canonical OAuth/OIDC implementation inventory, standards gaps, and Authorization Code +
PKCE/device-flow roadmap, see
[`docs/oauth-oidc-standards-roadmap.md`](oauth-oidc-standards-roadmap.md). In particular, accepted
ADR-0019/ADR-0021 design work is not evidence that `/authorize` or device endpoints are mounted.

The OAuth/OIDC rows and endpoint inventory were reconciled against the current repository on
2026-08-24. Other entries retain their source citations; when behavior changes, prefer the linked
implementation and the canonical roadmap over an old verification date.

## 1. Config keys → effect

All fields live under `crates/lightbridge-authz-core/src/config/mod.rs` unless noted. "Default"
means the Rust struct's `#[serde(default)]` behavior when the YAML key is absent — not necessarily
the value in the shipped `config/default.yaml` / `.docker/authz/container.yaml`, which is called
out separately where it differs.

### `oauth2.*`

| YAML path | Rust type | Required / default | Controls | Breaks when unset/wrong |
|---|---|---|---|---|
| `oauth2.type` | `Oauth2Type` (`self`\|`external`) | **Required, no default** — missing key fails config load | Credential-issuance mode: `self` mints RS256 JWTs via `oauth2.signing`; `external` proxies to an upstream IdP via `oauth2.issuance` | Config load fails immediately (`config/mod.rs:396-399`, test `oauth2_type_is_required_no_default` at `config/mod.rs:718-725`) |
| `oauth2.jwks_url` | `String` | **Required** | JWKS endpoint used to verify inbound bearer tokens (Keycloak in local compose) | Every bearer-protected request fails to validate |
| `oauth2.oauth2_url` | `Option<String>` | default `None` | Upstream token endpoint for `type: external` issuance (`handlers/mod.rs:184-193`); also a fallback for MCP's discovery-proxy `token_endpoint` (`app/lightbridge-authz/src/mcp.rs:456-460`) | Under `external`, `OAuth2TokenIssuer::from_config` fails startup if neither this nor `token_endpoint` is set (`handlers/mod.rs:188-193`) |
| `oauth2.issuer_url` | `Option<String>` | default `None` | Issuer for MCP's discovery-proxy metadata; falls back to deriving from `jwks_url` (`mcp.rs:447-450`) | MCP's `.well-known/oauth-authorization-server` returns 500 if neither resolves (`mcp.rs:519-528`) |
| `oauth2.authorization_endpoint` | `Option<String>` | default `None` | MCP discovery-proxy only; defaults to `{issuer}/protocol/openid-connect/auth` (`mcp.rs:452-455`) | Cosmetic only — MCP never serves `/authorize` itself |
| `oauth2.token_endpoint` | `Option<String>` | default `None` | Alternate to `oauth2_url` for `external` issuance and MCP discovery-proxy (`handlers/mod.rs:187`, `mcp.rs:456-460`) | Same failure mode as `oauth2_url` |
| `oauth2.registration_endpoint` | `Option<String>` | default `None` | MCP discovery-proxy only; defaults to `{issuer}/clients-registrations/openid-connect` (`mcp.rs:461-464`) | Cosmetic |
| `oauth2.issuance` | `Option<Oauth2Issuance>` | default `None` | Upstream token-exchange proxy config, used only under `type: external` | **Required when `type: external`** — `OAuth2TokenIssuer::from_config` fails startup if absent (`handlers/mod.rs:180-183`) |
| `oauth2.issuance.grant_type` | `Option<String>` | default `None`, falls back to `"urn:ietf:params:oauth:grant-type:token-exchange"` at call time | Grant type sent to the upstream token endpoint (`handlers/mod.rs:201-206`) | — |
| `oauth2.issuance.client_id` | `String` | default `""` | Client id presented to the upstream IdP | Empty at issue time → `Error::Server` (`handlers/mod.rs:214-218`) |
| `oauth2.issuance.client_secret` | `Option<String>` | default `None` | Client secret, only sent if present (`handlers/mod.rs:235-237`) | — |
| `oauth2.issuance.subject_token_type` | `Option<String>` | default `None`, falls back to `"urn:ietf:params:oauth:token-type:access_token"` | RFC 8693 `subject_token_type` sent upstream | — |
| `oauth2.issuance.requested_token_type` | `Option<String>` | default `None` | RFC 8693 `requested_token_type`, only sent if present | — |
| `oauth2.issuance.audience` / `.scope` | `Option<String>` | default `None` | Forwarded to the upstream exchange request if present | — |
| `oauth2.federation` | `Option<Federation>` | **Required by `authz-api`/`authz-idp`/`authz-opa`/`authz-budget`/`lightbridge-mcp` startup** | The identity-vs-location split for the one Keycloak this deployment federates with (see "Identity vs. location: `federation.issuer` vs. `federation.discovery_url`" below) | Missing or malformed `issuer` makes every component above refuse to start (ADR-0025) |
| `oauth2.federation.issuer` | `String` | required | IDENTITY: the `iss` claim value every ID token must carry, what `authz-idp`'s fetched OIDC discovery document's own `issuer` is checked against, what the browser is ultimately sent to via the discovered `authorization_endpoint`, and the ADR-0025 grandfather-adoption pin. The ONE issuer field — there is no longer a separate `oauth2.relying_party.issuer` this must be kept byte-equal to (removed; see below) | Empty or not a valid URL fails `Federation::validate` at startup |
| `oauth2.federation.discovery_url` | `Option<String>` | default: falls back to `oauth2.federation.issuer` | LOCATION: where `authz-idp` dials OIDC discovery from inside this deployment's own network. Set only when it diverges from `issuer` — e.g. local Compose, where the browser/host tooling reach Keycloak via `http://localhost:9100/realms/dev` but `authz-idp`'s own container must dial the in-network `http://keycloak:9100/realms/dev` instead (`.docker/authz/container.yaml`) | `KeycloakRelyingParty::discover` dials this URL but still validates the returned document's `issuer` against `oauth2.federation.issuer` — never relaxed to compare against this value instead. Leaving it unset when the issuer is genuinely unreachable from inside the network surfaces as `GET /authorize` returning 502 "sign-in unavailable" |
| `oauth2.relying_party` | `Option<OidcRelyingParty>` | **Required by `authz-idp` startup** | Keycloak browser-login broker used by `/authorize`, `/device/verify`, and `/idp/callback` | Missing or malformed state encryption key/callback URL makes `authz-idp` refuse startup; this is never treated as an optional unauthenticated fallback — a config that omits this block entirely is ALSO refused, unconditionally, since ADR-0023 reversed PR #473 (`468084a`)'s mount-conditional gate |
| `oauth2.relying_party.client_id`, `.callback_url` | `String` | required when the RP block is configured | ID-token audience, and the one exact Keycloak callback URL. The issuer used for discovery/ID-token validation is `oauth2.federation.issuer`, not a field on this struct — `oauth2.relying_party.issuer` was REMOVED (it used to have to be kept byte-equal to `oauth2.federation.issuer` by hand; that config trap is gone) | An issuer mismatch, token endpoint error, signature/`kid`/issuer/audience/`iat`/nonce failure, or callback-state failure refuses completion without approving a device code or issuing a browser cookie; multi-audience ID tokens must set `azp` to this client |
| `oauth2.relying_party.state_encryption_key` | `String` | required; base64url encoding of exactly 32 bytes | AES-256-GCM protection for the short-lived, `HttpOnly`, `Secure`, `SameSite=Lax` RP state cookie | Bad encoding/length makes `authz-idp` refuse startup; production must provide a unique secret |
| `oauth2.relying_party.token_encryption_key` | `String` | required; base64url encoding of exactly 32 bytes | AES-256-GCM protection (ADR-0024) for the Keycloak token set (refresh token + ID-token claims snapshot, never the access token) persisted at rest on `federated_identities.token_envelope` | Bad encoding/length, or a value equal to `state_encryption_key`, makes `authz-idp` refuse startup; production must provide a unique secret, distinct from `state_encryption_key`; rotating this value makes every previously-sealed token envelope permanently unopenable (treated as "no stored token", never deleted) until that identity's next login re-seals it |
| `oauth2.relying_party.timeout_ms` | `u64` | `5000` | Bound on Keycloak discovery and authorization-code redemption | Must be positive at startup. A timeout is a refused login; a pending device authorization stays pending |
| `oauth2.relying_party.browser_session_ttl_seconds` | `i64` | `28800` | Fixed expiry used by the shared browser-session callback primitive | Must be positive at startup; device pairing does not create a browser session |

### Identity vs. location: `federation.issuer` vs. `federation.discovery_url`

`oauth2.relying_party.issuer` used to do four jobs across two network planes — the discovery dial
target, the expected issuer in the discovery document, the ID-token `iss` check, and the ADR-0025
grandfather pin — while `oauth2.federation.issuer` had to be kept byte-equal to it by hand
(`start_idp_server` asserted this at startup; that assertion is now DELETED, since there is only
one field left to compare). Three of those four jobs are IDENTITY (must be the externally-reachable
issuer: what tokens validate against, what the browser is redirected to); only the discovery dial
is LOCATION (must be internally reachable). Conflating them made a deployment where internal ≠
external unable to start `authz-idp` at all: with the issuer set to the external address, `GET
/authorize` dialed that same external address from inside the container and got connection-refused,
surfacing as 502 "sign-in unavailable".

`oauth2.federation.discovery_url` (`crates/lightbridge-authz-core/src/config/mod.rs`) is the fix:
`authz-idp` dials `discovery_url.unwrap_or(issuer)` (`Federation::effective_discovery_url`,
`KeycloakRelyingParty::discover` in `crates/lightbridge-authz-rest/src/relying_party.rs`), but
still validates the returned document's `issuer` against `federation.issuer` — the identity check
is never relaxed to compare against the dial target. See `.docker/authz/container.yaml` for the
worked local-Compose example (`localhost:9100` identity, `keycloak:9100` discovery dial).
| `oauth2.audience` | `Option<Vec<String>>` | default `None` | Expected `aud` values for inbound JWT validation; unset disables audience checking | An unset/empty value means **no audience enforcement** — any `aud` is accepted |
| `oauth2.signing` | `Option<JwtSigning>` | default `None` | Enables self-signed RS256 API-key JWTs; required alongside `type: self` for both plain key signing and native token-exchange | Absent under `type: self` with `token_exchange.enabled` → startup fails (`lib.rs:1283-1285`) |
| `oauth2.signing.issuer` | `String` | **Required, non-empty** | `iss` claim + OIDC issuer for JWKS discovery | Empty → `ApiKeyJwtSigner::from_config` fails (`signing.rs:274-278`) |
| `oauth2.signing.audience` | `Option<String>` | default `None` | `aud`/`azp` stamped on plain (non-exchange) self-signed API-key JWTs | — |
| `oauth2.signing.ttl_seconds` | `i64` | default `7_776_000` (90 days) | Default lifetime **and hard cap** on any frontend-requested expiry (`signing.rs:145-155`) | `<= 0` → startup fails (`signing.rs:279-284`) |
| `oauth2.signing.max_key_age_days` | `i64` | default `30` | Auto-rotation interval for the active signing key, checked at startup (`bootstrap_signing_key`, `signing.rs:86-93`) | No hard failure; a very small value just rotates aggressively |
| `oauth2.token_exchange` | `Option<Oauth2TokenExchange>` | default `None`; **required by `authz-idp` startup** (ADR-0023) | Native RFC 8693 token-exchange (`POST /oauth2/token`) plus the `authorization_code`/device grants `/oauth2/token` also dispatches | Absent/`enabled: false` → `authz-idp` refuses to start (see `start_idp_server_refuses_to_start_without_token_exchange`/`..._when_token_exchange_is_disabled`, `idp_server_tests.rs`); other callers of `build_token_exchange_state` keep the older "not mounted" behavior for the `None` case, but `authz-idp` is the only production caller and treats it as fatal |
| `oauth2.token_exchange.enabled` | `bool` | default `false`; **`authz-idp` requires `true`** (ADR-0023) | Whether the exchange grant is mounted | **`enabled: true` under `oauth2.type: external` fails server startup hard** — `Error::Server("oauth2.token_exchange is enabled but requires oauth2.type: self")` (`lib.rs:1278-1282`, test `build_token_exchange_state_rejects_external_oauth2` at `lib.rs:1722-1731`). For `authz-idp` specifically, `enabled: false` (or the block being absent) is itself a startup failure — see the row above |
| `oauth2.token_exchange.access_ttl_seconds` | `i64` | default `900` (15 min) | Exchanged access-JWT lifetime | `<= 0` → startup fails (`lib.rs:1286-1290`) |
| `oauth2.token_exchange.refresh_ttl_seconds` | `i64` | default `2_592_000` (30 days) | Per-**token** lifetime, reset on every rotation (`new_row.expires_at = now + refresh_ttl_seconds`, `oauth2_op/store.rs:581`) — this is not a session-level ceiling by itself; see `refresh_absolute_ttl_seconds` immediately below for the field that actually bounds a session | `<= 0` → startup fails, same check as above |
| `oauth2.token_exchange.refresh_absolute_ttl_seconds` | `i64` | default `7_776_000` (90 days) | Absolute cap on a refresh-token **chain** (every token minted across one rotation lineage), not the individual token above. Set once, at chain birth (the offline-scope exchange grant), to `now + refresh_absolute_ttl_seconds` (`chain_expires_at`, `oauth2_op/store.rs:330-332`), and inherited unchanged by every subsequent rotation (`store.rs:578-579`) — this is what stops a session that keeps refreshing before every individual `expires_at` from living forever. See §4 below for the full chain/status model | **Not startup-validated**, unlike `access_ttl_seconds`/`refresh_ttl_seconds` above (`lib.rs:1754-1758` only checks those two). A `<= 0` value is silently clamped to `0` via `.max(0)`, so every new chain is born already past its cap and the first refresh attempt on it fails `invalid_grant` — not a startup crash |
| `oauth2.token_exchange.allowed_scopes` | `Vec<String>` | default `["openid","profile","email","offline_access"]`; **`authz-idp` requires `openid` present** (ADR-0023, OIDC Discovery 1.0 §3) | Server-wide scope ceiling, intersected with each client's own `scopes` at request time (`oauth2_op/mod.rs:44-76`) | A scope omitted here can never be granted regardless of client config. For `authz-idp` specifically, omitting `openid` is itself a startup failure (`start_idp_server_requires_openid_in_allowed_scopes`, `idp_server_tests.rs`) — `authz-idp` always mounts `/authorize` and always advertises `authorization_endpoint`, so it is always an OpenID Provider, never a bare OAuth2 authorization server |
| `oauth2.rbac` | `Rbac` | default: `roles_claim="roles"`, empty maps | RBAC config — see below | — |
| `oauth2.rbac.roles_claim` | `String` | struct default `"roles"` (`authz.rs:357-359`) when the key is absent; **shipped config sets** `"${RBAC_ROLES_CLAIM:-lightbridge_api_roles}"` (`config/default.yaml:122`) | JWT claim carrying the caller's roles (array or space-delimited string) | Wrong claim name → every caller resolves to zero permissions (no error, just silent 403s) |
| `oauth2.rbac.role_permissions` | `HashMap<String, Vec<String>>` | default empty → falls back to `default_role_permissions()` (`authz.rs:363-383`) | Role → grant-string mapping | Unknown grant strings are logged and skipped, never widen access (`authz.rs:305-311`) |
| `oauth2.rbac.default_grants` | `Vec<String>` | default empty | Grants applied **per role string that matches no `role_permissions` entry** (not a floor added to every caller) | Malformed entry → `Rbac::validate()` fails startup (`authz.rs:345-354`, wired into `start_api_server`/`start_mcp_server`). **Gotcha:** does not extend a role that *is* recognized — see `authz.rs:535-545` test |
| `oauth2.clients` | `Vec<OauthClient>` | default empty | Registered OAuth2/OIDC clients allowed to call `/oauth2/token` (ADR-0011 Decision 5) | Empty (the default) → **every** exchange request fails `invalid_client`, not "unprotected" (`config/mod.rs:432-439`) |
| `oauth2.clients[].client_id` | `String` | required | Client identifier | — |
| `oauth2.clients[].type` | `public`\|`confidential` | required | Auth method at `/oauth2/token`: `public` = no secret beyond `client_id`; `confidential` = `private_key_jwt` only (never `client_secret_basic`/`_post`, ADR-0011 Decision 6) | — |
| `oauth2.clients[].scopes` | `Vec<String>` | default empty | Scopes this client may request; intersected with `allowed_scopes` above | — |
| `oauth2.clients[].grant_types` | `Vec<String>` | default empty | Raw grant-type strings the client may use | Unlisted → "client not authorized for this grant type" at request time, not a config-load error |
| `oauth2.clients[].allowed_audiences` | `Vec<String>` | default empty | Downstream `audience` values this client may request; unrequested `aud`/`azp` default to the client's own `client_id` | Requesting an unlisted audience is rejected |
| `oauth2.clients[].jwks` | `Option<serde_json::Value>` | default `None` | Inline JWK Set verifying a `confidential` client's `private_key_jwt` assertions | **Required for `confidential`**, ignored for `public` |

### `database.*` / `usage_service.*`

| YAML path | Rust type | Required / default | Controls | Breaks when unset/wrong |
|---|---|---|---|---|
| `database.url` | `String` | **Required** | Main Postgres connection (accounts/projects/api_keys/budget tables) | Every server fails to start |
| `database.pool_size` | `Option<u32>` | default `None` (pool default) | Connection pool size | — |
| `usage_service` | `Option<UsageServiceClient>` | default `None` (`config/mod.rs:34`) | HTTP client for the budget domain's `UsageServiceSpendReader` to call the usage service's mTLS-required query listener (`/usage/v1/spend/query`, #347) | Absent → budget spend reads report `Spend::Unavailable` (fails closed to manual review); config still loads fine otherwise (`config_without_redis_or_usage_service_still_loads` test) |
| `usage_service.base_url` | `String` | required if `usage_service` is set | Usage service query-listener origin, e.g. `https://authz-usage:3006` (the mTLS-required listener — distinct from the ingest listener's port) | Wrong host/port → every spend read fails closed to `Spend::Unavailable` (connection refused/DNS failure), not an error |
| `usage_service.insecure_skip_verify` | `bool` | default `false` | Skip TLS server-cert verification — only ever `true` in local Compose | Left `false` against a self-signed deployment without `ca_bundle_path` set → every spend read fails closed (TLS handshake failure treated as unreachable) |
| `usage_service.ca_bundle_path` | `Option<String>` | default `None` | PEM CA bundle verifying the usage service's own certificate (production mechanism, e.g. `/etc/lightbridge/tls/ca.crt`) | Unreadable/malformed path → hard startup failure naming the path (never a silent fallback to skip-verify) |
| `usage_service.client_cert_path` | `Option<String>` | default `None` | PEM client certificate this reader presents for mTLS (#347), e.g. `/etc/lightbridge/tls/tls.crt` — must be set together with `client_key_path` | Set without `client_key_path` (or vice versa) → hard construction error naming the missing field; unreadable/malformed → hard error naming the path |
| `usage_service.client_key_path` | `Option<String>` | default `None` | Private key matching `client_cert_path` | See `client_cert_path` |
| `usage_service.timeout_ms` | `u64` | default `5000` | Per-request timeout for the spend-query call | A usage service that's merely slow (not down) still fails closed to `Spend::Unavailable` once this elapses |

**mTLS (#347) gates the usage service's query listener.** `/usage/v1/spend/query` and the
pre-existing `/usage/v1/usage/query` both moved to a listener that requires and verifies a client
certificate (`UsageServerGroup::query` in `crates/lightbridge-authz-usage/src/config.rs`) —
`client_cert_path`/`client_key_path` above are what let this reader present one. The usage
service's separate ingest listener (`/v1/otel/*`) stays unauthenticated, since its caller is an AI
Envoy/OpenTelemetry exporter outside this repo's deploy surface — see `AGENTS.md`'s Security Notes
and `docs/architecture/budget.md`'s "Spend dependency" section for the full posture.

### Env-var interpolation (`interpolate_env_vars`, `config/mod.rs:607-639`)

| Form | Behavior | Unset/empty var |
|---|---|---|
| `$VAR` | Replaced with the env var's value | Empty string |
| `${VAR}` | Same | Empty string |
| `${VAR-default}` | Uses `default` only when `VAR` is **unset** | Uses `default` when unset; empty var stays `""` (not `default`) |
| `${VAR:-default}` | Uses `default` when `VAR` is unset **or empty** | Uses `default` |
| `${VAR:default}` (single colon) | **Not supported** — left as literal text | n/a |

Verified by `config/mod.rs:646-701`.

## 2. Discovery document fields → derivation

Covers `GET /.well-known/openid-configuration`, built by `discovery_document`
in `crates/lightbridge-authz-rest/src/signing.rs:576-628` and served via `well_known_router`
(`signing.rs:666-736`). **Now served exclusively by `authz-idp`** — `authz-api` mounted this same
`well_known_router` call during the ADR-0012 Phase 1 transitional-duplication window, but that copy
was removed once the public `auth.ai.camer.digital` ingress was repointed directly at `authz-idp`;
`authz-api` no longer serves `/.well-known/*` at all (see `docs/architecture/services.md`).

> **Gating note:** the `token_endpoint` omission logic was fixed in PR #301
> (`fix(oauth2): drop token_endpoint from OIDC discovery when token-exchange is disabled`,
> commit `3f00ca6`, merged 2026-08-15) — before that fix, a disabled token-exchange still
> advertised a live-looking `token_endpoint` URL next to empty `grant_types_supported`. The
> derivation mechanics below were rewritten for the model-replacement PR (`OidcDiscovery` →
> the explicit `DiscoveryDocument`/`ClientAuthenticationMetadata` structs) and re-checked against
> that PR's final state. Re-check the current state of `discovery_document` before trusting this
> section if it looks stale — the doc comment directly above that function is intentionally dense
> and updated whenever the gating logic moves.

**Whether the document exists at all**: only mounted when `oauth2.type: self` **and**
`oauth2.signing` is set (`lib.rs:1178-1187`). Under `type: external`, `authz-idp` serves no
`/.well-known/openid-configuration` and no `/.well-known/jwks.json` (`authz-api` never serves
either regardless of `oauth2.type`, since it no longer mounts this router at all).

**Whether `enabled` (the exchange-specific fields) is true**: `token_exchange_scopes.is_some()`,
which is `oauth2.token_exchange.as_ref().filter(|t| t.enabled)` (`lib.rs:1169-1173`) — true only
when the block is present *and* `enabled: true`.

As of this PR, the document is no longer built from `authkestra_op::handlers::discovery::OidcDiscovery`.
It is a small, explicit `DiscoveryDocument` struct owned by this crate (`signing.rs:551-574`), built by
`discovery_document` (`signing.rs:576-628`) from two inputs: `token_exchange_scopes: Option<&[String]>`
(`None` when the block is absent or `enabled: false`; `Some(allowed_scopes)` otherwise) and a
`ClientAuthenticationMetadata` describing what the registered `oauth2.clients` can actually do
(`ClientAuthenticationMetadata::from_oauth2`, `signing.rs:51-82`). Every `Vec`/`Option` field on
`DiscoveryDocument` carries `#[serde(skip_serializing_if = ...)]`, so "empty" and "absent from the JSON"
are the same thing here — RFC 8414's "omit, don't emit an empty array" discipline applied uniformly.

| Field | Derivation | Gated by |
|---|---|---|
| `issuer` | `oauth2.signing.issuer` verbatim | mount condition above |
| `jwks_uri` | `{issuer origin}/.well-known/jwks.json` (`signing.rs:616`) | always present when doc exists |
| `token_endpoint` | `{issuer origin}/oauth2/token` | **omitted entirely** (not null, the key is absent) when `enabled` is false (`signing.rs:581,617`) |
| `revocation_endpoint` | `{issuer origin}/oauth2/revoke` (RFC 7009, mounted — see §6) | same gate as `token_endpoint` (`signing.rs:618`). **This field now exists and is emitted** — the old `OidcDiscovery`-based model had no field to carry it at all; that gap is closed, not just documented |
| `scopes_supported` | `oauth2.token_exchange.allowed_scopes` verbatim, else omitted | `enabled` (`signing.rs:582-584,619`) |
| `grant_types_supported` | `[token-exchange URN, refresh_token URN]`, else omitted | `enabled` (`signing.rs:585-590,620`) |
| `token_endpoint_auth_methods_supported` | from `ClientAuthenticationMetadata`: `"none"` iff at least one `type: public` client is registered, `"private_key_jwt"` iff at least one `type: confidential` client's registered JWKS yields a usable signing algorithm (`signing.rs:73-79`) — this replaces the old single `private_key_jwt_supported` boolean with the actual method list | `enabled` — forced empty/omitted regardless of the client registry when token-exchange is disabled (`signing.rs:593-597,621`) |
| `token_endpoint_auth_signing_alg_values_supported` | per-JWK algorithms collected across every confidential client's registered JWKS via `client_assertion_algorithms` (`signing.rs:101-115`): RSA keys advertise `RS256/RS384/RS512/PS256/PS384/PS512`; EC keys advertise `ES256`/`ES384` for curves P-256/P-384 only (other curves yield none); OKP keys advertise `EdDSA` only for curve `Ed25519` (any other OKP curve, e.g. X25519, yields none) — deduped via `HashSet` (`signing.rs:56-72`) | same as above (`signing.rs:598-602,622`) |
| `revocation_endpoint_auth_methods_supported` / `revocation_endpoint_auth_signing_alg_values_supported` | **mirror the token-endpoint auth fields exactly** — the same `ClientAuthenticationMetadata` values are reused for both endpoints (`signing.rs:623-624`), since the same registered clients authenticate against either one | `enabled` |
| `subject_types_supported` | `["public"]`, else omitted | `enabled` **and** `openid` present in `oauth2.token_exchange.allowed_scopes` (`oidc_tokens_supported`, `signing.rs:591,603-607,625`) |
| `id_token_signing_alg_values_supported` | `[ALGORITHM]` = `["RS256"]` (`ALGORITHM` const, `signing.rs:31`), else omitted | same gate as `subject_types_supported` (`signing.rs:608-612,626`) |
| `authorization_endpoint`, `response_types_supported`, `response_modes_supported`, `code_challenge_methods_supported` | ADR-0019/#467: gated on the authorization-code capability (`authorization_code_mounted`) | `enabled` **and** `/authorize` mounted |
| `end_session_endpoint` | `{issuer origin}/oauth2/end_session` (OIDC RP-Initiated Logout 1.0 §3) | same gate as `authorization_endpoint` — logout ends the BROWSER session, which only exists where `/authorize` is mounted |
| `userinfo_endpoint` | `{issuer origin}/oauth2/userinfo` (OIDC Core §5.3) | `oidc_tokens_supported` — the endpoint refuses any token without the `openid` scope, so where `openid` is not issuable it would answer nothing but `insufficient_scope` |
| `frontchannel_logout_supported`, `backchannel_logout_supported`, `claims_supported` | **Never emitted.** Neither logout channel has a handler, and advertising one without it is the exact ADR-0023 failure. `claims_supported` remains genuinely unimplemented. | — |

**Rows 149–154's `enabled` gate is always satisfied on `authz-idp` (ADR-0023).** `oauth2.token_exchange.enabled` is a mandatory `true` for every `authz-idp` deployment (see the `oauth2.token_exchange.enabled` row above), so every field in rows 149–154 gated on `enabled` is unconditionally present on `authz-idp`'s own discovery document — the "else omitted"/"forced empty" branches in this table describe `well_known_router`'s behavior for a hypothetical caller with `token_exchange` disabled, which `authz-idp` itself can no longer be. Only the client-registry-dependent content (which auth methods/algorithms actually appear) still varies. This pass does not chase every other stale line-number citation in this file — see the PR body.

**A second, unrelated discovery surface exists on `lightbridge-mcp`.** `GET
/.well-known/oauth-authorization-server` and `GET /.well-known/openid-configuration` on the MCP
server (`app/lightbridge-authz/src/mcp.rs:1612-1627`, handler at `mcp.rs:515-538`) are **not**
`signing::discovery_document` — they synthesize a document from `oauth2.issuer_url` /
`authorization_endpoint` / `token_endpoint` / `jwks_url`, i.e. they describe the **upstream IdP's**
real endpoints (for MCP OAuth dynamic-client-registration flows), not `authz-idp`'s own
token-exchange capabilities. Do not conflate the two when debugging a "wrong discovery document"
report — check which server served it first.

## 3. Token claims → source

Two claim-builder functions in `crates/lightbridge-authz-rest/src/signing.rs` are shared by the
plain API-key signer and the native token-exchange grant: `access_token_extra` (`signing.rs:186-233`)
and `id_token_extra` (`signing.rs:242-268`). Claims not listed in `extra` are added unconditionally
by `authkestra_engine::token::TokenManager` itself: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
`scope`, and a nested `identity` object mirroring `sub`/`email` (documented at `signing.rs:320-338`).

### Access token

| Claim | Source | Minted or propagated |
|---|---|---|
| `sub` | `Identity.external_id = owner.subject` (`identity_for`, `signing.rs:163-171`), which is the upstream Keycloak `sub` read verbatim off the presented bearer token (`token_info.sub`, `oauth2_op/store.rs:181,219`) | **Propagated, never re-minted** — verified by test `claims.sub == "kc-user-123"` (`signing_tests.rs:550`) and `claims.sub == SUBJECT` (`token_exchange_tests.rs:866`) |
| `jti` | `format!("lgbr:{}", cuid2())`, inserted into `extra["jti"]` (`signing.rs:196-198`) | **Minted** — ADR-0039 CUID2, `lgbr:`-prefixed. Since authkestra 0.5.0 (PR #215), `TokenManager::take_jti` removes a string-valued `extra["jti"]` and uses it verbatim instead of generating a UUIDv4 (doc comment `signing.rs:180-185`) |
| `typ` | Constant `"Bearer"` (`TOKEN_TYP`, `signing.rs:31,199`) | Minted |
| `azp` | Plain signer: `oauth2.signing.audience`. Token-exchange grant: the authenticated client's `client_id` (`signing.rs:200-202`, `store.rs:235`) | Supplied via `extra`, computed by this service |
| `lightbridge_caller_kind` | Constant `API_KEY_CALLER_KIND` from `lightbridge_authz_bearer` (`signing.rs:203-206`) | Minted — this is the claim `requestBudgetRefill` checks to refuse API-key-derived callers under `oauth2.type: self` (see `docs/rbac.md`'s "#191/#216" note) |
| `sid` | Plain `cuid2()`, no prefix (`signing.rs:207`) | Minted, per-issuance session id |
| `api_key_id`, `project_id`, `account_id` | Passed in by the caller of `sign`/the exchange handler | Minted (tenant context resolved server-side) |
| `email` / `email_verified` | `owner.email` / `owner.email_verified`. **Two sources, one per leg.** Device + RFC 8693 exchange: `decode_email(subject_token)` (`oauth2_op/mod.rs:113-123`) — best-effort, unverified re-decode of an already-signature-verified upstream token. Browser `authorization_code`: the sealed ID-token claims snapshot in `federated_identities.token_envelope` (ADR-0024), opened by `KeycloakRelyingParty::stored_email` at `/authorize` and stamped onto the authorization code's `Identity`, because that leg deliberately never persists the upstream access token there is nothing to decode at redemption time. Both are best-effort: a miss omits the pair rather than refusing the grant | **Propagated upstream snapshot**, omitted (not `null`) when absent |
| `allowed_models` | Project's `allowed_models`, if `Some` | Minted from DB state |
| `at_hash`, `auth_time`, `nonce` | **Not on the access token** — only on the `id_token` (see below) | — |

### ID token (`id_token_extra`, only issued when the `openid` scope is granted)

| Claim | Source | Minted or propagated |
|---|---|---|
| `jti` | Same `lgbr:`-prefixed `cuid2()` pattern as the access token (`signing.rs:250-252`) | Minted |
| `email` / `email_verified` | Same upstream snapshot as the access token, from whichever of the two sources that leg uses (`signing.rs:253-257`) | Propagated |
| `auth_time` | `decode_auth_time_and_nonce(subject_token)` — **propagated only if the upstream token carried one, never defaulted to "now"** (`oauth2_op/mod.rs:125-134`; this service authenticates nobody itself, so it has no authentication instant of its own to report) | Propagated-or-omitted |
| `nonce` | Same decode, passed as a separate parameter to `issue_id_token_with_extra` (not via the `extra` map) (`oauth2_op/store.rs:247-255`) — **propagated only if present, never invented** (a token exchange runs no authorization request for a nonce to bind to) | Propagated-or-omitted |
| `azp` | The exchange client's `client_id` (`signing.rs:262`) | Minted |
| `at_hash` | `compute_at_hash(access_token)` — OIDC Core §3.1.3.6: SHA-256 the access token's ASCII octets, take the left half, base64url-encode (`signing.rs:95-104,263-266`) | Computed by this service, binds the id_token to the access_token minted in the same response |

### Deliberately absent from every JWT: `role`, `quota_tier`, `project_quota`

No code path inserts `role`, `quota_tier`, or `project_quota` into any JWT `extra` map — verified
by grepping for those three literal keys across `crates/lightbridge-authz-rest/src/` and
`crates/lightbridge-authz-bearer/src/` (zero hits). They ride instead on the **introspection
response** (`IntrospectResponse`, `crates/lightbridge-authz-rest/src/models/mod.rs:18-...`,
populated at `crates/lightbridge-authz-rest/src/handlers/introspect.rs:52-67`), which Authorino
calls per request — so a roster/quota change is visible on the *next* request rather than waiting
for a token to expire. (`IntrospectResponse` struct: `crates/lightbridge-authz-rest/src/models/mod.rs:18-66`.)

> **Discrepancy vs this repo's own `AGENTS.md`.** The "Identity context resolution" section
> currently reads: *"This exchange is also where project context is sealed into the JWT for the
> human plane (`role`, `quota_tier`, `project_quota` alongside `account_id`/`project_id`)."* That
> is stale. `ResolveContextRequest`/`ResolvedContext`
> (`crates/lightbridge-authz-core/src/dto.rs:268-271`) carries only `account_id`/`project_id` — no
> `role`, `quota_tier`, or `project_quota` field exists on that type at all, and (per the grep
> above) nothing inserts those three into a JWT anywhere in the codebase. `AGENTS.md` should be
> corrected to match the introspection-based design described above.

## 4. Refresh-token chain & lifecycle

Covers `exchange_refresh_tokens` columns added/changed by the refresh-token hardening
(`crates/lightbridge-authz-rest/src/oauth2_op/store.rs:422-616` `handle_refresh_token`, migration
`20260815000001_exchange_refresh_tokens_add_chain.sql`). **None of the fields in this section are
JWT claims** — they live only on the server-side `exchange_refresh_tokens` row and are never
serialized into the access/id token (contrast with §3 above).

| Field | What it is | Source | Notes |
|---|---|---|---|
| `chain_id` | Shared by every token minted across one rotation lineage | Minted once via the sanctioned `cuid2()` chokepoint at chain birth — the offline-scope exchange grant (`store.rs:330`) — and inherited **unchanged** by every rotation thereafter (`store.rs:578`), never regenerated | Used to cascade-revoke a whole family in one `UPDATE` on reuse detection (`revoke_exchange_refresh_token_chain`, `crates/lightbridge-authz-api-key/src/repo.rs:758-771`) |
| `chain_expires_at` | Absolute deadline for the whole chain | Set once at birth to `now + oauth2.token_exchange.refresh_absolute_ttl_seconds` (`store.rs:331-332`), inherited unchanged by every rotation (`store.rs:579`) | Checked before every rotation (`old_row.chain_expires_at`, `store.rs:475`); a chain past this deadline refuses to rotate even if the presented token's own `expires_at` has not passed |
| `exchange_refresh_tokens.status` | Lifecycle state of one token row | `active` (minted, usable, set by `create_exchange_refresh_token`, `repo.rs:684`) → `rotated` (consumed by a successful refresh — the CAS single-use marker, `consume_exchange_refresh_token`, `repo.rs:792`) → `revoked` (killed by `/oauth2/revoke`, `revokeOwnSessions`/`revokeSubjectSessions`, or the reuse cascade, `repo.rs:762,813`) | Terminal once `rotated` or `revoked` — no transition ever moves a row backward. Only `find_exchange_refresh_token_by_hash`'s unconditional lookup (`repo.rs:735-750`) ever reads a non-`active` row; every honoring path filters on `status = 'active'` |

**Every refresh re-validates, not just checks the token row.** `handle_refresh_token` re-runs the
same `resolve_context(subject, project_id)` ownership/membership check `/idp/v1/resolve-context`
uses (ADR-0006: owns the project OR holds a `project_members` row, `store.rs:487-497`), then
requires the resolved project (`store.rs:498-504`) and account (`store.rs:505-511`) to both be
`Active`. Any failure refuses the refresh as a plain `invalid_grant` — never a permissive fallback.
Before this hardening, a refresh whose project could not be resolved fell through to
`allowed_models = None`, which this codebase reads as "no restriction" — a real fail-open bug,
closed by this re-validation (regression test
`refresh_after_project_deleted_is_invalid_grant_not_fail_open`,
`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs:1861-1899`).

**Replaying an already-rotated token (`status = 'rotated'`) revokes its entire chain** — RFC 6819
§5.2.2.3 reuse detection (`revoke_chain_on_reuse`, `store.rs:625-652`). An unknown, expired, or
already-`revoked` token is a plain `invalid_grant` with **no** cascade
(`unknown_refresh_token_is_invalid_grant_without_cascading`, `token_exchange_tests.rs:2032-2065`).

**The honest limit:** none of this calls back to Keycloak. `handle_refresh_token` re-checks only
this service's own `resolve_context` plus project/account status — a user disabled directly in the
IdP but still active on this service's roster is not detected by a refresh; that session is bounded
only by `chain_expires_at` above and by an explicit revoke (§5's `session:revoke*` rows, or §6's
`/oauth2/revoke` row).

The task-oriented walkthrough of all of the above, with the request/response shapes, lives in
[`docs/token-exchange-integration.md`'s "Refresh" section](https://github.com/ADORSYS-GIS/lightbridge-authz/blob/main/docs/token-exchange-integration.md#refresh).

## 5. Permissions → procedures

The full permission catalogue, the RPC `op_id`/MCP-tool mapping, and the default role→permission
table already live in `docs/rbac.md` — this section only adds the budget self-refill model that
caused confusion this session, and does not repeat the rest of that document.

Enforcement code: `crates/lightbridge-authz-rest/src/rpc_authorize.rs` (RPC gate,
`required_permission` at line 68), `crates/lightbridge-authz-core/src/authz.rs` (permission
catalogue + RBAC compilation), `app/lightbridge-authz/src/mcp.rs:378-403` (MCP tool→permission map).

### Three different things are all called "tier" in this codebase — do not conflate them

| Name | What it is | Where it lives | Governs |
|---|---|---|---|
| `project_members.quota_tier` | A per-project-member spending ceiling, validated against the operator-configured `QuotaTiers` catalogue (`crates/lightbridge-authz-core/src/config/mod.rs:210-251`) | `project_members` table, set via `procedure.setProjectMemberQuotaTier` | Stamped into the OPA/Authorino `x-quota-tier` header via introspection; matched by ai-helm's per-member rate-limit rules |
| ADR-0008's budget-tier ladder (`x-budget-tier`, `b-15`…`b-1000`) | A *proposed* (ADR status: `Proposed`) Keycloak-claim-based rate-limit ladder for the gateway's static `BackendTrafficPolicy` rules (`docs/adr/0008-refills-are-discrete-budget-tiers.md`) | Not this repo's runtime code — a design document | Would govern Envoy rate-limit rungs directly, if/when implemented |
| `self_service_grant_count` rule-data threshold | The **actual, live** ceiling on how many self-service refills an account gets before requests queue for review | `crates/lightbridge-authz-budget/src/rule_data.rs:118` — `{"field": "self_service_grant_count", "operator": "lt", "value": 2}` inside `default_rule_set_json()` | `procedure.requestBudgetRefill` — see below |

### `budget:self-refill` / `budget:review`

- `budget:self-refill` gates `procedure.requestBudgetRefill` (`rpc_authorize.rs:140`,
  `docs/rbac.md`'s "#191" section). A caller with this permission may request a refill for their
  own `budgetAccountId`/`period`. `RefillService::request_refill` evaluates the active rule-data
  policy: while `self_service_grant_count < 2` for the period, the refill **auto-grants**
  (`rule_data.rs:118`); at or beyond that count, the request is queued as `pending_review` instead
  of being denied outright.
- `budget:review` gates the admin queue — `procedure.listPendingAugmentationRequests`,
  `procedure.approveAugmentationRequest`, `procedure.rejectAugmentationRequest`
  (`rpc_authorize.rs:141-143`). A holder of `budget:review` acts on requests that crossed the
  self-service ceiling.
- Shipped config (`config/default.yaml:130`, `.docker/authz/container.yaml`) grants
  `budget:self-refill` to `lightbridge-editor`, not `lightbridge-viewer` (self-refill spends
  budget). Neither role holds `budget:review` — only `lightbridge-admin` (via `*`) does.
- `requestBudgetRefill` additionally refuses any caller whose token carries
  `lightbridge_caller_kind: api_key` — see `docs/rbac.md`'s "#191/#216" note for the `self` vs
  `external` coverage gap (fully closed under `self`, not yet closed under `external`).

### `session:revoke-own` / `session:revoke`

- `session:revoke-own` gates `procedure.revokeOwnSessions` (`rpc_authorize.rs`) — "log out
  everywhere" for the caller's own subject only; there is no subject field on the input, so this
  cannot target anyone else. Granted to every default role (`default_role_permissions`,
  `crates/lightbridge-authz-core/src/authz.rs`), including `lightbridge-viewer`.
- `session:revoke` gates `procedure.revokeSubjectSessions` — the offboarding kill switch, revoking
  every active refresh-token session for an operator-supplied `accountId`. Held only via
  `lightbridge-admin`'s `*`; not granted to `lightbridge-editor`/`lightbridge-viewer`.
- Both delegate to `StoreRepo::revoke_active_exchange_refresh_tokens_for_subject`, the same
  `status = 'active' -> 'revoked'` flip `POST /oauth2/revoke` (RFC 7009) uses for a single token —
  see §6's `/oauth2/revoke` row. `find_active_exchange_refresh_token`/
  `consume_exchange_refresh_token` both filter on `status = 'active'`, so revocation from either
  surface takes effect on the very next refresh attempt.

## 6. Endpoints

| Server | Route | Auth | Purpose |
|---|---|---|---|
| `authz-api` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | liveness/startup/readiness probes |
| `authz-api` | `POST /rpc/{op_id}`, `POST /rpc/batch` | Bearer JWT + RBAC (`rpc_authorize` outer gate, `CratestackAuthProvider` inner gate, then cratestack `@@allow` membership policy) | Generated CRUD + hand-written budget-domain procedures; base path configurable via `server.api.rpc_base_path`. `authz-api` no longer serves `/.well-known/*` or `/oauth2/{token,revoke}` — see `authz-idp` below (a request to either path here falls through to this fallback and fail-closes to `403`) |
| `authz-idp` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | liveness/startup/readiness probes |
| `authz-idp` | `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` | none | OIDC discovery + JWKS; only mounted under `oauth2.type: self` with `signing` set (see §2). The sole owner of this surface (ADR-0012) — moved off `authz-api` as a hard cutover |
| `authz-idp` | `POST /oauth2/token` | client auth (public `client_id` or `private_key_jwt`), no bearer | RFC 8693 token-exchange + refresh grant; only mounted when `oauth2.token_exchange.enabled` |
| `authz-idp` | `POST /oauth2/revoke` | client auth, same as `/oauth2/token` (public `client_id` or `private_key_jwt`), no bearer | RFC 7009 token revocation for `exchange_refresh_tokens` rows; mounted alongside `/oauth2/token` by the same `token_exchange_router` (`crates/lightbridge-authz-rest/src/token_exchange.rs`). **Not advertised in discovery** — see §2's `revocation_endpoint` row. §2.2: an unknown/already-revoked/out-of-scope token is `200`, never an error; only client-authentication failure is |
| `authz-idp` | `GET\|POST /oauth2/userinfo` | **Bearer JWT**, this deployment's own, verified against its live JWKS | OIDC Core §5.3 UserInfo. Returns `sub` always, `email`/`email_verified` under the `email` scope, plus `account_id`/`project_id`. **Never returns authorization data** (`budget_tier`, `quota_tier`, `model_policy`, `allowed_models`, roles) — that stays a per-request resource-server decision, not a cacheable identity response. A token without `openid` (notably a data-plane API-key JWT, which is signed by the same key and so verifies here) gets `403 insufficient_scope`, distinct from `401 invalid_token` (`userinfo.rs`) |
| `authz-idp` | `GET\|POST /oauth2/end_session` | none — the `__Host-authz_session` cookie is the credential | OIDC RP-Initiated Logout 1.0. Ends EVERY session the cookie's subject holds, browser and token alike, and cascades to their refresh chains (`revoke_sessions_and_cascade`) — the only way logout can terminate RP sessions without a back-channel. `id_token_hint` is verified but **never selects whose session ends**; it only names the client whose registered `post_logout_redirect_uris` are consulted, and is accepted while expired (§2). An unregistered `post_logout_redirect_uri` is refused and the OP renders its own page. Does NOT invalidate an access token already in flight — nothing consults `sessions` on the resource-server path, so a bearer stays valid to its `exp` (`end_session.rs`) |
| `authz-opa` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | probes |
| `authz-opa` | `GET /v1/opa/docs`, `GET /v1/opa/openapi.json` | none | Swagger UI (`lib.rs:1525`) |
| `authz-opa` | `POST /v1/authorino/validate/introspect` | **Basic auth** | RFC 7662-shaped API-key introspection; response includes `role`/`quota_tier`/`project_quota` (`routers/mod.rs:14-22`, `introspect.rs`) |
| `authz-opa` | `POST /idp/v1/resolve-context` | **Basic auth** | `{subject, project_id} → {account_id, project_id}`; uniform 404 for unknown project or non-member (`routers/mod.rs:20`, `handlers/idp.rs`) |
| `lightbridge-mcp` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | probes |
| `lightbridge-mcp` | `GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration`, `POST /oauth/register` | none | proxy/synthesized discovery pointing at the **upstream IdP's** real endpoints — a different document from `authz-idp`'s own (see §2) |
| `lightbridge-mcp` | `/mcp` (streamable HTTP) | Bearer JWT (`bearer_auth`) + per-tool permission check (`call_tool`, `mcp.rs:378-403`) | MCP tool surface mirroring the RPC/CRUD + validation operations |
| `lightbridge-authz-usage` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | probes |
| `lightbridge-authz-usage` | `GET /usage/v1/usage/docs` | none | Swagger UI |
| `lightbridge-authz-usage` | `POST /v1/otel/traces`, `POST /v1/otel/metrics`, `POST /v1/otel/logs` | **none** | OTLP/HTTP ingest (`routers/mod.rs`) |
| `lightbridge-authz-usage` | `POST /usage/v1/usage/query` | **none — and no `scope_id` ownership check** | Usage query API; `query_usage` only requires `scope_id` to be non-empty (`handlers/query.rs:37-40`), never that the caller is entitled to see that scope's data |

> **This service's usage query API has no authentication layer at all** — confirmed by reading
> `crates/lightbridge-authz-usage/src/lib.rs:64-82`, which assembles the router with no auth
> middleware anywhere in the chain (only an optional dev-only permissive CORS layer). It must
> never be routed externally without an authenticating proxy/gateway in front of it.

### Discrepancy: `/v1/opa/validate` and `/v1/authorino/validate` no longer exist

Both were removed; `POST /v1/authorino/validate/introspect` is the only validation endpoint on
`authz-opa` today. This is deliberately locked by a test:
`introspect_endpoint_should_exist_in_opa_openapi` in `crates/lightbridge-authz-rest/src/lib.rs:1788-1807`
asserts the OpenAPI document **excludes** both legacy paths ("the legacy … endpoint should no
longer be exposed"). `README.md` (lines 20, 93-94, 108, 117) and `docs/test-protocol.md` (line
129) still document the old paths as live; `docs/authorino-usage.md` is internally inconsistent —
line 5 and lines 68/85 still reference `/v1/authorino/validate`, while lines 118/212/256 correctly
use `/v1/authorino/validate/introspect`. All three should be updated to match the code.

## 7. Gotchas

- **Ids are opaque strings — never shape-validate, regex, or sort/paginate by them.** CUID2 has no
  ordering; this already broke once when cratestack's `Cuid` schema scalar rejected any id not
  starting with `'c'` (regression test: `crates/lightbridge-authz-rest/tests/rpc_it_tests.rs:712`).
- **cratestack `Value`'s wire format changed from externally-tagged to plain JSON at 0.7.11**
  (cratestack/cratestack#162, #506) — old rows persisted under the tagged form (`{"Map": {...}}`,
  `{"List": [...]}`) still decode cleanly under the untagged decoder, but code written against the
  old shape will not round-trip against the new one. See
  `crates/lightbridge-authz-rest/tests/rpc_it_tests.rs:624-627,687-688`.
- **`oauth2.rbac.default_grants` does not extend a role that already matched `role_permissions`.**
  It only applies to role strings present in the JWT claim that match *no* configured entry — a
  caller holding only recognized roles never receives it on top. Verified by
  `recognized_role_does_not_receive_default_grants_it_wasnt_given`
  (`crates/lightbridge-authz-core/src/authz.rs:535-545`).
- **The authkestra trio (`authkestra-resource`, `authkestra-op`, `authkestra-engine`) must move in
  lockstep** — every crate in the upstream workspace shares one `version.workspace = true`, so a
  partial bump reproduces the same "two majors in the lockfile" failure `jsonwebtoken` hit three
  times (#159/#166/#170). See the pinning comment at `Cargo.toml:60-97`.
- **The `/api/v1/*` REST permission map in `crates/lightbridge-authz-rest/src/middleware/mod.rs:81-154`
  (`required_permission`, `authorize`) is dead code in production.** No router mounts an `/api/v1`
  prefix anywhere in this codebase — the CRUD surface migrated entirely to cratestack's `/rpc/*`
  (ADR-0003). Only `bearer_auth` from that same module is actually wired up (into the MCP server,
  `app/lightbridge-authz/src/mcp.rs:26,1649`); `authorize` and its route map exist only for their
  own unit tests. Don't debug a live 403 by reading that map — read `rpc_authorize.rs` instead.
- **`oauth2.token_exchange.enabled: true` under `oauth2.type: external` fails server startup**,
  not a runtime 4xx — `Error::Server("oauth2.token_exchange is enabled but requires oauth2.type:
  self")` at `crates/lightbridge-authz-rest/src/lib.rs:1278-1282`.
- **Two unrelated `.well-known` discovery documents exist across the fleet** — `authz-idp`'s own
  (`signing::discovery_document`; moved off `authz-api` as a hard cutover, ADR-0012) describes its
  native token-exchange capabilities; `lightbridge-mcp`'s
  (`oauth_authorization_server_metadata_handler`) proxies/synthesizes a document describing the
  **upstream IdP's** endpoints. See §2.

## See also

- `docs/rbac.md` — the full RBAC model, the two-gate CRUD authorization story, project
  membership/roles, account/project suspension.
- `docs/budget-decision-contract.md` — the `Facts`/`Decision`/`PolicyEngine` contract behind budget
  refill decisions.
- `docs/adr/0011-authz-issues-a-full-oidc-token-object.md` — why token issuance goes through
  `authkestra_engine::TokenManager` instead of hand-rolled `jsonwebtoken::encode`.
- `docs/adr/0003-cratestack-crud-migration.md` — why the CRUD surface is `/rpc/*`, not REST.
- `docs/authorino-usage.md` — the Authorino `AuthConfig` wiring for `/v1/authorino/validate/introspect`.
- `docs/oauth-oidc-standards-roadmap.md` — current OAuth/OIDC implementation status and standards
  conformance roadmap.
