# Auth/token reference dictionary

A lookup layer over the auth/token surface of `authz-api`, `authz-opa`, `lightbridge-mcp`, and
`lightbridge-authz-usage`. Ctrl-F a config key, a claim, a discovery field, or a permission string
and get a `file:line` citation, not prose. This does **not** replace `docs/rbac.md` (the RBAC
model in full) or the ADRs (the *why*) — it points at them instead of restating them.

Verified against commit `1c2fc6e` on `origin/main` (2026-08-15). Every row below was checked
against the code at that commit; anything that could not be confirmed by reading source or a
passing test was left out rather than guessed.

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
| `oauth2.audience` | `Option<Vec<String>>` | default `None` | Expected `aud` values for inbound JWT validation; unset disables audience checking | An unset/empty value means **no audience enforcement** — any `aud` is accepted |
| `oauth2.signing` | `Option<JwtSigning>` | default `None` | Enables self-signed RS256 API-key JWTs; required alongside `type: self` for both plain key signing and native token-exchange | Absent under `type: self` with `token_exchange.enabled` → startup fails (`lib.rs:1283-1285`) |
| `oauth2.signing.issuer` | `String` | **Required, non-empty** | `iss` claim + OIDC issuer for JWKS discovery | Empty → `ApiKeyJwtSigner::from_config` fails (`signing.rs:274-278`) |
| `oauth2.signing.audience` | `Option<String>` | default `None` | `aud`/`azp` stamped on plain (non-exchange) self-signed API-key JWTs | — |
| `oauth2.signing.ttl_seconds` | `i64` | default `7_776_000` (90 days) | Default lifetime **and hard cap** on any frontend-requested expiry (`signing.rs:145-155`) | `<= 0` → startup fails (`signing.rs:279-284`) |
| `oauth2.signing.max_key_age_days` | `i64` | default `30` | Auto-rotation interval for the active signing key, checked at startup (`bootstrap_signing_key`, `signing.rs:86-93`) | No hard failure; a very small value just rotates aggressively |
| `oauth2.token_exchange` | `Option<Oauth2TokenExchange>` | default `None` | Native RFC 8693 token-exchange (`POST /oauth2/token`) | Absent/`enabled: false` → `/oauth2/token` is not mounted and discovery advertises no `token_endpoint` at all |
| `oauth2.token_exchange.enabled` | `bool` | default `false` | Whether the exchange grant is mounted | **`enabled: true` under `oauth2.type: external` fails server startup hard** — `Error::Server("oauth2.token_exchange is enabled but requires oauth2.type: self")` (`lib.rs:1278-1282`, test `build_token_exchange_state_rejects_external_oauth2` at `lib.rs:1722-1731`) |
| `oauth2.token_exchange.access_ttl_seconds` | `i64` | default `900` (15 min) | Exchanged access-JWT lifetime | `<= 0` → startup fails (`lib.rs:1286-1290`) |
| `oauth2.token_exchange.refresh_ttl_seconds` | `i64` | default `2_592_000` (30 days) | Refresh-token lifetime | `<= 0` → startup fails, same check as above |
| `oauth2.token_exchange.allowed_scopes` | `Vec<String>` | default `["openid","profile","email","offline_access"]` | Server-wide scope ceiling, intersected with each client's own `scopes` at request time (`oauth2_op/mod.rs:44-76`) | A scope omitted here can never be granted regardless of client config |
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

### `database.*` / `usage_database.*`

| YAML path | Rust type | Required / default | Controls | Breaks when unset/wrong |
|---|---|---|---|---|
| `database.url` | `String` | **Required** | Main Postgres connection (accounts/projects/api_keys/budget tables) | Every server fails to start |
| `database.pool_size` | `Option<u32>` | default `None` (pool default) | Connection pool size | — |
| `usage_database` | `Option<Database>` | default `None` (`config/mod.rs:33-34`) | Connection to the Timescale-backed usage-events DB, read by the budget domain's spend adapter (`usage_events.total_cost`) rather than calling the usage service's own unauthenticated query API | Absent → budget spend reads that need it are unavailable; config still loads fine otherwise (`config_without_redis_or_usage_database_still_loads` test, `config/mod.rs:818-852`) |
| `usage_database.url` / `.pool_size` | same as `database.*` | — | — | — |

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

Covers `authz-api`'s own `GET /.well-known/openid-configuration`, built by `discovery_document`
in `crates/lightbridge-authz-rest/src/signing.rs:438-529` and served via `well_known_router`
(`signing.rs:542-592`).

> **Gating note:** the `token_endpoint` omission logic was fixed in PR #301
> (`fix(oauth2): drop token_endpoint from OIDC discovery when token-exchange is disabled`,
> commit `3f00ca6`, merged 2026-08-15) — before that fix, a disabled token-exchange still
> advertised a live-looking `token_endpoint` URL next to empty `grant_types_supported`. This
> document was checked against `1c2fc6e` (one commit after that fix). Re-check the current state
> of `discovery_document` before trusting this section if it looks stale — the doc comment on
> that function is intentionally dense and updated whenever the gating logic moves.

**Whether the document exists at all**: only mounted when `oauth2.type: self` **and**
`oauth2.signing` is set (`lib.rs:1178-1187`). Under `type: external`, `authz-api` serves no
`/.well-known/openid-configuration` and no `/.well-known/jwks.json`.

**Whether `enabled` (the exchange-specific fields) is true**: `token_exchange_scopes.is_some()`,
which is `oauth2.token_exchange.as_ref().filter(|t| t.enabled)` (`lib.rs:1169-1173`) — true only
when the block is present *and* `enabled: true`.

| Field | Derivation | Gated by |
|---|---|---|
| `issuer` | `oauth2.signing.issuer` verbatim | mount condition above |
| `jwks_uri` | `{issuer}/.well-known/jwks.json` (`signing.rs:476`) | always present when doc exists |
| `token_endpoint` | `{issuer}/oauth2/token` | **removed from the JSON entirely** when `enabled` is false (`signing.rs:524-526`) — not a null/empty string, the key is absent |
| `authorization_endpoint` | n/a | **always removed** (`signing.rs:406,523`) — this service never serves `/authorize` (no authorization_code flow, ADR-0011) |
| `userinfo_endpoint` | n/a | always `null` (`signing.rs:478`) — no userinfo endpoint served |
| `response_modes_supported` | n/a | always `[]` regardless of `enabled` (`signing.rs:486`) — no redirect flow ever applies |
| `token_endpoint_auth_methods_supported` | `["none"]`, or `["none","private_key_jwt"]` | second form iff `oauth2.clients` contains at least one `type: confidential` entry (`private_key_jwt_supported`, computed at `lib.rs:1174-1177`) |
| `grant_types_supported` | `[]` when disabled; `[token-exchange URN, refresh_token URN]` when enabled | `enabled` |
| `response_types_supported` | `[]` when disabled; `["token","id_token","id_token token"]` when enabled | `enabled` |
| `scopes_supported` | `[]` when disabled; `oauth2.token_exchange.allowed_scopes` verbatim when enabled | `enabled` |
| `id_token_signing_alg` | hardcoded `"RS256"` (`ALGORITHM` const, `signing.rs:30`) | always |
| `claims_supported` | hardcoded static list: `iss, sub, aud, exp, iat, nbf, jti, typ, azp, lightbridge_caller_kind, sid, scope, api_key_id, project_id, account_id, email, email_verified, allowed_models, identity, nonce, auth_time, at_hash` (`signing.rs:492-518`) | always, regardless of `enabled` — lists claims that *can* appear, not ones guaranteed on every token |

**A second, unrelated discovery surface exists on `lightbridge-mcp`.** `GET
/.well-known/oauth-authorization-server` and `GET /.well-known/openid-configuration` on the MCP
server (`app/lightbridge-authz/src/mcp.rs:1612-1627`, handler at `mcp.rs:515-538`) are **not**
`signing::discovery_document` — they synthesize a document from `oauth2.issuer_url` /
`authorization_endpoint` / `token_endpoint` / `jwks_url`, i.e. they describe the **upstream IdP's**
real endpoints (for MCP OAuth dynamic-client-registration flows), not `authz-api`'s own
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
| `email` / `email_verified` | `owner.email` / `owner.email_verified`, populated via `decode_email(subject_token)` on the exchange path (`oauth2_op/mod.rs:113-123`) — best-effort, unverified re-decode of an already-signature-verified upstream token | **Propagated upstream snapshot**, omitted (not `null`) when absent |
| `allowed_models` | Project's `allowed_models`, if `Some` | Minted from DB state |
| `at_hash`, `auth_time`, `nonce` | **Not on the access token** — only on the `id_token` (see below) | — |

### ID token (`id_token_extra`, only issued when the `openid` scope is granted)

| Claim | Source | Minted or propagated |
|---|---|---|
| `jti` | Same `lgbr:`-prefixed `cuid2()` pattern as the access token (`signing.rs:250-252`) | Minted |
| `email` / `email_verified` | Same upstream snapshot as the access token (`signing.rs:253-257`) | Propagated |
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

## 4. Permissions → procedures

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

## 5. Endpoints

| Server | Route | Auth | Purpose |
|---|---|---|---|
| `authz-api` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | liveness/startup/readiness probes |
| `authz-api` | `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` | none | OIDC discovery + JWKS; only mounted under `oauth2.type: self` with `signing` set (see §2) |
| `authz-api` | `POST /oauth2/token` | client auth (public `client_id` or `private_key_jwt`), no bearer | RFC 8693 token-exchange + refresh grant; only mounted when `oauth2.token_exchange.enabled` |
| `authz-api` | `POST /rpc/{op_id}`, `POST /rpc/batch` | Bearer JWT + RBAC (`rpc_authorize` outer gate, `CratestackAuthProvider` inner gate, then cratestack `@@allow` membership policy) | Generated CRUD + hand-written budget-domain procedures; base path configurable via `server.api.rpc_base_path` |
| `authz-opa` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | probes |
| `authz-opa` | `GET /v1/opa/docs`, `GET /v1/opa/openapi.json` | none | Swagger UI (`lib.rs:1525`) |
| `authz-opa` | `POST /v1/authorino/validate/introspect` | **Basic auth** | RFC 7662-shaped API-key introspection; response includes `role`/`quota_tier`/`project_quota` (`routers/mod.rs:14-22`, `introspect.rs`) |
| `authz-opa` | `POST /idp/v1/resolve-context` | **Basic auth** | `{subject, project_id} → {account_id, project_id}`; uniform 404 for unknown project or non-member (`routers/mod.rs:20`, `handlers/idp.rs`) |
| `lightbridge-mcp` | `GET /`, `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready` | none | probes |
| `lightbridge-mcp` | `GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration`, `POST /oauth/register` | none | proxy/synthesized discovery pointing at the **upstream IdP's** real endpoints — a different document from `authz-api`'s own (see §2) |
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

## 6. Gotchas

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
- **Two unrelated `.well-known` discovery documents exist across the two servers** — `authz-api`'s
  own (`signing::discovery_document`) describes its native token-exchange capabilities;
  `lightbridge-mcp`'s (`oauth_authorization_server_metadata_handler`) proxies/synthesizes a
  document describing the **upstream IdP's** endpoints. See §2.

## See also

- `docs/rbac.md` — the full RBAC model, the two-gate CRUD authorization story, project
  membership/roles, account/project suspension.
- `docs/budget-decision-contract.md` — the `Facts`/`Decision`/`PolicyEngine` contract behind budget
  refill decisions.
- `docs/adr/0011-authz-issues-a-full-oidc-token-object.md` — why token issuance goes through
  `authkestra_engine::TokenManager` instead of hand-rolled `jsonwebtoken::encode`.
- `docs/adr/0003-cratestack-crud-migration.md` — why the CRUD surface is `/rpc/*`, not REST.
- `docs/authorino-usage.md` — the Authorino `AuthConfig` wiring for `/v1/authorino/validate/introspect`.
