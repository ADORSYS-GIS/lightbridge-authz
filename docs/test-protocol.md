# Test Protocol (OAuth2 + Authorino Validation)

This protocol validates the full flow:
1) OAuth2‑protected RPC API (cratestack, CBOR-only — see step 3 below)
2) API key creation
3) Authorino-facing validation with usage telemetry and enrichment

## Prerequisites
- Docker Compose services are running
- Keycloak is reachable at `http://localhost:9100`

Start or rebuild:

```bash
docker compose -f compose.yaml up -d --build
```

## 1) Confirm the dev clients

Keycloak is preloaded with realm `dev`, user `test@admin` / `test`
(email‑as‑username), public login client `test-client`, and confidential token
issuer client `lightbridge-token-issuer` with secret
`lightbridge-token-issuer-secret`. The `test-client` access token includes
`lightbridge-token-issuer` as an audience so Keycloak permits that confidential
client to exchange the user's token.

Direct access grants on `test-client` are only required to get user tokens via
password grant for local testing. `lightbridge-token-issuer` is the client used
by Authz for token exchange; it does not use username or password credentials.

```bash
docker compose -f compose.yaml exec -T keycloak \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:9100 --realm master \
  --user admin --password password

CLIENT_ID=$(docker compose -f compose.yaml exec -T keycloak \
  /opt/keycloak/bin/kcadm.sh get clients -r dev -q clientId=test-client \
  | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)[0]['id'])")

docker compose -f compose.yaml exec -T keycloak \
  /opt/keycloak/bin/kcadm.sh update clients/$CLIENT_ID -r dev \
  -s directAccessGrantsEnabled=true
```

## 2) Fetch an access token

If you see `{"error":"invalid_request","error_description":"HTTPS required"}`, disable SSL requirement for the realm:

```bash
docker compose -f compose.yaml exec -T keycloak \
  /opt/keycloak/bin/kcadm.sh update realms/dev -s sslRequired=none
```

```bash
TOKEN=$(curl -s -X POST 'http://localhost:9100/realms/dev/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=test-client' \
  -d 'username=test@admin' \
  -d 'password=test' \
  | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
```

## 3) Testing the RPC surface manually (CBOR only)

`authz-api`'s CRUD/RPC surface (`docs/adr/0003-cratestack-crud-migration.md`) is a cratestack
`rpc_router`, mounted as `POST /rpc/{op_id}` (plus `POST /rpc/batch`). Since ADR-0013
(`docs/adr/0013-cbor-is-the-only-transport-codec.md`) it accepts **only** `application/cbor` for
both the request body and the `Accept` header — there is no REST/JSON fallback any more. Sending
`Content-Type: application/json` gets `415 Unsupported Media Type`; asking for
`Accept: application/json` gets `406 Not Acceptable`. There is also no Swagger/OpenAPI UI for this
surface — it was removed in the same migration (see "OpenAPI docs" in `AGENTS.md`/`CLAUDE.md`). The
OPA/Authorino and usage APIs keep their own separate OpenAPI docs and are unaffected — see step 7
below.

Concretely, this means a bare `curl -d '{"...":"..."}' -H 'Content-Type: application/json'` —
which is what steps 4–6 and the cleanup step below used to show — **cannot** call `createAccount`,
`model.Project.create`, `procedure.setProjectAllowedModels`, `createApiKey`, or
`deleteAccountPermanently` at all; it fails at the codec layer before the request is ever
dispatched, regardless of the body's contents.

The sections below therefore give each call as `op_id` + the JSON shape to CBOR-encode, rather
than a runnable `curl` line — this repo does not ship a `curl`-friendly CBOR CLI, and a confidently
wrong hand-built command is worse than none. Two ways to actually exercise these calls with a real,
verified CBOR encoder:

- **The generated cratestack client** (Rust or TypeScript) is the primary integration contract for
  this surface — see `docs/adr/0003-cratestack-crud-migration.md`.
- **`crates/lightbridge-authz-rest/tests/rpc_it_tests.rs`** (helpers in `tests/common/mod.rs`)
  sends real CBOR-encoded requests against a live router + Postgres for every call used below,
  including `procedure.createAccount`, `model.Project.create`,
  `procedure.setProjectAllowedModels`, `procedure.createApiKey`, and
  `procedure.deleteAccountPermanently` — run or read those tests for a working example instead of
  hand-rolling one.

If you do want a genuine one-off manual call, CBOR-encode the JSON shown in each step yourself
(e.g. Python's `cbor2.dumps(...)`), POST the raw bytes to `https://localhost:13000/rpc/<op_id>`
with `-H 'Content-Type: application/cbor' -H 'Accept: application/cbor'`, and decode the (also
CBOR) response the same way.

## 4) Create an account

`op_id`: `procedure.createAccount`

Body to CBOR-encode:

```json
{ "args": { "defaultQuota": null } }
```

`defaultQuota` is optional — the account's own governance tier for usage under its default
project, validated against the operator-configured quota-tier catalogue. There is no
`billing_identity` field here any more: the account `id` is never caller-supplied — it is read
straight from the caller's JWT `sub` (ADR-0006) — and `billing_identity` itself moved onto
`Project.billingIdentity` in the same change ("who is paying" is a per-project concept now, one
project can bill a different party than another project on the same account).

The response is the created `Account`; `ACCOUNT_ID` is its `id` (== your JWT `sub`).

## 5) Create a project

`op_id`: `model.Project.create`

Body to CBOR-encode:

```json
{
  "id": "<a CUID2 you generate client-side>",
  "accountId": "$ACCOUNT_ID",
  "name": "demo",
  "defaultLimits": { "requests_per_second": 10, "requests_per_day": 1000 },
  "billingPlan": "free",
  "billingIdentity": "acme-demo-1"
}
```

Notes:

- Unlike `createAccount`, `model.Project.create` is a generic cratestack model-create verb, not a
  hand-written procedure — it does not mint the id for you. `id` must be a CUID2 (24 lowercase
  `a-z0-9` characters, starting with a letter — this service's house id format; see CLAUDE.md's
  "Identifier Format (CUID2)" section) that you generate before the call. It becomes `PROJECT_ID`.
- `billingIdentity` is globally unique — reusing a value from a previous run fails; pick a fresh
  one each time.
- **Do not put `allowed_models`/`allowedModels` in this body.** As of PR #417 (issue #415,
  ADR-0018 Decision 5), `Project.allowedModels` is `@readonly` on both `model.Project.create` and
  `model.Project.update` — the field is **silently ignored** if you send it here (dropped
  server-side, not rejected), so a reader who merges it into the create call gets a project with
  no allowlist and no error. The only write path is the dedicated procedure below.
  `Project.projectQuota` has the identical shape and the identical trap: `@readonly` on
  create/update, with `setProjectQuota` as its sole post-creation write path
  (`crates/lightbridge-authz-api/schema/authz.cstack`).

Set the allowlist as a separate call, after creation:

`op_id`: `procedure.setProjectAllowedModels`

```json
{ "args": { "projectId": "$PROJECT_ID", "allowedModels": ["gpt-4.1-mini"] } }
```

Every entry is validated against the operator-configured model catalogue
(`crates/lightbridge-authz-rest/src/handlers/mod.rs::set_project_allowed_models`) — an
unrecognized model id is refused with `400`, not silently dropped.

## 6) Create an API key

The CRUD API stores only the SHA-256 hash of the issued secret and returns the
plaintext `secret` exactly once, on create/rotate. The credential format depends on
config:

The credential format is chosen by the **required** `oauth2.type` key (no default):

- **Self-signed JWT** (`oauth2.type: self`, enterprise default): an RS256 JWT
  signed by this service, carrying `api_key_id`/`project_id`/`account_id`/`allowed_models`
  claims. The signing keypair is generated on first startup and stored in the DB
  (`signing_keys`), auto-rotated once older than `max_key_age_days` (rotated-out keys are
  marked stale and kept in the JWKS until their tokens expire). Authorino verifies the
  signature via the published JWKS (`/.well-known/jwks.json`) and enforces revocation via
  introspection (see `docs/authorino-usage.md`).
- **Keycloak token exchange** (`oauth2.type: external`): a Keycloak-issued OAuth2 JWT,
  exchanged via `oauth2.issuance`.

(The former opaque `lbk_secret_...` mode has been removed — `oauth2.type` is mandatory and
only `self` or `external` are valid.)

Regardless of format, revoking or deleting the API key takes effect on the **next
request**. Authorino authorizes each request by introspecting the presented key
(`POST /v1/authorino/validate/introspect`), which hashes it, looks up the `api_keys`
row, and rejects anything whose `status` is not `Active` or whose `expires_at` has
passed. Revocation flips `status` to `Revoked`; deletion removes the row (lookup then
misses). The DB row is the single source of truth — no denylist, no stored credential,
no provider round-trip to keep in sync. (A self-signed JWT also remains independently
verifiable until its own `exp`; keep the signing `ttl_seconds` bounded accordingly.)

`op_id`: `procedure.createApiKey`

Body to CBOR-encode:

```json
{
  "args": {
    "projectId": "$PROJECT_ID",
    "name": "demo-key",
    "expiresAt": "<ISO-8601 timestamp, no more than api_key_expiry (default 90 days) out>",
    "billingPlan": "free"
  }
}
```

`expiresAt` is now a **required** field (lightbridge-authz#395: "all api-keys created from our
system MUST have an expiry date"): omitting it is a validation error, not a default, and the value
is capped against the operator-configured `api_key_expiry` ceiling (default 90 days) — there is no
"never expires" option any more.

The response is `ApiKeySecret { apiKey, secret, oauth2Url? }`; `SECRET` is its `secret` field.

## 7) Validate through the internal Authorino backend

`$OPA_USER`/`$OPA_PASSWORD` are the `server.opa.basic_auth` credentials from the config YAML
(locally, `.docker/authz/container.yaml`'s defaults). Unlike the RPC surface above, this endpoint
is unaffected by ADR-0013 — Authorino dictates a plain form-encoded request, not CBOR — and it
still serves its own OpenAPI docs at `https://localhost:13001/v1/opa/docs`.

```bash
curl -k -u "$OPA_USER:$OPA_PASSWORD" https://localhost:13001/v1/authorino/validate/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=$SECRET&token_type_hint=access_token"
```

Expected: `200` with `{"active": true, ...}` plus `account_id`, `project_id`, `api_key_id`, and
`api_key_status` fields (RFC 7662 introspection — see `docs/authorino-usage.md`). `last_used_at`
is updated on the underlying `api_keys` row as part of this call.

In a deployed path, callers do not invoke this backend directly. Authorino's `AuthConfig` calls
the introspection endpoint using basic auth as a `metadata` provider, then gates the request on
the returned `active` field via an authorization rule — see `docs/authorino-usage.md`'s "AuthConfig
wiring" section for the exact wiring and how per-request metadata is handled now (inside
Authorino's own `AuthConfig`, not this API).

## Cleanup (optional)

`op_id`: `procedure.deleteAccountPermanently`

Body to CBOR-encode:

```json
{ "args": { "accountId": "$ACCOUNT_ID" } }
```
