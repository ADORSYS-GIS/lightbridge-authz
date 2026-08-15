# Authorino Validation API Usage

This document explains how to use the Authorino-oriented validation endpoint exposed by `authz-opa`:

- `POST /v1/authorino/validate/introspect` — RFC 7662 token introspection

This is the **only** key-validation route `authz-opa` exposes today. It's locked in place by
`introspect_endpoint_should_exist_in_opa_openapi`
(`crates/lightbridge-authz-rest/src/lib.rs:1788-1807`), which asserts the OPA server's OpenAPI
document excludes two earlier paths: `POST /v1/opa/validate` and `POST /v1/authorino/validate`.
Both were removed with no direct HTTP successor — `/v1/authorino/validate` in particular used to
accept a JSON body with an arbitrary `metadata` object and echo it back inside an enriched
`dynamic_metadata` response. That same account/project/key context plus metadata-enrichment shape
still exists in this codebase, but only as the `validate-authorino-api-key` MCP tool exposed by
`lightbridge-mcp`'s `/mcp` endpoint (bearer-JWT + RBAC gated, see `app/lightbridge-authz/src/mcp.rs`)
— it is not reachable by Authorino's `AuthConfig`, which needs a plain HTTP call, not an MCP
client. For the actual gateway integration, Authorino uses the introspection endpoint below for
liveness, and gets its per-request metadata from its own `AuthConfig` instead (see "AuthConfig
wiring" further down).

This endpoint is designed for policy engines and external auth services that need:

- API key validation (liveness / revocation / expiry, checked against the live `api_keys` row —
  no denylist, no stored credential, no provider round-trip)
- account/project/key context in the response

## Endpoint Contract

Base URL (local compose):

- `https://localhost:13001`

Authentication:

- HTTP Basic auth, credentials from `server.opa.basic_auth` in the config YAML (in the local
  compose stack these default to `authorino` / the placeholder password set in
  `.docker/authz/container.yaml`)

Request body (form-encoded, per RFC 7662):

```
token=<opaque-api-key>&token_type_hint=access_token
```

`token_type_hint` is accepted but ignored — only access tokens are supported.

Successful response (`200`, active key):

```json
{
  "active": true,
  "sub": "key_...",
  "account_id": "acct_...",
  "project_id": "proj_...",
  "api_key_id": "key_...",
  "api_key_status": "active",
  "billing_plan": "free",
  "allowed_models": ["gpt-4.1-mini"],
  "exp": 1767225600
}
```

Deleted / revoked / expired / unknown key (canonical inactive form — still a `200`, per RFC 7662):

```json
{ "active": false }
```

Wrong Basic-auth credentials (`401`):

```json
{
  "error": "unauthorized"
}
```

Because the check hashes the presented key and reads the live `api_keys` row on every call, a
deleted or revoked key flips to `active: false` on the very next request.

## Curl Example

`$OPA_USER`/`$OPA_PASSWORD` are the `server.opa.basic_auth` credentials from the config YAML
(locally, `.docker/authz/container.yaml`'s defaults).

```bash
curl -k -u "$OPA_USER:$OPA_PASSWORD" \
  https://localhost:13001/v1/authorino/validate/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'token=<plain_api_key>&token_type_hint=access_token'
```

## Integration Test Setup (Docker Compose)

A compose overlay is provided to run an end-to-end integration test:

- `compose.it.yaml`
- test runner script: `.docker/it/authorino_it.py`

The test runner performs:

1. wait for API and OPA readiness
2. fetch OAuth token from Keycloak
3. create account/project/api-key via the CRUD RPC surface (`POST /rpc/{op_id}` — e.g.
   `procedure.createAccount`, `model.Project.create`, `procedure.createApiKey`)
4. call `/v1/authorino/validate/introspect` for the minted key
5. assert `active: true` plus the `account_id`/`project_id`/`api_key_id`/`api_key_status` fields
6. call it again for an invalid key and assert `active: false` (still `200` — RFC 7662 has no
   401-for-invalid-token case; only a wrong Basic-auth credential returns `401`)

Run:

```bash
docker compose -f compose.yaml -f compose.it.yaml up -d --build
docker compose -f compose.yaml -f compose.it.yaml run --rm it-authorino
```

Cleanup:

```bash
docker compose -f compose.yaml -f compose.it.yaml down -v
```

## Notes for Authorino Integration

Authorino does not call this endpoint as an identity provider — it calls it as a `metadata`
provider, after its own `jwt` (or `oauth2Introspection`) identity phase has already run. Forward:

- the presented API key/token value as `token` (form-encoded, per RFC 7662)

Then gate the request on the response's `active` field in an authorization `patternMatching`
rule, and read the account/project/key fields via `auth.metadata[...]` selectors for header
mapping. See "AuthConfig wiring" below for the full example.

## Self-signed JWT API keys (enterprise default)

When `oauth2.type` is `self`, issued API keys are **RS256 JWTs signed by this
service**, shaped to mirror a Keycloak access token so gateways can consume them uniformly:

```json
{
  "iss": "https://authz.example/",
  "sub": "<creator's Keycloak user id>",
  "aud": "lightbridge-api-key",
  "azp": "lightbridge-api-key",
  "typ": "Bearer",
  "scope": "profile email",
  "jti": "...", "sid": "...", "iat": 0, "exp": 0,
  "api_key_id": "key_...",
  "project_id": "proj_...",
  "account_id": "acct_...",
  "allowed_models": ["gpt-4.1-mini"],
  "email": "owner@example.test",
  "email_verified": true
}
```

`sub` is the **creator's Keycloak subject** (not the api-key id — that lives in
`api_key_id`). `email`/`email_verified` are snapshotted from the creator's bearer token at
create/rotate time and frozen for the token's TTL; they are omitted when the creating token
carried no email. The public half is published so Authorino can verify signatures, via OIDC
discovery on the API server:

- `GET /.well-known/openid-configuration` — points at the JWKS
- `GET /.well-known/jwks.json` — the signing public key(s)

The signing keypair is **generated on first startup and stored in the DB** (`signing_keys`
table) — no key material is provisioned by operators. Set `JWT_SIGNING_ISSUER` to the API
server's externally-reachable URL (the `iss` claim and the discovery issuer). A JWT is
still verifiable *and* revocable: signature by JWKS, liveness by introspection.

**Rotation** is automatic and time-based: at startup, if the active key is older than
`max_key_age_days` (default 30) it is marked `stale` and a fresh key is generated and
activated. Stale keys stay in the JWKS so tokens they signed keep verifying until they
expire; only the active key signs new tokens. Boot key-provisioning is race-safe across
replicas (a Postgres advisory lock ensures exactly one active key).

### AuthConfig wiring — JWT signature + introspection (gateway repo)

Verify the signature via the `jwt` identity (issuer discovery), then gate on liveness with
an introspection `metadata` call plus an authorization rule. Claims are exposed as
`auth.identity.*` for header mapping:

```yaml
authentication:
  # ...github-actions / keycloak jwt identities stay as-is...
  apikey:
    jwt:
      issuerUrl: https://authz-api.converse.svc.cluster.local:3000   # OIDC discovery -> JWKS
      ttl: 300
metadata:
  apikey-liveness:
    http:
      url: https://authz-opa.converse.svc.cluster.local:3001/v1/authorino/validate/introspect
      method: POST
      contentType: application/x-www-form-urlencoded
      body:
        value: 'token={context.request.http.headers.authorization.@extract:{"sep":" ","pos":1}}'
      credentials:
        authorizationHeader: { prefix: Basic }
      sharedSecretRef: { name: lightbridge-authz-opa-basic, key: basic-auth }
    cache:
      key: { selector: auth.identity.api_key_id }
      ttl: 30
authorization:
  apikey-not-revoked:
    patternMatching:
      patterns:
        - predicate: auth.metadata["apikey-liveness"].active == true
      when:
        - selector: auth.identity.api_key_id
          operator: neq
          value: ''
```

The `jwt` identity fetches the JWKS via `issuerUrl` discovery (self-signed TLS in dev —
trust its CA or terminate TLS in-cluster). The `metadata` call forwards the raw JWT to
introspection so a deleted/revoked key flips to `active: false` within the cache TTL.

Introspection reports liveness from the `api_key_validation` view, which cascades
`account → project → key` status. So **suspending an account or project** (see
[docs/rbac.md](rbac.md) → *Account / project suspension*) also flips `active: false` for every key
beneath it, and the same `apikey-not-revoked` rule denies the request.

This gives a clean 401-vs-403 split, decided by which phase fails:

- an **invalid or expired** JWT fails the `jwt` **identity** phase → Authorino returns **401
  Unauthorized** (Envoy's default for identity failure);
- a **valid** JWT whose key is revoked or whose account/project is **suspended** fails the
  `apikey-not-revoked` **authorization** rule → Authorino returns **403 Forbidden** (the default
  status for an authorization deny; override with `denyWith.unauthorized`/`denyWith.forbidden` if
  you want to customise the body).

### Alternative: opaque keys (no signing)

With signing disabled, issued keys are opaque `lbk_secret_...` secrets. They are not JWTs,
so Authorino authenticates them with its native `oauth2Introspection` identity pointed at
the same `/v1/authorino/validate/introspect` endpoint — one call authenticates and returns
the context claims. No `jwt` identity or separate metadata rule is needed in that mode.
