# Authorino Validation API Usage

This document explains how to use the Authorino-oriented validation endpoint exposed by `authz-opa`:

- `POST /v1/authorino/validate`

This endpoint is designed for policy engines and external auth services that need:

- API key validation
- account/project/key context in the response
- dynamic metadata passthrough + enrichment

## Endpoint Contract

Base URL (local compose):

- `https://localhost:13001`

Authentication:

- HTTP Basic auth (`authorino:change-me` by default)

Request body:

```json
{
  "api_key": "lbk_secret_xxx",
  "ip": "203.0.113.10",
  "metadata": {
    "tenant": "acme",
    "request_id": "req-123"
  }
}
```

`metadata` supports arbitrary keys (dynamic object).

Successful response (`200`):

```json
{
  "api_key": { "...": "..." },
  "project": { "...": "..." },
  "account": { "...": "..." },
  "dynamic_metadata": {
    "tenant": "acme",
    "request_id": "req-123",
    "account_id": "acct_...",
    "project_id": "proj_...",
    "api_key_id": "key_...",
    "api_key_status": "active"
  }
}
```

Unauthorized response (`401`):

```json
{
  "error": "unauthorized"
}
```

## Curl Example

```bash
curl -k -u authorino:change-me \
  https://localhost:13001/v1/authorino/validate \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"<plain_api_key>","ip":"203.0.113.10","metadata":{"tenant":"acme","request_id":"req-123"}}'
```

## Integration Test Setup (Docker Compose)

A compose overlay is provided to run an end-to-end integration test:

- `compose.it.yaml`
- test runner script: `.docker/it/authorino_it.py`

The test runner performs:

1. wait for API and OPA readiness
2. fetch OAuth token from Keycloak
3. create account/project/api-key via CRUD API
4. call `/v1/authorino/validate` with dynamic metadata
5. assert metadata passthrough + enrichment keys
6. assert invalid key returns `401`

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

When configuring Authorino to call this API, forward:

- presented API key value as `api_key`
- request source IP as `ip` (if available)
- any request-scoped attributes you want to preserve as `metadata`

Then consume `dynamic_metadata` fields in downstream policy decisions or for audit/telemetry.

## Token Introspection (RFC 7662)

Whatever the API-key format, revocation is enforced by a single RFC 7662 endpoint that
checks the live `api_keys` row (delete/revoke takes effect on the very next request — no
denylist, no stored credential, no provider round-trip):

- `POST /v1/authorino/validate/introspect`

Request (form-encoded, per RFC 7662; the endpoint sits behind the same Basic auth as
`/validate`):

```
token=<opaque-api-key>&token_type_hint=access_token
```

Response — active key:

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

Response — deleted / revoked / expired / unknown key (canonical inactive form):

```json
{ "active": false }
```

Because the check hashes the presented key and reads the live `api_keys` row, a
deleted or revoked key returns `active: false` on the very next request — no denylist,
no stored credential, no provider round-trip.

## Self-signed JWT API keys (enterprise default)

When `oauth2.signing.enabled` is set, issued API keys are **RS256 JWTs signed by this
service**, carrying `api_key_id`, `project_id`, `account_id`, and `allowed_models` claims.
The public half is published so Authorino can verify signatures, via OIDC discovery on the
API server:

- `GET /.well-known/openid-configuration` — points at the JWKS
- `GET /.well-known/jwks.json` — the signing public key(s)

Provision the RS256 private key (`JWT_SIGNING_PRIVATE_KEY_PEM`) and the matching public
JWKS (`JWT_SIGNING_JWKS`) via secret/env, with `JWT_SIGNING_ISSUER` set to the API
server's externally-reachable URL (the `iss` claim and the discovery issuer). A JWT is
still verifiable *and* revocable: signature by JWKS, liveness by introspection.

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

### Alternative: opaque keys (no signing)

With signing disabled, issued keys are opaque `lbk_secret_...` secrets. They are not JWTs,
so Authorino authenticates them with its native `oauth2Introspection` identity pointed at
the same `/v1/authorino/validate/introspect` endpoint — one call authenticates and returns
the context claims. No `jwt` identity or separate metadata rule is needed in that mode.
