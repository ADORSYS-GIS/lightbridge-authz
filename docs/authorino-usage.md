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

## Token Introspection (opaque API keys, RFC 7662)

API keys are opaque secrets (`lbk_secret_...`), not JWTs, so Authorino validates them
with its native `oauth2Introspection` identity against a single RFC 7662 endpoint that
both authenticates the key and returns its context:

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

### AuthConfig wiring (gateway repo)

Add it as an identity alongside your existing JWKS issuers. An opaque key fails the
`jwt` identities and falls through to introspection; the returned claims are exposed as
`auth.identity.*` for header mapping:

```yaml
authentication:
  # ...github-actions / keycloak jwt identities stay as-is...
  apikey:
    oauth2Introspection:
      endpoint: https://authz-opa.converse.svc.cluster.local:3001/v1/authorino/validate/introspect
      tokenTypeHint: access_token
      credentialsRef:
        name: lightbridge-authz-opa-basic   # secret holds authorino:<opa-password>
response:
  success:
    headers:
      x-account-id:
        plain:
          expression: >-
            has(auth.identity.account_id) ? string(auth.identity.account_id) :
            string(auth.identity.sub)
      # ...map project_id / billing_plan / allowed_models from auth.identity.* similarly
```

`credentialsRef` supplies the Basic credentials the OPA server expects. Note the
endpoint is TLS (self-signed in dev) — trust its CA or terminate TLS in-cluster;
`http://…` will not handshake against the `:3001` listener.
