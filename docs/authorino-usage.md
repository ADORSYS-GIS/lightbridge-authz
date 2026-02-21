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
