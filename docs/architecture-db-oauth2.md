# Lightbridge Authz Architecture (DB + OAuth2 + OPA)

## Overview
This service exposes two HTTP APIs that share the same Postgres database and migrations:

- **Frontend API (OAuth2)**: CRUD for accounts, projects, and API keys.
- **Authorino/OPA API (Basic Auth)**: API key validation + last-used telemetry.

Both servers **require TLS** at startup.

## Services

### API server (frontend)
- Axum HTTP server started by `start_api_server()` in `crates/lightbridge-authz-rest/src/lib.rs`.
- Secured by OAuth2 bearer tokens (JWKS from the configured IdP).
- Exposes account/project/key CRUD and lifecycle operations.

### OPA server (Authorino)
- Axum HTTP server started by `start_opa_server()` in `crates/lightbridge-authz-rest/src/lib.rs`.
- Secured by basic auth credentials configured under `server.opa.basic_auth`.
- Validates API keys and updates `last_used_at`, `last_ip`, and `last_region`.

### Database
Postgres database shared by both servers.

### Migrations
Standalone migration binary is built as its own image and run before the API services.

## Ports
- API (frontend): `3000`
- OPA (Authorino): `3001`

## Data model summary

### Account
- `id`
- `billing_identity`
- `owners` / `admins`

### Project (Workspace)
- `id`, `account_id`
- `name`
- `allowed_models`
- `default_limits`
- `billing_plan`

### API Key
- `id`, `project_id`
- `name`
- `key_prefix` (display only)
- `key_hash` (stored)
- `status` (`active` / `revoked`)
- `created_at`, `expires_at`
- `last_used_at`, `last_ip`, `last_region`

## Request flows

### Frontend CRUD
1. Client sends OAuth2 bearer token.
2. API server verifies JWT via JWKS.
3. CRUD operations run against Postgres using the shared store.

### Authorino validation
1. Authorino sends request to OPA server with basic auth and API key.
2. OPA server validates key hash and status.
3. On success, OPA server updates last-used telemetry.

## TLS
Both servers refuse to start without valid TLS certs/keys configured in the server config.
