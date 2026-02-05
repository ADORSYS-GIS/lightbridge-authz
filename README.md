# Lightbridge Authz

Lightbridge Authz is a two‑API service for managing API keys with OAuth2‑secured CRUD and an Authorino/OPA validation interface. Both servers use TLS, share the same database, and share the same migrations.

## Services

- **authz-api** (frontend CRUD, OAuth2)
  - TLS on `:3000` inside the container, exposed as `:13000` via compose.
  - Public routes: `GET /` and `GET /health`
  - Protected routes under `/api/v1` (OAuth2 bearer token).
- **authz-opa** (Authorino, basic auth)
  - TLS on `:3001` inside the container, exposed as `:13001` via compose.
  - `POST /v1/opa/validate` (basic auth).
- **authz-migrate**
  - Runs SQL migrations before the API services start.
- **postgresql**, **keycloak**, **adminer**, **authz-tls**

## Quick start (Docker Compose)

```bash
just up
```

Verify health:

```bash
curl -k https://localhost:13000/health
curl -k https://localhost:13001/health
```

`-k` is required because the certs are self‑signed.

## Configuration

Default container config is mounted from `.docker/authz/container.yaml`:

- API TLS: `/tls/api.crt` + `/tls/api.key`
- OPA TLS: `/tls/opa.crt` + `/tls/opa.key`
- OPA basic auth: `authorino / change-me`
- OAuth2 JWKS: `http://keycloak:9100/realms/dev/protocol/openid-connect/certs`

## API overview

**CRUD API (OAuth2, `/api/v1`)**
- Accounts: `POST/GET /accounts`, `GET/PATCH/DELETE /accounts/{account_id}`
- Projects: `POST/GET /accounts/{account_id}/projects`, `GET/PATCH/DELETE /projects/{project_id}`
- API keys: `POST/GET /projects/{project_id}/api-keys`, `GET/PATCH/DELETE /api-keys/{key_id}`
- Lifecycle: `POST /api-keys/{key_id}/revoke`, `POST /api-keys/{key_id}/rotate`
- OpenAPI docs: `https://localhost:13000/api/v1/docs`

**OPA API (Basic Auth)**
- `POST /v1/opa/validate`
- OpenAPI docs: `https://localhost:13001/v1/opa/docs`

Use this endpoint from Authorino’s OPA external authz policy to validate API keys; send the presented API key and optional client IP.

Example:

```bash
curl -k -u authorino:change-me \
  https://localhost:13001/v1/opa/validate \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"<plain_api_key>","ip":"203.0.113.10"}'
```

## Testing with Keycloak (OAuth2)

Keycloak is preloaded with:
- Realm: `dev`
- User: `test@admin` / `test` (email-as-username)
- Client: `test-client` (public)

### Option A: Enable direct access grants (recommended for quick local testing)

1. Open Keycloak admin: `http://localhost:9100`  
   Admin user: `admin` / `password`
2. Realm `dev` → Clients → `test-client`
3. Enable **Direct Access Grants** and save.

If you see `{"error":"invalid_request","error_description":"HTTPS required"}`, set the realm SSL requirement to `none` (realm `dev` → Realm Settings → SSL Required), or run:

```bash
docker compose exec keycloak /opt/keycloak/bin/kcadm.sh update realms/dev -s sslRequired=none
```

Then fetch a token:

```bash
curl -s -X POST 'http://localhost:9100/realms/dev/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=test-client' \
  -d 'username=test@admin' \
  -d 'password=test'
```

Use the `access_token`:

```bash
curl -k https://localhost:13000/api/v1/accounts \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"billing_identity":"acme","owners_admins":["test@admin"]}'
```

### Option B: Use authorization code flow

If you prefer not to enable direct access grants, configure a redirect URI in Keycloak and follow the standard authorization code flow to obtain an access token.

## Justfile shortcuts

```bash
just build
just up
just up-no-build
just logs-api
just logs-opa
just migrate
```
