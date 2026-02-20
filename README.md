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

## Helm deployment

- Install the `charts/lightbridge` umbrella chart—the shared `global.config` block is rendered into a single config map (`global.configMapName`, defaults to `lightbridge-authz-config`) that both `lightbridge-api` and `lightbridge-opa` mount at `/etc/lightbridge/config.yaml`. Use YAML anchors (see `charts/lightbridge/values.yaml`) to keep the base `logging`, `database`, `oauth2`, and `server` sections in sync while overriding the API/OPA ports or service-specific knobs.
- The same umbrella chart also owns the TLS secret (`global.tlsSecretName`, defaults to `lightbridge-authz-tls`) via a pre-install/pre-upgrade `global-tls` job. The job skips generation if the secret already exists, so reruns are safe; disable it (e.g., when cert-manager manages certs) with `--set global.tls.job.enabled=false`.
- Every dependency still renders its own hooks locally, but the umbrella chart disables the per-service TLS job/configmap so the shared resources are reused. Each `lightbridge-authz` release now also has a pre-install/pre-upgrade `migrate` job that writes the templated config to `/tmp/lightbridge-config/config.yaml` and runs `lightbridge-authz migrate --config-path ...`, keeping the schema ready before the servers start.
- Override TLS paths, service types, image tags, etc., via the per-release `lightbridge-api` and `lightbridge-opa` value blocks; for example, bump `lightbridge-api.service.type` to `LoadBalancer` or tweak `lightbridge-opa.image.tag` while relying on the shared `global.config`.
- Validate the charts before deployment with `helm lint charts/lightbridge-authz` and `helm lint charts/lightbridge`. You can preview the combined output (config map, TLS secret job, migrations job, and services) with `helm template charts/lightbridge`. After installing, run `helm test <release>` to exercise the `lightbridge-authz` test pod that hits the rendered service port.


## API overview

**CRUD API (OAuth2, `/api/v1`)**
- Accounts: `POST/GET /accounts`, `GET/PATCH/DELETE /accounts/{account_id}`
- Projects: `POST/GET /accounts/{account_id}/projects`, `GET/PATCH/DELETE /projects/{project_id}`
- API keys: `POST/GET /projects/{project_id}/api-keys`, `GET/PATCH/DELETE /api-keys/{key_id}`
- Lifecycle: `POST /api-keys/{key_id}/revoke`, `POST /api-keys/{key_id}/rotate`
- OpenAPI docs: `https://localhost:13000/api/v1/docs`

**OPA API (Basic Auth)**
- `POST /v1/opa/validate`
- `POST /v1/authorino/validate` (supports dynamic metadata passthrough/enrichment)
- OpenAPI docs: `https://localhost:13001/v1/opa/docs`

Use this endpoint from Authorino’s OPA external authz policy to validate API keys; send the presented API key and optional client IP.

Example:

```bash
curl -k -u authorino:change-me \
  https://localhost:13001/v1/opa/validate \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"<plain_api_key>","ip":"203.0.113.10"}'
```

Authorino-oriented example with metadata:

```bash
curl -k -u authorino:change-me \
  https://localhost:13001/v1/authorino/validate \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"<plain_api_key>","ip":"203.0.113.10","metadata":{"tenant":"acme"}}'
```

Detailed usage + integration test guide:
- `docs/authorino-usage.md`

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
