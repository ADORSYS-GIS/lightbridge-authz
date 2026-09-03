# Lightbridge Authz

**Start here:** [`docs/local-testing.md`](docs/local-testing.md) — run the whole platform locally
(backend + frontend console) and test it end to end.

**Find any document:** [`docs/README.md`](docs/README.md) is the navigation map for this
repository's documentation — use it to jump straight to the guide, ADR, or runbook you need.

Lightbridge Authz is a multi-service backend for API key management and usage analytics:
- `authz-api` and `authz-opa` handle key lifecycle and validation.
- `authz-idp` is the OIDC broker for both the human plane (browser SSO, RFC 8628 device flow, token
  exchange) and the machine plane (RFC 6749 §4.4 `client_credentials`, M2M, ADR-0030). It renders
  no HTML of its own — see its entry under Services below.
- `lightbridge-authz-usage` ingests OTEL traffic data and serves usage analytics (plain Postgres in
  production, not Timescale — see `docs/architecture.md`).
- `lightbridge-mcp` exposes all `lightbridge-authz` endpoints as MCP tools over streamable HTTP (`/mcp`).

See [`docs/architecture.md`](docs/architecture.md) for the service/caller topology, crate layering, and
the `resolve-context` + Authorino validation flows (mermaid diagrams).

## Services

- **authz-api** (frontend CRUD, OAuth2)
  - TLS on `:3000` inside the container, exposed as `:13000` via compose.
  - Public routes: `GET /` and `GET /healthz`
  - Probe routes: `GET /healthz` (liveness), `GET /healthz/startup` (startup), `GET /healthz/ready` (DB readiness)
  - Protected routes under `/api/v1` (OAuth2 bearer token).
- **authz-opa** (Authorino, basic auth; also the ownership authority for the usage query API)
  - TLS on `:3001` inside the container, exposed as `:13001` via compose.
  - `POST /v1/authorino/validate/introspect` (basic auth, RFC 7662 introspection) — the only
    key-validation route; see `docs/authorino-usage.md`.
  - `POST /idp/v1/resolve-context` (basic auth) — resolves tenant context for token-exchange.
  - `POST /idp/v1/authorize-usage-scope` (basic auth) — body `{issuer, subject, scope, scope_id}`;
    the ownership authority `lightbridge-authz-usage`'s query listener calls for `account`/`project`
    usage-query scopes (#570). Uniform `404` on any miss, same non-oracle convention as
    `resolve-context`.
  - Probe routes: `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready`
- **authz-idp** (OIDC broker: browser SSO, RFC 8628 device flow, token exchange, and the
  `client_credentials` machine plane, ADR-0030)
  - TLS on `:3004` inside the container, exposed as `:13004` via compose.
  - Every route is public — the presented token/assertion or a completed Keycloak login is itself
    the credential. See `docs/architecture/services.md`'s `authz-idp` section for the full route
    table.
  - Renders no HTML: the browser/device-flow pages are a React SPA, `apps/authz-ui` in the
    [`ADORSYS-GIS/converse-frontends`](https://github.com/ADORSYS-GIS/converse-frontends) monorepo,
    built on the estate's `ui-web` design system. `authz-idp` serves the built bundle same-origin
    under `/ui`, consumed as a digest-pinned, assets-only OCI artifact
    (`ghcr.io/adorsys-gis/converse-frontends/authz-ui`) rather than compiled in this repo — the one
    pin is `Dockerfile`'s `ARG AUTHZ_UI_REF=`. `/ui` is a route ALLOWLIST sourced from the
    artifact's own `dist/routes.json`, not a catch-all: only the manifest's listed paths resolve to
    `index.html`, everything else under `/ui` is a plain `404`. See **ADR-0029** for the full
    artifact contract and pin policy, and `docs/local-testing.md` §5 for the cross-repo dev loop.
- **authz-migrate**
  - Runs SQL migrations before the API services start.
- **lightbridge-mcp**
  - TLS on `:3000` inside the container, exposed as `:13003` via compose.
  - MCP streamable HTTP endpoint: `POST/GET /mcp`
  - OAuth metadata/discovery endpoints: `GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration`
  - OAuth dynamic client registration proxy endpoint: `POST /oauth/register`
  - Health probes: `GET /healthz` (liveness), `GET /healthz/ready` (DB readiness), `GET /healthz/startup` (startup)
  - Protected with OAuth2/JWT bearer validation (same JWKS flow as `authz-api`).
  - Reuses the same config file as `lightbridge-authz` (API bind/tls + shared DB settings).
- **lightbridge-authz-usage** (OTEL ingest + usage query, split across two listeners since #347)
  - Ingest listener — TLS on `:3002` inside the container (compose), unauthenticated:
    `POST /v1/otel/traces`, `POST /v1/otel/metrics`, `POST /v1/otel/logs`; OpenAPI docs at
    `/usage/v1/usage/docs`.
  - Query listener — TLS on `:3006` inside the container (compose; the umbrella chart uses `:3000`
    ingest / `:3006` query instead), mTLS-required: `POST /usage/v1/usage/query` (mTLS **plus** an
    end-user `Authorization: Bearer` token and an ownership check via `authz-opa`'s
    `authorize-usage-scope`, #570/#603) and `POST /usage/v1/spend/query` (mTLS-only,
    service-to-service, refuses any request carrying an `Authorization` header, #603). See
    `docs/usage-api.md` and `docs/lightbridge-query-api.md` for the full auth contract.
  - Probe routes on both listeners: `GET /healthz`, `GET /healthz/startup`, `GET /healthz/ready`
- **postgresql**, **keycloak**, **adminer**, **authz-tls**

## Quick start (Docker Compose)

```bash
just up
```

Verify health:

```bash
curl -k https://localhost:13000/healthz
curl -k https://localhost:13000/healthz/ready
curl -k https://localhost:13000/healthz/startup
curl -k https://localhost:13001/healthz
curl -k https://localhost:13001/healthz/ready
curl -k https://localhost:13001/healthz/startup
curl -k https://localhost:13002/healthz
curl -k https://localhost:13002/healthz/ready
curl -k https://localhost:13002/healthz/startup
curl -k https://localhost:13003/healthz
curl -k https://localhost:13003/healthz/ready
curl -k https://localhost:13003/healthz/startup
```

`-k` is required because the certs are self‑signed.

## Configuration

Default container config is mounted from `.docker/authz/container.yaml`:

- API TLS: `/tls/api.crt` + `/tls/api.key`
- OPA TLS: `/tls/opa.crt` + `/tls/opa.key`
- OPA basic auth: `authorino / change-me`
- OAuth2 JWKS: `http://keycloak:9100/realms/dev/protocol/openid-connect/certs`
- Optional OAuth2 overrides for MCP metadata/registration relay: `issuer_url`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`

## Helm deployment

- Install the `charts/lightbridge-authz-stack` umbrella chart — it wires six aliased dependencies
  (`api`/`opa`/`idp`/`budget` from `charts/lightbridge-authz`, `usage` from
  `charts/lightbridge-authz-usage`, `mcp` from `charts/lightbridge-mcp`). The shared `global.config`
  block is rendered into a single config map (`global.configMapName`, defaults to
  `lightbridge-authz-config`) that the `api`/`opa` aliases mount at `/etc/lightbridge/config.yaml`.
  Use YAML anchors (see `charts/lightbridge-authz-stack/values.yaml`) to keep the base `logging`,
  `database`, `oauth2`, and `server` sections in sync while overriding the API/OPA ports or
  service-specific knobs.
- The same umbrella chart also owns the TLS secret (`global.tlsSecretName`, defaults to `lightbridge-authz-tls`) via a pre-install/pre-upgrade `global-tls` job. The job skips generation if the secret already exists, so reruns are safe; disable it (e.g., when cert-manager manages certs) with `--set global.tls.job.enabled=false`.
- Every dependency still renders its own hooks locally, but the umbrella chart disables the per-service TLS job/configmap so the shared resources are reused. Each `lightbridge-authz` release also runs its own `controllers.migrate` Job (`charts/lightbridge-authz/values.yaml`), writing the templated config to `/etc/lightbridge/config.yaml` and running `lightbridge-authz migrate --config-path ...` — an ordinary ArgoCD-tracked resource on an earlier sync-wave than the main Deployment (ADR-0016), not a Helm hook — keeping the schema ready before the servers start. See `docs/platform-guides.md`'s "Migration job" section for the full mechanism.
- Override TLS paths, service types, image tags, etc., via the per-release `lightbridge-api` and `lightbridge-opa` value blocks; for example, bump `lightbridge-api.service.type` to `LoadBalancer` or tweak `lightbridge-opa.image.tag` while relying on the shared `global.config`.
- Validate the charts before deployment with `helm lint charts/lightbridge-authz` and `helm lint charts/lightbridge-authz-stack`. You can preview the combined output (config map, TLS secret job, migration jobs, and services) with `helm template charts/lightbridge-authz-stack`. After installing, run `helm test <release>` to exercise the `lightbridge-authz` test pod that hits the rendered service port.


## API overview

**CRUD API (OAuth2, `/api/v1`)**
- Accounts: `POST/GET /accounts`, `GET/PATCH/DELETE /accounts/{account_id}`
- Projects: `POST/GET /accounts/{account_id}/projects`, `GET/PATCH/DELETE /projects/{project_id}`
- API keys: `POST/GET /projects/{project_id}/api-keys`, `GET/PATCH/DELETE /api-keys/{key_id}`
- Lifecycle: `POST /api-keys/{key_id}/revoke`, `POST /api-keys/{key_id}/rotate`
- OpenAPI docs: removed (CRUD API is now generated via cratestack, which has no OpenAPI/Swagger UI generation). The generated cratestack Rust client is the primary integration contract; see `docs/adr/0003-cratestack-crud-migration.md`.

**Internal Authz/Authorino validation API (Basic Auth)**
- `POST /v1/authorino/validate/introspect` — RFC 7662 token introspection; the only key-validation
  route (the earlier JSON `POST /v1/authorino/validate` endpoint, with a `metadata`
  passthrough/enrichment field, was removed — see `docs/authorino-usage.md`).
- `POST /idp/v1/resolve-context` — resolves the tenant context for a subject scoped to a project (body `{subject, project_id}`) → `{account_id, project_id}`. Membership-enforced; any miss is a uniform `404`. Called by the Keycloak IdP adapter during token exchange; Basic-auth protected (the adapter presents the OPA credentials).
- `POST /idp/v1/authorize-usage-scope` — body `{issuer, subject, scope, scope_id}`; the ownership authority `lightbridge-authz-usage`'s query listener calls for `account`/`project` usage-query scopes (#570/#603). Non-oracle: any miss (unknown scope_id, non-member subject) is the same uniform `404` `resolve-context` uses. Basic-auth protected.
- OpenAPI docs: `https://localhost:13001/v1/opa/docs`

This backend is intended to be called by Authorino, not by end users or client
applications directly. Authorino calls the introspection endpoint with the presented
credential as a `metadata` provider; the response's `active` field plus account/project/key
context feed an authorization rule in Authorino's own `AuthConfig`. Per-request metadata
enrichment happens entirely inside that `AuthConfig` now (`auth.identity.*` /
`auth.metadata[...]` selectors), not this API — see `docs/authorino-usage.md`'s "AuthConfig
wiring" section.

Manual validation example (`$OPA_USER`/`$OPA_PASSWORD` are the `server.opa.basic_auth`
credentials from the config YAML; locally these default to `authorino` / the placeholder
password in `.docker/authz/container.yaml`):

```bash
curl -k -u "$OPA_USER:$OPA_PASSWORD" \
  https://localhost:13001/v1/authorino/validate/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'token=<plain_api_key>&token_type_hint=access_token'
```

Detailed usage + integration test guide:
- `docs/authorino-usage.md`
- `docs/usage-api.md`

**Budget domain (RPC, OAuth2, same surface as the CRUD API)**

A per-account ledger of budget grants, a hot-swappable policy engine, and self-service refill +
an admin review queue — so a user who runs out of budget can ask for more and either get it
immediately or have it queued for a human, instead of a maintainer hand-editing config. Exposed as
`/rpc/*` procedures (cratestack), gated by `budget:*` permissions:

- Policy administration: `activateBudgetPolicy`, `getBudgetPolicyStatus`, `simulateBudgetPolicy`
- Self-service refill: `requestBudgetRefill`
- Admin review queue: `listPendingAugmentationRequests`, `approveAugmentationRequest`, `rejectAugmentationRequest`

This is upstream of, and today has no effect on, the Envoy/Authorino-side rate limiting described
in `docs/governance-model-and-enforcement.md` — see that document's "Where this is not yet true"
section.

See `docs/rbac.md` for the full permission mapping, `docs/budget-decision-contract.md` for the
policy-engine contract, and `docs/budget-refill-ui-contract.md` for the RPC shapes and
UI-relevant behaviors (reset-not-add semantics, token-refresh delay).

**Usage API (ingest is unauthenticated; the query endpoint is not)**

Split across two listeners since #347 — ingest `:3002` (compose) / query `:3006` (compose; mTLS):

- `POST /v1/otel/traces` (OTLP/HTTP traces, protobuf or JSON) — ingest listener, no auth.
- `POST /v1/otel/metrics` (OTLP/HTTP metrics, protobuf or JSON) — ingest listener, no auth.
- `POST /v1/otel/logs` (OTLP/HTTP logs, protobuf or JSON) — ingest listener, no auth.
- `POST /usage/v1/usage/query` (bucketed timeseries for `user`, `project`, `account`, or `all`
  scopes) — query listener: requires mTLS (#347) **plus** `Authorization: Bearer <end-user access
  token>` and an ownership check against `authz-opa`'s `authorize-usage-scope` for `account`/
  `project` scopes; `scope=all` instead requires the `usage:read-all` permission (#570/#603/#605).
  `scope=api_key` has no resolvable ownership authority and is always `403`. A caller holding
  `usage:read-all` may query `user`/`project`/`account` with ANY `scope_id` (#648's admin bypass);
  `api_key` stays refused for them too, and nothing changes for a caller without the permission.
- `POST /usage/v1/spend/query` (summed spend for an account/period) — query listener: mTLS-only,
  `authz-budget`'s service-to-service reader; refuses any request carrying an `Authorization`
  header (#603).

See `docs/usage-api.md` and `docs/lightbridge-query-api.md` for the full contract.

Example query body:

```json
{
  "scope": "project",
  "scope_id": "proj_123",
  "start_time": "2026-02-20T00:00:00Z",
  "end_time": "2026-02-23T00:00:00Z",
  "bucket": "1 hour",
  "group_by": ["model", "azp"],
  "filters": {
    "signal_type": "metric",
    "operation_in": ["chat_completions", "responses", "messages"]
  },
  "limit": 1000
}
```

`usage_events` also carries the three dimensions #648 promoted out of the `attributes` JSONB blob
into real indexed columns — `azp` (the OAuth client / channel), `operation` (which API surface,
from the closed vocabulary `chat_completions` | `responses` | `messages` | `embeddings` | `other`)
and `billing_plan` — each groupable and filterable, plus the `operation_in` set filter. Interim by
design: #581's `usage_request_events` rewrite carries them forward and drops `usage_events`.

Run locally:

```bash
cargo run -p lightbridge-authz-usage -- serve --config-path config/usage.yaml
cargo run -p lightbridge-authz --bin lightbridge-mcp -- serve --config-path config/default.yaml
```

## Testing with Keycloak (OAuth2)

Keycloak is preloaded with:
- Realm: `dev`
- User: `test@admin` / `test` (email-as-username)
- Login client: `test-client` (public)
- Token issuer client: `lightbridge-token-issuer` (confidential, client secret `lightbridge-token-issuer-secret`)

API key creation uses Keycloak token exchange in dev: the API exchanges the
caller's bearer token at the same realm token endpoint through the confidential
`lightbridge-token-issuer` client, then stores the hash of the exchanged access
token. The exchange forwards the key's `project_id` as a form param so the
Keycloak Lightbridge SPI can seal `account_id`/`project_id` into the issued
token (see `lightbridge-keycloak-spi`); when the issuer client has no SPI wired,
Keycloak ignores the extra param, so this stays backward-compatible. The public `test-client` includes `lightbridge-token-issuer` as an access
token audience so Keycloak allows that confidential client to perform the exchange.
See `docs/test-protocol.md` for the same-realm token exchange notes, the
requester/target client/audience distinction, and revocation behavior.

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
  -d '{"billing_identity":"acme"}'
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
just usage-migrate
just stage-authz-ui
just it-authorino
just it-servers
just it-tests
just it-idp
just all-checks
```
