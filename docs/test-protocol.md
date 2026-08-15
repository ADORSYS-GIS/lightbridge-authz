# Test Protocol (OAuth2 + Authorino Validation)

This protocol validates the full flow:
1) OAuth2‑protected CRUD API
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

## 3) Create an account

```bash
ACCOUNT_JSON=$(curl -k -s https://localhost:13000/api/v1/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"billing_identity":"acme"}')

ACCOUNT_ID=$(echo "$ACCOUNT_JSON" | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")
```

## 4) Create a project

```bash
PROJECT_JSON=$(curl -k -s https://localhost:13000/api/v1/accounts/$ACCOUNT_ID/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo","allowed_models":["gpt-4.1-mini"],"default_limits":{"requests_per_second":10,"requests_per_day":1000},"billing_plan":"free"}')

PROJECT_ID=$(echo "$PROJECT_JSON" | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")
```

## 5) Create an API key

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

```bash
KEY_JSON=$(curl -k -s https://localhost:13000/api/v1/projects/$PROJECT_ID/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-key","billing_plan":"free"}')

SECRET=$(echo "$KEY_JSON" | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)['secret'])")
```

## 6) Validate through the internal Authorino backend

`$OPA_USER`/`$OPA_PASSWORD` are the `server.opa.basic_auth` credentials from the config YAML
(locally, `.docker/authz/container.yaml`'s defaults).

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

```bash
curl -k -s https://localhost:13000/api/v1/accounts/$ACCOUNT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE
```
