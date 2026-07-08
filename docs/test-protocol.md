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

API keys are opaque, locally-generated secrets (`lbk_secret_...`). The CRUD API
stores only the SHA-256 hash of the secret and returns the plaintext `secret`
exactly once, on create/rotate. The token has no standalone meaning: it is not a
JWT and no JWKS validator accepts it — it is only interpretable by asking the
Lightbridge validation layer, which makes it inert if leaked or replayed outside
that path.

(The `oauth2.issuance` config can switch key creation to Keycloak token exchange,
which returns a real OAuth2 access token instead. That is disabled by default:
an exchanged JWT is stateless and cannot be revoked before its `exp`, which
defeats immediate revocation. Leave issuance disabled unless you specifically need
provider-issued tokens and accept a revocation window equal to the token lifetime.)

Revoking or deleting the API key takes effect on the **next request**. Authorino
authorizes each request by calling the Lightbridge validation endpoint
(`POST /v1/authorino/validate`), which hashes the presented key, looks up the
`api_keys` row, and rejects anything whose `status` is not `Active` or whose
`expires_at` has passed. Revocation flips `status` to `Revoked`; deletion removes
the row (lookup then misses). Either way the very next authorize call fails — the
DB row is the single source of truth, so there is no denylist, no stored
credential, and no provider round-trip to keep in sync.

```bash
KEY_JSON=$(curl -k -s https://localhost:13000/api/v1/projects/$PROJECT_ID/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-key"}')

SECRET=$(echo "$KEY_JSON" | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)['secret'])")
```

## 6) Validate through the internal Authorino backend

```bash
curl -k -u authorino:change-me https://localhost:13001/v1/opa/validate \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$SECRET\",\"ip\":\"203.0.113.10\"}"
```

Expected: `200` with `api_key`, `project`, and `account` fields, and `last_used_at` populated.

In a deployed path, callers do not invoke this backend directly. Authorino calls
the validation endpoint using basic auth, then uses the returned context to enrich
the authorized request with account, project, API key, and any preserved request
metadata.

## Cleanup (optional)

```bash
curl -k -s https://localhost:13000/api/v1/accounts/$ACCOUNT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE
```
