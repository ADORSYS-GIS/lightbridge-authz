# Test Protocol (OAuth2 + OPA)

This protocol validates the full flow:
1) OAuth2‑protected CRUD API
2) API key creation
3) OPA validation with usage telemetry

## Prerequisites
- Docker Compose services are running
- Keycloak is reachable at `http://localhost:9100`

Start or rebuild:

```bash
docker compose -f compose.yaml up -d --build
```

## 1) Enable direct access grants for test-client

Keycloak is preloaded with realm `dev`, user `test@admin` / `test` (email‑as‑username), and client `test-client` (public).
Direct access grants are required to get tokens via password grant for local testing.

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
  -d '{"billing_identity":"acme","owners_admins":["test@admin"]}')

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

```bash
KEY_JSON=$(curl -k -s https://localhost:13000/api/v1/projects/$PROJECT_ID/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-key"}')

SECRET=$(echo "$KEY_JSON" | /usr/bin/python3 -c "import sys, json; print(json.load(sys.stdin)['secret'])")
```

## 6) Validate via OPA (basic auth)

```bash
curl -k -u authorino:change-me https://localhost:13001/v1/opa/validate \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$SECRET\",\"ip\":\"203.0.113.10\"}"
```

Expected: `200` with `api_key`, `project`, and `account` fields, and `last_used_at` populated.

## Cleanup (optional)

```bash
curl -k -s https://localhost:13000/api/v1/accounts/$ACCOUNT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE
```
