# Signing-key management (`idp jwk`)

**Symptom:** users are suddenly asked to log in again; a refresh returns `400 invalid_grant`; or
you need to inspect or rotate `authz-idp`'s signing keys.

`authz-idp` holds **two independent signing keys**, distinguished by the `purpose` column on
`signing_keys`. Confusing them is the single most common cause of a mysterious auth failure, so
start here:

| purpose | signs | published in `/.well-known/jwks.json`? | who verifies with it |
|---|---|---|---|
| `access` | access tokens, ID tokens, API-key JWTs | **yes** | every resource server (`authz-api`, `authz-budget`, `lightbridge-mcp`, Authorino) |
| `refresh` | refresh-token JWTs only | **no, deliberately** | only `authz-idp` itself |

The refresh key is withheld from the published JWKS on purpose (#631): a resource server that holds
no key capable of verifying a refresh token cannot be tricked into accepting one as a Bearer token.
**If you ever see a `refresh` kid appear in the public JWKS, that is a security regression, not a
cosmetic one.**

## 0. Look before you touch anything

```bash
POD=$(kubectl --context hetzner-prod -n converse get pods -o name \
      | grep idp-main | head -1 | sed 's#pod/##')
kubectl --context hetzner-prod -n converse exec "$POD" -- \
  lightbridge-authz idp --config-path /etc/lightbridge/config.yaml jwk list
```

```
KID                       PURPOSE  STATUS  CREATED_AT
x7uyjvlaisdirnufz02uh971  access   active  2026-08-14 12:19:16 UTC
fwg9pti0s5dh2pknz4o7fb2q  access   stale   2026-07-09 03:39:01 UTC
vvzrrkb6meunost6zp52kudc  refresh  active  2026-09-02 03:05:57 UTC
```

Read it as: **exactly one `active` key per purpose** (enforced by the unique index
`(status, purpose) WHERE status = 'active'`), plus any number of `stale` ones. Stale keys are not
dead — they stay in the verification set so tokens signed before the last rotation keep validating
until they expire. That is what makes rotation non-disruptive.

`list` never selects `signing_keys.private_key_pem`; the type it returns has no such field. It is
safe to paste its output into an issue.

## 1. "Everyone is being asked to log in again"

Almost always a **key/token mismatch**, not an outage. Decode the failing refresh token's header —
no verification needed, it is just base64:

```bash
python3 -c "
import base64,json,sys
h=sys.argv[1].split('.')[0]; h+='='*(-len(h)%4)
print(json.loads(base64.urlsafe_b64decode(h)))" "$REFRESH_TOKEN"
```

Compare the `kid` against `jwk list`:

| what you see | meaning | fix |
|---|---|---|
| `kid` is the **`refresh` active** key | not a key problem — see §2 | — |
| `kid` is an **`access`** key | token predates the #631 cutover; refresh tokens are now verified only against `refresh` keys | user runs `login` once. Permanent |
| `kid` is a `refresh` **stale** key | normal — stale keys still verify | not the cause; see §2 |
| `kid` is **not listed at all** | the key was deleted, or the token came from another environment | user runs `login` once |

## 2. It is not the key — which of the five deaths was it?

Every refresh failure returns the same `400 invalid_grant`, deliberately (distinguishing them on
the wire would tell an attacker whether a token ever existed). See
[`docs/architecture/auth-flows.md`](../architecture/auth-flows.md) §3a for the state machine.

Since the refusal-reason logging landed, the server says which one it was:

```bash
kubectl --context hetzner-prod -n converse logs "$POD" | grep 'reason='
```

Look up the reason in §3a's table. The two that are **not** the user's fault and need action are
`chain_expires_at` exhaustion (a 90-day-old lineage — expected, they re-login) and a reuse cascade
(`refresh token reuse detected` — investigate before dismissing; RFC 6819 §5.2.2.3 treats a replay
as evidence of theft).

## 3. Create a key that is missing

```bash
kubectl ... exec "$POD" -- lightbridge-authz idp \
  --config-path /etc/lightbridge/config.yaml jwk new --type refresh
```

`new` **refuses if a key of that purpose is already active** and exits non-zero, naming the existing
kid. That is intentional: it will not silently rotate a live key out from under you. If you actually
want to replace it, that is §4.

You should rarely need this — `bootstrap_idp_signing_keys` creates both keys at startup, and the
mint path self-heals a missing refresh key. It exists for the case where neither has run.

## 4. Rotate a key

```bash
kubectl ... exec "$POD" -- lightbridge-authz idp \
  --config-path /etc/lightbridge/config.yaml jwk rotate --type access --yes
```

`--yes` is required. Without it the command refuses and exits non-zero — there is no interactive
prompt available over `kubectl exec`, so the flag is the confirmation.

**What rotation does and does not break:**

- The old key becomes `stale`, **not deleted**. It stays in the verification set, so already-issued
  tokens signed by it keep validating until they expire normally. No forced logout.
- New tokens are signed by the new key immediately.
- Rotating the **`access`** key changes the published JWKS. Resource servers cache it
  (`JWKS_REFRESH_INTERVAL`, 300s), so allow up to five minutes for propagation before concluding
  something is wrong.
- Rotating the **`refresh`** key does **not** touch the published JWKS at all.

Safe to run concurrently across replicas: it goes through `ensure_active_signing_key`, which is
advisory-lock serialized, so parallel invocations cannot produce two active keys of one purpose.

## 5. What this command cannot do, and why

- **It cannot delete a key.** Deleting a `stale` key invalidates every unexpired token signed by it,
  with no way to undo. If you genuinely need that (a key is believed compromised), it is a manual,
  reviewed database operation — and revoking the affected sessions is usually the better tool.
- **It cannot import a key.** Keys are generated in-process; there is no path that accepts private
  key material from outside, deliberately.
- **It cannot show a private key.** There is no flag for it. The type `list` returns does not carry
  the field.

## 6. Verifying the security property after any change

```bash
curl -s https://auth.ai.camer.digital/.well-known/jwks.json \
  | python3 -c "import sys,json;print([k['kid'] for k in json.load(sys.stdin)['keys']])"
```

Cross-check against `jwk list`: **every kid here must have `purpose = access`.** A `refresh` kid in
this output means the JWKS is publishing the key that verifies refresh tokens, which defeats #631.
Treat it as an incident.

## See also

- [`docs/architecture/auth-flows.md`](../architecture/auth-flows.md) §3a — the refresh-token state
  machine, and why every failure looks identical on the wire
- [`docs/auth-reference.md`](../auth-reference.md) — `oauth2.signing.*` config keys and the JWT
  claim shapes
- ADR-0031 — why migrations (including the one that added `purpose`) run where they do
