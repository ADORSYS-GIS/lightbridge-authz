# ADR-0024: we own our users — `accounts` are federated identities, and the Keycloak token set is sealed at rest

- Status: Accepted
- Date: 2026-08-24
- Corrected: 2026-08-25 (see "Correction" below)
- Decision owners: Stephane Segning Lambou
- Amends: ADR-0006 (see that ADR's own "## Related" section for the forward pointer)

## Context

ADR-0006 made `accountId` "a person's defining identity in the system... one account = one
person." That was true as long as this service only ever saw one Keycloak realm/issuer per
person. It stops being true the moment a person can authenticate through more than one issuer
(a second Keycloak realm, a future non-Keycloak IdP) — `accounts.id` is the caller's JWT `sub`
(ADR-0006), and a `sub` is only unique *within* an issuer. Two different issuers can legitimately
mint the same `sub` value for two different people, or the same person can hold a different `sub`
per issuer. Continuing to treat `accounts.id` as the person's identity would mean either:

- silently merging two different people's accounts because their `sub`s happened to collide across
  issuers (a security bug — cross-tenant data exposure), or
- minting a brand-new, disconnected `accounts` row per issuer for the same real person, with no way
  to ever recognize "this is the same human who already has three other projects."

Separately, the browser SSO / device-pairing relying-party leg (`KeycloakRelyingParty::complete`,
ADR-0020/ADR-0021) redeems an authorization code for a full Keycloak token set (ID token, access
token, refresh token, expiries) and — until this ADR — throws all of it away after extracting the
`sub`/`nonce` it needs for the current request. There is no way to act on that person's behalf
later (e.g. a background refresh) without asking them to log in again, and no durable record of
which issuer/subject pairs a given account has ever authenticated through.

This ADR does both at once because they share the same insert point (`complete`'s single funnel)
and the same underlying table (`federated_identities` needs a `token_envelope` column regardless).

**JWT claims are unchanged.** This PR does not add `user_id` (or anything else) to any minted
token. See Follow-ups.

## Decision

### Q1 — Compatibility line: `accounts.id` does not move

Federation key = `(issuer, subject)` on a new, separate `federated_identities` table.
`accounts.id` keeps meaning exactly what it always has (the caller's stored `sub`, ADR-0006);
`createAccount` still inserts `id = subject`, untouched. Three additive objects:

- **`users`**: `id TEXT PRIMARY KEY` (a CUID2 for newly-minted users; the subject verbatim for
  backfilled/trigger-created ones — see Q5), `status`, timestamps. The new defining identity: **one
  account = one federated identity; a person may hold several.**
- **`accounts.user_id TEXT NOT NULL REFERENCES users(id)`**, populated by a `BEFORE INSERT`
  trigger — no existing writer changes (`StoreRepo::create_account`, and every raw-SQL
  `INSERT INTO accounts (id, ...)` test fixture in the workspace, keep working unmodified).
- **`federated_identities`**: the federation key plus the sealed token set (Q2) and an optional
  `account_id` (populated only when this identity adopts a pre-existing `accounts` row — see Q3).
  **Corrected 2026-08-25**: `account_id` is `NOT NULL` and the mint-a-user branch is gone — see
  "Correction" below.

Cross-issuer collision is impossible **structurally**, not by convention:

- `federated_identities_issuer_subject_uidx UNIQUE (issuer, subject)` — the federation key itself.
- `federated_identities_account_uidx UNIQUE (account_id) WHERE account_id IS NOT NULL` — a
  **partial** unique index, so at most one federated identity may ever adopt a given grandfathered
  account. The first issuer to present a subject matching an existing `accounts.id` adopts it;
  every subsequent issuer presenting the *same* subject value hits `23505` on this index and is
  refused (`Error::Conflict`) — the login fails closed, it is never silently merged onto someone
  else's account/projects/budget.

Every existing downstream consumer of `accounts` is unchanged: `resolve_context` never reads
`accounts` at all (it joins `projects`/`project_members` directly); every account read in this
codebase uses an explicit column list (no `SELECT *` exists anywhere in `crates/` or `app/` —
verified); `create_account`'s own `INSERT` statement is untouched (the trigger fills `user_id`
after the fact); and the cratestack `Account` model does **not** gain a `userId` field (see Q4).

### Q2 — Token storage: a sealed envelope, never the access token

**Never stored, at rest or otherwise: the access token.** What *is* sealed (`KeycloakTokenSet`):
`refresh_token: Option<String>`, `id_token_claims: IdTokenClaimsSnapshot` (`sub`, `iss`, `email`,
`email_verified`, `preferred_username`, `name`, `auth_time`, `sid`, `exp`, `iat`), `token_type`,
`session_state`. **Never stored: the raw ID token JWT itself** — unlike an opaque claims snapshot,
a raw ID token is replayable as a `subject_token` into this service's own RFC 8693 token-exchange
endpoint (precedent for "snapshot the claims, not the raw credential": the identity snapshot added
in `20260814000002_exchange_refresh_tokens_add_identity_snapshot.sql`).

Plaintext, queryable metadata sits alongside the sealed blob: `issuer`, `subject`, `scope`,
`access_expires_at`, `refresh_expires_at`, `token_sealed_at`, `last_authenticated_at`.

**Mechanism**: AES-256-GCM (the `aes-gcm` 0.10 crate — already resolved transitively via
`authkestra-engine`, promoted to a direct workspace dependency). New,
`lightbridge-authz-core::crypto`:

```
pub fn seal(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> Result<String>
pub fn open(key: &[u8; 32], aad: &str, sealed: &str) -> Result<Vec<u8>>
```

Envelope shape: `"v1." + base64url_nopad(nonce_12 || ciphertext || tag)`. `aad` (associated data,
authenticated but not encrypted) is `format!("{issuer}\u{1f}{subject}")` — the stable federation
key, **not** the row id, so a regenerated row id never invalidates an existing seal.

A **separate** key protects it: `oauth2.relying_party.token_encryption_key` — non-`Option`
`String`, validated fully offline in `KeycloakRelyingParty::new` (base64url; exactly 32 bytes; and
a third check that it **must differ** from `state_encryption_key` — the state key protects a
10-minute, browser-held cookie, a very different exposure/rotation posture from a token set that
can sit at rest for a session's full lifetime). No `PING`, no discovery fetch at startup — presence
plus offline shape validation only, the same posture ADR-0023 established for `relying_party` as a
whole.

**Redaction**: `TokenResponse` and `KeycloakTokenSet` both get hand-written `Debug` impls printing
`<redacted>` for every credential-bearing field (precedent: `lightbridge_authz_bearer::TokenInfo`'s
own manual `Debug`, plus its redaction test). The new repo methods carry
`#[instrument(skip(...))]` naming every argument that could carry a secret.

**Rotation**: documented, not automated — there is no key history. Rotating
`token_encryption_key` makes every previously-sealed `token_envelope` permanently unopenable.
`open()`'s failure is treated as **"no stored token"**, never as "corrupt row, delete it" — the row
sits inert until that identity's next successful login re-seals it under the new key.

### Q3 — Persistence seam: one funnel, one transaction

`KeycloakRelyingParty::complete` is the single funnel for **both** device pairing and browser SSO
(`callback()` is its only caller). The new call —
`self.persist_federated_identity(&claims, &token).await?;` — sits immediately after ID-token
validation (issuer, audience, signature, nonce all already checked) and **before** either flow
arm's own side effects, so a persistence failure never leaves a device approved or a browser
session minted without a federated identity behind it.

`StoreRepo::upsert_federated_identity` — one transaction (pattern: `rotate_api_key_transaction`):

1. Seal the built `KeycloakTokenSet` with `token_key`, AAD = `issuer \u{1f} subject`.
2. `SELECT id FROM federated_identities WHERE issuer = $1 AND subject = $2 FOR UPDATE`.
3. **Found** → `UPDATE` the envelope + metadata + `last_authenticated_at`. Never rewrite
   `issuer`/`subject`/`user_id` — those are the federation key and its owner, fixed at creation.
4. **Not found** → `SELECT user_id FROM accounts WHERE id = $subject`:
   - `Some(user_id)` → **adopt**: `INSERT ... account_id = $subject`.
   - `None` → **mint**: `INSERT INTO users (id) VALUES (cuid2())`, then
     `INSERT ... account_id = NULL`.
   - A `23505` from either unique index (Q1) maps to `Error::Conflict`, reusing
     `create_account`'s own `code() == "23505"` idiom.
   - **Corrected 2026-08-25**: step 4 is now adopt-or-REFUSE, not adopt-or-mint — see "Correction"
     below for the full replacement.
5. Commit.

**Failure policy: fail closed.** Every step propagates `?`. `callback()` already maps any `Err`
from `complete` to a generic `BAD_GATEWAY` failure — there is no flow-specific fallback that
proceeds without a persisted federated identity. No refresh-against-Keycloak background job exists
yet (Follow-ups); reads are on-demand only. **The first consumer now exists:**
`KeycloakRelyingParty::stored_email` opens the envelope at `/authorize` so the browser
`authorization_code` leg can mint the `email`/`email_verified` claims the device and RFC 8693 legs
get from `decode_email` — that leg never persists the upstream access token, so this snapshot is
the only surviving copy. That read is deliberately **best-effort, not fail-closed** (unlike the
write above): a missing row, a `NULL` envelope, or an envelope left unopenable by a
`token_encryption_key` rotation all collapse to "no email". `email` gates nothing — RBAC reads
`lightbridge_api_roles` alone — so withholding it degrades a UserInfo response, whereas refusing
would turn a key rotation into a login outage.

### Q4 — ADR-0038: `federated_identities` stays hand-written SQL

Documented exception in `migrations/`, same header-comment convention as
`20260823000002_sessions.sql`. `federated_identities` is deliberately **absent** from
`authz.cstack` entirely — not merely `@@allow`-less — the same class of exception as
`signing_keys`/`exchange_refresh_tokens`/`device_authorizations`/`authorization_codes`: a
credential-bearing table must be structurally unreachable from any generated read path.

`users` **is** modelled (a plain single-column `id` PK, no CAS-rotation race — nothing stops it),
with **no `@@allow`** — the `Session` model's own precedent: the absence of any `@@allow` clause
already fail-closes every generic `model.User.*` verb by construction, and
`rpc_authorize.rs`'s `required_permission` map needs no new entry, since an op-id it does not list
is denied unconditionally.

`accounts.user_id` is **not** added to the cstack `Account` model, and neither model gains a
relation to the other. Alternative considered and rejected: modelling the relation (`Account.user
User @relation(...)` / `User.accounts Account[]`). Rejected because this repo has already measured
a real cratestack codegen blowup (~51GB RAM, 36 minutes, CI-killed) from a second relation path
between two already-connected models (`ProjectMember.account`'s own removal, and `Session`'s
deliberate omission, are the prior instances of this exact lesson). Nothing needs the relation
today: neither model has an `@@allow` that would want to traverse it, and `accounts.user_id` is
read/written exclusively through hand-written SQL (the migration's trigger,
`StoreRepo::upsert_federated_identity`), never through the generated client.

### Q5 — Backfill: one-shot, pure SQL, no app cooperation

`users.id := accounts.id` for every pre-existing account — reusing the STORED Keycloak `sub`
(ADR-0039 "bans minting, not storing" an id already sourced from an external IdP), not generating
anything new. A `BEFORE INSERT` trigger (`set_account_user`) provisions `user_id` for any future
account insert that doesn't supply one, so `StoreRepo::create_account` and the dozen-plus raw
`INSERT INTO accounts (id) VALUES ($1)` test fixtures across the workspace need zero changes —
same precedent as `set_project_is_default` (`20260725000001_default_account_project.sql`).

**Alternatives considered and rejected:**

- **Two-phase migration / nullable `user_id`, backfilled later.** Rejected: unbounded failure
  mode — a deployment that never runs the follow-up phase is left with an inconsistent schema
  indefinitely, and every read site would need to handle a `NULL` that "shouldn't" exist.
- **Application-side backfill (a one-shot script in `migrate.rs`).** Rejected: splits the schema's
  truth between the migration files and app code, and `sqlx::test` (which every integration test
  in this workspace relies on) never exercises `migrate.rs` at all — the backfill would go
  completely untested by the suite that actually runs in CI.

### Q6 — Relationship to ADR-0006 and ADR-0039

The **one** ADR-0006 sentence this ADR supersedes: *"A person's defining identity in the system is
their `accountId`. One account = one person."* Replaced with: a person's identity is `users.id`; an
account is a federated identity ("one account = one federated identity"); a person may hold
several.

**Survives unamended**: `accounts.id` is still the caller's stored `sub` (a historical property,
not touched here — making it opaque is Follow-up 2); there is still no account-*level* membership
of any kind; the entire project-membership/billing/quota apparatus ADR-0006 established is
untouched.

**ADR-0039 (CUID2) reconciliation, field by field**: `issuer`/`subject` are read off the validated
ID token and never rewritten (never minted, per that ADR's own "bans minting, not storing"
carve-out for externally-sourced ids). A backfilled `users.id` is the stored subject verbatim
(same carve-out). A newly-minted `users.id` or `federated_identities.id` goes through the one
chokepoint, `cuid2()`. Nothing here validates an id's shape, sorts/paginates by id, or introduces a
native `uuid` column — every id stays opaque `TEXT`.

### Q7 — Config and deployment: a mandatory new startup requirement

This PR makes `authz-idp` refuse to start without
`oauth2.relying_party.token_encryption_key` — the same shape of hard requirement ADR-0023
established for `relying_party`/`token_exchange` as a whole.

> **SEQUENCING GATE**: the `ai-helm-values` change (sourcing this key from a Secret via
> `secretKeyRef`) must be merged, synced, and verified live **before** this image rolls to
> production. Merging the image first crash-loops the live issuer.

`config/default.yaml` and `.docker/authz/container.yaml` carry a development-only fixed
placeholder (`${KEYCLOAK_RP_TOKEN_ENCRYPTION_KEY:-...}`), deliberately different from
`state_encryption_key`'s own `AAAA...` placeholder. `charts/lightbridge-authz/values.yaml` carries
the matching dev-shaped default with an explicit comment that production must override it via a
`secretKeyRef` env, never inline in the rendered ConfigMap.

## Correction (2026-08-25): a federated identity links to an ACCOUNT, never directly to a user

**What was wrong.** The original schema gave `federated_identities` two ways to reach a person: the
derived path (`account_id -> accounts.user_id -> users.id`, when this identity adopted a
grandfathered account) and a second, direct `user_id` column, populated by minting a brand-new
`users` row whenever no account matched (Q3 step 4's "mint" branch). That second edge was both
redundant with the derived path and, worse, semantically wrong: a Keycloak login is not itself a
person this service has a relationship with — `users` is supposed to mean "someone who is reachable
through this service's own account/project/budget apparatus," and the mint branch created a `users`
row for anyone who could merely authenticate against the configured Keycloak realm, with no
`accounts` row, no project, nothing else reachable behind RBAC.

This was not a hypothetical gap: the original "## Consequences" section's "ACCEPTED RISK" bullet
already named it explicitly, and the acceptance was CONDITIONAL: "This is **attacker-controlled** only to the extent the realm itself
permits self-registration or unthrottled account creation... If the realm's registration policy ever
opens up... the owner must re-check this acceptance." The owner has since confirmed the configured
realm DOES permit self-registration. The condition failed, so the acceptance is withdrawn here — not
by re-accepting a wider risk, but by removing it structurally: an accountless login is now refused,
not persisted.

**The corrected rule.** `federated_identities.account_id` is `NOT NULL`; `federated_identities`
loses its `user_id` column entirely. The owning `users` row is always DERIVED —
`federated_identities.account_id -> accounts.user_id -> users.id` — never stored a second time.
`accounts.user_id` keeps exactly the two writers it already had (the `accounts_set_user` `BEFORE
INSERT` trigger for every new account, and the one-shot backfill for pre-existing ones);
`StoreRepo::upsert_federated_identity` never wrote it and still doesn't. One practical consequence:
`users.id` is now ALWAYS the backfilled/trigger-provisioned account id verbatim — the "fresh
`cuid2()` for a newly-minted user" case in Q1/Q6 no longer arises, because there is no longer a code
path that mints a `users` row without an `accounts` row alongside it.

**Q3 step 4, replaced.** Where the original said:

> 4. **Not found** → `SELECT user_id FROM accounts WHERE id = $subject`:
>    - `Some(user_id)` → **adopt**: `INSERT ... account_id = $subject`.
>    - `None` → **mint**: `INSERT INTO users (id) VALUES (cuid2())`, then `INSERT ... account_id =
>      NULL`.

the corrected step is adopt-or-REFUSE, decided in the same transaction, before any write:

> 4. **Not found** → `SELECT id FROM accounts WHERE id = $subject`:
>    - `Some(account_id)` → **adopt**: `INSERT ... account_id = $subject`.
>    - `None` → **REFUSE**: return `Error::Forbidden` — no row is written, nothing is left behind.
>    - A `23505` from either unique index (Q1, unchanged) still maps to `Error::Conflict`. A new
>      `23503` (the adopted account was deleted between this step's own `SELECT` and the `INSERT` —
>      a narrow race, not the common case) maps to the same `Error::Forbidden` as the `None` case:
>      both mean "this subject has no lightbridge account right now."

`KeycloakRelyingParty::complete`'s single funnel (Q3's own framing) is now also the GATE: the
refusal happens inside `persist_federated_identity`, before either flow arm's side effects, so a
refused login approves no device code and mints no browser session. `callback()`'s existing
`Err -> BAD_GATEWAY` mapping is untouched and already uniform — a refusal and a collision
(`Error::Conflict`) both reach the caller as the same generic 502, never revealing which case
occurred or whether the presented subject has an account at all.

**Why refusing here is bounded, not a new failure mode.** An accountless subject already dead-ended
downstream in both flows before this correction: browser SSO's `find_default_project_id` returns
`None` for a subject with no projects, which `complete`'s browser arm turns into `Error::NotFound`
(a different failure, same shape of "this doesn't work"); device pairing's token-issuance leg
independently rejects an approved-but-accountless subject with `access_denied: "subject has no
default project"`. This correction moves the refusal earlier — to the callback, before any row is
written — rather than introducing a new way for a login to fail. It also means the refusal is
row-free: nothing to clean up, nothing left inconsistent.

**`ON DELETE SET NULL` becomes `ON DELETE CASCADE`.** This is the one change in this correction that
is not optional cleanup — it is required for the `NOT NULL` constraint above to be satisfiable at
all. `SET NULL` on a column being made `NOT NULL` is a contradiction the database cannot honor; left
alone, the live `deleteAccountPermanently` procedure (the only way an `accounts` row is ever
deleted) would start failing every call that touched an adopted federated identity with `23502 null
value in column "account_id" violates not-null constraint`. Under the corrected model this is also
the semantically right behavior: a federated identity with no account is no longer a representable
state, so deleting the account it is keyed to must delete the identity row too, not orphan it into
an invalid `NULL`. The person (`users` row) itself is unaffected either way — deleting an account
never deletes the `users` row it derives to.

**Migration**: `migrations/20260825000002_federated_identities_link_accounts_not_users.sql` (see
its own header comment for the full row-disposition algorithm, lock posture, and reasoning). In
order: delete the `users` rows the old mint branch created (scoped narrowly — a `users` row
legitimately orphaned by `deleteAccountPermanently` is left alone), delete any remaining accountless
`federated_identities` row, drop the `user_id` column, swap the FK action to `ON DELETE CASCADE`,
then set `account_id NOT NULL`.

**Unchanged by this correction**: both unique indexes
(`federated_identities_issuer_subject_uidx`, `federated_identities_account_uidx`) survive verbatim
— the account-adoption uniqueness they enforce (Q1) is exactly as before, and the partial index's
predicate (`WHERE account_id IS NOT NULL`) simply becomes vacuously true once `account_id` is `NOT
NULL`. The token-sealing mechanism (Q2), the `authz.cstack` exception (Q4, still absent from the
schema entirely, and `accounts.user_id` still never written through the generated client), the
backfill (Q5, unaffected — it only ever touched `accounts`/`users`, never `federated_identities`),
and the config/deployment requirement (Q7) are all untouched.

## Consequences

- **ACCEPTED RISK — unauthenticated row growth is bounded by the realm's own authentication
  policy, not by this service.** Every successful Keycloak login mints a `users` +
  `federated_identities` row pair (Q3), including for a subject with no pre-existing `lightbridge`
  account at all — device pairing deliberately requires none (ADR-0012). That means anyone who can
  successfully authenticate against the configured Keycloak realm can cause this service to persist
  a row, whether or not they ever go on to use a `lightbridge` account/project. This is
  **attacker-controlled** only to the extent the realm itself permits self-registration or
  unthrottled account creation — this service has no independent gate on it. If the realm's
  registration policy ever opens up (self-service sign-up, a federated identity provider with lax
  vetting, etc.), the owner must re-check this acceptance; the fix, if needed, lives at the realm
  policy layer, not here.
  - **This acceptance is WITHDRAWN as of the 2026-08-25 Correction below.** It was explicitly
    conditional on the configured realm not permitting self-registration; the owner has confirmed
    the realm DOES permit it, so the condition failed and the risk is now removed structurally
    (the accountless login is refused, not persisted) rather than left as a standing exception. See
    "Correction" below.
- **Deployment note — the backfill migration takes an `AccessExclusiveLock` on `accounts` for
  ~500ms at 100k rows, and fails fast instead of queueing.** See
  `migrations/20260825000001_users_and_federated_identities.sql`'s own header comment for the full
  measurement and mechanism (`SET LOCAL lock_timeout = '5s'`, scoped correctly because sqlx applies
  the whole file as one transaction). Operationally: if the `authz-migrate` hook's run of this
  migration fails with a `lock_timeout` error, that means a long-running transaction was holding
  even a shared lock on `accounts` when the migration started — re-running the migrate hook once
  that transaction clears is the correct, safe response, not a rollback or a schema investigation.

## Alternatives considered

### Do nothing; keep treating `accounts.id` as the person's identity

Rejected — this is the security bug the ADR exists to close: two different issuers minting the
same `sub` for two different real people would otherwise be indistinguishable from "the same
person logging in twice," a cross-tenant merge with no consent step.

### Store the access token too (for on-demand downstream API calls on the user's behalf)

Rejected (Q1/Q2). Access tokens are short-lived, bearer-equivalent credentials this service has no
current need to replay, and Q2's "never store the access token" line is a deliberate, narrower
attack surface — see that section.

### Build link/merge procedures now, alongside the schema

Rejected for this pass. The schema makes account-merging *structurally possible* (a `users` row
can, in principle, back several `federated_identities` rows), but no RPC procedure exists to
perform a merge or link. Building that surface now would be speculative — there is no product
requirement driving it yet, and getting the schema right first is the higher-leverage move. See
Follow-ups.

## Related

- ADR-0006 (amended, see above)
- ADR-0038 (cratestack is the only sanctioned database API — the exception this ADR documents)
- ADR-0039 (CUID2 is the house id format — the reconciliation in Q6)
- ADR-0023 (the `authz-idp` surface is mandatory — the same startup-requirement shape Q7 reuses)
- ADR-0020/ADR-0021 (sessions, browser SSO — `KeycloakRelyingParty::complete`'s existing shape this
  ADR inserts into)

## Follow-ups (not built in this PR)

- A `user_id` JWT claim (would cascade through RBAC, introspection, the budget domain, and every
  `x-*` header Authorino stamps — a separate, larger change).
- Making `accounts.id` itself opaque (forward-compatible with a non-Keycloak IdP whose `sub` isn't
  shaped like this one).
- Account link/merge RPC procedures (the schema supports this structurally; nothing calls for it
  yet).
- Refreshing stored tokens on a schedule/on-demand (today: on-demand at read time, once a consumer
  exists — no background job).
- A keyring (multiple `token_encryption_key` generations, so a rotation doesn't strand every
  existing envelope).
- A user-facing "linked identities" surface (list/revoke the federated identities behind one's own
  account).
