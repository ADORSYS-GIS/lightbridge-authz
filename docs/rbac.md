# RBAC: JWT claim → permission mapping

Authentication is delegated to Keycloak; **authorization** is decided here. Every request to the
CRUD API (`authz-api`) and the MCP server (`lightbridge-mcp`) is gated on a **permission**. This
document describes how the roles Keycloak puts on a JWT become permissions, and which permission
each operation requires.

> Ownership still applies. RBAC is a *coarse capability* check (may this caller create projects at
> all?). The existing per-row `account_memberships` model still decides *which* accounts/projects a
> caller can touch. A request must pass **both**: the RBAC gate (or it is `403 Forbidden`) and the
> membership check (or it is `404 Not Found`).

## How it works

1. Keycloak issues a JWT carrying the caller's roles in a single, flat, top-level claim.
2. `lightbridge-authz-bearer` validates the JWT (JWKS) and reads that claim by name.
3. Each role string is mapped to a set of permissions via configuration.
4. The union of those permissions is attached to the request.
5. A single enforcement point checks the permission the requested operation needs; a caller who
   lacks it is rejected with `403 Forbidden` before the handler runs.

Enforcement is centralized, so the handlers/tools themselves contain no authorization code:

- **CRUD API (RPC)** — an `rpc_authorize` middleware
  (`crates/lightbridge-authz-rest/src/rpc_authorize.rs`) wraps the cratestack RPC router as its
  **outermost** layer. For every `POST /rpc/{op_id}` it extracts the bearer token, validates it via
  the same `BearerTokenServiceTrait` used everywhere (reusing the `TokenInfo.permissions` set it
  already computes), maps the `op_id` to the required permission, and rejects with `403 Forbidden`
  **before the request reaches cratestack's dispatch** if the token lacks it. It **fails closed**: an
  unmapped op-id, the `/rpc/batch` fan-out endpoint, and any missing/invalid token are all denied.
- **MCP** — `call_tool` maps the tool name to the required permission and checks it before
  dispatching. It likewise fails closed (an unmapped tool name is rejected).

### Two gates on the CRUD surface, in order

The CRUD surface (`authz-api`) migrated to cratestack-generated RPC routing (see
`docs/adr/0003-cratestack-crud-migration.md`). Authorization there is now **two independent layers,
both mandatory, evaluated in this order**:

1. **RBAC gate (coarse capability) — first.** The `rpc_authorize` middleware above. Answers "may
   this caller perform this *kind* of operation at all?" A caller lacking the permission gets
   `403 Forbidden` and the request never reaches cratestack. This is the layer this document's
   `op_id` → permission table defines.
2. **Membership policy (per-tenant ownership) — second.** cratestack's generated `@@allow` policies
   on the schema (`crates/lightbridge-authz-api/schema/authz.cstack`), which check
   `…memberships.some.subject == auth().id`. Answers "does this specific account/project/key belong
   to a tenant this caller is a member of?" A non-member gets a policy-driven empty result / `404`.

So a `lightbridge-viewer` who is a legitimate account member is still blocked from
create/update/delete by gate 1 (they hold only `*:read`), and a `lightbridge-editor` acting on an
account they do **not** belong to passes gate 1 but is stopped by gate 2. Both must pass.

RBAC enforcement on non-CRUD paths — OPA/Authorino validation and `/idp/v1/resolve-context` (Basic
auth, outside RBAC) — is unchanged, and the MCP enforcement above is unaffected.

The `op_id` → permission and tool → permission maps are the single sources of truth and must stay in
sync with the tables below. The claim is read at request time; the role→permission map is compiled
once at startup (wildcards expanded), so the request-time check is a plain set lookup.

## Configuration (`oauth2.rbac`)

```yaml
oauth2:
  rbac:
    # Top-level JWT claim carrying the caller's roles. Configurable; defaults to
    # "lightbridge_api_roles" (matches the dev realm's protocol mapper).
    # Value may be a JSON array of strings, or a single space-delimited string.
    roles_claim: "${RBAC_ROLES_CLAIM:-lightbridge_api_roles}"

    # Each role → the permission grants it confers. When this map is omitted/empty, the
    # built-in default mapping below is used instead.
    role_permissions:
      lightbridge-admin:
        - "*"                # every permission
      lightbridge-editor:
        - "account:read"
        - "project:*"        # every project action
        - "apikey:*"         # every api-key action
      lightbridge-viewer:
        - "account:read"
        - "project:read"
        - "apikey:read"
```

A **grant** is one of:

| Grant form            | Meaning                                    | Example          |
| --------------------- | ------------------------------------------ | ---------------- |
| `*`                   | every permission (super-admin)             | `*`              |
| `<resource>:*`        | every action on a resource                 | `project:*`      |
| `<resource>:<action>` | a single permission                        | `account:delete` |

Unknown grant strings are logged and ignored — they never widen access. A role present in the JWT
but absent from the map grants nothing.

> **Wildcards expand dynamically over the whole permission set.** `<resource>:*` and `*` include
> **every** action on that resource — that means `project:*` grants `project:disable` (suspend a
> project → invalidate all its keys) and `*` grants `account:disable`, not just the CRUD verbs. So
> `lightbridge-editor` (`project:*`) can suspend projects, and any operator config using
> `<resource>:*` inherits new actions as they are added. If you want CRUD without the disable
> capability, list the individual grants instead of a wildcard.

### Configurable claim name

`roles_claim` selects which JWT claim is read. The default `lightbridge_api_roles` matches the
protocol mapper the dev realm installs (`oidc-usermodel-realm-role-mapper` → top-level
`lightbridge_api_roles` array — named to match the frontend's `getJwtRoles` expectations). Point it
at any other flat claim (e.g. a custom `permissions` claim emitted by your own mapper) without a
rebuild.

## Default role → permission mapping

Used when `oauth2.rbac.role_permissions` is not configured
(`lightbridge_authz_core::authz::default_role_permissions`):

| Role                 | Grants                                | Effective permissions                              |
| -------------------- | ------------------------------------- | -------------------------------------------------- |
| `lightbridge-admin`  | `*`                                   | all permissions                                    |
| `lightbridge-editor` | `account:read`, `project:*`, `apikey:*` | read accounts; full project + api-key lifecycle   |
| `lightbridge-viewer` | `account:read`, `project:read`, `apikey:read` | read-only                                    |

## Permissions and the operations they gate

Each permission is the canonical `resource:action` string used in config and grants. On the CRUD
API the operation is an RPC `op_id` (`POST /rpc/{op_id}`); the equivalent MCP tool requires the same
permission. cratestack's `op_id` scheme is `model.<Model>.<verb>` (verb ∈ `list|get|create|update|
delete`) for generated model CRUD and `procedure.<name>` for the hand-written procedures.

This table is the source of truth for `rpc_authorize::required_permission`. **Any RPC `op_id` not
listed here is denied unconditionally (fail closed).**

| Permission        | RPC `op_id`                                          | MCP tool                            |
| ----------------- | ---------------------------------------------------- | ----------------------------------- |
| `account:create`  | `model.Account.create`                               | `create-account`                    |
| `account:read`    | `model.Account.list`, `model.Account.get`, `model.AccountSummary.list`, `model.AccountSummary.get` | `list-accounts`, `get-account` |
| `account:update`  | `model.Account.update`                               | `update-account`                    |
| `account:delete`  | `procedure.deleteAccountPermanently`                 | `delete-account`                    |
| `account:disable` | `procedure.disableAccount`, `procedure.enableAccount`| `disable-account`, `enable-account` |
| `account:member`  | `procedure.addAccountMember`, `procedure.removeAccountMember`, `procedure.setAccountMemberRole` | `add-account-member`, `remove-account-member`, `set-account-member-role` |
| `project:create`  | `model.Project.create`                               | `create-project`                    |
| `project:read`    | `model.Project.list`, `model.Project.get`            | `list-projects`, `get-project`      |
| `project:update`  | `model.Project.update`                               | `update-project`                    |
| `project:delete`  | `model.Project.delete`                               | `delete-project`                    |
| `project:disable` | `procedure.disableProject`, `procedure.enableProject`| `disable-project`, `enable-project` |
| `apikey:create`   | `procedure.createApiKey`                             | `create-api-key`                    |
| `apikey:read`     | `model.ApiKey.list`, `model.ApiKey.get`              | `list-api-keys`, `get-api-key`      |
| `apikey:update`   | `model.ApiKey.update`                                | `update-api-key`                    |
| `apikey:delete`   | `model.ApiKey.delete`                                | `delete-api-key`                    |
| `apikey:revoke`   | `procedure.revokeApiKey`                             | `revoke-api-key`                    |
| `apikey:rotate`   | `procedure.rotateApiKey`                             | `rotate-api-key`                    |
| `apikey:validate` | — (OPA server, Basic-auth)                           | `validate-api-key`, `validate-authorino-api-key` |

`read` covers both the list and get operations for a resource.

**Deliberately unmapped → denied (defense in depth):**

- `model.ApiKey.create` — the schema removed its `@@allow("create")`, so the generic create verb is
  already fail-closed at the policy layer; the RBAC gate denies it too. API-key creation is
  server-side only, via `procedure.createApiKey` (the server generates + hashes the secret and
  validates the billing plan; a caller can never supply `keyHash`/`keyPrefix`/`billingPlan`).
- `model.Account.delete` — same reasoning as above: membership-*role* gating (owner-only) can't be
  expressed as a schema `@@allow` policy predicate (see "Account roles" below for why), so the
  generic delete verb has no `@@allow` at all and is denied here too. Account deletion is
  `procedure.deleteAccountPermanently` only.
- `model.AccountMembership.*` — that model is policy-locked to read-self with no generated mutation
  verbs; membership changes go through the `addAccountMember` / `removeAccountMember` /
  `setAccountMemberRole` procedures.
- `/rpc/batch` — a batch bundles multiple ops in its frame body, so a single URL-derived `op_id`
  cannot represent the per-op permissions; the whole endpoint is denied.

> **Field-level immutability on `ApiKey` update.** The coarse `apikey:update` gate allows
> `model.ApiKey.update`, but the schema additionally marks the key's server-managed columns
> (`status`, `keyHash`, `billingPlan`, `keyPrefix`, `projectId`, `revokedAt`, timestamps) as
> `@readonly` / `@server_only`, so they are dropped from the generated `UpdateApiKeyInput`. The
> update surface is therefore `{ name, expiresAt }` only — a caller with `apikey:update` cannot flip
> a key's `status`, overwrite its `keyHash`, or change its `billingPlan`; those transitions are
> reachable exclusively through `apikey:rotate` / `apikey:revoke` / `apikey:create`.

The OPA validation endpoints (introspection / `/idp/v1/resolve-context`) are protected by Basic
auth, not JWT, so they are outside RBAC; the equivalent MCP validation tools (which run behind JWT)
require `apikey:validate`.

## Keycloak setup

The dev realm (`.docker/keycloak_config/realm.json`) shows the required wiring:

- **Realm roles** `lightbridge-admin` / `lightbridge-editor` / `lightbridge-viewer`.
- The seeded user is granted `lightbridge-admin` (`realmRoles`).
- A protocol mapper on `test-client` (`oidc-usermodel-realm-role-mapper`) emits the user's realm
  roles into a top-level, multivalued `lightbridge_api_roles` claim on the **access token**:

  ```json
  {
    "name": "lightbridge-roles",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "config": {
      "claim.name": "lightbridge_api_roles",
      "jsonType.label": "String",
      "multivalued": "true",
      "access.token.claim": "true"
    }
  }
  ```

For your own realm, create the roles, assign them to users/groups, and add an equivalent mapper
whose `claim.name` matches `oauth2.rbac.roles_claim`.

## Account / project suspension (data-plane authorization)

RBAC above gates the **control plane** (who may call the management API). Suspension gates the
**data plane** (whether an issued API key still works at the gateway).

An admin holding `account:disable` / `project:disable` can soft-disable a tenant without deleting
anything, via the RPC procedures (`account:disable` gates both disable and enable, `project:disable`
likewise):

- `procedure.disableAccount` · `procedure.enableAccount`
- `procedure.disableProject` · `procedure.enableProject`

Disabling sets `status = 'suspended'` on the row. The `api_key_validation` SQL view resolves the
full cascade (`account → project → key`) in one indexed read, so **every API key beneath a
suspended account or project immediately fails validation** — no token reissue, no per-key writes.
It takes effect within the gateway's auth-cache TTL. `validate_api_key_context`
(`crates/lightbridge-authz-rest/src/handlers/opa.rs`) reads this view and reports the key as
inactive with a precise reason (`account_suspended`, `project_suspended`, `key_revoked`,
`key_expired`).

### 401 vs 403 at the gateway

API keys are JWTs, so Authorino evaluates them in two phases, and the phase that fails determines
the status code:

| Situation | Failing phase | Status |
|---|---|---|
| Missing / malformed / **expired** JWT (bad signature or `exp`) | Identity (JWKS) | **401 Unauthorized** |
| Valid JWT, but key revoked or **account/project suspended** | Authorization (liveness rule) | **403 Forbidden** |

So "the JWT passes but OPA refuses" is precisely the authorization-phase deny: the introspection
metadata reports `active: false`, the `active == true` authorization rule fails, and Authorino
returns 403. See `docs/authorino-usage.md` for the AuthConfig.

## Account membership (who a tenant's resources belong to)

RBAC decides *what actions* a caller may attempt; **membership** decides *whose* accounts and
projects they act on. A caller can only see or mutate an account (and every project and API key
beneath it) if their JWT `sub` is in that account's `account_memberships`. This is enforced in SQL
on every account/project/key query — RBAC is checked first (else `403`), then membership (else
`404`).

Membership is **account-level**: a member of an account can act on all of its projects. There is no
project-scoped membership.

An admin holding `account:member` manages the roster directly (no invite/accept handshake), via the
RPC procedures:

- `procedure.addAccountMember` with `{ accountId, subject, role? }` — add a member. `role` defaults
  to `"member"` if omitted; granting `"owner"` requires the caller to already be an `"owner"` (see
  "Account roles" below). Idempotent on the membership itself — re-adding an existing member is a
  no-op and does **not** change their role; use `setAccountMemberRole` for that.
- `procedure.removeAccountMember` with `{ accountId, subject }` — remove a member. Refuses to remove
  the **last** remaining member (`409 Conflict`; emptying the roster would trip the account-prune
  trigger and delete the account) *and* refuses to remove the account's **last remaining owner**, even
  if other non-owner members remain (would otherwise orphan the account with nobody able to perform
  owner-only operations). To intentionally delete the account and all its resources, use
  `procedure.deleteAccountPermanently` (`account:delete`) instead.
- `procedure.setAccountMemberRole` with `{ accountId, subject, role }` — change an existing member's
  role. Owner-only. Refuses to demote the account's last remaining owner away from `"owner"`.

The acting caller must themselves be a member of the account (a non-member gets a uniform `404`),
so `account:member` lets an admin manage rosters of accounts they belong to, not arbitrary tenants.
The creating subject is always seeded as the account's first member **with the `"owner"` role**.
Membership is mutated **only** through these three procedures — the cratestack `Account` model
exposes no `owners_admins` column, so `model.Account.update` cannot change the roster.

### Account roles

Every `account_memberships` row carries a `role` — `"owner"`, `"admin"`, or `"member"`
(`migrations/20260722000001_account_membership_roles.sql`; the account-scoped taxonomy ADR-0002
originally called for). This is a **second, finer authorization layer inside a single account**,
distinct from both the coarse RBAC gate above (global, JWT-role-driven, "may this caller attempt
this kind of operation at all") and account membership (binary, "is this caller a member of this
account at all"). Role gates account-scoped membership-management and destructive operations only —
project and api-key create/read/update/delete stay open to *any* member of the account, unchanged:

| Role     | Can do beyond plain membership |
| -------- | ------------------------------- |
| `member` | Nothing extra — read/create/update on the account's projects and api-keys, same as any member. |
| `admin`  | + `addAccountMember` / `removeAccountMember` (cannot grant `"owner"` or remove an `"owner"`), + `disableAccount` / `enableAccount`. |
| `owner`  | Everything `admin` can do, plus: grant/revoke the `"owner"` role itself, remove another owner, `setAccountMemberRole` (owner-only entirely), `deleteAccountPermanently` (owner-only entirely). |

An account can have more than one owner. Two lockout-avoidance invariants are enforced in SQL
regardless of caller intent: **the last remaining owner of an account can never be removed or
demoted** (`removeAccountMember` / `setAccountMemberRole` both check this before acting), so an
account can never end up with members but zero owners.

**Why this isn't expressed as an `@@allow` schema policy, unlike account membership itself:**
cratestack's relation-quantifier policy predicates (`account.memberships.some.subject == auth().id`)
resolve each dotted path to exactly one target scalar field per relation hop — there's no support for
a compound condition jointly checked on the *same* related row. Writing
`memberships.some.subject == auth().id && memberships.some.role == "owner"` would compile to two
independent `EXISTS` checks ("some member matches my subject" AND, separately, "some member — any
member — has role owner"), not "the member row matching my subject also has role owner". So role
gating lives entirely in hand-written SQL inside the five procedures above (confirmed by reading
`cratestack-macros/src/policy/model/relation_path.rs`) rather than in the schema's `@@allow` policies.
