# RBAC: JWT claim → permission mapping

Authentication is delegated to Keycloak; **authorization** is decided here. Every request to the
CRUD API (`authz-api`) and the MCP server (`lightbridge-mcp`) is gated on a **permission**. This
document describes how the roles Keycloak puts on a JWT become permissions, and which permission
each operation requires.

> Ownership still applies. RBAC is a *coarse capability* check (may this caller create projects at
> all?). Account ownership (`accounts.id = sub`) and the per-row `project_members` roster still
> decide *which* accounts/projects a caller can touch. A request must pass **both**: the RBAC gate
> (or it is `403 Forbidden`) and the membership check (or it is `404 Not Found`).

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
  unmapped op-id and any missing/invalid token are denied. `POST /rpc/batch` is a special case — see
  "Batch RPC: per-frame RBAC" below.
- **CratestackAuthProvider** (`crates/lightbridge-authz-rest/src/auth_provider.rs`) enforces the
  *same* `op_id` → permission map a second time, from inside cratestack's own dispatch. Redundant for
  a unary call (already checked by `rpc_authorize` above), but this is what actually authorizes a
  `POST /rpc/batch` request: cratestack calls this provider once per frame, each time with that
  frame's own canonical `/rpc/<op_id>` path, so every frame in a batch is authorized independently.
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
   `account.id == auth().id || members.some.accountId == auth().id`. Answers "does this specific
   account/project/key belong to this caller, or to a project they sit on?" A non-member gets a
   policy-driven empty result / `404`.

So a `lightbridge-viewer` who is a legitimate account member is still blocked from
create/update/delete by gate 1 (they hold only `*:read`), and a `lightbridge-editor` acting on an
account they do **not** belong to passes gate 1 but is stopped by gate 2. Both must pass.

RBAC enforcement on non-CRUD paths — OPA/Authorino validation and `/idp/v1/resolve-context` (Basic
auth, outside RBAC) — is unchanged, and the MCP enforcement above is unaffected.

### Batch RPC: per-frame RBAC

`POST /rpc/batch` bundles multiple ops in one JSON array of frames (`{id, op, input}`), each
carrying its own `op` (op-id). `rpc_authorize` is a URL-derived, whole-HTTP-request gate — it has no
visibility into the frames inside the body, so it cannot check a single permission for the batch call
the way it does for `POST /rpc/{op_id}`. Instead:

1. **`rpc_authorize`** requires only that the caller present *some* valid, active bearer token, then
   forwards the request — a wholly unauthenticated batch call still gets a clean top-level `401`
   rather than a `200` envelope full of per-frame `unauthenticated` errors.
2. **`CratestackAuthProvider::authenticate`** does the actual permission check, once per frame:
   cratestack's batch dispatch calls it once for every frame, each time with that frame's own
   canonical `/rpc/<op_id>` path, and it looks that op-id up in the *same* map `rpc_authorize` uses
   for unary calls. A frame whose op the caller lacks permission for fails independently with
   `{"error": {"code": "permission_denied", ...}}` in its own slot — the rest of the batch, and the
   overall `200`, are unaffected.

One token authorizes every frame in a batch (there's one `Authorization` header per HTTP request, not
per frame) — so a batch mixing a permitted read and a forbidden write for the *same* caller returns
`200` with the read's `output` in one frame and a `permission_denied` `error` in the other. Membership
(`@@allow`) is still the second gate per frame, exactly as for unary calls.

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
        - "account:create"   # self-provision own account (#321)
        - "account:read"
        - "project:*"        # every project action
        - "apikey:*"         # every api-key action
        - "budget:self-refill" # self-refill own budget, capped by policy (#294)
        - "budget:read-own"  # see own budget balance/history
      lightbridge-viewer:
        - "account:create"   # self-provision own account (#321)
        - "account:read"
        - "project:read"
        - "apikey:read"
        - "budget:read-own"  # see own budget balance/history

    # Applied on behalf of any role string present in the caller's claim that matches none of
    # the entries above. Empty by default -- an unrecognized role then contributes nothing,
    # exactly as before this field existed. Populate it to give every authenticated caller a
    # safe minimum even when their specific role isn't configured.
    default_grants:
      - "budget:read"
```

A **grant** is one of:

| Grant form            | Meaning                                    | Example          |
| --------------------- | ------------------------------------------ | ---------------- |
| `*`                   | every permission (super-admin)             | `*`              |
| `<resource>:*`        | every action on a resource                 | `project:*`      |
| `<resource>:<action>` | a single permission                        | `account:delete` |

Unknown grant strings are logged and ignored — they never widen access. A role present in the JWT
but absent from the map grants nothing, **unless** `oauth2.rbac.default_grants` is configured (see
below), in which case that role contributes the default grants instead.

### `default_grants`: a floor for unrecognized roles

`role_permissions` alone means a caller whose role string doesn't match any configured entry gets
*no* permissions at all — not even to see their own budget status. `default_grants` (`Vec<String>`,
empty by default) fixes that: it is compiled the same way as any role's grants (wildcards expanded,
unknown grants logged and skipped), and applied **per unmatched role string**, not as an
unconditional floor added to every caller. Concretely, for each role string in the caller's claim:

- if it matches an entry in `role_permissions`, that role's compiled permissions are unioned in;
- if it matches **no** entry, `default_grants`'s compiled permissions are unioned in instead.

A caller holding a mix of recognized and unrecognized roles gets the union of both — the fallback
composes per unmatched role rather than being all-or-nothing. A caller holding only recognized
roles never receives `default_grants` on top, even if those roles don't happen to include
whatever `default_grants` lists.

Leaving `default_grants` empty/unset reproduces today's exact behavior (an unrecognized role
contributes nothing). Configuring it wrong is a startup-time error, not a silent gap: `Rbac::validate()`
rejects any `default_grants` entry that doesn't expand to a real permission, and is wired into the
same startup path as `Billing::validate()` (`start_api_server` / `start_mcp_server`), so a bad
`default_grants` value fails server startup rather than surfacing later as "some users can't see
their own budget."

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
| `lightbridge-editor` | `account:create`, `account:read`, `project:*`, `apikey:*`, `session:revoke-own`, `budget:read-own` | self-provision own account; read accounts; full project + api-key lifecycle; log out own sessions; see own budget |
| `lightbridge-viewer` | `account:create`, `account:read`, `project:read`, `apikey:read`, `session:revoke-own`, `budget:read-own` | self-provision own account; otherwise read-only, plus log out own sessions and see own budget |

## Permissions and the operations they gate

Each permission is the canonical `resource:action` string used in config and grants. On the CRUD
API the operation is an RPC `op_id` (`POST /rpc/{op_id}`); the equivalent MCP tool requires the same
permission. cratestack's `op_id` scheme is `model.<Model>.<verb>` (verb ∈ `list|get|create|update|
delete`) for generated model CRUD and `procedure.<name>` for the hand-written procedures.

This table is the source of truth for `rpc_authorize::required_permission`. **Any RPC `op_id` not
listed here is denied unconditionally (fail closed).**

**Every `budget:*` row below is served at `POST /budget/rpc/{op_id}` on the separate
`authz-budget` service, not `POST /rpc/{op_id}` on `authz-api`** (hard cutover — see
[`docs/architecture/budget.md`](./architecture/budget.md#service-boundary-authz-budget-hard-cutover)).
The permission each op-id requires is unchanged by that move; only the host and path prefix
differ. A third gate, `RpcScope` (`rpc_authorize.rs`), sits ahead of the RBAC/membership pair
described above and enforces this split: `authz-api` 404s every `budget:*` op-id before the RBAC
gate even runs, and `authz-budget` 404s everything else the same way — including per-frame inside
a `/rpc/batch` call, via the same `CratestackAuthProvider::authenticate` mechanism "Batch RPC:
per-frame RBAC" above describes for the permission check.

| Permission        | RPC `op_id`                                          | MCP tool                            |
| ----------------- | ---------------------------------------------------- | ----------------------------------- |
| `account:create`  | `procedure.createAccount`                            | `create-account`                    |
| `account:read`    | `model.Account.list`, `model.Account.get`, `model.AccountSummary.list`, `model.AccountSummary.get` | `list-accounts`, `get-account` |
| `account:update`  | `model.Account.update`                               | `update-account`                    |
| `account:delete`  | `procedure.deleteAccountPermanently`                 | `delete-account`                    |
| `account:disable` | `procedure.disableAccount`, `procedure.enableAccount`| `disable-account`, `enable-account` |
| `project:create`  | `model.Project.create`                               | `create-project`                    |
| `project:read`    | `model.Project.list`, `model.Project.get`            | `list-projects`, `get-project`      |
| `project:update`  | `model.Project.update`, `procedure.setDefaultProject`, `procedure.listModelCatalog` | `update-project`, `set-default-project` |
| `project:delete`  | `model.Project.delete`                               | `delete-project`                    |
| `project:disable` | `procedure.disableProject`, `procedure.enableProject`| `disable-project`, `enable-project` |
| `project:member`  | `procedure.listProjectRoster`, `procedure.addProjectMember`, `procedure.removeProjectMember`, `procedure.setProjectMemberRole`, `procedure.setProjectMemberQuotaTier` | `list-project-roster`, `add-project-member`, `remove-project-member`, `set-project-member-role`, `set-project-member-quota-tier` |
| `apikey:create`   | `procedure.createApiKey`, `procedure.listBillingPlans` | `create-api-key`                  |
| `apikey:read`     | `model.ApiKey.list`, `model.ApiKey.get`              | `list-api-keys`, `get-api-key`      |
| `apikey:update`   | `model.ApiKey.update`                                | `update-api-key`                    |
| `apikey:delete`   | `model.ApiKey.delete`                                | `delete-api-key`                    |
| `apikey:revoke`   | `procedure.revokeApiKey`                             | `revoke-api-key`                    |
| `apikey:rotate`   | `procedure.rotateApiKey`                             | `rotate-api-key`                    |
| `apikey:validate` | — (OPA server, Basic-auth)                           | `validate-api-key`, `validate-authorino-api-key` |
| `budget:policy-activate` | `procedure.activateBudgetPolicy`                | — (no MCP tool yet)                 |
| `budget:policy-read`     | `procedure.getBudgetPolicyStatus`               | — (no MCP tool yet)                 |
| `budget:policy-simulate` | `procedure.simulateBudgetPolicy`                | — (no MCP tool yet)                 |
| `budget:self-refill`     | `procedure.requestBudgetRefill`, `procedure.getMyBudgetRefillLadder` | — (no MCP tool yet)   |
| `budget:review`          | `procedure.listPendingAugmentationRequests`, `procedure.approveAugmentationRequest`, `procedure.rejectAugmentationRequest` | — (no MCP tool yet) |
| `budget:read-own`        | `procedure.getMyBudgetBalance`, `procedure.listMyBudgetGrants`, `procedure.listMyAugmentationRequests` | — (no MCP tool yet) |
| `budget:read`            | `procedure.getBudgetBalance`                    | — (no MCP tool yet)                 |
| `budget:audit-read`      | `procedure.listBudgetGrants`                    | — (no MCP tool yet)                 |
| `budget:grant`           | `procedure.grantBudget`                         | — (no MCP tool yet)                 |
| `budget:revoke`          | `procedure.revokeBudgetGrant`                   | — (no MCP tool yet)                 |
| `budget:policy-write`    | `procedure.createBudgetPolicyRevision`          | — (no MCP tool yet)                 |
| `session:revoke-own`     | `procedure.revokeOwnSessions`                        | — (no MCP tool yet)                 |
| `session:revoke`         | `procedure.revokeSubjectSessions`                    | — (no MCP tool yet)                 |

`read` covers both the list and get operations for a resource.

### Refresh-token session revocation

There was previously no way to kill a live session short of a manual SQL `UPDATE` against
`exchange_refresh_tokens` in prod. Two surfaces now exist, both flipping the same rows'
`status` from `active` to `revoked` (`StoreRepo::revoke_active_exchange_refresh_tokens_for_subject`),
which `find_active_exchange_refresh_token`/`consume_exchange_refresh_token` already filter on, so
revocation takes effect on the very next refresh attempt:

- **`POST /oauth2/revoke`** (RFC 7009) — a client-facing, single-token revoke. Not gated by RBAC at
  all (it authenticates the way `/oauth2/token` does — `client_id`/`client_assertion`, no bearer
  token); see `crates/lightbridge-authz-rest/src/token_exchange.rs`.
- **The RPC procedures above** — operator/self-service, gated the same self/admin way the budget
  refill pair is (`budget:self-refill` vs `budget:review`): `procedure.revokeOwnSessions` (gated
  `session:revoke-own`) revokes every active session for `auth().id` only — there is no subject
  field on its input at all, so it is structurally incapable of targeting anyone but the caller.
  `procedure.revokeSubjectSessions` (gated `session:revoke`, admin-only via `lightbridge-admin`'s
  `*`) revokes every active session for an operator-supplied `accountId` — the offboarding kill
  switch. Both return `{ revokedCount }` so the caller gets confirmation the kill switch actually
  did something. Both are `@allow(auth() != null)` only in the schema, same pattern as the budget
  procedures above — there is no per-tenant ownership relation between a caller and an arbitrary
  target subject for a schema `@@allow` to check, so the entire authorization story is the RBAC
  gate.

`session:revoke-own` is granted to every default role (including `lightbridge-viewer`) in
`default_role_permissions` — logging yourself out everywhere is self-protective, not a write
capability inconsistent with a read-only role, unlike `budget:self-refill` (which spends budget and
so is withheld from `lightbridge-viewer`).

### Budget policy lifecycle (ADR-0007)

`procedure.activateBudgetPolicy` activates a budget policy: either brand-new rule data
(`ruleDataJson`) or a rollback to an already-existing revision (`revisionId`, the
`docs/runbooks/roll-back-a-budget-policy.md` flow) — exactly one of the two must be supplied.
`procedure.getBudgetPolicyStatus` reports the revision genuinely serving `evaluate()` calls right
now, which can differ from the one most recently *attempted* if that attempt was rejected (a
failed load leaves the previous revision in force). `procedure.simulateBudgetPolicy` evaluates a
proposed rule-data policy against a caller-supplied scenario entirely in memory, with no
side effects of any kind (#190). All three procedures are gated only by `@allow(auth() != null)`
in the schema — there is no per-tenant ownership check, because the budget policy is a single,
platform-wide singleton, not owned by any particular account. The entire authorization story for
these op-ids is therefore the RBAC gate above: `budget:policy-activate` (coarser action, changes
what's serving), `budget:policy-read` (coarser gate, only reads it), and `budget:policy-simulate`
(neither — a proposed policy that is never applied).

### Self-service refill and the admin review queue (#191)

`procedure.requestBudgetRefill` is the RPC surface over
`lightbridge_authz_budget::refill::RefillService::request_refill`: a caller asks for more budget
for `budgetAccountId`/`period`, and the service decides — immediately (auto-grant, possibly
capped), or by queuing the request for a human (`pending_review`) — without anyone hand-editing
policy config. Gated at `budget:self-refill`.

`procedure.getMyBudgetRefillLadder` is the read-only companion over
`RefillService::refill_status`, gated at the same `budget:self-refill` permission: it returns where
the caller currently sits on the ADR-0008 ladder for `period`, the next rung (`null` at the top
rung), and the full static ladder — visibility only, no policy evaluation, no reason codes. It
exists so a UI can show the ladder instead of offering a tier picker; ADR-0008's ladder stays the
server's decision space (`current_tier.next()` inside `request_refill`), never a caller-supplied
choice — see converse-frontends#148 for the prior attempt at a picker and why it was rejected.

`procedure.listPendingAugmentationRequests` / `procedure.approveAugmentationRequest` /
`procedure.rejectAugmentationRequest` are the admin review queue over
`lightbridge_authz_budget::review::ReviewService`, all three gated at `budget:review` — listing the
queue and acting on it are both "the reviewer capability" here, unlike the budget-policy trio above
where read/write/simulate are three separate permissions. A rejection requires a non-empty `reason`
at both the schema layer (the field is non-optional) and the service layer (`ReviewService::reject`)
— see #191's own implementation note: a rejection without a visible reason turns into a support
conversation.

All four procedures are gated only by `@allow(auth() != null)` in the schema, same pattern as the
rest of the budget domain — the real authorization is entirely the RBAC permission gate.

> **Internal/API-key-client refusal (#191/#216):** `requestBudgetRefill` refuses any caller whose
> validated token carries the `lightbridge_caller_kind` claim set to `api_key`
> (`lightbridge_authz_bearer::CALLER_KIND_CLAIM` / `API_KEY_CALLER_KIND`), projected into the
> `Procedures` layer by `CratestackAuthProvider` as `auth_provider::CALLER_KIND_CONTEXT_KEY`.
> Absence of the claim is treated as "unknown, not API-key", so ordinary human callers (who never
> carry it) are unaffected.
>
> Coverage differs by `oauth2.type`, investigated at length in #216:
> - **`self`** (this repo's shipped default — `config/default.yaml`,
>   `.docker/authz/container.yaml`): fully closed. `ApiKeyJwtSigner`
>   (`crates/lightbridge-authz-rest/src/signing.rs`) stamps this claim on every self-signed
>   API-key JWT it mints, unconditionally, so it is present exactly when the caller is
>   API-key-derived.
> - **`external`**: **not yet closed**. Tokens minted by the upstream IdP's own API-key
>   token-exchange flow do not carry this claim until that flow — outside this repo — is updated
>   to stamp it. Until then, an `external`-mode API-key-derived caller is indistinguishable from a
>   human one at this layer and is **not** refused. This is why #216 stays open even though this
>   change closes its `self`-mode acceptance criterion.
>
> See `Procedures::request_budget_refill`'s doc comment (`crates/lightbridge-authz-rest/src/lib.rs`)
> for the code-level detail, and #216 for the full investigation of why no pre-existing claim
> (`aud` included — this deployment's own `oauth2.audience` config requires every valid token,
> human or API-key, to carry `lightbridge-api-key`, which is why that particular claim could never
> have worked as a distinguishing signal) reliably distinguished the two caller kinds before this
> dedicated claim was added.

**Role grant (#294):** `lightbridge-editor` holds `budget:self-refill` in the shipped configs
(`config/default.yaml`, `.docker/authz/container.yaml`) — a caller with any budget role can
self-refill their own budget, capped by the active policy's `self_service_grant_count` threshold
(see `crates/lightbridge-authz-budget/src/rule_data.rs`'s `default_rule_set_json`); going past that
ceiling routes to `pending_review` rather than being denied outright. `lightbridge-viewer` does
**not** get it — self-refill spends budget, which is inconsistent with a read-only role. Neither
role holds `budget:review`: only `lightbridge-admin` (via `*`) can act on the review queue.

### Direct budget-balance/ledger reads, and admin grant/revoke/policy-write

`RFC-0001` (`docs/rfc/0001-budget-refill.md`) sketches a `budget:*` permission surface for the
budget domain. `budget:policy-activate`, `budget:policy-read`, `budget:policy-simulate`,
`budget:self-refill`, and `budget:review` were wired up first (sections above); this section
covers the remaining five permissions plus `budget:read-own` (added alongside them), all now wired
to real `op_id`s. Before this, `budget_balances` (maintained transactionally on every grant) and
`budget_grants` (the append-only ledger, ADR-0009) had no reader at all — not even for an admin.

**Self vs admin is split into two pairs of procedures**, the same shape
`revokeOwnSessions`/`revokeSubjectSessions` already established for session revocation, rather than
one procedure with an optional/defaulted target:

- `procedure.getMyBudgetBalance` / `procedure.listMyBudgetGrants` / `procedure.
  listMyAugmentationRequests` take no target subject or account at all — the target is always the
  caller's own budget account, mirroring `RevokeOwnSessionsInput` having no subject field. Gated
  at **`budget:read-own`**, a permission added specifically for this: granting the existing
  `budget:read`/`budget:audit-read` broadly so every caller could see their own budget would also
  let them read every OTHER account's budget — exactly the "quietly conflating self and admin
  access" a permission review should catch. Reading your own balance/history is a read-only
  capability with no spend risk, so `budget:read-own` is granted to every default role
  (`lightbridge-admin` via `*`, and explicitly to `lightbridge-editor` and `lightbridge-viewer` in
  the shipped configs), the same posture `session:revoke-own` already has and unlike
  `budget:self-refill` (which spends budget and so is withheld from `lightbridge-viewer`).
  `listMyAugmentationRequests` (#295) is the caller's own `AugmentationRequest` history across
  EVERY status — not filtered to `pending_review` the way `listPendingAugmentationRequests` is,
  and not reviewer-scoped.
- `procedure.getBudgetBalance` / `procedure.listBudgetGrants` take an explicit `budgetAccountId`
  and read ANY account's balance/ledger. Gated at the admin **`budget:read`** /
  **`budget:audit-read`** respectively — reading a balance and reading the full ledger history
  behind it are kept as separate permissions, not collapsed into one, mirroring the existing
  `budget:policy-read` vs `budget:policy-write` split rather than the `budget:review` precedent
  (which bundles list + act into one permission). Neither default role holds these; only
  `lightbridge-admin` (via `*`) can read another account's budget.

`listMyBudgetGrants`/`listBudgetGrants`/`listMyAugmentationRequests` paginate strictly by
`createdAt`, never by id (ADR-0039 — CUID2 has no defined ordering): the response's `nextCursor` is
the last entry's `createdAt`; a short page (fewer than the requested `limit`) means there is
nothing further. `listMyAugmentationRequests` passes its cursor back as `before` (newest-first,
matching `listMyBudgetGrants`/`listBudgetGrants`'s own convention) — but `listPendingAugmentationRequests`
(#296) is the one exception: it keeps its pre-existing oldest-first order (a review queue, not a
ledger — the longest-waiting request surfaces first), so its cursor is `after`, not `before`. See
`authz.cstack`'s `ListPendingAugmentationRequestsInput`/`ListMyAugmentationRequestsInput` doc
comments for the full reasoning.

**Admin grant/revoke** (`procedure.grantBudget` / `procedure.revokeBudgetGrant`, gated at
**`budget:grant`** / **`budget:revoke`**) delegate to the exact same transactional write path
(`BudgetRepo::grant`) every other grant source already uses — one ledger insert plus one
`budget_balances` update, atomically, under the same per-`(account, period)` row lock. Per ADR-0009
the ledger is append-only (a DB trigger rejects any `UPDATE`/`DELETE` outright, even for a
superuser): `revokeBudgetGrant` never mutates the original row, it looks it up and writes a NEW
`source = "correction"` row for the same `(budgetAccountId, accountId, projectId, period)` carrying
the negated amount, which nets the original grant out of `effective_budget_micros` while leaving
the original completely visible and unchanged. The correction's idempotency key is derived from the
target `grantId` server-side, so calling `revokeBudgetGrant` twice for the same grant is idempotent
rather than double-negating.

**Authoring a policy revision** (`procedure.createBudgetPolicyRevision`, gated at
**`budget:policy-write`**) is deliberately kept separate from `activateBudgetPolicy`
(`budget:policy-activate`) per ADR-0007: with arbitrary rule data, writing a policy means shipping
executable logic into the decision path, so the identity authoring it should not be the same one
that activates it. It delegates to `PolicyStore::create_revision`, which validates
`ruleDataJson` with the exact same `validate_rule_data` `activateBudgetPolicy` uses BEFORE writing
anything, and never touches `active_revision_id` or the live in-memory engine — the currently
active revision keeps serving exactly as before, and a separate `activateBudgetPolicy { revisionId
}` call is what would later make the new revision live.

All seven procedures above are gated only by `@allow(auth() != null)` in the schema, same pattern
as the rest of the budget domain — the real authorization is entirely the RBAC permission gate. The
generic `budget:*` resource wildcard, once something grants it, expands to **all eleven** budget
permissions (including `budget:read-own` and both halves of the write/activate split) — consistent
with how `project:*`/`apikey:*` already behave for their resources (see the wildcard note above).
Operators wanting the finer separations enforced should list the individual grants rather than the
wildcard, exactly as already advised for the existing resources.

**Deliberately unmapped → denied (defense in depth):**

- `model.ApiKey.create` — the schema removed its `@@allow("create")`, so the generic create verb is
  already fail-closed at the policy layer; the RBAC gate denies it too. API-key creation is
  server-side only, via `procedure.createApiKey` (the server generates + hashes the secret and
  validates the billing plan; a caller can never supply `keyHash`/`keyPrefix`/`billingPlan`).
- `model.Account.delete` — the generic delete verb carries no `@@allow` at all and is denied here
  too. Account deletion is `procedure.deleteAccountPermanently` only, whose SQL check is simply "the
  caller is this account".
- `model.ProjectMember.*` — that model is policy-locked to read-only with no generated mutation
  verbs; roster changes go through the `addProjectMember` / `removeProjectMember` /
  `setProjectMemberRole` / `setProjectMemberQuotaTier` procedures, which enforce the lead check in
  SQL (see "Project roles" below for why it cannot be an `@@allow` predicate).

`/rpc/batch` is not in this fail-closed list — it's handled specially with real per-frame permission
enforcement; see "Batch RPC: per-frame RBAC" above.

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
## Project membership (who a tenant's resources belong to)

RBAC decides *what actions* a caller may attempt; **membership** decides *whose* projects and API
keys they act on. Since ADR-0006 there is **no account-level membership at all** — a person's
identity in this system *is* their `accountId`, and `accounts.id` holds their JWT `sub` verbatim.
So "does this account belong to me" is a primary-key comparison (`accounts.id = sub`), not a join.

A caller can see or mutate a project (and every API key beneath it) if either:

- they own the account the project belongs to (`projects.account_id = sub`), or
- they hold a `project_members` row for it (`project_members.account_id = sub`).

Enforced in SQL on every project/key query — RBAC is checked first (else `403`), then membership
(else `404`).

Membership is **project-level**. An account's *default* project has no roster at all: nothing ever
inserts a `project_members` row for it, so the "no membership concept on the default project"
requirement falls out of the data model rather than needing a special case in policy.

A caller holding `project:member` manages a roster directly (no invite/accept handshake):

- `procedure.listProjectRoster` with `{ projectId }` — the roster's **only** read path. The four
  mutations below all return `Project`, and the generic `model.ProjectMember.list`/`get` verbs are
  fail-closed (the model is policy-traversal-only, and its `id` is synthetic — `project_members` is
  keyed `(project_id, account_id)` with no `id` column), so this procedure is how a roster is read
  at all. Its SQL check is deliberately **wider** than the mutations': any member of the project may
  read it, plus the owning account — leads are not privileged here, since knowing who you work
  alongside is not a management capability. A caller with no standing gets `404`, not `403`.

- `procedure.addProjectMember` with `{ projectId, accountId, role? }` — add a member by their
  account id (which is their subject). `role` defaults to `"member"`. Idempotent on the membership
  itself; use `setProjectMemberRole` to change an existing member's role.
- `procedure.removeProjectMember` with `{ projectId, accountId }` — remove a member. Unlike the
  account-membership model this replaces, there is **no** last-member invariant to enforce: the
  project's owning account is a standing authority over the roster, so a project can never be left
  with nobody able to administer it.
- `procedure.setProjectMemberRole` with `{ projectId, accountId, role }` — `"lead"` or `"member"`.
- `procedure.setProjectMemberQuotaTier` with `{ projectId, accountId, quotaTier }` — the member's
  per-project spending ceiling, validated against the configured tier catalogue at write time.

All four are **lead-gated**: the acting caller must own the project's account or hold `role = "lead"`
on that project. A caller who is neither gets a uniform `404`, the same non-leaking pattern used
everywhere on this surface.

### Project roles

Every `project_members` row carries a `role` — `"lead"` or `"member"` — plus an optional
`quota_tier`. Role is a **second, finer authorization layer inside a single project**, distinct from
the coarse RBAC gate above (global, JWT-role-driven) and from membership itself (binary).

| Role     | Can do beyond plain membership |
| -------- | ------------------------------- |
| `member` | Nothing extra — read/update the project and its API keys, same as any member. |
| `lead`   | + roster add/remove, + `setProjectMemberRole`, + `setProjectMemberQuotaTier`, + `createApiKey`. |

API-key creation is lead-gated deliberately: a key is live spending power with no per-request human
in the loop, so letting any member mint unlimited keys would remove the lead's ability to bound the
project's blast radius. It is cheaper to loosen this later than to tighten it after people depend on
the loose behaviour.

**Why this isn't expressed as an `@@allow` schema policy, unlike membership itself:** cratestack's
relation-quantifier policy predicates (`project.members.some.accountId == auth().id`) resolve each
dotted path to exactly one target scalar field per relation hop — there is no support for a compound
condition jointly checked on the *same* related row. Writing
`members.some.accountId == auth().id && members.some.role == "lead"` would compile to two
independent `EXISTS` checks ("some member matches me" AND, separately, "some member — any member —
is a lead"), not "the member row matching me is also a lead". So role gating lives entirely in
hand-written SQL inside the procedures above (confirmed by reading
`cratestack-macros/src/policy/model/relation_path.rs`) rather than in the schema's `@@allow`
policies. ADR-0005 first hit this limitation with account roles; ADR-0006 re-confirmed it for
project roles.

### The default project can't be hard-deleted

The first project ever created under an account is marked `isDefault = true` — server-computed once
at insert time by a `BEFORE INSERT` trigger (`migrations/20260725000001_default_account_project.sql`),
since `model.Project.create` is the generic cratestack verb and has no hand-written hook for the
"is this the account's first project" computation. A partial unique index
(`projects_account_id_default_uidx`) backstops the race where two concurrent first-project creates
for the same brand-new account would otherwise both see zero existing rows. `isDefault Boolean
@readonly` keeps it out of the generated create/update inputs, so a raw RPC caller can never supply
or overwrite it.

This is a hard safety rail, not a role check: `model.Project.delete`'s `@@allow` policy denies a
default project outright. Suspending (`disableProject`) still works — only the permanent-delete path
is blocked, so a tenant can never accidentally wipe out their only project and every API key
underneath it with no way back.

There is **no** equivalent default-*account* concept. One account is one person, so there is nothing
to default away from; the `accounts.is_default` column and the `setDefaultAccount` procedure that
briefly existed were removed by ADR-0006 (`migrations/20260727000006_accounts_drop_is_default.sql`).

### Escape hatch: reassigning the default (`setDefaultProject`)

Because the default project can never be hard-deleted, an account's bootstrap project would be
*permanently* undeletable if `isDefault` could never move — so it can, but only through
`setDefaultProject(projectId)`, never through the generic `model.Project.update` (the field stays
`@readonly`). It promotes a different project to default while atomically demoting whichever project
is currently default, in a single transaction (`StoreRepo::set_default_project`) — never a bare
"unset then set" a caller could race against. The partial unique index still backstops the
invariant: if two reassignments for the same account raced past the unset step, the second
`SET is_default = true` would hit a unique-constraint conflict (surfaced as `409 Conflict`) rather
than silently leaving two defaults.

Once a different project is promoted, the old default is a plain row and `model.Project.delete`
works on it normally. Coarsely the procedure requires `project:update` — reassigning `isDefault` is
conceptually an update, just one that cannot go through the generic verb. A caller who owns neither
the account nor a roster seat gets a uniform `404`.
