# The governance model, and how it is actually enforced

How accounts, projects, members and API keys are modelled, and how a request carrying one of them
gets rate-limited, model-restricted or refused at the gateway. Written to be readable end-to-end by
someone who has seen neither the database nor the Envoy config.

Companion to [`rbac.md`](./rbac.md) (which permission gates which *operation* on the authz API) and
[ADR-0006](./adr/0006-project-membership-supersedes-account-roles.md) (why the model is shaped this
way). This document is about the **data plane**: what happens to an inference request.

> **"Budget" here means the static, per-plan Envoy/BackendTrafficPolicy rate-limit window** (§3,
> §5). It is a different mechanism from the newer per-account ledger + self-service refill system
> (`crates/lightbridge-authz-budget/`, [`rbac.md`](./rbac.md)'s budget sections,
> [`budget-decision-contract.md`](./budget-decision-contract.md)) — see the "A second, newer
> budget system exists" entry in §5 for how the two relate today.

> **Read the "Where this is not yet true" section before trusting any of the enforcement
> walkthroughs.** Parts of this chain are live; one link is built but not yet configured, and the
> document says which.

---

## 1. The entities

```mermaid
erDiagram
    ACCOUNT ||--o{ PROJECT : "owns (account_id)"
    ACCOUNT ||--o{ PROJECT_MEMBER : "holds a seat"
    ACCOUNT ||--o{ API_KEY : "owns (owner_account_id)"
    PROJECT ||--o{ PROJECT_MEMBER : "roster"
    PROJECT ||--o{ API_KEY : "scopes"

    ACCOUNT {
        text id PK "IS the person's JWT sub"
        text default_quota "tier catalogue; not yet stamped"
        text status "active | suspended"
    }
    PROJECT {
        text id PK
        text account_id FK "the OWNING account"
        text billing_identity UK "who is paying"
        json allowed_models "NULL or [] means ALL"
        text project_quota "pooled ceiling"
        text billing_plan
        bool is_default "trigger-set; undeletable"
        text status
    }
    PROJECT_MEMBER {
        text project_id PK "composite PK with account_id -- no id column"
        text account_id PK
        text role "lead | member"
        text quota_tier "THIS person on THIS project"
    }
    API_KEY {
        text id PK
        text project_id FK
        text owner_account_id FK "the minter, not the project owner"
        text key_hash UK "SHA-256; plaintext never stored"
        text billing_plan
        text status "+ expires_at, revoked_at, deleted_at"
    }
```

> The owning account of a project normally holds **no** `PROJECT_MEMBER` row. Ownership and roster
> membership are separate standings, which is why an owner's `quota_tier` is legitimately `NULL`.

### Account — a person

| Column | Notes |
|---|---|
| `id` | **Is the person's JWT `sub`.** Not a surrogate key. |
| `default_quota` | Governance tier for their own default project. Validated against an operator-configured catalogue at write time (config, not a DB table). |
| `status` | `active`/`suspended`. Server-managed. |

One account is one person. There is **no account-level membership of any kind** — that concept
existed until ADR-0006 and was removed entirely, table and all.

Because `accounts.id` *is* the subject, `createAccount` succeeds exactly once per person; a second
call is a `409 Conflict`, not a second row. There is no way for a caller to choose their own account
id, which would otherwise be an impersonation primitive.

### Project — a shared goal, and the unit of billing

| Column | Notes |
|---|---|
| `id`, `name` | |
| `account_id` | The **owning** account. Not the same thing as being on the roster. |
| `billing_identity` | **Unique.** Who is paying. Lives here, not on the account, so one person can bill projects to different parties (a consultant with three clients). |
| `allowed_models` | JSON list. `NULL` or `[]` both mean **all models allowed**. |
| `project_quota` | The *pooled* ceiling, shared by everyone on the project. Tier catalogue value. |
| `billing_plan` | The plan tier (`free`, `pro`, `enterprise`, `internal`, `service`). |
| `is_default` | Server-computed by a `BEFORE INSERT` trigger; an account's first project. Undeletable. |
| `status` | `active`/`suspended`. |

Every account gets a **default project** automatically — "you, working alone". It has no roster by
construction: nothing ever inserts a member row for it. That is not enforced by a special case; it
falls out of the data model, which is why no policy anywhere branches on `is_default`.

### ProjectMember — a seat on a roster

| Column | Notes |
|---|---|
| `project_id`, `account_id` | **Composite primary key.** There is no `id` column. |
| `role` | `lead` or `member` (DB `CHECK`). |
| `quota_tier` | This specific person's ceiling on this specific project. Set by a lead. |

Two things about this table surprise people:

**Ownership and membership are separate standings.** The project's owning account normally holds
*no* member row. So "is this caller allowed?" is `projects.account_id = subject OR EXISTS(member
row)`, and an owner's `quota_tier` is legitimately `NULL` — meaning no per-member ceiling applies to
them, only the pooled one.

**The schema's `ProjectMember.id` is synthetic.** cratestack requires exactly one scalar `@id` per
model, but the real table has none. The model exists mainly so `@@allow` policies on `Project`/
`ApiKey` can traverse into it (`members.some.accountId == auth().id`). Consequences: the generic
`model.ProjectMember.*` verbs are fail-closed at the RBAC gate, and the roster is read through the
`listProjectRoster` procedure, which synthesises the id as `"<project>:<account>"`.

### ApiKey — delegated spending power

| Column | Notes |
|---|---|
| `id`, `project_id`, `name` | |
| `key_hash` | SHA-256 of the secret. **The plaintext is never stored** — returned only on create/rotate. |
| `key_prefix` | For identification in listings. |
| `owner_account_id` | **Which member the key belongs to**, set from the acting subject on create/rotate. |
| `allowed_models` | Inherited from the project at mint time (into the JWT), not stored per key. |
| `billing_plan` | |
| `status`, `expires_at`, `revoked_at`, `deleted_at` | |
| `last_used_at`, `last_ip` | Usage telemetry, updated on validation. |

`owner_account_id` is the newest and least obvious column. A key is project-scoped, but **creating
one is lead-gated**, so the minter is either the owning account or a lead. Attributing the key to
the *project owner* instead of the actual minter would let a lead's keys escape the lead's own
per-member ceiling. It is `NOT NULL` deliberately: an unattributable key is precisely the case where
"whose ceiling applies?" has no answer.

### The `api_key_validation` view

Introspection reads one indexed view rather than assembling the picture with joins per request:

```sql
SELECT api_key_id, key_hash, project_id, account_id,
       api_key_status, project_status, account_status, expires_at,
       effective_status,                              -- the cascade, resolved by the DB
       owner_account_id, owner_role, owner_quota_tier -- LEFT JOIN project_members
FROM   api_key_validation WHERE key_hash = $1
```

```mermaid
flowchart LR
    K["api_keys<br/>status, expires_at"] --> E{{"effective_status"}}
    P["projects<br/>status"] --> E
    A["accounts<br/>status"] --> E
    PM["project_members<br/>role, quota_tier<br/><i>LEFT JOIN</i>"] -.->|"NULL for an owner-minted key"| E
    E --> R1["key_revoked"]
    E --> R2["key_expired"]
    E --> R3["project_suspended"]
    E --> R4["account_suspended"]
    E --> R5["active"]
```

`effective_status` collapses the whole chain — `key_revoked` → `key_expired` → `project_suspended` →
`account_suspended` → `active`. **Suspending an account instantly invalidates every key beneath
it**, because the cascade is computed in SQL, not reconstructed in application code.

The owner columns are a `LEFT JOIN`, so `owner_role`/`owner_quota_tier` are `NULL` for an
owner-minted key. That is a meaningful value, not a missing one.

---

## 2. The two identity planes

Everything downstream depends on which of these a request arrives on.

**The API-key plane.** A machine caller presents a key. The key *is* a self-signed JWT carrying
`api_key_id`, `project_id`, `account_id`, `allowed_models`, `sub`, `jti`, `exp`. Authorino
recognises it by `api_key_id` being present.

**The Keycloak plane.** A human, via opencode/LibreChat. Project context is sealed into the token at
**token-exchange time** by the `lightbridge-keycloak-spi` adapter, which calls
`POST /idp/v1/resolve-context` (Basic-auth protected) and a protocol mapper copies the result into
claims.

The practical consequence of the second: **switching project means requesting a new token, not
sending a different header.**

---

## 3. How a request gets governed

```mermaid
flowchart TD
    C(["client<br/><code>Authorization: Bearer &lt;api-key JWT | keycloak token&gt;</code>"])

    subgraph ENVOY["Envoy — HTTP filter chain (order verified from a live config_dump)"]
        direction TB
        F1["<b>filter #1</b> — ext_proc / AI Gateway<br/>parses the body, sets <code>x-ai-eg-model</code>"]
        F7["<b>filter #7</b> — ext_authz / Authorino"]
        F1 --> F7
    end

    C --> F1

    F7 -->|"has api_key_id?"| PLANE{identity plane}
    PLANE -->|"API key"| INTRO["POST /v1/authorino/validate/introspect<br/>Basic auth · <b>cached 30s per jti</b>"]
    PLANE -->|"Keycloak"| CLAIMS["read auth.identity.*<br/>sealed at token-exchange time"]

    INTRO --> RESP["active, account_id, project_id, api_key_status,<br/>billing_plan (+name, +limits), allowed_models,<br/>project_quota, role, quota_tier, exp"]

    RESP --> ALLOW{"model allowlist<br/>CEL predicate"}
    CLAIMS --> HDR
    ALLOW -->|"model not in list"| DENY(["403 denied"])
    ALLOW -->|"allowed, or any<br/>fail-open escape hatch"| HDR

    HDR["response headers stamped:<br/><code>x-account-id</code> · <code>x-project-id</code> · <code>x-project-role</code><br/><code>x-quota-tier</code> · <code>x-project-quota</code> · <code>x-billing-plan</code>"]

    HDR --> BTP

    subgraph BTP["BackendTrafficPolicy (per model) — Envoy denies if ANY matched bucket is exhausted"]
        direction TB
        R1["<b>1.</b> burst requests/min<br/>x-account-id + x-billing-plan"]
        R2["<b>2.</b> burst tokens/min<br/>same key · cost = llm_total_token · skipped for image models"]
        R3["<b>3.</b> monthly budget<br/>micro-USD · cost = llm_custom_total_cost"]
        R4["<b>4.</b> quota tiers<br/>x-project-id + x-account-id (Distinct) + x-quota-tier (Exact)"]
        R5["<b>5.</b> project envelope<br/>x-project-id (Distinct) + x-project-quota (Exact)"]
    end

    BTP -->|"any bucket exhausted"| R429(["429 rate limited"])
    BTP -->|"all within budget"| BACKEND(["model backend"])

    style DENY fill:#7f1d1d,color:#fff
    style R429 fill:#7f1d1d,color:#fff
    style BACKEND fill:#14532d,color:#fff
    style R4 stroke-dasharray: 5 5
    style R5 stroke-dasharray: 5 5
```

> Rule families **4** and **5** are drawn dashed: the header pipeline feeding them is live, but
> `tiers: []` / `projectEnvelope: {}` mean they do not currently render. See §5.


### Filter order is per **listener**, and it is not the same on all of them

Dumped live from `envoy-converse-gateway-core-gateway` (`/config_dump`, 2026-07-31). The diagram
above describes the **external** chain, which is the one that matters for API-key traffic:

```
api.ai.camer.digital
   1. ext_proc/aigateway            <- sets x-ai-eg-model
   2-6. custom_response (MCP oauth metadata)
   7. ext_authz  (Authorino)        <- model name already present
   8. jwt_authn   9. rbac   10-11. ratelimit   12-14. compressor/hdr/router
```

The internal listener has the **opposite** order:

```
core-gateway-internal.envoy-gateway-system.svc.cluster.local
   1. ext_authz  (Authorino)        <- runs FIRST
   2. ext_proc/aigateway            <- x-ai-eg-model set AFTER
   3-4. ratelimit  5-7. compressor/hdr/router
```

So on the internal plane `x-ai-eg-model` is **absent** when the allowlist predicate evaluates, its
third escape hatch fires, and the check silently passes. See §5.

(A third listener, `api.ai.kivoyo.com`, has no `ext_authz` at all — a deprecated endpoint, retained
here only so the dump above is not read as incomplete.)

### Why introspection and not claims

An earlier plan was to put everything in claims and reduce introspection to a single active-check.
It was **rejected after measuring**: introspection is 3 round trips, cached 30s per key by
Authorino. At ~100 keys that is ~27 DB ops/sec against a store measured at 600–1000 rps.

Paying it buys a property claims cannot: **a quota or roster change takes effect within 30 seconds**,
rather than waiting for the key to be rotated. Claims freeze at mint time.

That is why `project_quota` and `role` ride on the introspection response only, while
`allowed_models` is *also* in the JWT (it is stamped at mint time and used for the header path).

`quota_tier` used to sit in that same "introspection only" bucket, but as of ADR-0017 the
API-key plane still reads it from introspection (unchanged — this section's reasoning applies to
it in full there) while the human/OIDC plane now *also* gets it as a token-exchange-time claim,
resolved live from `project_members` on every exchange and refresh rather than copied forward —
see §4.7 and ADR-0017 for why `quota_tier` specifically could take the claims-based carve-out that
`project_quota`/`role` deliberately do not (there is no equivalent live, per-request path for the
human plane the way introspection provides for API keys).

### Absence-safety, and why every header falls back to `""`

Every CEL expression guards each level with `has()` under `&&` short-circuit. Evaluating an absent
parent is a hard "no such key" error that **drops the header entirely** — a failure mode that has
bitten this config before. A dropped header is worse than an empty one: an empty value simply
matches no `Exact` selector, so the rule does not apply and the plan-level limits still govern.

The allowlist predicate fails **open** in three directions, deliberately: no `api_key_id` (human
identity), allowlist absent or empty (`NULL`/`[]` means all models — or introspection is down), or
no `x-ai-eg-model` (a non-model route).

---

### The monthly budget window is not a calendar month

Rule family 3 uses `unit: Month`. That does **not** mean "this calendar month". `envoyproxy/
ratelimit` builds the counter key as `(now / divider) * divider` — the window start floored from the
**Unix epoch** (`src/limiter/cache_key.go`) — and `MONTH` is a flat `60*60*24*30`, exactly 30 days
(`src/utils/utilities.go`, `UnitToDivider`).

A calendar month averages 30.44 days, so the boundary **walks backward roughly 11 days per year**:

```
window open 2026-07-06  ->  resets 2026-08-05
2026-08-05 -> 2026-09-04 -> 2026-10-04 -> 2026-11-03
2026-12-03 -> 2027-01-02 -> 2027-02-01 -> 2027-03-03
```

That is why budgets appear to reset "on the 5th or 6th" — it is anchored to 1970-01-01, not to
anyone's signup date or the calendar.

**Can it be made to reset on the 1st?** Not cleanly, today. The BTP owns both the window (`unit`)
and the descriptor keys (`clientSelectors`); Authorino only supplies those headers' *values*. Adding
a calendar-period descriptor (say `x-billing-period: 2026-08`) does **not** replace the 30-day
boundary — the key contains both, so you would get resets on the 1st *and* on the drifting date,
which is worse. Making the period descriptor the only boundary requires a unit whose window never
rolls inside a month, i.e. `unit: Year`, which then misbehaves once a year when the year bucket
rolls mid-month.

The options, none free:

| Approach | Cost |
|---|---|
| `unit: Year` + `x-billing-period` descriptor | one anomalous reset per year, at the year-bucket roll |
| Scheduled reset of the RLS Redis keys on the 1st | does not remove the drifting boundary, only adds one; reaches into another component's keyspace |
| Calendar-aligned units upstream | a change to `UnitToDivider` — fork or feature request |

## 4. Walkthroughs

### 4.1 A member exceeds their per-member tier but has personal quota left

Ana is a `member` on project *Atlas* with `quota_tier: t-s`. She also has her own default project
with `default_quota: t-m`.

She calls with an Atlas API key:

1. Introspection returns `project_id: atlas`, `quota_tier: t-s`, `project_quota: t-l`,
   `account_id: ana`.
2. Headers: `x-project-id: atlas`, `x-quota-tier: t-s`, `x-project-quota: t-l`,
   `x-account-id: ana`.
3. Rule family 4 matches `(atlas, ana, t-s)` — **exhausted → 429**.

Her personal quota does **not** rescue her, and that is the intended semantics: the tier bounds what
*this person may spend on this project*. Her own default project is a different `x-project-id`, so a
key minted there lands in a different bucket entirely.

The rule keys on `x-project-id` **and** `x-account-id` as `Distinct`, so Ana's exhaustion does not
affect her colleagues — each member gets their own counter within the tier.

### 4.2 A caller requests a model outside the project allowlist

Project *Atlas* has `allowed_models: ["gpt-4.1-mini"]`. The request asks for `gpt-4.1`.

1. ext_proc (filter #1) sets `x-ai-eg-model: gpt-4.1`.
2. Authorino (filter #7) evaluates the predicate: allowlist present, non-empty, header present, and
   `"gpt-4.1" in ["gpt-4.1-mini"]` is **false** → all four escape hatches fail → **denied**.

The ordering is the whole trick, and it was verified against a live `config_dump` rather than
assumed — an earlier assessment declared this impossible because it assumed Authorino ran first.

**This holds on the external listener only.** On the internal one the two filters are in the
opposite order, so the same request would pass the allowlist unchecked. See "Filter order is per
listener" above and §5.

Note what is *not* checked: `allowed_models` is the **project's**, read live from introspection. A
lead narrowing the allowlist takes effect within the 30s cache window, without rotating keys.

### 4.3 A lead removes a member; the member keeps using a key from that project

Ben is removed from *Atlas* by a lead. He still holds an Atlas API key he minted.

Here it matters exactly what "the key" is:

- The key row is **not** deleted. `removeProjectMember` deletes the roster row, nothing else.
- `api_key_validation` still resolves: the key is active, the project is active, the account is
  active → `effective_status: active`.
- **The key keeps working.**

What *does* change: `owner_role` and `owner_quota_tier` become `NULL` (the `LEFT JOIN` finds no
row), so `x-quota-tier` empties and Ben falls back to the **pooled** project envelope and plan
limits. He loses his per-member ceiling — which, if his tier was *tighter* than the pool, actually
**loosens** his limits.

He also immediately loses API access to the project through the authz API itself (`get_project`
returns `NotFound`), so he cannot mint new keys or read the roster — but the existing key is a
bearer credential against the gateway, and nothing revoked it.

> **This is a real gap, not a designed behaviour.** If you need removal to cut off existing keys,
> `removeProjectMember` must also revoke keys where `owner_account_id` = the removed member. See
> §5.

### 4.4 An account is suspended

Immediate and total. `api_key_validation.effective_status` becomes `account_suspended` for **every**
key under every project of that account, because the cascade is a SQL `CASE` over the joined status
columns. Introspection returns `{"active": false}` and Authorino rejects.

Worst-case propagation is the 30s introspection cache.

### 4.5 A key is rotated

`rotateApiKey` revokes the old key and mints a new one **in one transaction**. The new key's
`owner_account_id` is the **rotating** subject, not inherited from the old key — rotation re-mints
for whoever performs it, so the per-member ceiling follows the person doing the rotating.

### 4.6 An owner-minted key

The project owner mints a key. They hold no roster row, so `owner_quota_tier` is `NULL` and
`x-quota-tier` is `""`, which matches no `Exact` selector. Rule family 4 does not apply; they are
bounded by the project envelope (family 5) and their plan limits (1–3).

This is correct, not a hole: the owner is not a roster seat, and the pooled ceiling is what bounds
the project as a whole.

### 4.7 A human on the Keycloak plane

Claire signs in through opencode and exchanges for project *Atlas*. `x-project-id` and
`x-account-id` come from **claims**, not introspection (there is no `api_key_id`). The model
allowlist predicate **skips entirely** — its first escape hatch is "no `api_key_id`".

So: **the model allowlist is not enforced on the human plane.** See §5.

**As of ADR-0017**, `x-quota-tier` on this plane is no longer unconditionally `""` either. The
native RFC 8693 exchange (`TokenExchangeOpStore`, `crates/lightbridge-authz-rest/src/oauth2_op/store.rs`)
that mints Claire's access token also resolves her `project_members.quota_tier` on *Atlas* at
exchange/refresh time and stamps it as a `quota_tier` claim when present. If she holds no roster
row on *Atlas* (e.g. she owns it, or is a member with no tier set), the claim is omitted — the same
"no per-member ceiling" answer the `Exact`-selector rule already treats an empty header as, per §5.
If the lookup itself fails (the database is unreachable), the exchange/refresh is refused outright
rather than minting a token with the claim silently omitted — an unresolvable tier must never look,
on the wire, like a resolved "no ceiling" answer. See ADR-0017 for the full contract; §5's "tier and
envelope rules are not configured" still applies unchanged — nothing at the gateway reads this claim
yet.

### 4.8 Introspection is unavailable

The allowlist predicate's first two clauses (`!has(...)`) are true → the request is **allowed**, and
every `x-project-*` header falls back to `""` → tier and envelope rules do not match → the caller
falls through to plan-level limits keyed on `x-account-id` + `x-billing-plan`.

Deliberately fail-open on *governance*, not on *authentication* — the key must still validate.

### 4.9 A key whose billing plan is not in the configured catalogue

Introspection logs a warning and omits `billing_plan_name`/`billing_plan_limits`. The key still
validates. Downstream, `x-billing-plan` carries an id no plan rule matches, so **no plan rate limit
applies**. Reconcile the catalogue with keys still in use; the warning is the only signal.

---

## 5. Where this is not yet true

Stated plainly, because most of these fail *silently*.

### The tier and envelope rules are not configured

`charts/ai-models/values.yaml` still carries `tiers: []` and `projectEnvelope: {}`. With those
defaults **neither rule family renders at all**. The header pipeline described in §3 is live end to
end, but there is currently **no rule to match `x-quota-tier` against**.

So walkthrough 4.1 describes what happens *once a tier menu is configured*, not what happens today.
Today Ana falls through to plan limits. Populating those two values is the remaining step, and it is
a chart change, not code.

### The model allowlist is not enforced on the internal listener

Not a policy gap but a **filter-ordering** one, and independent of the human-plane gap below. On
`core-gateway-internal…` Authorino runs *before* the AI Gateway's ext_proc, so `x-ai-eg-model` does
not exist yet when the predicate evaluates and the "no model header" escape hatch passes it. Verified
from a live `config_dump` on 2026-07-31.

Fixing it means influencing filter order on that listener (Envoy Gateway orders ext_authz and
ext_proc per-listener from the attached policies), not changing the CEL.

### The monthly budget does not reset on the 1st

30-day buckets anchored at the Unix epoch, drifting ~11 days backward per year. Full explanation and
the (unattractive) options are in §3. Worth knowing before anyone reconciles a bill against it.

### The model allowlist does not apply to humans

Walkthrough 4.7. The predicate is gated on `api_key_id`, and the Keycloak plane has no allowlist
source — `resolve-context` returns account/project context, not `allowed_models`. A human can reach
any model their plan allows, regardless of the project they are working in.

### Removing a member does not revoke their keys

Walkthrough 4.3. Arguably the most surprising gap for an operator: revoking someone's *access* does
not revoke their *credentials*.

### `x-project-role` is stamped but unused

Nothing consumes it. It is populated for completeness and future policy; no rule keys on it today.

### The `internal` plane has no project context

The LibreChat / k8s-service-account AuthConfig has no `metadata:` block, so `x-project-*` there is
always empty, mirroring its existing `x-billing-plan` behaviour.

### Per-model budget counters are per-route

Envoy Gateway namespaces the monthly-budget counter **per HTTPRoute**, so despite a model-agnostic
descriptor the budget is enforced per model, not shared (a heavy user held ~29 separate counters).
The shared fix exists behind `sharedBudget.enabled`.

### A second, newer budget system exists and is not yet connected here

`crates/lightbridge-authz-budget/` (epic #188) adds a per-account **ledger** of budget grants, a
hot-swappable policy engine, and self-service refill + an admin review queue —
`requestBudgetRefill`, exposed as an RPC procedure on `authz-api`. As of this writing it grants,
records, and queues correctly (see [`rbac.md`](./rbac.md)'s budget sections), but has **zero
effect on anything this document describes**: it does not write `x-quota-tier`, does not touch
`project_members.quota_tier` or `projects.project_quota`, and nothing in §3's header pipeline reads
from it. Connecting the two is Phase 6a (re-key the enforcement rules onto the tier ladder,
`docs/runbooks/budget-tier-rekey-cutover.md`) and Phase 6b (write the granted tier back to
Keycloak so it reaches a token's claims) — both still open. Until then, a successful
`requestBudgetRefill` call changes the ledger and nothing a request actually experiences at the
gateway.

---

## 6. Quick reference — what governs what

| Bound | Source of truth | Reaches the gateway via | Live today? |
|---|---|---|---|
| Plan burst + budget | Keycloak group attribute / key's `billing_plan` | `x-billing-plan` | yes |
| Model allowlist | `projects.allowed_models` | introspection → CEL predicate | API keys only |
| Pooled project ceiling | `projects.project_quota` | introspection → `x-project-quota` | header yes, **rule not configured** |
| Per-member ceiling | `project_members.quota_tier` | introspection (API keys) or a token-exchange-time claim (human/OIDC, ADR-0017) → `x-quota-tier` | header yes, **rule not configured** |
| Key validity cascade | `api_key_validation.effective_status` | introspection `active` | yes |
| Monthly budget window | `unit: Month` in the BTP | RLS counter key | yes, **calendar month (`YYYY-MM`, UTC), not a 30-day epoch bucket** |
| Account's own default-project tier | `accounts.default_quota` | *not currently stamped* | no |

`accounts.default_quota` deserves a note: it is settable and validated, but nothing reads it at the
gateway. A person's default project has no roster, so there is no `quota_tier` row for it — the
field was meant to fill that gap and is not yet wired.
