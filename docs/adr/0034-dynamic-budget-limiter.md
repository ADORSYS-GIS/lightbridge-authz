# ADR-0034: The Dynamic Budget Limiter — the gateway reads the live balance, it does not trust the token

- Status: Proposed
- Date: 2026-09-03
- Decision owners: @stephane-segning
- Story: [lightbridge-authz#658](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/658)
  (Phase 6a decision memo)
- Builds on: [ADR-0007](0007-refill-decisions-rule-data-then-opa-wasm.md) (facts are gathered by the host, the
  evaluator is pure), [ADR-0008](0008-refills-are-discrete-budget-tiers.md) (the period is a
  calendar month), [ADR-0009](0009-budget-grants-are-an-immutable-ledger.md),
  [ADR-0026](0026-one-identity-may-own-many-accounts.md) (*Proposed* — the counter-identity
  caveat in §7), [ADR-0032](0032-budget-reset-schedules.md) (`next_reset_at`)
- Supersedes for enforcement purposes: [ADR-0014](0014-budget-tier-claim-via-token-mint-not-keycloak-writeback.md)'s
  role as the *enforcement* path. The `budget_tier` claim is **not** retired by this ADR — see §12.

---

## 1. Context

`lightbridge-authz#658`'s audit settled the question it was asked: **a refill buys nothing.** The
ledger moves, the console updates, the `budget_tier` claim is minted — and the gateway keeps
enforcing two static Envoy rate-limit rules keyed on `(x-account-id, x-billing-plan,
calendar-window)`, whose limits come from Helm values and whose counters live in the Lyft
ratelimit service's Redis. Nothing in that chain reads `budget_grants`.

The memo's §4.1/§4.2 answer was to stamp the *tier* as a header and add one `Exact`-matched
rate-limit rule per rung. That works, and it has three properties the owner rejected on
2026-09-03:

1. **It trusts the token.** The tier rides a claim (or an introspection response cached for 30 s)
   that was computed at mint time. The gateway then keys a rule on a value it did not derive.
2. **It quantises money into rungs.** ADR-0015 already made refill amounts admin-configured
   ranges; the ladder forces every one of them back onto seven compile-time numbers, and the memo
   itself found two defects (`repo.rs:551-571`, `rule_data.rs:148`) where an off-ladder amount
   silently collapses to a label that matches either the wrong rule or *no* rule — and a request
   matching no budget rule is **unlimited**.
3. **A tier change resets the window's counter.** Moving an account between two `Exact` rules
   changes the descriptor, hence the Redis key, hence the counter. `ai-helm`'s
   `plans/lightbridge-dynamic-budget.md` §0.1(a) documents this as a deliberate product choice;
   it is still the ADR-0084 incident mechanism, invoked on purpose.

**Owner's direction (2026-09-03), verbatim in intent:** *when the JWT is from authz, check the
budget and allow or block. Keep `billing_plan`, but scope it strictly to rate limiting. Use
AuthConfig `metadata` — after JWKS authentication and OPA authorization — to bring the budget
downstream, and block on empty remaining with a custom error. I don't trust the token.*

That is the memo's §4.3 option 2 (*"Dynamic per-request balance check"*), which the memo
recommended **against**. The objection is real and must be answered rather than waved past.

### 1.1 The objection this ADR has to survive

`ai-helm`'s `plans/lightbridge-dynamic-budget.md` §1.2 is unambiguous:

> Authorino stamps only **stable** identifiers […] and the *limiter* does the allowance lookup.
> **Never add a budget lookup to the Authorino step.**

The reason is a live incident. On 2026-07-02 the Keycloak introspection `metadata` step was
commented out of the prod AuthConfig because a cold-cache request made a synchronous call inside
the ext_authz path; when Keycloak slowed under load, Envoy's ext_authz timeout fired and — with
`failOpen: false` — became a 403 for real users. The AuthConfig still carries that note
(`ai-helm-values/environments/prod/values/security-policies.yaml:250-263`).

Four things make this proposal a different shape from that incident, and all four are load-bearing:

| The 2026-07-02 failure | This design |
|---|---|
| Keycloak: an external IdP, shared with unrelated traffic, no latency budget of our own | `authz-budget`, in-cluster, ClusterIP, one route, owned by us |
| A read whose cost was unbounded (a full introspection, cold cache per token) | Two indexed reads (`SUM` over `budget_grants` for one account/period, plus one HTTP call to `authz-usage`), cached per identity per TTL |
| No cache on the failure path, and no fallback: a slow call *was* the outcome | A bounded server-side grace window (§5.3) that answers from the last known reading while the spend source is down |
| A failure mode that produced a *403 to the user* | A failure mode that produces a **503 `budget_unavailable`** — a different status, a different message, a different runbook, and an alertable signal |

And one thing that is unchanged and must stay unchanged: **ext_authz `failOpen` stays `false`.**
The manifests assert it explicitly rather than relying on the CRD default, because the entire
value of this feature evaporates if a slow Authorino means "allow".

---

## 2. Decision

Enforce the **live ledger balance** at the gateway, per request, through the existing ext_authz
step — and keep the enforcement *decision* out of the token entirely.

```
JWKS identity (unchanged)
  → OPA / CEL authorization (unchanged)
    → AuthConfig `metadata` → GET /budget/v1/remaining   [NEW, mTLS-only, authz-budget]
      → response.success.dynamicMetadata  (NOT a header)
        → Envoy Lua EnvoyExtensionPolicy: remaining_micros <= 0 ⇒ 402 budget_exhausted
```

Six decisions, in the order they matter:

**D1 — the gateway asks us, per identity per TTL, and never reads a budget claim.**
`auth.identity.budget_tier` is not consulted by any part of this path. The only identity input is
the account id, which Authorino already derives from the credential.

**D2 — the answer travels as ext_authz dynamic metadata, never as a request header.** Success
headers are *request* headers Envoy injects toward the upstream; they are also the thing a
misconfigured chain lets a client supply. Dynamic metadata is internal to the filter chain, is
never emitted to the client, and cannot be spoofed inbound because it does not exist inbound.
(`x-model-policy`'s own anti-spoofing note — `security-policies.yaml:922-936`, and
`charts/core-gateway/files/model-policy.lua`'s "ANTI-SPOOFING" section — is the cautionary tale
this avoids by construction rather than by discipline.)

**D3 — the refusal is issued by a Lua `EnvoyExtensionPolicy`, not by Authorino's own denial.**
This was re-examined at the owner's request; see §4 for the exact reason the Authorino-native path
cannot ship, and §4.2 for why it is not ext_proc either.

**D4 — the endpoint reports, it does not decide.** `GET /budget/v1/remaining` returns
`ceiling`, `spend` and their difference, plus when the balance next changes. Thresholding is the
gateway's job. This is ADR-0007's "the evaluator is a pure function of facts gathered by the host"
applied to the data plane.

**D5 — unknown is never zero, at every layer.** A `NULL` `SUM`, an unreachable usage service, an
unreadable ledger, an absent metadata value, a Lua exception: each one routes to a *distinct*
outcome, and none of them routes to "you have spent everything" (§5).

**D6 — `billing_plan` is a rate-limit key and nothing else.** No plan → budget mapping, no tier
rules, no plan-derived money. §6 states what the `BackendTrafficPolicy` becomes.

---

## 3. The endpoint

`GET /budget/v1/remaining?account_id=<budget account id>[&period=YYYY-MM]`

Served by `authz-budget` on a **second listener** whose `Tls::client_ca_bundle_path` requires and
verifies a client certificate at the TLS handshake, before any application code runs — the same
posture, and the same reasoning, as `lightbridge-authz-usage`'s `/usage/v1/spend/query` (#347).
Client-certificate verification is enforced per *listener*, not per route, so this cannot be a
route on the bearer-JWT RPC listener without locking out the console. It additionally **refuses**
any request carrying an `Authorization` header: it is a cross-account read with no per-caller
ownership check at all, and a proxy misconfigured to forward a user's token here should fail
loudly.

```jsonc
// 200
{
  "budget_account_id": "cuid2…",
  "period": "2026-09",
  "ceiling_micros": 24000000,     // effective_balance: expiry/revocation-aware SUM(budget_grants)
  "spent_micros": 3210000,        // SUM(usage_events.total_cost) via /usage/v1/spend/query
  "remaining_micros": 20790000,   // signed, NOT clamped — negative means overspend
  "next_reset_at": "2026-10-01T00:00:00Z",
  "source_lag_seconds": null      // null = no cache age to report; NOT "zero staleness"
}
// 400 {"error":"bad_request",…}         malformed account id / period
// 403 {"error":"forbidden",…}           an Authorization header was present
// 503 {"error":"budget_unavailable",…}  the answer is not knowable right now
```

Four things about that payload are decisions, not details:

- **`ceiling_micros` is `BudgetRepo::effective_balance`**, not the raw
  `budget_balances.effective_budget_micros` projection. The projection counts grants that have
  since expired or been revoked (it reproduces `BudgetRepo::grant`'s unconditional `UPDATE`
  bit-for-bit, deliberately). An expired grant must not buy gateway traffic, so the enforcement
  read uses the stricter, expiry-aware sum — which is also what `Facts::effective_balance_micros`
  already means by "balance", so the gateway and the refill policy engine cannot disagree.
- **`remaining_micros` is signed and unclamped.** Overspend is reachable by construction (§5.4);
  reporting `0` for it would hide the one number the overspend alert needs.
- **`next_reset_at` is never null.** It is the winning ADR-0032 schedule's `next_run_at` when one
  covers the account, and otherwise midnight UTC on the 1st of the next month — the same instant
  the ledger's period key and the gateway's `x-billing-period` marker (`ai-helm` ADR-0111) both
  rotate.
- **`source_lag_seconds` is `null` unless we are serving a cached reading.** It is the *cache age*
  when stale-serving (§5.3), and `null` otherwise — which means "no cache age", **not** "current".
  A fresh reading still trails reality by the OTLP ingest lag, and `/usage/v1/spend/query` returns
  a bare `SUM` with no timestamp, so nothing in this process can measure that. Reporting `0` would
  understate §5.4's overspend window, which is computed from exactly this term. Teaching
  `/usage/v1/spend/query` to return `MAX(time)` alongside the sum is the tracked follow-up that
  makes the fresh case a real number too.

### 3.1 The AuthConfig side

```yaml
metadata:
  "budgetremaining":
    when:
      - predicate: |
          auth.identity.iss == "https://auth.ai.camer.digital"
    cache:
      key:
        expression: |
          "budget:" + string(auth.identity.account_id) + ":" + string(auth.identity.iss)
      ttl: 10          # seconds — a value; see §5.4 for how it enters the overspend window
    http:
      urlExpression: |
        "https://authz-budget.converse.svc.cluster.local:3007/budget/v1/remaining?account_id="
          + string(auth.identity.account_id)
      method: GET
      timeout: 300     # ms — MUST be well inside the SecurityPolicy's extAuth timeout
response:
  success:
    dynamicMetadata:
      "budget":
        json:
          properties:
            "remaining_micros": { expression: 'auth.metadata.budgetremaining.remaining_micros' }
            "next_reset_at":    { expression: 'auth.metadata.budgetremaining.next_reset_at' }
            "account_id":       { expression: 'string(auth.identity.account_id)' }
            "known":            { expression: 'has(auth.metadata.budgetremaining.remaining_micros)' }
```

Two verified facts this depends on, both worth re-checking against the deployed CRD before the
enforce step (`kubectl explain authconfigs.spec.metadata.http`), because one of them contradicts a
comment currently in prod:

- `HttpEndpointSpec` **does** carry a `Timeout *int` field in `authorino.kuadrant.io/v1beta3`
  (Authorino `api/v1beta3/auth_config_types.go`). `security-policies.yaml:305-309` asserts the
  opposite — *"authorino.kuadrant.io/v1beta3 has NO metadata.http.timeout field (server-side apply
  rejects it)"* — and the disabled `keycloakintrospection` block two stanzas above it uses
  `timeout: 2000`. One of those two is wrong for the installed version (authorino-operator chart
  **0.23.1**, `ai-helm/charts/apps/values.yaml:670-684`). **Resolve this by `kubectl explain`
  before the shadow deploy, not by argument** — if the field really is rejected, the timeout must
  be bounded at the SecurityPolicy's `extAuth.timeout` instead, and the ADR's latency budget (§9)
  is enforced there rather than here.
- Authorino's dynamic metadata lands in the Envoy namespace **`envoy.filters.http.ext_authz`**,
  under a root key equal to the config name (`budget` above). That is the exact key the Lua reads.

**A failed `metadata` fetch is non-fatal in Authorino**: `evaluateMetadataConfigs` logs and leaves
the value **absent**, it does not deny (this is documented verbatim in prod's own AuthConfig at
`security-policies.yaml:234-245`, from reading Authorino's source). So the fail-closed behaviour
of this feature cannot come from Authorino. It comes from the Lua, which is why the exported
`known` boolean exists: absence is a decision input, not a gap.

---

## 4. Why the Lua filter, and not the two alternatives

The owner asked specifically for the Authorino-native shape to be evaluated and preferred if it
works: `metadata` → an `authorization` rule (`remaining_micros > 0`) → `response.unauthorized`
returning 402 with a JSON body and dynamic headers. It was evaluated properly. It does not work
here, for one specific and checkable reason.

### 4.1 The Authorino-native denial — rejected, with the citation

`response.unauthorized` is a `DenyWithSpec`
(Authorino `api/v1beta3/auth_config_types.go`):

```go
type DenyWithSpec struct {
	Code    DenyWithCode           `json:"code,omitempty"`     // DenyWithCode = int64
	Message *ValueOrSelector       `json:"message,omitempty"`
	Headers NamedValuesOrSelectors `json:"headers,omitempty"`
	Body    *ValueOrSelector       `json:"body,omitempty"`
}
```

`Message`, `Headers` and `Body` are `ValueOrSelector` — so a **per-request JSON body and dynamic
headers are fully expressible in CEL**, and the owner's instinct there was right. `Code` is not:
it is a bare `int64`, with no `value`/`selector`/`expression`. It is **one constant per
AuthConfig**.

And there is exactly one `response.unauthorized` per AuthConfig — Authorino has no per-rule denial
customisation. The prod `main` AuthConfig already denies for at least three unrelated reasons that
must keep returning **403**: `model_policy: deny_all` / an unrecognised policy value, a revoked
self-signed API key (`lightbridge-key-active`), and the RBAC/OPA authorization rules. Setting
`code: 402` to make budget exhaustion a 402 would turn *"your key was revoked"* and *"that model
is not allowed for this project"* into `402 Payment Required` as well. That is not a cosmetic
regression: 402 is the status the console and every client will be taught to interpret as "top up
and retry", and it would then fire on conditions no payment can fix.

There is no way out inside Authorino: the AuthConfig is selected by Host, the hosts are fixed, and
a second AuthConfig for the same host is not how Authorino resolves (most-specific host wins). So:

> **Shipped: the Lua path.** Authorino does identity, authorization and the `metadata` call, and
> exports the answer as dynamic metadata. It adds **no** new `authorization` rule — one would deny
> with 403 and defeat the purpose. The Lua filter owns the status code and the body.

If Authorino ever gains a `ValueOrSelector` `Code` (or per-rule denial specs), this decision should
be revisited: the native path would then be strictly simpler, and the Lua could be deleted.

### 4.2 ext_proc — rejected, unchanged from the memo

An ext_proc component in the data path is what `plans/lightbridge-dynamic-budget.md` §0 option C
describes and what the memo's §4.3 option 2 warned about. It is rejected here for reasons that have
nothing to do with the budget question: it is a new component in the inference data path, it shares
the insertion-order problem the Censgate plan spiked, and it only earns its keep if you want
*reserve-and-settle*, which needs a **pre-request cost estimate** that does not exist —
`llm_custom_total_cost` is computed by the AI Gateway's own processor *after* the response
(§1.3 of that plan). Nothing in this design needs a pre-request estimate: it compares two numbers
that are both already known before the request starts.

### 4.3 Filter ordering — this works by construction, not by luck

Envoy Gateway v1.8.2 assigns a fixed order to the HTTP filters it generates
(`internal/xds/translator/httpfilters.go`, `newOrderedHTTPFilter`): **ext_authz = 5**, **Lua =
12 + index**, EnvoyExtensionPolicy ext_proc = 100 + index, router last. The AI Gateway's own
ext_proc is injected ahead of that table entirely. So the Lua always runs after Authorino has
written its dynamic metadata. This is the same guarantee `model-policy.lua` already relies on and
documents.

**Envoy Gateway accepts exactly ONE `EnvoyExtensionPolicy` per targetRef.** A second policy
targeting the same Gateway is rejected outright (`Accepted: False, reason: Conflicted`) and simply
never attaches — caught live on 2026-08-03 when a redaction policy silently did nothing. The budget
filter is therefore a **third `lua` list entry in the existing
`charts/core-gateway/templates/envoyextensionpolicy-billing-period.yaml`**, not a new file. Each
`lua` entry becomes its own filter at `12 + index`, so ordering among the three is by list position:
billing-period (12) → model-policy (13) → budget-limiter (14).

---

## 5. Failure modes — the whole point of the design

### 5.1 The matrix

| Condition | Endpoint | Dynamic metadata | Gateway result |
|---|---|---|---|
| Balance known, `remaining > 0` | `200` | `known=true`, `remaining_micros>0` | **pass** |
| Balance known, `remaining <= 0` | `200` | `known=true`, `remaining_micros<=0` | **402 `budget_exhausted`** |
| Usage service down, cached reading inside grace | `200` + `source_lag_seconds` | `known=true` | pass / 402 on the stale figure |
| Usage service down, no cached reading (or past grace) | `503 budget_unavailable` | value **absent** | **503 `budget_unavailable`** |
| Ledger unreadable | `503 budget_unavailable` | value **absent** | **503 `budget_unavailable`** |
| `authz-budget` unreachable / times out | — | value **absent** | **503 `budget_unavailable`** |
| Authorino itself times out / fails | — | — | **403** from Envoy (`extAuth.failOpen: false`) |
| The Lua script raises | — | — | **503 `budget_unavailable`** via the `pcall` guard |

Two entries deserve their own sentence.

**Absent metadata is a refusal, not a pass.** Authorino leaves a failed `metadata` value absent
rather than denying, so if the Lua treated absence as "no opinion" the feature would fail *open* on
exactly the condition it exists to handle. It refuses with 503 instead. The one carve-out is
requests that never went through this AuthConfig at all — the public model-catalog paths its own
`when` gate skips, and the `/mcp/*` routes that carry their own SecurityPolicy — which the Lua
recognises the same way `model-policy.lua` does: no budget metadata **and** no `x-ai-eg-model`
means it is not a metered model request, and it passes.

**A Lua exception must not fail open.** Envoy's default for an uncaught Lua error is to log it and
continue the filter chain. `model-policy.lua` already converts that into a refusal with a `pcall`
guard, and the harness proves the guard is load-bearing by running an unguarded copy on a third
listener and showing the request reaches the upstream. The budget filter uses the same shape and
the same proof.

### 5.2 Shadow mode

`budgetLimiter.shadowMode: true` (the initial prod value) makes the Lua compute the identical
decision, write it into its own dynamic-metadata namespace (`lightbridge.budget_limiter`:
`decision`, `reason`, `remaining_micros`) and log it — then **always** continue. Nothing is
refused. This is not a dormant feature flag in the sense the house rules forbid: the code path is
live and running on every request from day one, producing the exact decision it will later act on.
What the flag switches is whether the decision is *acted on*, which is the only safe way to
discover the false-positive rate of an enforcement rule that can 402 real paying traffic.

### 5.3 Cached grace — where it lives, and why it cannot live at the gateway

The grace window is implemented **in `authz-budget`**, in `RemainingService`: on a fresh reading it
remembers `(spent_micros, observed_at)` per `(account, period)`; when the usage service goes
unreachable it serves that reading for up to `remaining_grace_seconds` (default **120**), stamping
its age into `source_lag_seconds`; past the window the answer goes back to `Unavailable` → `503`.

It has to live there, because neither component downstream can express it:

- **Envoy's Lua filter has no cross-request state.** `filterContext` is static configuration.
- **Authorino's `metadata` cache is a plain TTL cache, not serve-stale-on-error.** A failed fetch
  leaves the value absent; the cached entry is not resurrected. (Prod's own AuthConfig commentary
  says this in as many words.)

Only the ceiling half is re-read during a stale serve — `spent_micros` comes from the cache, but
`effective_balance` is queried fresh every time. So a **refill that lands during a usage-service
outage takes effect immediately** instead of being masked by a cached answer. That asymmetry is
deliberate and tested.

The cache is per-replica. N replicas hold N independent caches, which only affects whether a
request during an outage finds a warm entry — never whether two replicas disagree about a *fresh*
reading. Putting it in Redis was rejected: it would add a second network dependency inside the one
code path whose entire job is surviving a network dependency being down.

### 5.4 The overspend window, quantified

An account can spend past its ceiling by, at worst, the sum of four terms:

| Term | Size | Why it exists |
|---|---|---|
| Authorino metadata cache TTL | **10 s** (a value) | every request inside the TTL sees the same balance |
| OTLP ingest lag | **unmeasured today** — the `MAX(time)` follow-up (§3) is what makes this a number | `usage_events` rows appear some time after the response completes |
| One in-flight request | one request's `llm_custom_total_cost` | the gateway charges *after* the response (`plans/lightbridge-dynamic-budget.md` §1.3); this is unavoidable in the current architecture and exists today too |
| Cached grace, when active | ≤ **120 s** (a value) | only during a usage-service outage |

In normal operation the window is `TTL + ingest_lag + one request`. Against a $24 monthly budget
and a per-request cost in the low thousands of micro-USD, ten seconds of concurrency is worth
cents, not dollars. **The honest gap is the ingest lag**, which nobody has measured — and until
`/usage/v1/spend/query` reports `MAX(time)`, the true window is bounded by a number we are
guessing at. That is stated here rather than hidden, and it is a shadow-mode exit criterion, not a
blocker for shadow mode.

Lowering the TTL narrows the window and raises load linearly. Ten seconds is the recommended
starting point; it is a value precisely so it can be tuned from the shadow-mode data.

---

## 6. What the `BackendTrafficPolicy` becomes

Today two rules govern every prod request, both **cost** buckets charging
`llm_custom_total_cost` against a per-plan monthly / weekly limit
(`ai-helm/charts/core-gateway/templates/backendtrafficpolicy.yaml:101-133` and `:149-184`;
prod values `core-gateway.yaml:79-102`, where all three plans are identically $24/mo, $6/wk).

**At the enforce step, those two cost buckets are deleted.** Not moved to a longer window, not
left inert with a huge limit — deleted, in the same commit that flips
`budgetLimiter.shadowMode: false`. Two enforcement mechanisms for the same quantity is exactly the
"dormant config" this repo's delivery rules forbid, and it is worse than dormant: with both live,
the effective cap is `min(plan, ledger)` and a refill still buys nothing once the plan bucket is
exhausted — the bug this whole ADR exists to fix would survive its own fix.

What the BTP keeps is **rate**, not money: requests-per-minute and tokens-per-minute per
`(x-account-id, x-billing-plan, x-ai-eg-model)` — the `burst` blocks that already exist in
`charts/ai-model` and are currently commented out in prod (`models.yaml:146,156,168,174,181`).
That is the honest role for `billing_plan`: **how fast**, never **how much**. Money moves entirely
to the ledger.

**Shadow mode leaves the cost buckets exactly as they are.** During shadow they are still the only
thing enforcing anything, which is what makes shadow safe.

Ordering rule, unchanged and non-negotiable: rules are matched by **position** in the rendered
list, and the Redis counter key is a function of which rule matched. Removing the two cost families
renumbers everything after them and orphans every in-window counter — the ADR-0084 incident
mechanism. So the enforce commit **must land on a 1st-of-month boundary, 00:00 UTC**, when every
counter is being abandoned anyway because `x-billing-period` has just flipped. The exporter
co-change (`prometheus-redis-exporter.yaml:110-137`, which hard-maps `rule-0..rule-5`) ships in the
**same commit**, per `docs/runbooks/budget-tier-rekey-cutover.md` §2.

### 6.1 Offered, not recommended: a coarse per-account daily cost cap

If defence in depth is wanted after the cost buckets go, the cheapest form is **one** additional
cost rule keyed on `(x-account-id Distinct, x-billing-day Distinct)` with a single flat limit far
above any legitimate day's spend — a blast-radius cap for a limiter bug, not a budget. The daily
marker costs one extra line in the billing-period Lua (`os.date("!%F")`, the shape ADR-0119 already
proved with the weekly marker).

**Not recommended**, for one reason: it reintroduces a second cost counter whose relationship to
the ledger is undefined, and the first time it fires the user gets a 429 that no refill can clear
and no console screen explains. If the limiter's own fail-closed behaviour is not trusted enough to
run without a net, the right response is a longer shadow period, not a second enforcement
mechanism. Recorded here because the owner asked for it to be on the table, with the trade stated.

---

## 7. Identity — which id is the counter keyed on

The endpoint is keyed on the **budget account id**: `budget_grants.budget_account_id`, which the
AuthConfig sources from the token's `account_id` claim — **not** from `sub`, and not from
`x-account-id`.

Today those are the same string, because `accounts.id` *is* the subject (ADR-0026 §Context). They
stop being the same the day **ADR-0026 (`Status: Proposed`)** lands and one identity may own many
accounts. At that point:

- keying on `sub` would meter all of a person's accounts against **one** balance while the console
  shows them separate balances — a bug that is invisible until someone owns two accounts;
- keying on `account_id`, as here, is correct before and after ADR-0026, and needs no cutover.

The existing rate-limit descriptor `x-account-id` is `auth.identity.sub`
(`security-policies.yaml:815-817`) and is **left alone** — it now keys rate, not money, and
per-person rate limiting on `sub` is the right grain regardless of how many accounts that person
owns. The two ids diverging is therefore not a migration; it is the design.

---

## 8. What this does *not* change

- **`budget_tier` keeps being minted** (ADR-0014). Nothing here reads it, but it is a useful
  audit/telemetry signal and removing it is a separate decision with its own blast radius.
  Consequently the memo's defects (a) and (b) — `current_tier` collapsing an off-ladder amount to
  `b-15`, and ADR-0032 `automatic` resets doing so systematically — stop being *enforcement* bugs
  the moment this ADR ships, and become cosmetic-but-wrong claim values. They should still be
  fixed; they are no longer urgent. See §13 D7.
- **The OPA/CEL authorization step is untouched.** Budget is not an authorization concern; a user
  with no budget is authorized and broke, and those are different words on purpose.
- **`/usage/v1/spend/query` is untouched.** The `MAX(time)` addition is a follow-up.
- **The AI Gateway's cost accounting is untouched.** `llm_custom_total_cost` still lands in
  `usage_events` exactly as it does now; that pipeline *is* our spend source.

---

## 9. Cost: latency and CPU

**On the request path (per request, warm cache):** the Lua filter does one dynamic-metadata map
lookup, two integer comparisons and, on the refusal path, one string concatenation. Envoy's Lua
runtime executes this in the low **microseconds** — it is comparable to `model-policy.lua`, which
does strictly more work (three header reads, a duplicate check and a list scan) and is already in
the prod chain at filter 13 with no measurable effect. There is **no** added network hop on a cache
hit: Authorino answers from its own metadata cache.

**On the request path (cold cache):** one HTTPS GET from Authorino to `authz-budget`, in-cluster,
which performs one indexed `SUM` over `budget_grants` for a single `(account, period)` and one
HTTPS POST to `authz-usage` for the spend `SUM`. Budget: **≤ 300 ms**, bounded by the metadata
`timeout` (§3.1), itself well inside the SecurityPolicy's `extAuth` timeout. Expected p50 is a few
milliseconds; the timeout exists for the tail, and the tail's outcome is a 503, not a 403.

**Call rate:** at most **one call per identity per TTL**. With a 10 s TTL that is `active_accounts
/ 10` requests per second against `authz-budget` — for a fleet of 200 concurrently active
accounts, **20 rps**, each two indexed reads. That is not a new load class for a service that
already serves the console's RPC surface. It scales with *accounts*, not with *requests*, which is
the property that makes this viable at all and the reason the TTL is the first knob to reach for
if `authz-budget` CPU moves.

**Authorino CPU:** one extra `metadata` evaluator and one extra `dynamicMetadata` CEL expression
per request. Both are in-process; the CEL is four field reads. Prod runs 2 replicas
(`security-policies.yaml:13`); no change expected, and Authorino CPU is on the watch list for the
shadow window regardless.

**`authz-budget` memory:** the grace cache holds one `(i64, timestamp)` per active
`(account, period)` seen within the grace window, pruned on write. Tens of kilobytes.

**ext_proc, for comparison:** a new sidecar in the data path, a full request-cycle round trip per
request, and — for reserve-and-settle — a second one on the response. Rejected in §4.2.

---

## 10. Rollout

**Stage 0 — merged now, inert.** The endpoint ships and binds only where `server.budget_internal`
is configured. Prod does not configure it yet, so `authz-budget` logs that the read is not served
and behaves exactly as before. Nothing at the gateway references it.

**Stage 1 — plumbing.** The `authz-budget` chart gains the container/Service port and the
`budget_internal` config block (owner action; see the runbook). Verify by hand from inside the
cluster, with and without a client certificate — the without case must fail the TLS handshake.

**Stage 2 — shadow.** `budgetLimiter.enabled: true`, `shadowMode: true`. The AuthConfig metadata
step and the dynamic-metadata export go live; the Lua computes and logs decisions and refuses
nothing. Watch for a full period, minimum one week:
- `lightbridge.budget_limiter` decision counts, split by reason — how many requests *would* have
  been refused, and how many of those were `budget_unavailable` rather than `budget_exhausted`;
- `authz-budget` p99 on `/budget/v1/remaining`, and its 503 rate;
- Authorino p99 and any ext_authz timeout at the gateway;
- disagreement between the ledger's `remaining` and the Redis cost counter, which is the direct
  measure of the ingest lag §5.4 leaves unquantified.

Exit criteria: zero unexplained `budget_unavailable`; the would-refuse set is exactly the set of
accounts the console also shows as exhausted; ingest lag measured.

**Stage 3 — enforce.** One commit, on a 1st-of-month 00:00 UTC boundary:
`shadowMode: false` **+** delete the monthly and weekly cost rule families **+** the exporter
co-change. Announce the 402 contract to client owners first — a new terminal status on a
previously-always-200 path is a client-visible API change.

**Rollback.** Stage 3 → Stage 2 is `shadowMode: true` and restoring the cost buckets; the counter
renumbering makes that a mid-window budget reset for the fleet, which is *generous*, not harmful,
and is the reason Stage 3 goes out on a boundary. Stage 2 → Stage 0 is `budgetLimiter.enabled:
false`, which removes the filter and the metadata step; no state to unwind. Stage 1 → Stage 0 is
removing the config block. Every step is a values change with no image roll.

---

## 11. Diagrams

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant EG as Envoy (core-gateway)
    participant AZ as Authorino<br/>ext_authz, filter 5
    participant B as authz-budget<br/>:3007 mTLS
    participant U as authz-usage<br/>/usage/v1/spend/query
    participant LUA as Lua budget-limiter<br/>filter 14
    participant M as model backend

    C->>EG: POST /v1/chat/completions (Bearer)
    EG->>AZ: ext_authz Check (failOpen:false)
    AZ->>AZ: JWKS identity, OPA/CEL authorization (unchanged)

    alt metadata cache HIT (within ttl, keyed on account_id)
        AZ-->>AZ: reuse cached budget answer — no hop
    else cache MISS
        AZ->>B: GET /budget/v1/remaining?account_id=… (mTLS, timeout 300ms)
        B->>B: effective_balance(account, period) — expiry-aware SUM(budget_grants)
        B->>U: POST /usage/v1/spend/query (mTLS)
        alt spend answered (incl. empty SUM ⇒ 0)
            U-->>B: {total_cost}
            B-->>AZ: 200 {ceiling, spent, remaining, next_reset_at}
        else spend unreachable, cached reading within grace
            B-->>AZ: 200 {…, source_lag_seconds: n}
        else spend unreachable, no cache / past grace
            B-->>AZ: 503 {"error":"budget_unavailable"}
        end
    end

    AZ-->>EG: OK + dynamicMetadata envoy.filters.http.ext_authz["budget"]
    Note over AZ,EG: a FAILED metadata fetch is non-fatal:<br/>Authorino leaves the value ABSENT, it does not deny

    EG->>LUA: continue filter chain (Lua is 12+index, always after ext_authz 5)
    alt shadow mode
        LUA-->>LUA: record decision in lightbridge.budget_limiter, always continue
        LUA->>M: forward
    else remaining_micros > 0
        LUA->>M: forward
        M-->>C: 200 (cost charged to usage_events AFTER the response)
    else remaining_micros <= 0
        LUA-->>C: 402 {"error":"budget_exhausted", account_id, next_reset_at, refill_url}
    else metadata absent (or the script raised)
        LUA-->>C: 503 {"error":"budget_unavailable"}
    end
```

```mermaid
stateDiagram-v2
    direction LR

    [*] --> Asking: request enters the Lua filter

    state "budget answer" as Ans {
        Asking --> Fresh: 200, source_lag_seconds = null
        Asking --> Stale: 200, source_lag_seconds = n<br/>(usage down, within grace)
        Asking --> Absent: metadata absent<br/>(503 / timeout / authz-budget down)
    }

    Fresh --> HasBudget: remaining_micros > 0
    Fresh --> NoBudget: remaining_micros <= 0
    Stale --> HasBudget: remaining_micros > 0
    Stale --> NoBudget: remaining_micros <= 0

    Absent --> NotMetered: no budget metadata AND no x-ai-eg-model<br/>(public catalog / MCP routes)
    Absent --> Unknown: a metered model request with no answer

    state "enforce mode" as Enf {
        HasBudget --> Pass
        NoBudget --> Deny402: budget_exhausted
        Unknown --> Deny503: budget_unavailable
        NotMetered --> Pass
    }

    state "shadow mode" as Sh {
        NoBudget --> PassLogged: decision=deny logged, request continues
        Unknown --> PassLogged
    }

    Pass --> [*]
    PassLogged --> [*]
    Deny402 --> [*]
    Deny503 --> [*]

    note right of Deny503
        UNREACHABLE by design: there is no edge from any
        state to "remaining = 0 because we could not ask".
        Unknown NEVER collapses into NoBudget — that is the
        single invariant this whole ADR exists to protect.
    end note
```

---

## 12. Consequences

**Good**

- A refill takes effect within one cache TTL (~10 s), on **both** planes — human and API-key —
  with no token refresh, no Keycloak write-back, and no claim to keep in sync. The product message
  becomes *"your refill is live in a few seconds"*.
- Arbitrary amounts work. ADR-0015's admin-configured ranges stop being quantised into seven
  rungs, and the memo's two claim-collapse defects stop being enforcement bugs.
- One source of truth for money. The console, the refill policy engine and the gateway all read the
  same `effective_balance − spend`; they cannot drift.
- No counter renumbering on a refill. Nothing about a grant changes which Envoy rule matches.
- `billing_plan` finally means one thing.

**Bad, and accepted**

- **A new dependency on the request path.** Bounded by a timeout, a cache, a grace window and
  `failOpen: false`, and it degrades to 503 rather than 403 or "allow" — but it is a new way for a
  model request to fail, and pretending otherwise would be dishonest. §1.1 is the argument that
  this shape is not the 2026-07-02 shape; shadow mode is how that argument gets tested rather than
  asserted.
- **Two counters disagree until Stage 3.** During shadow, the Redis cost counter and the ledger
  will not match, and the difference is the ingest lag. That is a feature of shadow mode (it is how
  the lag gets measured) and a source of confusion for anyone reading the quota dashboard mid-
  rollout. Say so in the runbook.
- **The 402 is a client-visible API change** on a path that has only ever returned 200/429/403.
- **Per-replica grace cache** means the grace window is best-effort during an outage, not a
  guarantee.
- **Enforcement now depends on ingest.** If `usage_events` ingest breaks silently, spend stops
  growing and every account looks under budget. Today's Redis counter has the same property (it is
  charged from the same `llm_custom_total_cost`), so this is not a regression — but it moves an
  ingest outage from "the dashboard is wrong" to "the limiter is wrong", and it needs an ingest
  freshness alert. That alert is a Stage 2 exit criterion.

---

## 13. The memo's eight owner decisions

The memo (`#658` §5) put eight questions. Most of them **dissolve** under this ADR rather than
being answered — that is the strongest argument for it. Recommendations, one line each:

| # | Question | Recommendation |
|---|---|---|
| **D1** | Claim or introspection as the source of `x-budget-tier`? | **Neither.** No tier header exists in this design. The gateway reads the live balance from the ledger; both planes are covered identically, because the answer is keyed on the account id, not on how the caller authenticated. ADR-0014's obsolete rationale (§1.2 of the memo) stops mattering. |
| **D2** | Tier ladder ↔ limit mapping — does `b-15` mean $15 or is the ladder re-anchored at today's $24? | **Dissolved.** There is no ladder at the gateway. The enforced number is whatever the ledger says, to the micro-USD. The base grant amount is a *policy* question for ADR-0015's rule data, not a gateway question. |
| **D3** | Off-ladder amounts — round down, round up, or constrain policy? | **Dissolved**, and this was the memo's highest-risk decision precisely because every answer was wrong. Arbitrary amounts are enforced exactly. |
| **D4** | Window semantics — does a refill reset the calendar bucket, or is a daily pacing descriptor added? | **A refill adds to the ledger balance; nothing resets.** ADR-0032 reset schedules already express "reset remaining to $2 every day" *as ledger rows*, and this design enforces the ledger — so the owner's literal ask becomes literally true for the first time, with no pacing-bucket substitute. |
| **D5** | Keep or retire the per-plan cost rules? | **Retire, at Stage 3, in the enforce commit** (§6). Running both is not belt-and-braces here: `min(plan, ledger)` means a refill still buys nothing once the plan bucket is spent, which is the original bug. Shadow mode is the safety net instead, and it is a better one. |
| **D6** | Counter identity — `sub` or `account_id`? | **`account_id` for money, `sub` for rate** (§7). Correct before and after ADR-0026, no cutover. |
| **D7** | Reset schedules vs. the tier claim — exclude `automatic` from the tier sources, or fix the mapping? | **Fix the mapping** (`from_amount_micros` → highest rung ≤ amount), and **do not** exclude `automatic`: excluding it would make the claim silently ignore the only mechanism that changes budget daily. No longer urgent — nothing enforces on the claim after this ADR — but still wrong, and cheap. Separate PR. |
| **D8** | Cutover date — does the reset-schedule rollout precede or follow 6a? | **Independent; ship reset schedules first** (they are already deployed). Shadow mode can start any day. **Stage 3 must be a 1st-of-month 00:00 UTC boundary** — 2026-10-01 at the earliest, and only if the shadow window's exit criteria are met, which one week of data will not settle if the ingest lag turns out to be large. 2026-11-01 is the realistic date. |

---

## 14. Alternatives considered

- **Memo §4.1/§4.2 — `x-budget-tier` header + one `Exact` rule per rung.** Rejected: §1's three
  properties. It remains the cheapest path if the live-lookup shape ever proves unsafe under load,
  and shadow mode is what would tell us that.
- **Authorino-native denial** (`authorization` rule + `response.unauthorized: {code: 402}`).
  Rejected on a checkable fact: `DenyWithSpec.Code` is a bare `int64` with one value per
  AuthConfig, and this AuthConfig already denies for three unrelated reasons that must stay 403
  (§4.1). Revisit if Authorino makes `Code` a `ValueOrSelector`.
- **ext_proc / a true Dynamic Budget Limiter component with reserve-and-settle.** Rejected: §4.2.
  It is the honest end state only if a *pre-request* cost estimate ever exists.
- **Grants decrement the Redis counter** (`plans/lightbridge-dynamic-budget.md` option B).
  Rejected: it makes `gateway_ratelimit_spend_micro_usd` mean "net of grants", silently changing
  what the ADR-0070 quota dashboard shows, and it means writing another service's key space.
- **Publish the balance as a request header instead of dynamic metadata.** Rejected: D2. A header
  is client-visible and, on any path where Authorino fails to stamp it, client-*supplied*.
