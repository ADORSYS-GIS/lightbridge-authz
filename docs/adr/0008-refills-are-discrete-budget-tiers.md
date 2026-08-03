# ADR-0008: Refills are discrete budget tiers on their own header, not arbitrary amounts

- Status: Proposed
- Date: 2026-07-31
- Decision owners: @stephane-segning

## Context

A refill has to actually change what the gateway lets a user spend. It does not, today, and
the reason is mechanical.

The monthly budget is a **static Envoy rate-limit rule** rendered by Helm into a
`BackendTrafficPolicy` (ai-helm `charts/ai-model`): one rule per billing plan, the limit
value baked in at render time, matched on `x-account-id` (`Distinct`) + `x-billing-plan`
(`Exact`). The Lyft ratelimit service then keys each redis counter on the rule's **position
in the rendered list**, because plan names are `Exact` matches and render as masked constants.

ai-helm **ADR-0084** records what that costs when it is got wrong: adding a plan to a Helm
*map* sorted it to index 0 mid-window, shifted the others, orphaned every account's
accumulated spend, and silently gave the whole fleet a fresh budget. It was a live incident,
confirmed by `SCAN`.

So there is no per-account allowance to raise. There are N static limits and a counter per
(rule index, account, window).

## Decision

Refills are **discrete tiers**, and the budget dimension moves onto its **own header**.

`x-budget-tier` is stamped on every request; the billing plan determines the **starting
rung**; a refill moves the account up one shared ladder. The per-plan budget rules retire.

```text
b-15     <- free starts here
b-30
b-60
b-120
b-250
b-500
b-1000   <- enterprise starts here
```

Two rungs unaided per period; beyond that, `manual_review`. Both numbers are rule data, so
they change without a deploy.

The tier reaches the gateway as a **Keycloak claim** -- this service writes a user attribute
when a grant lands, a protocol mapper turns it into a claim, Authorino stamps it with a CEL
default. **Not** a live lookup: the Keycloak introspection metadata step was disabled in
production on 2026-07-02 (#533) because the ext_authz timeout is shorter than the lookup
latency, which turns a slow dependency into fail-open.

Refills are **OIDC users only**. Internal/API-key clients have a different access model and
keep plan-level budgets.

## Consequences

**Positive**
- Expressible in the append-only rule machinery that already exists. **No new component in
  the inference data path.**
- One ladder instead of plans x steps, and `x-billing-plan` keeps meaning exactly one thing.

**Negative**
- ⚠️ **A tier change resets the window's counter.** Moving from the $15 rule to the $20 rule
  means the account stops matching one rule and starts matching another: new key, counter at
  zero. A user at $15-of-$15 who refills does not get $5 more, they get **$20 more**. This is
  accepted: a refill is *"an upgrade for the remainder of the period"*, not a top-up. Tiers
  are therefore period **totals**, repeated refills inflate, and the per-period rung cap is
  what bounds it. The ledger stays truthful regardless.
- **A refill takes effect at the next token refresh**, not instantly. Say so in the UI.

**Neutral / follow-ups**
- ⚠️ The ladder is **append-only**. `b-2000` may be added; no rung may ever be reordered or
  removed. This is ADR-0084's rule and it applies unchanged.
- ⚠️ The cutover retiring the per-plan rules moves every counter and **must land near a
  period boundary**. The window is a fixed 30-day epoch bucket (`floor(now/2592000)*2592000`),
  **not** a calendar month. See the runbook.

## Alternatives considered

- **Extend the plan list** (`free+1`, `free+2`, per plan) -- rejected: plans x steps
  combinatorics, and `x-billing-plan` would mean two things.
- **Grants decrement the redis counter** -- rejected: it makes
  `gateway_ratelimit_spend_micro_usd` mean *net of grants*, silently changing what the
  ADR-0070 quota dashboard displays.
- **Replace Envoy's enforcement with a live-allowance limiter** -- deferred. It is the honest
  answer for arbitrary amounts, and it is a new component in the path of every AI request.

## Related

- ADR-0007 (decisions), ADR-0009 (ledger)
- Runbook: `docs/runbooks/budget-tier-rekey-cutover.md`
- ai-helm ADR-0021, **ADR-0084**, ADR-0110, ADR-0070
