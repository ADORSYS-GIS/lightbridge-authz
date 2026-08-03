# RFC-0001: Dynamic budget refill and policy

- Status: Draft
- Date: 2026-07-31
- Author: @stephane-segning
- Source of truth: `~/Downloads/lightbridge_dynamic_budget_refill_opa_wasm_plan.md`

## Summary

Users can request more AI budget from the self-service UI. A policy decides whether that is
auto-approved, capped, sent for review or denied. Administrators can grant directly.
Automatic augmentation can fire when a configured threshold is crossed. Every increase is an
immutable grant; the gateway enforces the result.

## Motivation

Today a user who exhausts their monthly budget is simply stopped until the window rolls, and
the only remedy is an operator editing configuration. That is bad for the user and it puts a
human in the path of a decision that is usually mechanical.

## Design

### Domain (ADR-0009)

`budget_grants` (immutable) -> `budget_balances` (materialized, rebuildable by replay), plus
`budget_augmentation_requests` carrying the request state machine: `created`, `evaluating`,
`auto_approved`, `pending_review`, `approved`, `partially_approved`, `denied`, `cancelled`,
`expired`, `applied`.

Request, grant and balance update commit in one transaction under a lock on the balance.

### Decisions (ADR-0007)

One decision contract; rule-data evaluator first, OPA-Wasm second for `policy-admin`.
The host loads the facts, locks, evaluates, **re-validates hard invariants in application
and SQL**, applies, and records the decision with its policy revision and matched rule IDs.

Policy failure of any kind -> `manual_review` or `deny`. Never automatic approval.

### Automatic augmentation

Triggered by a state transition or scheduled reconciliation, **never** by granting on every
inference request. Idempotency comes from a deterministic key with a UNIQUE constraint:

```text
auto:{policy_revision}:{period}:{budget_account_id}:{rule_id}:{threshold}
```

That is what stops a budget which stays above a threshold from being granted repeatedly.

### Enforcement (ADR-0008)

Discrete tiers on `x-budget-tier`, propagated as a Keycloak claim. OIDC users only.

### Permissions

Roles are **not** hardcoded. The token carries a claim; this service maps claim values onto
the internal `budget:*` permission list via `config.yaml`:

```yaml
permissionMapping:
  claim: realm_access.roles
  map:
    ai-user:         [budget:read, budget:self-refill]
    budget-approver: [budget:read, budget:review]
    budget-admin:    [budget:read, budget:grant, budget:revoke, budget:audit-read]
    policy-author:   [budget:policy-read, budget:policy-write, budget:policy-simulate]
    policy-operator: [budget:policy-read, budget:policy-activate]
  default: [budget:read]
```

⚠️ Missing or unparseable config grants **nothing** and the service refuses to start.
⚠️ An unknown claim value maps to `default`, never to everything.

## Verification

- Replaying `budget_grants` reproduces `budget_balances` exactly.
- The same client request submitted twice with one idempotency key produces one grant.
- A budget held above a threshold across many evaluation cycles produces **one** automatic grant.
- A policy that fails to load leaves the previous revision serving, and the health endpoint
  reports the revision actually in use — not the one we tried to load.
- A tier change produces the expected new counter key, and the old one is orphaned by design.

## Risks and unknowns

- ⚠️ The tier re-key must land near a period boundary; the period is a calendar month
  (`YYYY-MM`, UTC), with the boundary on the 1st (ADR-0008, and the cutover runbook).
- ⚠️ Re-validate hard limits in application and SQL after the policy returns. A policy that
  recommends an amount above the platform cap must be clamped or denied by the backend, not
  trusted.
- Unlimited administrative grants are unlimited **at the business-policy level only** — they
  still require `budget:grant`, an audit reason, an actor, an idempotency key and a ledger row.

## Open questions

1. Which claim value maps to `budget:review` — i.e. who actually reviews? The mapping
   mechanism does not pick the people.
2. Do automatic augmentation triggers need a per-period cap of their own, separate from the
   self-service rung cap?
3. Should a pending request expire, and after how long?

## Decisions produced

- [ADR-0009](../adr/0009-budget-grants-are-an-immutable-ledger.md)
- [ADR-0007](../adr/0007-refill-decisions-rule-data-then-opa-wasm.md)
- [ADR-0008](../adr/0008-refills-are-discrete-budget-tiers.md)
