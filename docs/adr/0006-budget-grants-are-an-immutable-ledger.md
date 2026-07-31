# ADR-0006: Budget grants are an immutable ledger with a materialized balance

- Status: Proposed
- Date: 2026-07-31
- Decision owners: @stephane-segning

## Context

Users need to be able to ask for more AI budget, and administrators need to be able to
grant it. The obvious implementation -- a mutable `budget` column that goes up when someone
is granted more -- destroys the audit trail: after the fact there is no way to say who
granted what, under which policy, or whether a number is the result of one grant or five.

This also has to survive being wrong. A refill system will mis-grant at some point, and the
recovery has to be better than "edit the number back".

## Decision

Every allocation or adjustment is an **immutable grant row**. Nothing is ever updated in
place; corrections are new rows.

```text
budget_grants        id, budget_account_id, account_id, project_id, period,
                     amount_micros, source, actor_id, reason, policy_revision,
                     matched_rule_ids, idempotency_key, trigger_key,
                     created_at, expires_at, revoked_at, metadata

budget_balances      budget_account_id, period, base_total_micros,
                     self_service_total_micros, admin_total_micros,
                     automatic_total_micros, refund_total_micros,
                     effective_budget_micros, self_service_grant_count,
                     automatic_grant_count, version, updated_at
```

`budget_balances` is a **materialized view of the ledger** and must be rebuildable by
replaying it. Grant sources: `base`, `self_service`, `admin`, `automatic`,
`manual_approval`, `refund`, `correction`, `promotion`, `migration`.

The request, the grant and the balance update commit in **one transaction**, under a lock
on the balance row.

Amounts are integer micro-USD. No floats.

## Consequences

**Positive**
- "Why does this account have this budget" is answerable exactly, months later.
- Recovery from a bad grant is a compensating `correction` row, not an edit -- so the
  mistake and the fix are both visible.
- The replay test (rebuild balances from grants, compare) is a real invariant that catches
  a whole class of accounting bug.

**Negative**
- More rows and a reconciliation job. Trivial at our volume.
- Every write path must go through the ledger. That is the point, and it needs enforcing in
  review, because a direct balance update would be silent and would work.

**Neutral / follow-ups**
- `idempotency_key` (client-supplied) and `trigger_key` (automatic augmentation) both carry
  UNIQUE constraints. Duplicate submission returns the original result rather than granting twice.
- If the balance and the ledger ever diverge, **stop mutating and reconcile**. Do not
  "fix" the balance -- the divergence is the evidence.

## Alternatives considered

- **A mutable balance column** -- rejected: no audit trail, and no way to recover from a bad
  grant except another untraceable edit.
- **Event sourcing the whole domain** -- rejected as disproportionate. The ledger gives the
  auditability we need for the one thing that needs it.

## Related

- ADR-0007 (how a refill is decided), ADR-0008 (how it is enforced at the gateway)
- RFC: `docs/rfc/0001-budget-refill.md`
- ai-helm ADR-0021 (rate limiting), ADR-0028 (cost-recovery pricing)
