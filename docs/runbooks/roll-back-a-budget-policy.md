# Roll back a budget policy

**Symptom:** a policy revision is approving things it should not, denying things it should
not, or sending everything to manual review.

## 0. Find out what is actually active

Not what was last activated — what is **serving**. Those differ precisely when something has
gone wrong, because a failed load leaves the previous revision in place (by design).

```bash
curl -s https://<host>/health | jq '{activePolicyRevision, bundleChecksum, lastLoadError}'
```

```sql
SELECT policy_revision, policy_effect, COUNT(*)
FROM budget_augmentation_requests
WHERE created_at > now() - interval '24 hours'
GROUP BY 1, 2 ORDER BY 3 DESC;
```

That query answers "is this revision behaving differently from the last one" with data
rather than impression.

## 1. Stop the bleeding

Deactivating is faster than fixing, and a revision that is denying everything is doing less
harm than one approving everything — triage accordingly.

```bash
# Reactivate the previous revision
curl -X POST https://<host>/rpc/activateBudgetPolicy \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"policySetId":"<id>","revisionId":"<previous>"}'
```

Activation is atomic: the running evaluator keeps serving until the new bundle is fully
loaded and validated. A failed rollback therefore leaves the **bad** revision serving — so
re-check `/health` rather than assuming the call worked.

## 2. Confirm with a simulation, not a live request

```bash
curl -X POST https://<host>/rpc/simulateBudgetPolicy \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"policyRevision":"<active>","scenario":{ ... }}'
```

Simulation never writes a grant or touches a balance. Use the scenario that misbehaved.

## 3. Clean up what the bad revision did

Grants are immutable (ADR-0006), so a wrong grant is corrected by a **compensating
`correction` row**, never by editing or deleting:

```sql
SELECT id, account_id, amount_micros, policy_revision, matched_rule_ids
FROM budget_grants WHERE policy_revision = '<bad revision>' ORDER BY created_at;
```

Both the mistake and the fix stay visible. That is the point of the ledger.

⚠️ A correction changes the **allowance**, not consumption. It does not claw back money
already spent, and it does not reset the runtime counter — see ADR-0008 for why the counter
and the ledger are deliberately different things.

## 4. Before re-activating a fixed revision

Run the scenario suite against it, including the case that failed. A revision that only
passes the tests written before the incident is a revision that will fail the same way.
