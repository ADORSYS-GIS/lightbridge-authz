# Roll back a budget policy

**Symptom:** a policy revision is approving things it should not, denying things it should
not, or sending everything to manual review.

## 0. Find out what is actually active

Not what was last activated — what is **serving**. Those differ precisely when something has
gone wrong, because a failed load leaves the previous revision in place (by design).

```bash
curl -s -X POST https://<host>/rpc/getBudgetPolicyStatus \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policySetId":"budget-refill"}'
# -> {"policySetId":"budget-refill","activePolicyRevision":"<revision>"}
```

There is no separate `/health` field for this today — the rule-data engine this procedure reads
has no bundle to checksum and no separate load-error state to expose (`bundleChecksum`/
`lastLoadError` are OPA-Wasm-engine concepts, a later phase; nothing in this service produces them
yet). `getBudgetPolicyStatus` reads the live in-memory engine directly (no DB round-trip), so it
always reflects what a real request would see right now, not what was last *attempted*.

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
# Reactivate the previous revision (by id, not by resubmitting its rule data -- resubmission
# would collide with the revisions table's uniqueness constraint on policy_revision).
curl -X POST https://<host>/rpc/activateBudgetPolicy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policySetId":"budget-refill","revisionId":"<previous>"}'
# -> {"policySetId":"budget-refill","activePolicyRevision":"<the previous revision's policy_revision>"}
```

Activation is atomic: the running evaluator keeps serving the old revision until the new one is
fully loaded and validated. A failed rollback therefore leaves the **bad** revision serving — so
re-check with `getBudgetPolicyStatus` (step 0) rather than assuming the call worked.

## 2. Confirm with a simulation, not a live request

```bash
curl -X POST https://<host>/rpc/simulateBudgetPolicy \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"policyRevision":"<active>","scenario":{ ... }}'
```

Simulation never writes a grant or touches a balance. Use the scenario that misbehaved.

## 3. Clean up what the bad revision did

Grants are immutable (ADR-0009), so a wrong grant is corrected by a **compensating
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
