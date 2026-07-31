# Stuck augmentation request

**Symptom:** a user says they requested more budget and "nothing happened", or a request is
sitting in `pending_review` longer than expected.

## 0. Separate the three things this can mean

They look identical to the user:

1. The request was **denied** and the UI did not make that clear.
2. The request is **pending review** and no reviewer has acted.
3. The request was **approved** and applied, but the gateway has not seen the new tier yet.

```sql
SELECT id, status, requested_amount_micros, approved_amount_micros,
       policy_effect, policy_reason_codes, matched_rule_ids, policy_revision,
       created_at, reviewed_at
FROM budget_augmentation_requests
WHERE account_id = :account AND period = :period
ORDER BY created_at DESC LIMIT 5;
```

`policy_effect` and `reason_codes` say exactly which rule decided, and under which revision.

## 1. If it is (3) — approved but not effective

This is the common one and it is **expected behaviour, briefly**. The tier reaches the
gateway as a Keycloak claim (ADR-0008), so it takes effect **at the user's next token
refresh**, not immediately.

```bash
# Did the grant land?
psql -c "SELECT id, amount_micros, source, created_at FROM budget_grants
         WHERE account_id = '<account>' ORDER BY created_at DESC LIMIT 3;"
# Did the Keycloak attribute get written?
kubectl --context admin@homeos -n keycloak exec deploy/keycloak -- \
  /opt/keycloak/bin/kcadm.sh get users -r camer-digital -q username=<user> --fields id,attributes
```

- Grant present, attribute present -> tell them to sign out and back in. Nothing is broken.
- Grant present, attribute **missing** -> the write-back failed. That is a real bug; capture
  the request ID and the grant ID before retrying anything.

Confirm what the gateway actually sees rather than inferring it — decode the user's current
token and look for the tier claim.

## 2. If it is (2) — pending review

```sql
SELECT id, requested_by, created_at, policy_reason_codes
FROM budget_augmentation_requests WHERE status = 'pending_review' ORDER BY created_at;
```

Check that anyone holds `budget:review` at all — a claim value that maps to nothing means
requests queue forever with no reviewer and no error anywhere:

```bash
grep -A15 permissionMapping config/default.yaml
```

⚠️ **Re-evaluate before approving.** Budget state moves while a request waits, so approving
a stale decision can grant against facts that are no longer true. Approval re-runs the
policy under lock by design; do not bypass that.

## 3. If it is (1) — denied

`policy_reason_codes` and `matched_rule_ids` name the rule. If the denial is wrong, that is
a **policy** problem, not a request problem — fix the rule data and let them resubmit. Do
not hand-grant around a policy you believe is correct; if you do, record why in the grant's
`reason`, because that row is the only place the exception will ever be visible.

## 4. Balance and ledger disagree

```bash
governance-ctl budget verify --account <id> --period <period>   # or the equivalent job
```

⚠️ If they diverge: **stop mutating and reconcile.** Do not "fix" the balance — it is a
materialized view of the ledger (ADR-0006), so the divergence is evidence of a bug, and
overwriting it destroys the evidence while leaving the bug.
