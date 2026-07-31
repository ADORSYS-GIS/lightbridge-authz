# Budget tier re-key cutover

**When:** the one-time move from per-plan monthly-budget rules to the `x-budget-tier` ladder
(ADR-0008). Read this whole page before starting. This is the ai-helm ADR-0084 blast zone.

## What actually happens

Retiring the per-plan rules and introducing tier rules changes **which rule each request
matches**, and the Lyft ratelimit service keys its redis counters on the rule's position in
the rendered list. So every account's counter moves to a new key and starts at zero.

That is not avoidable. It is *timed* instead.

## 1. Know where the window boundary is — it is not the 1st

The budget window is a fixed 30-day epoch bucket, `floor(now / 2592000) * 2592000`. It has
nothing to do with calendar months, despite `unit: Month` in the rendered rule.

```bash
python3 -c "
import datetime; W=2592000
now=int(datetime.datetime.now(datetime.timezone.utc).timestamp())
f=lambda t: datetime.datetime.fromtimestamp(t,datetime.timezone.utc)
print('current window starts', f((now//W)*W))
print('next window starts   ', f((now//W)*W + W))"
```

Confirm against reality rather than arithmetic — the live keys carry the window:

```bash
kubectl -n redis-system exec deploy/redis-ha-haproxy -- \
  redis-cli --tls --cacert /etc/ssl/certs/internal-gateway-ca.pem \
  -a "$REDIS_PASSWORD" --scan --pattern '*rule-*-match-0*' | head -5
```

**Deploy shortly BEFORE a boundary, not on it and not just after.** Landing a few days
before means the boundary absorbs the reset; landing just after means everyone carries an
extra full budget for nearly 30 days. Deploying exactly at 00:00 UTC is needlessly fiddly.

## 2. Same PR, or the quota dashboard goes blank

The `prometheus-redis-exporter` SCANs on **rule indices**
(`REDIS_EXPORTER_CHECK_KEYS=db0=*rule-2-match-0*,db0=*rule-7-match-0*`), and its values file
says to keep it in lockstep with `monthlyBudget.plans`. Retiring those rules without
updating it makes `gateway_ratelimit_spend_micro_usd` go silent.

One PR must cover:

- the tier rules in `charts/ai-model` / `core-gateway` (**appended**, never reordered);
- the exporter's `REDIS_EXPORTER_CHECK_KEYS` patterns;
- the ServiceMonitor `metricRelabelings` (they parse `plan` out of the key);
- `tools/dashboards/.../ratelimit_quota.py`, regenerated and committed.

⚠️ Keep `window` as a label. Dropping it collides two buckets at rollover and produces a
duplicate-sample scrape error.

## 3. Before you deploy

- Every account has a `x-budget-tier` claim, **and** the Authorino CEL has a default rung.
  An account with no claim must land on a sane rung, not on *no matching rule* — that is the
  difference between "starts at their base budget" and "is unlimited".
- Render and read the manifest. Rule indices are in the generated comments; check them.

## 4. After you deploy

```bash
# New keys appearing?
... --scan --pattern '*budget-tier*' | head
# Metric still populated?  (blank here means step 2 was missed)
curl -s "$MIMIR/api/v1/query?query=gateway_ratelimit_spend_micro_usd" | jq '.data.result | length'
```

Then send one real request from a test account and confirm its counter increments **on the
new key**. A dashboard that still looks right can be reading stale data; the counter is the
witness.

## 5. If it goes wrong

Reverting re-keys everyone *again* and is usually worse than going forward. The exception is
step 2 being missed — that is a metrics-only fix and can be rolled forward immediately
without touching the rules.
