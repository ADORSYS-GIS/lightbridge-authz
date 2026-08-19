# ADR-0016: The migrate Job is an ArgoCD sync-wave, not a Helm hook

- Status: Accepted
- Date: 2026-08-19
- Decision owners: @stephane-segning

## Context

Prod (`lightbridge-app`, ArgoCD `home-remote`/`converse`) is crash-looping on:

```
Error: Server("failed to load active budget policy: invalid rule data: failed to parse rule
data JSON: missing field `allowed_amounts_micros` at line 1 column 347")
```

PR #386 (ADR-0015) added required fields to the rule-data `RuleSet` and shipped
`migrations/20260819000001_budget_policy_adr0015_amounts.sql` to backfill them. The image
promoted via argocd-image-updater; the migration never ran. `maxUnavailable: 0` kept the old
(pre-#386) pods serving, so there was no outage, but the rollout is wedged: new pods for
`api`/`idp`/`budget` crash on the missing field and never become Ready.

### Why the migrate Job never ran

`charts/lightbridge-authz`'s `migrate` controller (a bjw-s/common `job`, inherited unchanged by
the `api`/`opa`/`idp`/`budget` aliases) was a Helm hook:

```yaml
annotations:
  "helm.sh/hook": post-install,post-upgrade
  "helm.sh/hook-weight": "-5"
  "helm.sh/hook-delete-policy": hook-succeeded
```

`post-install,post-upgrade` is a **PostSync** hook in ArgoCD's mapping. A PostSync hook runs
only after every non-hook resource in the sync — including the `main` Deployment — is already
Synced *and* Healthy. That ordering is backwards from what the name suggests: it was never a
"run before the app starts" hook, it always ran *after*. This was survivable as long as every
migration was backward-compatible enough that the app stayed healthy on the old schema. ADR-0015
made a rule-data field required at startup, so a new pod can never pass its readiness probe
without the migration — which means the Deployment can never go Healthy — which means the
PostSync hook that would run the migration never fires. A permanent deadlock, not a timing
window: ArgoCD's `selfHeal` retries the sync every few minutes forever and lands in the exact
same place each time.

Confirmed live against prod on 2026-08-19, independent of the chart source:

- `argocd app resources lightbridge-app` listed **zero** `Job` resources anywhere in the tree —
  not managed, not orphaned.
- `kubectl --context hetzner-prod get jobs -n converse` and `get events -n converse` — no Job,
  no Job event, in either the live namespace or its event history.
- `kubectl get application lightbridge-app -n argocd -o json` → `status.operationState`: `phase:
  Failed`, `message: one or more synchronization tasks completed unsuccessfully`,
  `syncResult.resources` lists every `Deployment`/`Service`/`ConfigMap`/... in that sync — with
  **no `batch/Job` entry at all**. The three affected Deployments each show `hookPhase` absent
  and `status: Failed` with `message: Deployment "..." exceeded its progress deadline`.
- `argocd app manifests lightbridge-app --revision 3.6.0` (the pinned target revision) **does**
  render the `lightbridge-api-migrate` / `-budget-migrate` / `-idp-migrate` / `-opa-migrate` /
  `-usage-migrate` Jobs, each still carrying the `post-install,post-upgrade` hook annotation —
  so the Job was never *missing* from the desired manifest and was never disabled in prod
  values (`charts/.../values.yaml` and `ai-helm-values`' `environments/prod/values/
  lightbridge-app.yaml` both configure `migrate:` fully, only overriding its `DATABASE_URL`
  secretKeyRef). It was rendered, recognized as a PostSync hook, and never applied to the API
  server because the hook phase was never entered.

This has been the hook type since the Job was introduced in #135 (`dcf1e71`) — it did not
regress recently. Ruled out candidates from the incident brief: the migration alias is not
disabled in prod values (confirmed above); the hook did not run-then-get-TTL-deleted (if it had
run, the migration would have applied and the pods would be healthy, which they are not); this
is not a partial-sync artifact (the sync's own resource list shows every non-hook resource
Synced, only the hook was never entered).

### Why the previous fix (#150) doesn't reach this failure mode

PR #150 added `ttlSecondsAfterFinished: 300` after a *different* incident: a completed
static-named hook Job that ArgoCD's `hook-delete-policy: hook-succeeded` cleanup silently failed
to delete, which then made every later deploy's hook-creation step a silent no-op against the
existing, immutable Job object (2026-07-23, two days of stale schema in prod). That fix assumed
the hook fires; it does nothing when the hook never fires at all, which is this incident.

## Decision

Replace the Helm hook with an **ArgoCD sync-wave**, and give the Job a **name that varies with
the image being deployed** instead of a static name plus TTL cleanup.

```yaml
# charts/lightbridge-authz/values.yaml (mirrored in charts/lightbridge-authz-usage)
controllers:
  migrate:
    type: job
    suffix: '{{ printf "%s:%s" .Values.global.authz.image.repository
                .Values.global.authz.image.version | sha256sum | trunc 10 }}'
    job:
      backoffLimit: 3
      ttlSecondsAfterFinished: 604800   # 7 days
    annotations:
      "argocd.argoproj.io/sync-wave": "1"

  main:
    type: deployment
    annotations:
      "argocd.argoproj.io/sync-wave": "2"
```

**Ordering.** ArgoCD applies resources in ascending sync-wave order and waits for each wave to
be Healthy before starting the next. `migrate` is wave `1`; `main` is wave `2`; everything else
(ConfigMaps, Secrets, Services, Ingresses, PDBs, Certificates) stays at the implicit default wave
`0`, which the migrate Job depends on (its config/DB secret) and which is therefore guaranteed to
already exist. This reverses the hook's ordering: the app's own Deployment health is no longer a
precondition for the migration to run — the migration's own health (`Job` reaching `Complete`) is
now a precondition for the Deployment to be touched at all.

**Immutability / naming.** Kubernetes Jobs are immutable after creation, and without a hook there
is no `hook-delete-policy` to remove a stale one before the next apply. Re-applying an unchanged
name with a changed spec fails outright ("field is immutable"), and once hooks are gone that
failure would recur, silently, on every future deploy — reproducing this exact incident by a
different mechanism. `suffix` (a generic bjw-s/common field, already run through the same `tpl`
pass this chart uses for its image repository/tag strings) makes the Job's name a hash of the
image repository + tag actually being deployed:

- A new image tag renders a new Job name → a fresh Job is guaranteed to run.
- Re-syncing the *same* image (e.g. a values-only change unrelated to the migrate container)
  renders the *same* name with an *identical* spec → a true no-op, not a collision.

**Retention.** `ttlSecondsAfterFinished: 604800` (7 days) replaces the 300-second value #150
set for an entirely different purpose (name-collision avoidance, no longer a concern once the
name is per-image). The only remaining question is "how long should a completed migration stay
inspectable", and native Kubernetes Job GC answers it independently of ArgoCD's own
hook-finalizer/prune paths — the same "don't depend on the one mechanism that already failed
once" reasoning #150 used, applied one layer further out.

**Failure is loud.** If `migrate` fails (exceeds `backoffLimit`, Job condition `Failed`), ArgoCD
marks it Degraded and does not advance to wave `2` — `main` is never touched, so the
currently-running (already-migrated) pods keep serving unchanged. The sync operation itself
shows `Failed`/`Degraded` in `argocd app get` and the Application's own health, which is exactly
the visibility a hook-based failure did not have (a failed *hook* still leaves the Application
"Synced", and this repo's prod incident review had to reconstruct hook state from `argocd app
manifests` rather than reading it off the Application's live status).

## Consequences

**Positive**
- The exact deadlock in this incident (migration required for app health, app health required
  to run the migration) cannot recur — the dependency direction is now the other way.
- `kubectl get jobs -n converse` after any deploy shows the migrate Job that ran, its name
  encoding which image it ran for, for up to 7 days — this incident could have been diagnosed
  in seconds instead of requiring `argocd app manifests`/`syncResult` archaeology.
- No dependency on ArgoCD's hook-finalizer or `hook-delete-policy` paths at all, which is the
  exact mechanism #150 already found to be unreliable once (the stuck-hook incident).

**Negative**
- One extra sync-wave round-trip on every deploy (ArgoCD waits for the Job to complete before
  touching the Deployment) — bounded by the existing `backoffLimit: 3`, and strictly less total
  wall-clock than the retry loop a wedged sync already runs today.
- `api`/`opa`/`idp`/`budget` still each render and run their own `migrate` Job against the same
  database (pre-existing redundancy noted in `charts/lightbridge-authz-stack/values.yaml`, not
  introduced or changed here) — safe because sqlx takes a Postgres advisory lock, but now that
  is 4 Jobs per deploy instead of 4 PostSync hooks; not addressed by this ADR.

**Neutral / follow-ups**
- This ADR does not touch `charts/lightbridge-authz-stack/templates/global-tls-job.yaml`'s own
  `pre-install,pre-upgrade` hook (TLS bootstrap) — that one is a correct use of a PreSync hook
  and is out of scope here.
- Prod is separately emitting `MultiplePodDisruptionBudgets` warnings: chart 3.6.0 added a
  native `controllers.<name>.podDisruptionBudget` (creating `lightbridge-api-main`/`-idp-main`/
  `-mcp` PDBs) while `ai-helm-values`' `environments/prod/values/lightbridge-app.yaml` still
  carries the older hand-written `rawRessources` PDBs (`lightbridge-api-pdb`/`-idp-pdb`/
  `-mcp-pdb`) targeting the same pods via `rawRessources`' comment ("the upstream chart doesn't
  support controller PDBs natively" — no longer true as of the vendored common 4.6.2). Confirmed
  live: `kubectl get pdb -n converse` lists both pairs, and `get events --field-selector
  reason=MultiplePodDisruptionBudgets` shows Kubernetes arbitrarily picking one per pod. This is
  a values-repo cleanup (delete the three `rawRessources` PDB entries), not a chart change, and
  is not made in this ADR/PR.

## Alternatives considered

- **`argocd.argoproj.io/sync-options: Replace=true` on a static name** — makes ArgoCD use
  `kubectl replace` instead of `apply` for that resource. Rejected: `Replace=true` applies on
  *every* sync operation, not only when an immutable-field conflict would otherwise occur —
  including ArgoCD's periodic no-op reconciliation and every `selfHeal` pass — so the Job would
  be deleted and recreated every few minutes even when nothing changed, defeating the
  inspectability this ADR is also trying to fix.
- **`generateName` instead of a deterministic name** — rejected: ArgoCD tracks and diffs managed
  resources by exact name against the desired manifest; a random per-apply suffix can never be
  reconciled against anything ArgoCD rendered, which is a documented ArgoCD anti-pattern and
  would either spawn a new Job every reconcile or leave every generated Job unmanaged/orphaned.
- **A whole-`values.yaml` checksum as the name suffix** — rejected: would mint a new migrate Job
  on every values change, including ones the migrate container never observes (e.g. an Ingress
  annotation), which is noisier than necessary. The image repository + tag is the one input that
  actually determines which migrations the `migrate` binary embeds.
- **Keep the hook, fix only the weight/order** — rejected: no hook-weight value fixes a *PostSync
  vs PreSync* type mismatch; `pre-install,pre-upgrade` would fix the ordering but reintroduces
  the exact static-name/immutability failure mode #150 already fixed once, this time with no TTL
  backstop at all unless re-added, and hook resources remain invisible in the Application's own
  live resource tree the way this incident already showed is a diagnosis cost.

## Related

- PR #386 (ADR-0015, the required rule-data fields that exposed this deadlock)
- PR #150 (`4cd163c`, the prior static-name/TTL incident, a different failure mode of the same
  underlying "hook Job" design)
- `charts/lightbridge-authz-stack/templates/global-tls-job.yaml` (a correctly-ordered PreSync
  hook, left unchanged)
