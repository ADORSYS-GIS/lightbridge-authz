# Runbooks

| Runbook | Open it when |
|---|---|
| [release-and-rollout.md](./release-and-rollout.md) | You merged something and need to know whether it is live — or it should be and is not. Covers the CI→GHCR→cosign→argocd-image-updater→ArgoCD chain step by step, the `/version` check, and the two links in it that are currently broken |
| [budget-tier-rekey-cutover.md](./budget-tier-rekey-cutover.md) | Performing the one-time move from per-plan budget rules to the tier ladder |
| [stuck-augmentation-request.md](./stuck-augmentation-request.md) | A user says their refill "did nothing", or a request is stuck pending |
| [roll-back-a-budget-policy.md](./roll-back-a-budget-policy.md) | A policy revision is approving or denying the wrong things |
| [budget-remaining-snapshot.md](./budget-remaining-snapshot.md) | Metered requests return `503 budget_unavailable`, `budget_snapshot_age_seconds` is climbing, or a refill "did not take effect" (ADR-0034 §15 — the backend half of the Dynamic Budget Limiter) |
| [signing-key-management.md](./signing-key-management.md) | Users are suddenly asked to log in again, a refresh returns `400 invalid_grant`, or you need to inspect/create/rotate `authz-idp`'s signing keys |

## Runbooks that live elsewhere, on purpose

| Task | Where it lives | Why not here |
|---|---|---|
| **Grant the first platform admin** (`lightbridge-authz rbac grant`) | the CLI half is [`docs/rbac.md` → Bootstrap runbook](../rbac.md#bootstrap-runbook-the-first-admin); the cluster half — which Job runs it, against which secret, and the `claim_mappers` flip that must follow — is an **`ai-helm-values`** runbook | The command needs a pod with `CONFIG_PATH` and database credentials, and the step after it edits `environments/prod/values/lightbridge-app.yaml`. Both are deploy-repo facts, and a second copy here would rot against the one that is actually executed. The **ordering** it must obey (A2 → A5 → B3 → B1 → C9) is recorded in [ADR-0033](../adr/0033-platform-roles-are-a-table-stamped-at-mint.md) and in [release-and-rollout.md Step 6](./release-and-rollout.md#step-6--the-first-admin-is-not-in-this-repo) |
| **Fund an account by hand** (`lightbridge-authz budget grant`) | [`docs/budget-cli.md`](../budget-cli.md) | It is an operator *tool*, not a symptom. The runbook that sends you to it is [budget-remaining-snapshot.md](./budget-remaining-snapshot.md) §7, when an account reads `known: true, remaining <= 0` because it was never granted anything |
| Per-platform Helm install/config/deploy commands | [`docs/platform-guides.md`](../platform-guides.md) | Not incident response — it is a setup guide |
| **Rolling the Dynamic Budget Limiter out** (`budgetLimiter` flags, the AuthConfig, shadow → enforce) | an **`ai-helm-values`** runbook, `docs/runbooks/budget-limiter-rollout.md` | Every step of it is a values change: the AuthConfig lives in `environments/prod/values/security-policies.yaml` and the flags in `core-gateway.yaml`. The backend half — the snapshot table, the refresher, the introspection fields — is [budget-remaining-snapshot.md](./budget-remaining-snapshot.md) above |
| Re-measuring a slow usage query on the replica | [`docs/usage-performance.md`](../usage-performance.md#re-measuring-safely) | It belongs with the measurements it reproduces |
