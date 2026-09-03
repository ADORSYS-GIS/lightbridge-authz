---
name: authz-release-verify
description: Answer "is my merged change actually live?" for lightbridge-authz — CI concurrency and what a cancelled run means for images, the cosign signature that IS the production gate, the argocd-image-updater write-back, the lightbridge-app ArgoCD app on home-remote, GET /version, and the two links in the chain that are currently broken (#666 chart publishing, ADR-0031 accepted but unimplemented). Use after merging, before saying something shipped, or when production is running older code than main.
---

# Is it live?

The full procedure with commands, expected output and a triage table is
[`docs/runbooks/release-and-rollout.md`](../../../docs/runbooks/release-and-rollout.md); the topology
behind it is [`docs/architecture/deployment.md`](../../../docs/architecture/deployment.md). **Read
the runbook rather than re-deriving any of this.** What follows is the short form and the traps.

## The one-screen answer

```bash
# 1. Did a run survive for this commit?
zsh -i -c 'gh run list -R ADORSYS-GIS/lightbridge-authz --branch main -L 10 \
  --json headSha,conclusion,displayTitle --jq ".[] | [.headSha[0:7], .conclusion] | @tsv"'

# 2. What is production actually pinned to?
zsh -i -c 'kubectl get application lightbridge-app -n argocd -o json' \
  | python3 -c 'import json,sys;[print(" ",i) for i in json.load(sys.stdin)["status"]["summary"]["images"]]'

# 3. What does the running binary say it is?
curl -s https://auth.ai.camer.digital/version | python3 -m json.tool
```

If (3) reports your commit, it is live. If it does not, (1) and (2) say where it stopped.

## Five things that will mislead you

1. **A green CI run does not mean an image exists for your commit.** `ci.yml:21-23` puts all of
   `main` in one concurrency group with `cancel-in-progress: true`. Two merges close together cancel
   the first run — it goes `cancelled`, not red — and `container-build` never reaches `cosign sign`.
   The *content* still ships inside the later commit's image, but `sha-<commit>` is not a tag that
   exists for every commit on `main`.

2. **The cosign signature IS the production gate.** `argocd-image-updater` promotes only a digest
   that has a signature. Trivy runs *after* the push and *before* the signature (`ci.yml:253` then
   `:281-294`), so a HIGH/CRITICAL finding leaves a perfectly good-looking image in GHCR that will
   never be promoted, with nothing red downstream. Check `<digest>.sig` → `200`; the script is in
   `deployment.md`.

3. **`version` in `/version` is not a deploy identity.** It is the crate version release-please last
   cut, and two pods built from different commits can share it. Compare `gitShortSha` /
   `imageBuildSha`.

4. **Images and releases run on different clocks.** Images ship per commit; GitHub Releases and
   charts ship per tag. As of 2026-09-03 they are seven PRs apart — `10.0.0` was cut *before* #663,
   #665, #667, #668, #669, #670 and #672, all of which are live as images.

5. **Chart publishing has been silently broken since `v5.0.0`**
   ([#666](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/666), open). release-please tags
   with `GITHUB_TOKEN`, which never fires a `push: tags` workflow, so `helm-oci.yml` simply stopped
   running. A chart change is **not** live when the release PR merges. Verify, then dispatch by hand:

   ```bash
   zsh -i -c 'gh run list -R ADORSYS-GIS/lightbridge-authz --workflow=helm-oci.yml -L 3'
   zsh -i -c 'gh workflow run helm-oci.yml -R ADORSYS-GIS/lightbridge-authz --ref v<version>'
   ```

## Where things live

| | |
| --- | --- |
| ArgoCD | `kubectl` context **`homeos`**, namespace `argocd`, app `lightbridge-app` |
| Destination | ArgoCD cluster name **`home-remote`** — directly reachable as context `hetzner-prod`, namespace `converse` |
| Chart | `oci://ghcr.io/adorsys-gis/charts/lightbridge-authz-stack` |
| Values | `ai-helm-values` `environments/prod/values/lightbridge-app.yaml` (`main`) |
| Public `/version` | `https://auth.ai.camer.digital/version` (the idp). Other hosts do not all mount it |

**Migrations run as five wave-1 Jobs, not init containers.** ADR-0031 is Accepted and says init
containers; the chart has not been changed and prod runs
`lightbridge-{api,opa,idp,budget,usage}-migrate-*`. A sync stuck on `field is immutable` for one of
them is ADR-0031's Class 1 — `kubectl delete job <name>`, then re-sync.

## Reading production data while you are in there

Only ever the **replica**, only ever read-only, and both at once:

```bash
zsh -i -c 'kubectl --context hetzner-prod -n converse port-forward pod/lightbridge-main-db-2 55434:5432'
psql "$DSN" -X -q -v ON_ERROR_STOP=1 -c \
  "BEGIN; SET LOCAL default_transaction_read_only = on; EXPLAIN (ANALYZE, BUFFERS) <stmt>; COMMIT;"
```

`lightbridge-main-db-2` is the physical replica; `SET LOCAL default_transaction_read_only` is the
second belt so a mistyped statement fails instead of landing. For query-plan work specifically, use
the `usage-query-perf` skill — it has the shapes, the baselines to compare against, and what the
numbers mean.
