---
name: governance-pr
description: Open a pull request (or an issue) in lightbridge-authz that passes the AI Governance check — the repo's own PR template section order, the source-of-truth link the regex actually accepts, what counts as verification evidence, the AI Usage Declaration, and the gh/zsh mechanics for creating and squash-merging. Use whenever opening a PR or an issue in this repo.
---

# Opening a governance-compliant PR

`.github/workflows/governance.yml` delegates to `ADORSYS-GIS/ai-governance`'s reusable
`governance-check` workflow, pinned to an immutable SHA. It **fails the PR** when the body lacks an
AI Usage Declaration, a source-of-truth reference, or verification evidence, and posts a sticky
comment listing what is missing. Doctrine: *"AI may accelerate the work, but it must not launder
ignorance into polished artifacts."* — <https://adorsys-gis.github.io/ai-governance/>

## Use the repo's own template

`.github/pull_request_template.md` is the shape to fill. Keep its section names and order — the
checker and every human reviewer here read that order:

```
## Summary                 (what, plus `Closes #<n>`)
## Related Issues
## Type of Change          (checkboxes)
## Changes Made
## Checklist
## Security Considerations (pick "no security impact" OR describe — never leave both blank)
## Testing
---
## Intent / Source of Truth
## Verification
## AI Usage Declaration
```

Add `## Scope`, `## Screenshots / Evidence`, `## Risk Assessment` and `## Reviewer Focus` when the
change earns them; every substantial PR in this repo carries them.

## The three things the check is actually looking for

### 1. A source-of-truth link — a real URL

```
Source of truth: https://github.com/ADORSYS-GIS/lightbridge-authz/issues/645
```

**A bare `owner/repo#123` does not satisfy the regex.** Use the full URL. Add supporting links
(ADR path, the epic, the console consumer story, a failing Actions run, the governance site) on their
own lines beneath it. If there is no source of truth, the work is not ready — that is the rule, not a
formality.

### 2. Verification evidence — real output, not a description

Paste the commands and their **actual tail output**. Never write what a command *would* print.

```
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 52s
clippy_exit=0

$ DATABASE_URL=... cargo test --workspace
TOTAL passed: 704 failed: 0
```

Per-binary counts for the DB-backed suites, not an aggregate. If CI does not run a suite you ran
locally (the usage it-tests), say so. If you could not run something, say that plainly instead of
omitting it. See the `authz-verify` skill for what to run.

### 3. The AI Usage Declaration

```markdown
## AI Usage Declaration

- [ ] Not used
- [x] AI-assisted

AI (Claude) wrote <what>, from <the acceptance criteria / the owner ruling in …>. Every claim in the
Verification section is the actual output of the command shown above it, run in this worktree;
nothing is reproduced from memory or predicted. The human owner (@stephane-segning) reviews and
accepts this change and remains accountable for it.

- [x] Generated code was reviewed
- [x] I can explain every line of this change
- [x] Verification evidence is real command output, not a description of what would happen

> AI may accelerate the work, but it must not launder ignorance into polished artifacts.
> Governance: https://adorsys-gis.github.io/ai-governance/
```

End the body with:

```
🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## Mechanics

`gh` needs the interactive zsh profile on this machine (the token comes from it):

```bash
zsh -i -c 'gh pr create -R ADORSYS-GIS/lightbridge-authz \
  --title "feat(budget): …" --body-file /path/to/body.md --base main'
```

- **Title:** conventional commits — `feat(scope):`, `fix(scope):`, `chore(ci):`,
  `docs(scope):`, and `feat(scope)!:` for a breaking change. release-please reads these to cut the
  version and write `CHANGELOG.md`, so the type and the `!` are load-bearing, not cosmetic.
- **Commit trailer:** `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- **Assign yourself when work starts,** not at close:
  `zsh -i -c 'gh issue edit <n> -R ADORSYS-GIS/lightbridge-authz --add-assignee stephane-segning'`.
- **Issues** use the forms (Epic / User Story / Dev Ticket) in `.github/ISSUE_TEMPLATE/` — never a
  blank issue.
- **Merge:**
  `zsh -i -c 'gh pr merge <n> -R ADORSYS-GIS/lightbridge-authz --squash --delete-branch --admin'`,
  then confirm with `gh pr view <n> --json state,mergeCommit`.

## Two content rules this repo enforces beyond governance

- **Every process gets a mermaid pair** — a `sequenceDiagram` for the interaction and a
  `stateDiagram-v2` for the lifecycle — in the doc you touched, with the blocked or unreachable
  edges labelled explicitly rather than left implied. Cite `file:line` behind each participant so the
  diagram can be re-verified instead of quietly rotting.
- **No ADR duplication.** An ADR is the home of its decision. Domain docs and runbooks link to it and
  add what it cannot carry: line citations, procedure, measured numbers.

## After merging

`main` going red is your problem for the next few minutes, and it is usually one of two things
neither branch's CI could see: a **migration version collision** with a PR that merged alongside
yours (see `authz-migration`), or a **hand-typed list outside the derived chain** (see
`authz-procedure` §7-8). Then check it actually shipped — the `authz-release-verify` skill.
