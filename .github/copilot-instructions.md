<!-- ai-governance:stanza -->
<!-- BEGIN: AI Governance stanza (managed by ADORSYS-GIS/ai-governance) -->
## AI Governance

AI may accelerate the work, but humans own intent, verification, and consequences.
AI output is not truth: review AI-generated code as untrusted, and never submit work you cannot explain.

When opening issues or pull requests in this repo:

- Use the provided **issue forms** (Epic, User Story, Dev Ticket) and the **pull request template** — do not open blank issues/PRs.
- Fill in the **AI Usage Declaration** honestly (what AI was used for, what you verified).
- Include a **source-of-truth link** (a URL or `#123` reference). No source of truth means the work is not ready.
- Provide **verification evidence** (commands, logs, links, or checked verification boxes). No evidence means it is not done.

Source of truth and full doctrine: https://adorsys-gis.github.io/ai-governance/
This stanza is intentionally thin — read the site; do not duplicate the doctrine here.
<!-- END: AI Governance stanza -->

## Where the project rules actually live

This file carries only the governance stanza above (managed by `ADORSYS-GIS/ai-governance` between
its `BEGIN`/`END` markers — do not hand-edit inside them).

The project's own conventions, architecture and workflows are in **[`AGENTS.md`](../AGENTS.md)**,
which VS Code also detects on its own. Task playbooks are surfaced to Copilot as
`.github/instructions/*.instructions.md` and role definitions as `.github/agents/*.agent.md`; both
are **symlinks** into `.claude/`, so there is one copy of each. Edit the target, never the link.

See [`docs/agent-harnesses.md`](../docs/agent-harnesses.md) for the full map.
