# Code Size Baseline

The house rule is **200 LoC per file**, alongside SOLID and DRY. This document records how far the
tree currently is from that, in what order the gap will be closed, and — plainly — what is not
achievable in the current release window.

It exists so that "we follow a 200-LoC rule" is backed by a number and a plan rather than repeated
as an aspiration. A rule violated by a third of the tree on the day it is written is not yet a rule.

## Baseline

Measured on `main` at `4f9e17d`, 2026-08-27.

| Metric | Value |
| --- | --- |
| `src` files | 101 |
| `src` files over 200 LoC | **32** (32%) |
| Excess lines above the limit | **24,010** |
| Largest single file | 4,068 LoC |

Regenerate with:

```bash
find crates app -name '*.rs' -path '*/src/*' -not -path '*/target/*' | xargs wc -l | sort -rn
```

Do not trust a remembered figure — re-run the command. The numbers here are a snapshot, not a
constant.

### Top ten

| LoC | File |
| --- | --- |
| 4068 | `crates/lightbridge-authz-rest/src/lib.rs` |
| 3274 | `app/lightbridge-authz/src/mcp.rs` |
| 2950 | `crates/lightbridge-authz-api-key/src/repo.rs` |
| 2010 | `crates/lightbridge-authz-core/src/config/mod.rs` |
| 1909 | `crates/lightbridge-authz-usage/src/handlers/ingest.rs` |
| 1725 | `crates/lightbridge-authz-rest/src/oauth2_op/store.rs` |
| 1627 | `crates/lightbridge-authz-rest/src/handlers/mod.rs` |
| 1092 | `crates/lightbridge-authz-rest/src/relying_party.rs` |
| 1033 | `crates/lightbridge-authz-rest/src/token_exchange.rs` |
| 1000 | `crates/lightbridge-authz-budget/src/rule_data.rs` |

### Where the debt lives

| Crate | Files over 200 |
| --- | --- |
| `lightbridge-authz-rest` | 14 |
| `lightbridge-authz-budget` | 8 |
| `lightbridge-authz-core` | 3 |
| `lightbridge-authz-usage` | 3 |
| `lightbridge-authz` (app) | 2 |
| `lightbridge-authz-api-key` | 1 |
| `lightbridge-authz-bearer` | 1 |

`lightbridge-authz-rest` holds 44% of the offending files. It is the crate where server startup,
router composition, and hand-written RPC procedures all live, so it accumulates by default.

## Test files are measured separately

| Metric | Value |
| --- | --- |
| Test files | 63 |
| Test files over 200 LoC | 47 |
| Total test LoC | 36,747 |
| Largest | 6,052 (`crates/lightbridge-authz-rest/tests/token_exchange_tests.rs`) |

A 200-line cap on a 6,000-line integration suite is a different argument from a cap on a module,
and conflating the two would either gut the cap or produce dozens of fragmentary test files split
along seams that serve the line count rather than the reader. Test size is reported here and
otherwise left alone; the CI gate does not apply to it.

## What is achievable, and what is not

**Full compliance is not achievable by 2026-09-04.** Clearing 24,010 excess lines across 32 files
is roughly 40+ ideal dev-days of pure refactor — more than both releases in the current window
combined — and every line of it is churn on an authentication boundary, where a mechanical mistake
is a security defect rather than a bug. Attempting it in the window would be reckless.

The plan is therefore a **ratchet plus a funded burn-down**, not a big-bang:

1. **Stop the growth.** CI blocks any file *added or modified* in a PR that exceeds 200 LoC.
   Untouched legacy files never fail the gate, so it can land immediately without a flag day.
2. **Burn down the worst, deliberately.** One file at a time, behaviour-preserving, proven by the
   existing suite passing unedited.

### Split order

Ordered by risk-weighted churn, not by size alone. A large file that rarely changes costs less than
a mid-sized one every feature touches.

| Order | File | Rationale |
| --- | --- | --- |
| 1 | `lightbridge-authz-rest/src/lib.rs` | Largest, and touched by nearly every change. Holds three unrelated concerns: per-service startup, router construction, and procedure bodies. |
| 2 | `lightbridge-authz-core/src/config/mod.rs` | Every service loads it; every new config field lands here. |
| 3 | `lightbridge-authz-api-key/src/repo.rs` | High churn, and the ADR-0038-exception query paths deserve to be readable in isolation. |
| 4 | `app/lightbridge-authz/src/mcp.rs` | Large but lower-risk: additive, one tool at a time. |

Files 5 onward are re-prioritised once the first four land — the ordering above is likely to change
once `lib.rs` is split, because several later entries shrink as code moves.

### Rules for a split

- **Move code; do not rewrite it.** A split that changes behaviour is not a split.
- **The existing suite is the oracle.** It must pass before and after with *no test edits*. Editing a
  test during a mechanical split is a signal that behaviour moved.
- **Watch for `E0277` unsizing** where a moved impl loses a `Self: Sized` bound. This tree has hit
  that before.
- **Load-bearing comments move intact.** The advisory-lock and CAS paths
  (`ensure_active_signing_key`, `rotate_exchange_refresh_token`, `consume_device_authorization`,
  `consume_authorization_code`) carry explanations of *why* they are hand-written SQL under
  ADR-0038. Losing those comments in a move is a real regression.
- **Some files will legitimately exceed 200 LoC.** Say so in the file, with the reason. A fake seam
  invented to satisfy a line count is worse than an honest oversized module.

## Trajectory

| Milestone | Files over 200 | Note |
| --- | --- | --- |
| 2026-08-27 (baseline) | 32 | — |
| After the CI gate lands | 32 | The number stops *rising*; that is the gate's whole job |
| Target 2026-09-04 | ~31 | One file (`lib.rs`) split, and it yields several modules |

The near-flat trajectory is the honest one. The gate is what changes the shape of this table over
months; the burn-down is slow by design because the alternative is fast, wide, unreviewable change
on the authentication path.

## See also

- `AGENTS.md` — "What the linter enforces" and "Spend review attention here instead"
- `docs/adr/0038` context — why the hand-written SQL exceptions exist and must survive a split
