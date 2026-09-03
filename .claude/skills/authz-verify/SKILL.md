---
name: authz-verify
description: How to actually verify a change in lightbridge-authz so the numbers you report are true — the private CARGO_TARGET_DIR that stops sibling worktrees serving each other's rlibs, fmt/clippy/test, the DB-backed it-tests suites against an ephemeral Postgres (and Redis) on a free port, and the 200-LoC gate with its grandfather baseline and behaviour-preserving module-split convention. Use before claiming any Rust change here is verified, and before opening a PR.
---

# Verifying a change here

A claim without pasted output is not evidence. Run these; paste what they printed.

## 0 — a private `CARGO_TARGET_DIR`, if any other worktree of this repo exists

**This is not hygiene, it is correctness.** With several worktrees of this repo sharing one target
directory, `cargo` served rlibs compiled from a **sibling branch**. It surfaced on 2026-09-02 as
`missing field requested_by_user_id in initializer of RefillRequest` — a field that existed on no
branch in the failing tree — while `cargo check` on the same tree passed. Both a red **and** a green
from a shared dir are untrustworthy while a sibling is building.

```bash
export CARGO_TARGET_DIR="$PWD/target"   # inside YOUR worktree, not the repo root's
```

Cost: a cold build. Pay it. If you are the only worktree, the shared warm cache at
`<repo-root>/target` is fine, and `Blocking waiting for file lock` there means another cargo has it —
that is waiting, not stuck.

## 1 — the three that gate every PR

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

**There is no advisory lint tier here.** CI runs clippy with `-D warnings`; `warn` and `deny` both
fail the build. Do not add an `#[allow]` to get past one without a comment saying why — `AGENTS.md`
"Suppressions and declined changes" is the rule.

`just all-checks` exists but *mutates* (`cargo fmt --all`, `cargo fix`, `clippy --fix`). Run the three
above when you want a verdict; run `just all-checks` when you want it fixed.

## 2 — the DB-backed suites

`cargo test --workspace` does **not** exercise the repos, the schedulers, the RPC dispatch or the
usage query. Those live behind `--features it-tests` and need a real Postgres (plus Redis for the
`rest` crate — the cratestack RPC surface's rate limiter is Redis-backed, ADR-0003).

`just it-tests` is the sanctioned path and brings up compose on 5432/6379. Those ports are routinely
held by other work on this machine, so the reliable form is **an ephemeral pair on a free port**:

```bash
PGPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')
RDPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("",0));print(s.getsockname()[1]);s.close()')
CID=$(docker run -d --rm -e POSTGRES_PASSWORD=postgres -p "${PGPORT}:5432" postgres:17)
RID=$(docker run -d --rm -p "${RDPORT}:6379" redis:7)
trap 'docker rm -f "$CID" "$RID" >/dev/null 2>&1' EXIT

until docker exec "$CID" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
docker exec "$CID" createdb -U postgres lightbridge_authz

export DATABASE_URL="postgres://postgres:postgres@localhost:${PGPORT}/lightbridge_authz"
export AUTHZ_REDIS_URL="redis://127.0.0.1:${RDPORT}"

cargo run -p lightbridge-authz -- migrate --config-path config/default.yaml   # or `just migrate`

cargo test -p lightbridge-authz-api-key --features it-tests --tests
cargo test -p lightbridge-authz-budget  --features it-tests --tests
cargo test -p lightbridge-authz-rest    --features it-tests
cargo test -p lightbridge-authz         --features it-tests --test mcp_tool_it_tests
```

The **usage** crate's suites run against the same Postgres (production runs plain Postgres, not
Timescale — `20260829000001_usage_event_latency.sql` is deliberately written to degrade on vanilla
PG). They use ephemeral `sqlx::test` databases, and `just it-tests` guards them **per binary**:

```bash
cargo test -p lightbridge-authz-usage-rest --features it-tests --test repo_it_tests
cargo test -p lightbridge-authz-usage-rest --features it-tests --test spend_query_it_tests
cargo test -p lightbridge-authz-usage-rest --features it-tests --test scope_ownership_it_tests
```

Each must itself report **> 0 passed**. An aggregate total hides one binary silently reporting
"0 tests, exit 0". **A skipped test is not a passing test** — check the counts, not just the exit
code.

CI does **not** run the usage it-tests today. If you touched the usage crate, running them locally is
the only coverage there is; say so in the PR.

## 3 — the schema/MCP drift guards

If you touched `authz.cstack`, `rpc_permission_map`, or an MCP tool:

```bash
cargo test -p lightbridge-authz-rest --test schema_policy_sync_tests   # @allow clauses vs the map
cargo test -p lightbridge-authz --test mcp_parity_tests                # 6 tool/op-id/permission guards
```

`UPDATE_SCHEMA_POLICIES=1` on the first one **regenerates** the clauses; the plain run verifies them.
See the `authz-procedure` skill.

## 4 — the LoC gate

`.github/actions/loc-gate/loc-gate.sh`, source of truth
[lightbridge-governance#172](https://github.com/ADORSYS-GIS/lightbridge-governance/issues/172).

- **Diff-scoped, never tree-wide** (`git diff --name-status BASE...HEAD`): untouched legacy files
  never fail it.
- `.rs` files under `crates/` and `app/` only. Files under a `tests/` directory are **measured and
  reported, never failed** (`is_test_file`, #516).
- Default ceiling **200** lines. Files already over it are **grandfathered** against
  `.github/loc-baseline.json`: *they may be touched but must not grow past the count recorded there.*
- A rename measures the **new** path against the **old** path's ceiling — renaming is touching, not
  growing.

Run it locally before pushing:

```bash
INPUT_BASE_SHA=$(git merge-base origin/main HEAD) INPUT_HEAD_SHA=HEAD \
  bash .github/actions/loc-gate/loc-gate.sh
```

**The consequence people trip over:** a grandfathered file on its exact ceiling cannot grow by one
line. If your change needs to add to `rest/src/lib.rs` (or `authz.rs`, `mcp.rs`, `refill.rs`,
`relying_party.rs`, …), you must **make room** first.

### The module-split convention

The house move, used a dozen times over 2026-09-02/03 (`PermissionSet` → `core/permission_set.rs`,
`MAPPED_OP_ID_PERMISSIONS` → `rest/rpc_permission_map.rs`, `default_role_permissions` →
`role_defaults`, `ClaimMapper`/`ClaimSource` → `config/claim_mapper.rs`, the budget wire converters →
`budget_convert.rs`/`reset_schedule_convert.rs`):

1. Move a coherent piece into a **new sibling module**, verbatim.
2. **Re-export it from where it lived**, so every existing `use` path still resolves. No caller
   changes in the same commit.
3. Add a module doc comment saying the split was forced by the gate and that the pairing it
   participates in is unchanged (`rpc_permission_map.rs:1-16` is the model).

The rules, from [`docs/code-size-baseline.md`](../../../docs/code-size-baseline.md#rules-for-a-split):

- **Move code; do not rewrite it.** A split that changes behaviour is not a split.
- **The existing suite is the oracle** — it must pass before and after with **no test edits**.
  Editing a test during a mechanical split means behaviour moved.
- Watch for `E0277` unsizing when a moved impl loses a `Self: Sized` bound. This tree has hit it.
- **Load-bearing comments move intact** — the advisory-lock and CAS explanations are why those
  functions are hand-written SQL under ADR-0038.
- **Some files legitimately exceed 200 lines.** Say so in the file, with the reason. A fake seam
  invented to satisfy a line count is worse than an honest oversized module.

**Only correct a baseline entry when the file is already over its recorded ceiling on `main`** — that
is recording reality, and #667 did exactly that for sixteen files. Raising a ceiling to fit your own
growth is not; split instead, and if you do grow a grandfathered file, name your own lines
explicitly rather than burying them in the diff.

## 5 — before you push

- [ ] `cargo fmt --all --check` clean.
- [ ] `clippy --workspace --all-targets --all-features -- -D warnings` exits 0.
- [ ] `cargo test --workspace`, with the pass/fail counts.
- [ ] Every DB-backed suite your change touches, with **per-binary** counts.
- [ ] The drift guards, if the schema or MCP moved.
- [ ] `loc-gate.sh` locally against `origin/main...HEAD`.
- [ ] Migration prefix re-checked on `origin/main` — see the `authz-migration` skill.
- [ ] Every number in your PR body is output you actually saw. Never predict a result.
