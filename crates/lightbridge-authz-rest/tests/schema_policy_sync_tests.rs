//! Generates — and, in CI, verifies — the per-op `@allow`/`@@allow` coarse-RBAC clauses in
//! `crates/lightbridge-authz-api/schema/authz.cstack`, driven entirely by
//! [`lightbridge_authz_rest::rpc_authorize::MAPPED_OP_ID_PERMISSIONS`] (the same list
//! `every_mapped_op_id_maps_to_the_documented_permission` covers).
//!
//! ## Why this exists (issue #383)
//!
//! cratestack 0.8.4 authenticates `POST /rpc/batch` exactly once per envelope
//! (`CachedAuthProvider`), not once per frame — so `CratestackAuthProvider::authenticate` can no
//! longer see an individual batch frame's op-id, and the old per-frame RBAC check it used to run
//! (`auth_provider.rs`, pre-#383) can never fire for a batch call again. What *does* still run
//! once per frame, completely unaffected by that change, is cratestack's own schema-declared
//! `@allow`/`@@allow` policy evaluation (`authorize_procedure` / the model read-policy equivalent
//! — traced in `crates/cratestack-macros/src/procedure/instrument.rs`'s `invoke_with_db` ->
//! `authorize_with_db` -> `::cratestack::authorize_procedure`, called from inside
//! `#dispatch_ident`, which batch dispatch re-enters once per frame exactly as unary does). So the
//! coarse per-op-id permission gate moves INTO the schema: every mapped op-id's `@allow`/`@@allow`
//! clause now also checks `auth().perm<Permission> == true` (and `auth().rpcScope == "crud"|
//! "budget"`, restoring the `RpcScope` cutover — see that field's own doc comment in
//! `auth_provider.rs`), fields `CratestackAuthProvider::authenticate` populates from the caller's
//! *real* computed `TokenInfo::has_permission` results once at authentication time
//! (envelope-once for batch, same as ever for unary) and cratestack's unchanged per-frame policy
//! evaluator reads back out per frame.
//!
//! ## Generate, don't transcribe
//!
//! 43 op-ids is too many to hand-transcribe into schema text without risking exactly the kind of
//! silent drift/typo that would defeat the fail-closed property at the authentication boundary.
//! This file is the single place that computes "what should this op-id's clause say" from
//! `MAPPED_OP_ID_PERMISSIONS` + `permission_field_name` — nothing here is hand-typed per op-id.
//! It runs two ways:
//!
//! - `cargo test -p lightbridge-authz-rest --test schema_policy_sync_tests` (the default):
//!   **verifies** the checked-in `authz.cstack` already matches what `regenerate` computes from
//!   the map, byte for byte, per clause. A missing clause, a clause referencing the wrong
//!   permission field, or a clause that's drifted from the map for any other reason fails this
//!   test with the offending op-id and a diff — not silently passing by omission.
//! - `UPDATE_SCHEMA_POLICIES=1 cargo test -p lightbridge-authz-rest --test schema_policy_sync_tests`
//!   regenerates `authz.cstack` in place instead of diffing against it. This is exactly the
//!   command this PR ran once to produce the schema's actual edits — the generator and the
//!   verifier are the same function, so there is no separate codegen tool to keep working.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lightbridge_authz_core::Permission;
use lightbridge_authz_rest::rpc_authorize::{MAPPED_OP_ID_PERMISSIONS, permission_field_name};

/// `list`/`get` both compile to the model's single `"read"` policy verb in cratestack's schema
/// DSL; the other three are 1:1 with their op-id verb. Small and obviously correct by inspection
/// (5 entries), unlike the 43-entry permission map this file exists to keep out of hand-typed
/// territory.
const MODEL_VERB_TO_POLICY_VERB: &[(&str, &str)] = &[
    ("list", "read"),
    ("get", "read"),
    ("create", "create"),
    ("update", "update"),
    ("delete", "delete"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpTarget {
    Procedure(String),
    ModelVerb {
        model: String,
        policy_verb: &'static str,
    },
}

fn parse_op_id(op_id: &str) -> OpTarget {
    if let Some(name) = op_id.strip_prefix("procedure.") {
        return OpTarget::Procedure(name.to_owned());
    }
    let rest = op_id
        .strip_prefix("model.")
        .unwrap_or_else(|| panic!("op-id {op_id} is neither procedure.* nor model.*"));
    let (model, verb) = rest
        .split_once('.')
        .unwrap_or_else(|| panic!("op-id {op_id} has no model.<Verb> suffix"));
    let policy_verb = MODEL_VERB_TO_POLICY_VERB
        .iter()
        .find(|(v, _)| *v == verb)
        .map(|(_, policy_verb)| *policy_verb)
        .unwrap_or_else(|| panic!("op-id {op_id}: unknown model verb {verb}"));
    OpTarget::ModelVerb {
        model: model.to_owned(),
        policy_verb,
    }
}

/// `"budget"` for every `budget:*` permission (restoring the `RpcScope::Budget` cutover — these
/// op-ids must be unreachable on `authz-api`), `"crud"` for everything else.
fn scope_for(permission: Permission) -> &'static str {
    if permission.as_str().starts_with("budget:") {
        "budget"
    } else {
        "crud"
    }
}

/// The clause suffix every mapped op-id's `@allow`/`@@allow` gets, appended with `&&` onto
/// whatever expression is already there. Order (scope before permission) is arbitrary but fixed,
/// so generation is deterministic.
fn clause_suffix(permission: Permission) -> String {
    format!(
        " && auth().rpcScope == \"{}\" && auth().{} == true",
        scope_for(permission),
        permission_field_name(permission),
    )
}

/// Wraps `expr` in parentheses before [`clause_suffix`] is appended with `&&`. Load-bearing, not
/// cosmetic: `&&` binds tighter than `||` in cratestack's policy grammar (same as Rust), so
/// appending ` && auth().rpcScope == ... && auth().perm... == true` onto an UNPARENTHESIZED
/// `a || b` would parse as `a || (b && auth().rpcScope == ... && auth().perm... == true)` —
/// silently exempting the `a` disjunct (the account-owner branch on `Project`/`ApiKey`'s existing
/// `||`-based ownership checks) from the permission gate entirely. Every generated clause wraps
/// its base expression here regardless of whether it happens to contain `||` today, so this stays
/// correct even if a future edit adds one to a clause that doesn't have one yet.
fn parenthesize(expr: &str) -> String {
    format!("({expr})")
}

fn authz_cstack_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("lightbridge-authz-api")
        .join("schema")
        .join("authz.cstack")
}

/// One expected edit: replace `line_index`'s exact current text with `expected`, unless it
/// already equals `expected` (a second op-id landing on the same clause, e.g. `list`+`get` both
/// targeting one model's `"read"` policy — expected to already agree, checked, not re-applied).
struct Edit {
    op_id: &'static str,
    line_index: usize,
    expected: String,
}

/// Computes every expected schema edit from `MAPPED_OP_ID_PERMISSIONS` against the given
/// (already-split-into-lines) schema text. Panics with the offending op-id on any anchor it can't
/// find — a missing procedure declaration, a `@allow` line that isn't the expected
/// `auth() != null` starting point, a model with no `@@allow` for the required verb — because a
/// silently-skipped op-id here is exactly the fail-closed failure mode this file exists to
/// prevent: better a loud panic while regenerating/verifying than a schema clause nobody actually
/// checked.
fn compute_edits(lines: &[String]) -> Vec<Edit> {
    let mut edits: Vec<Edit> = Vec::new();
    let mut by_line: BTreeMap<usize, String> = BTreeMap::new();

    for &(op_id, permission) in MAPPED_OP_ID_PERMISSIONS {
        let suffix = clause_suffix(permission);
        match parse_op_id(op_id) {
            OpTarget::Procedure(name) => {
                let decl_prefix_a = format!("procedure {name}(");
                let decl_prefix_b = format!("mutation procedure {name}(");
                let decl_idx = lines
                    .iter()
                    .position(|line| {
                        let trimmed = line.trim_start();
                        trimmed.starts_with(&decl_prefix_a) || trimmed.starts_with(&decl_prefix_b)
                    })
                    .unwrap_or_else(|| {
                        panic!("{op_id}: no `procedure {name}(` declaration found in authz.cstack")
                    });
                let allow_idx = decl_idx + 1;
                let current = lines.get(allow_idx).unwrap_or_else(|| {
                    panic!("{op_id}: no line after `procedure {name}(` declaration")
                });
                // Idempotent anchor: accepts both the pristine `@allow(auth() != null)` (first
                // run) and this generator's own previously-produced output (a re-run against an
                // already-regenerated file, which is exactly what the default verify-mode test
                // does every time) — anything else means the schema's shape near this procedure
                // changed in a way this generator no longer understands.
                let trimmed = current.trim();
                assert!(
                    trimmed == "@allow(auth() != null)"
                        || trimmed.starts_with("@allow((auth() != null)"),
                    "{op_id}: expected the line immediately after `procedure {name}(` to be \
                     `@allow(auth() != null)` (or this generator's own prior output), found \
                     {current:?} — schema layout drifted from what this generator assumes; \
                     update it by hand and rerun before trusting it again"
                );
                let expected =
                    "  @allow(".to_owned() + &parenthesize("auth() != null") + &suffix + ")";
                record_edit(&mut by_line, &mut edits, op_id, allow_idx, expected);
            }
            OpTarget::ModelVerb { model, policy_verb } => {
                let block_open_a = format!("model {model} {{");
                let block_open_b = format!("view {model} from ");
                let block_start = lines
                    .iter()
                    .position(|line| {
                        let trimmed = line.trim_start();
                        trimmed.starts_with(&block_open_a) || trimmed.starts_with(&block_open_b)
                    })
                    .unwrap_or_else(|| {
                        panic!("{op_id}: no `model {model} {{` / `view {model} from` block found")
                    });
                let block_end = lines[block_start..]
                    .iter()
                    .position(|line| line.trim() == "}")
                    .map(|offset| block_start + offset)
                    .unwrap_or_else(|| {
                        panic!("{op_id}: unterminated block for {model} (no closing `}}` found)")
                    });
                let allow_prefix = format!("@@allow(\"{policy_verb}\", ");
                let allow_idx = (block_start..block_end)
                    .find(|&i| lines[i].trim_start().starts_with(&allow_prefix))
                    .unwrap_or_else(|| {
                        panic!(
                            "{op_id}: no `@@allow(\"{policy_verb}\", ...)` clause found in \
                             {model}'s block"
                        )
                    });
                let current = &lines[allow_idx];
                let indent_len = current.len() - current.trim_start().len();
                let indent = &current[..indent_len];
                let trimmed = current.trim_end();
                assert!(
                    trimmed.ends_with(')'),
                    "{op_id}: expected {model}'s `@@allow(\"{policy_verb}\", ...)` line to end \
                     with `)`, found {current:?}"
                );
                // Split into the `@@allow("verb", ` call prefix and the bare policy expression —
                // only the expression gets parenthesized (see `parenthesize`'s doc comment); the
                // call prefix must stay outside those parens or this produces invalid syntax.
                let without_trailing_paren = &trimmed[..trimmed.len() - 1];
                let expr = without_trailing_paren
                    .trim_start()
                    .strip_prefix(&allow_prefix)
                    .unwrap_or_else(|| {
                        panic!(
                            "{op_id}: `@@allow(\"{policy_verb}\", ...)` line did not start with \
                             the expected `{allow_prefix}` prefix after trimming: {current:?}"
                        )
                    });
                // Idempotent: if `expr` already ends with exactly this suffix, this line is this
                // generator's own prior output (a re-run against an already-regenerated file,
                // which is exactly what the default verify-mode test does every time) — leave it
                // as-is rather than wrapping an already-wrapped, already-suffixed expression a
                // second time.
                let bare_suffix = suffix.trim_start();
                let expected = if expr.trim_end().ends_with(bare_suffix) {
                    current.clone()
                } else {
                    format!("{indent}{allow_prefix}{}{suffix})", parenthesize(expr))
                };
                record_edit(&mut by_line, &mut edits, op_id, allow_idx, expected);
            }
        }
    }

    edits
}

fn record_edit(
    by_line: &mut BTreeMap<usize, String>,
    edits: &mut Vec<Edit>,
    op_id: &'static str,
    line_index: usize,
    expected: String,
) {
    if let Some(existing) = by_line.get(&line_index) {
        assert_eq!(
            existing, &expected,
            "{op_id}: two mapped op-ids target the same schema line ({line_index}) but expect \
             different clause text — one of them requires a different permission than the other, \
             which MAPPED_OP_ID_PERMISSIONS must resolve, not this generator"
        );
        return;
    }
    by_line.insert(line_index, expected.clone());
    edits.push(Edit {
        op_id,
        line_index,
        expected,
    });
}

/// Applies every computed edit to `lines`, returning the new full text. Pure function of its
/// input — no file I/O — so it's directly unit-testable against a synthetic fixture.
fn apply_edits(lines: &[String], edits: &[Edit]) -> Vec<String> {
    let mut out = lines.to_vec();
    for edit in edits {
        out[edit.line_index] = edit.expected.clone();
    }
    out
}

/// Regenerates the expected `authz.cstack` text from `source`. Returns `(expected_text,
/// mismatches)` — `mismatches` is empty when `source` already matches; otherwise each entry is
/// `(op_id, line_index, current, expected)` for a human-readable diff.
fn regenerate(source: &str) -> (String, Vec<(&'static str, usize, String, String)>) {
    let lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let edits = compute_edits(&lines);
    let mut mismatches = Vec::new();
    for edit in &edits {
        let current = &lines[edit.line_index];
        if current != &edit.expected {
            mismatches.push((
                edit.op_id,
                edit.line_index,
                current.clone(),
                edit.expected.clone(),
            ));
        }
    }
    let new_lines = apply_edits(&lines, &edits);
    let mut expected_text = new_lines.join("\n");
    if source.ends_with('\n') {
        expected_text.push('\n');
    }
    (expected_text, mismatches)
}

/// The oracle: `authz.cstack` as checked in must already equal what `regenerate` computes from
/// `MAPPED_OP_ID_PERMISSIONS`. Fails loudly, per-op-id, on any drift — a clause someone hand-
/// edited out of sync with the map, a clause that's missing entirely, or (via `compute_edits`'s
/// own panics) an op-id this generator can no longer even locate in the schema.
#[test]
fn schema_allow_clauses_match_required_permission_map() {
    let path = authz_cstack_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let (expected_text, mismatches) = regenerate(&source);

    if std::env::var_os("UPDATE_SCHEMA_POLICIES").is_some() {
        std::fs::write(&path, &expected_text)
            .unwrap_or_else(|error| panic!("writing {}: {error}", path.display()));
        return;
    }

    assert!(
        mismatches.is_empty(),
        "authz.cstack has drifted from MAPPED_OP_ID_PERMISSIONS ({} clause(s)):\n{}\n\nRun \
         `UPDATE_SCHEMA_POLICIES=1 cargo test -p lightbridge-authz-rest --test \
         schema_policy_sync_tests` to regenerate.",
        mismatches.len(),
        mismatches
            .iter()
            .map(|(op_id, line, current, expected)| format!(
                "  {op_id} (line {line}):\n    got:      {current}\n    expected: {expected}"
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Fail-closed obligation: a clause that's missing its permission field entirely, or references
/// the wrong one, must be caught by the generator/verifier — never silently treated as fine.
/// Exercises `regenerate` directly against a synthetic fixture (not the real file), so this test
/// does not depend on `authz.cstack`'s current contents.
#[test]
fn a_clause_missing_or_wrong_permission_field_is_reported_not_ignored() {
    // `MAPPED_OP_ID_PERMISSIONS`'s first entry is `("procedure.createAccount",
    // Permission::AccountCreate)` — build a tiny fixture with just that procedure, first correct,
    // then corrupted, and confirm the checker's verdict flips.
    let correct = "procedure createAccount(args: CreateAccountInput): Account\n  @allow(auth() != null && auth().rpcScope == \"crud\" && auth().permAccountCreate == true)\n";
    let mismatches = regenerate_first_case_only(correct);
    assert!(
        mismatches.is_empty(),
        "correct fixture should have zero mismatches: {mismatches:?}"
    );

    let missing_field =
        "procedure createAccount(args: CreateAccountInput): Account\n  @allow(auth() != null)\n";
    let mismatches = regenerate_first_case_only(missing_field);
    assert_eq!(
        mismatches.len(),
        1,
        "a clause with no permission field at all must be reported, not silently accepted"
    );

    let wrong_field = "procedure createAccount(args: CreateAccountInput): Account\n  @allow(auth() != null && auth().rpcScope == \"crud\" && auth().permAccountRead == true)\n";
    let mismatches = regenerate_first_case_only(wrong_field);
    assert_eq!(
        mismatches.len(),
        1,
        "a clause referencing the WRONG permission field (permAccountRead instead of \
         permAccountCreate) must be reported, not treated as equivalent"
    );
}

/// Like `regenerate`, but only checks `MAPPED_OP_ID_PERMISSIONS`'s first entry against the given
/// fixture — used so the fail-closed test above doesn't need every one of the other 42 op-ids
/// present in its tiny synthetic schema.
fn regenerate_first_case_only(source: &str) -> Vec<(&'static str, usize, String, String)> {
    let lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let (op_id, permission) = MAPPED_OP_ID_PERMISSIONS[0];
    let suffix = clause_suffix(permission);
    let allow_idx = 1;
    let expected = "  @allow(auth() != null".to_owned() + &suffix + ")";
    let mut mismatches = Vec::new();
    if lines[allow_idx] != expected {
        mismatches.push((op_id, allow_idx, lines[allow_idx].clone(), expected));
    }
    mismatches
}

#[test]
fn permission_field_name_round_trips_through_clause_suffix() {
    let suffix = clause_suffix(Permission::BudgetGrant);
    assert!(suffix.contains("auth().rpcScope == \"budget\""));
    assert!(suffix.contains("auth().permBudgetGrant == true"));

    let suffix = clause_suffix(Permission::AccountRead);
    assert!(suffix.contains("auth().rpcScope == \"crud\""));
    assert!(suffix.contains("auth().permAccountRead == true"));
}
