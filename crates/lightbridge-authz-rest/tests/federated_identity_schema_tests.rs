//! Pins the ADR-0024 Q4 reversal (#740, explicit owner directive): `FederatedIdentity` is
//! declared in `authz.cstack` so the table is schema-of-record, but stays exactly as unreachable
//! through generated CRUD as it was while absent -- zero `@@allow` clauses, mirroring `model
//! User` immediately above it, plus the two credential columns (`tokenEnvelope`/`tokenSealedAt`)
//! never declared at all. See the model's own comment in
//! `crates/lightbridge-authz-api/schema/authz.cstack` for the full reasoning.
//!
//! This test fails if any of the three protections erodes: an `@@allow` clause added to the
//! model, a credential column declared on it, or a generic `model.FederatedIdentity.*` op-id
//! later wired into `rpc_authorize::required_permission`.
//!
//! Parses `authz.cstack` the same way `schema_policy_sync_tests.rs` does -- the tiny
//! `authz_cstack_path` helper is duplicated rather than shared, since this is the only other test
//! that needs to locate a model block, not walk its `@@allow` clauses.

use std::path::PathBuf;

use lightbridge_authz_rest::rpc_authorize::required_permission;

fn authz_cstack_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("lightbridge-authz-api")
        .join("schema")
        .join("authz.cstack")
}

/// Returns the exact source lines of `model FederatedIdentity { ... }`, opening and closing
/// braces included. Panics (with the file path) if the model is missing or its closing `}` can't
/// be found -- a silently-skipped model here would defeat the point of this test.
fn federated_identity_model_lines(source: &str) -> Vec<&str> {
    let lines: Vec<&str> = source.lines().collect();
    let block_start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("model FederatedIdentity {"))
        .unwrap_or_else(|| panic!("no `model FederatedIdentity {{` block found in authz.cstack"));
    let block_end = lines[block_start..]
        .iter()
        .position(|line| line.trim() == "}")
        .map(|offset| block_start + offset)
        .unwrap_or_else(|| {
            panic!("unterminated `model FederatedIdentity` block (no closing `}}` found)")
        });
    lines[block_start..=block_end].to_vec()
}

#[test]
fn federated_identity_model_carries_zero_allow_clauses() {
    let path = authz_cstack_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {path:?}: {err}"));
    let block = federated_identity_model_lines(&source);

    let allow_clauses: Vec<&&str> = block
        .iter()
        .filter(|line| line.trim_start().starts_with("@@allow("))
        .collect();
    assert!(
        allow_clauses.is_empty(),
        "model FederatedIdentity must carry ZERO @@allow clauses, mirroring `model User` -- \
         found: {allow_clauses:?}"
    );
}

#[test]
fn federated_identity_model_never_declares_the_sealed_credential_columns() {
    let path = authz_cstack_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {path:?}: {err}"));
    let block = federated_identity_model_lines(&source);

    for forbidden_field in ["tokenEnvelope", "tokenSealedAt"] {
        assert!(
            !block.iter().any(|line| line.contains(forbidden_field)),
            "model FederatedIdentity must never declare `{forbidden_field}` -- the sealed \
             Keycloak credential stays reachable only through hand-written SQL (ADR-0024 Q4)"
        );
    }
}

#[test]
fn federated_identity_generic_crud_verbs_are_denied_unconditionally() {
    for op_id in [
        "model.FederatedIdentity.list",
        "model.FederatedIdentity.get",
        "model.FederatedIdentity.create",
        "model.FederatedIdentity.update",
        "model.FederatedIdentity.delete",
    ] {
        assert!(
            required_permission(op_id).is_none(),
            "{op_id} must be denied unconditionally (fail-closed, unmapped op-id) -- if this \
             fails, someone wired FederatedIdentity into the RPC surface without reopening the \
             ADR-0024 Q4 decision"
        );
    }
}
