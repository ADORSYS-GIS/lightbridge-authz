//! Drift guard for `migrations/20260904000002_cratestack_bootstrap_tables.sql`.
//!
//! That migration takes ownership of `cratestack_audit` because cratestack creates it lazily with
//! `CREATE TABLE IF NOT EXISTS` on the first audited write of each `SqlxRuntime`, and that
//! statement is not atomic across sessions: concurrent first-callers collide on
//! `pg_type_typname_nsp_index` and the loser's request dies as an opaque `500 internal error`
//! (lightbridge-authz#684).
//!
//! Owning the DDL creates a drift seam. If a future cratestack adds a column to `AUDIT_TABLE_DDL`,
//! its own `IF NOT EXISTS` bootstrap silently skips the table our migration already created, and
//! the new column never appears — a runtime failure with no build-time signal. That seam is not
//! NEW (the same silent skip already applied to every database bootstrapped by an older
//! cratestack), but owning the file is what makes it checkable, so check it.
//!
//! This asserts the migration reproduces the crate's constant statement-for-statement. When a
//! cratestack bump fails it, the fix is a NEW forward migration bringing the table up to the new
//! definition, plus updating the copy here — never editing the applied migration, whose bytes are
//! frozen by sqlx's checksum (`authz-migration` skill, rule 1).
//!
//! Only the audit half is guarded. `IDEMPOTENCY_TABLE_DDL` lives in `cratestack-sql`, which is
//! neither a direct dependency here nor re-exported through `cratestack-pg`, and adding a direct
//! dependency on it would put a seventh crate outside the version lockstep block `Cargo.toml`
//! documents as load-bearing. The migration says so in its own comment.

/// The migration is embedded, not read from disk, so this test cannot pass because of a stale file
/// on a developer's machine and cannot fail because of the working directory it ran from.
const MIGRATION: &str =
    include_str!("../../../migrations/20260904000002_cratestack_bootstrap_tables.sql");

/// Split a DDL blob into statements, each normalized to single-spaced text with SQL comments
/// stripped, so the comparison is about SQL rather than about indentation or line breaks.
fn statements(ddl: &str) -> Vec<String> {
    let without_comments: String = ddl
        .lines()
        .map(|line| match line.find("--") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    without_comments
        .split(';')
        .map(|statement| statement.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|statement| !statement.is_empty())
        .collect()
}

#[test]
fn the_migration_reproduces_cratestacks_audit_table_ddl_statement_for_statement() {
    let expected = statements(cratestack::AUDIT_TABLE_DDL);
    let actual = statements(MIGRATION);

    assert!(
        !expected.is_empty(),
        "cratestack::AUDIT_TABLE_DDL parsed to zero statements -- the guard would pass vacuously"
    );

    for statement in &expected {
        assert!(
            actual.contains(statement),
            "cratestack::AUDIT_TABLE_DDL has a statement the migration does not:\n  {statement}\n\
             A cratestack bump changed the audit table. Add a NEW forward migration bringing \
             `cratestack_audit` up to the new definition and update the migration this test reads \
             -- do not edit the applied one (sqlx checksums it)."
        );
    }
}

#[test]
fn the_migration_creates_both_tables_it_claims_to_own() {
    let actual = statements(MIGRATION);

    for table in ["cratestack_audit", "cratestack_idempotency"] {
        assert!(
            actual
                .iter()
                .any(|s| s.starts_with(&format!("CREATE TABLE IF NOT EXISTS {table} "))),
            "the migration must create {table}: it is the only owner of that table now, since \
             both runtime bootstrap call sites were removed with it (#684)"
        );
    }
}

/// `IF NOT EXISTS` on every statement is what makes this migration a no-op against a database whose
/// tables were already bootstrapped at runtime by a deployment predating it. Without that, the
/// migration would fail on exactly the environments it most needs to be safe on.
#[test]
fn every_statement_in_the_migration_is_idempotent() {
    for statement in statements(MIGRATION) {
        assert!(
            statement.contains("IF NOT EXISTS"),
            "every statement must be idempotent, this one is not:\n  {statement}"
        );
    }
}
