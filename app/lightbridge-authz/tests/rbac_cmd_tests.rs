// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Tests for `lightbridge-authz rbac {grant,revoke,list}` (ADR-0033).
//!
//! `format_grants_*` run unconditionally (no database): they pin the one presentation rule that
//! carries meaning — a NULL `granted_by` renders as the explicit sentinel `CLI`, because "nobody
//! granted this, an operator with database credentials did" and "the granter is unknown" must not
//! look the same in a bootstrap audit.
//!
//! Everything that drives `rbac_cmd::dispatch` against real tables lives in the `db` module, gated
//! behind `it-tests` like every other Postgres-backed test in this workspace. The two refusals it
//! pins are the security-relevant behaviour of the whole command: an ambiguous `--user <email>` is
//! REFUSED rather than guessed at (guessing grants admin to the wrong human, silently), and an
//! unknown `--role` is refused rather than written (the row would confer nothing while looking
//! exactly like a successful grant).

use chrono::Utc;
use lightbridge_authz::rbac_lookup::format_grants;
use lightbridge_authz_api_key::entities::platform_role_grant_row::PlatformRoleGrantRow;

fn row(id: &str, user_id: &str, role: &str, granted_by: Option<&str>) -> PlatformRoleGrantRow {
    PlatformRoleGrantRow {
        id: id.to_string(),
        user_id: user_id.to_string(),
        role: role.to_string(),
        granted_by: granted_by.map(str::to_string),
        granted_at: Utc::now(),
        revoked_at: None,
        reason: None,
    }
}

#[test]
fn format_grants_marks_a_cli_bootstrap_explicitly() {
    let out = format_grants(&[
        row("g1", "user-a", "lightbridge-admin", None),
        row("g2", "user-b", "lightbridge-editor", Some("user-a")),
    ]);
    assert!(
        out.contains("CLI"),
        "a NULL granter is the CLI bootstrap sentinel, not a blank: {out}"
    );
    assert!(out.contains("user-a"));
    assert!(out.contains("lightbridge-editor"));
    assert!(
        out.contains("GRANT_ID"),
        "the header names every column: {out}"
    );
}

#[test]
fn format_grants_reports_empty_state() {
    assert_eq!(
        format_grants(&[]),
        "No active platform role grants.",
        "an empty listing says so in words -- a bare blank line reads like a broken command"
    );
}

#[cfg(feature = "it-tests")]
mod db {
    use lightbridge_authz::rbac_cmd::{RbacAction, dispatch};
    use lightbridge_authz::rbac_lookup::resolve_user;
    use lightbridge_authz_api_key::entities::platform_role_grant_row::PlatformRoleGrantFilter;
    use lightbridge_authz_api_key::repo::StoreRepo;
    use lightbridge_authz_core::CreateAccount;
    use lightbridge_authz_core::Error;
    use lightbridge_authz_core::authz::Rbac;
    use lightbridge_authz_core::cuid::cuid2;
    use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
    use lightbridge_authz_core::identity::AccountId;
    use lightbridge_authz_core::platform_role::known_platform_roles;
    use sqlx::PgPool;
    use std::sync::Arc;

    fn repo(pool: PgPool) -> StoreRepo {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        StoreRepo::new(pool)
    }

    fn roles() -> Vec<String> {
        known_platform_roles(&Rbac::default())
    }

    async fn seed_person(repo: &StoreRepo, subject: &str) -> String {
        repo.create_account(
            &AccountId::assert_already_resolved(subject),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
        subject.to_string()
    }

    async fn seed_identity(pool: &PgPool, account_id: &str, issuer: &str, email: &str) {
        sqlx::query(
            r#"
            INSERT INTO federated_identities
                (id, issuer, subject, account_id, email, email_verified, name,
                 last_authenticated_at, created_at, updated_at)
            VALUES ($1, $2, $3, $3, $4, true, 'Test Person', now(), now(), now())
            "#,
        )
        .bind(cuid2())
        .bind(issuer)
        .bind(account_id)
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
    }

    /// The bootstrap path end to end: grant by user id, list it, revoke it. `granted_by` stays NULL
    /// on this path ALWAYS -- that is what distinguishes a bootstrap from a console grant forever
    /// after, and it is the honest value even when the operator happens to have a user id.
    #[sqlx::test(migrations = "../../migrations")]
    async fn grant_by_user_id_records_a_cli_bootstrap_and_is_idempotent(pool: PgPool) {
        let repo = repo(pool);
        let user = seed_person(&repo, &format!("bootstrap-{}", cuid2())).await;

        for _ in 0..2 {
            dispatch(
                &repo,
                &roles(),
                RbacAction::Grant {
                    user: user.clone(),
                    role: "lightbridge-admin".to_string(),
                    reason: Some("first admin".to_string()),
                },
            )
            .await
            .expect("the bootstrap grant must succeed, and repeat cleanly");
        }

        let grants = repo
            .list_platform_role_grants(&PlatformRoleGrantFilter {
                user_id: Some(user.clone()),
                ..PlatformRoleGrantFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(grants.len(), 1, "idempotent: one row, not two: {grants:?}");
        assert_eq!(
            grants[0].granted_by, None,
            "a CLI grant records NULL -- there is no admin behind it, by construction"
        );
        assert_eq!(grants[0].reason.as_deref(), Some("first admin"));

        dispatch(
            &repo,
            &roles(),
            RbacAction::List {
                user: Some(user.clone()),
                role: None,
            },
        )
        .await
        .expect("list must succeed");

        dispatch(
            &repo,
            &roles(),
            RbacAction::Revoke {
                user: user.clone(),
                role: "lightbridge-admin".to_string(),
                reason: Some("done".to_string()),
            },
        )
        .await
        .expect("revoke must succeed");
        assert!(
            repo.active_platform_roles_for_user(&user)
                .await
                .unwrap()
                .is_empty()
        );

        let err = dispatch(
            &repo,
            &roles(),
            RbacAction::Revoke {
                user,
                role: "lightbridge-admin".to_string(),
                reason: None,
            },
        )
        .await
        .expect_err("revoking a role nobody actively holds must refuse, not silently succeed");
        assert!(matches!(err, Error::BadRequest(_)), "{err:?}");
    }

    /// An email matching more than one person is a HARD REFUSAL. Two people can genuinely share an
    /// email string -- `federated_identities` is unique on `(issuer, subject)`, not on `email` --
    /// and picking one would grant admin to the wrong human with no signal that it happened.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_ambiguous_email_is_refused_and_names_every_candidate(pool: PgPool) {
        let repo = repo(pool.clone());
        let one = seed_person(&repo, &format!("amb-one-{}", cuid2())).await;
        let two = seed_person(&repo, &format!("amb-two-{}", cuid2())).await;
        let email = format!("shared.{}@example.com", cuid2());
        seed_identity(&pool, &one, "https://issuer-a.example", &email).await;
        seed_identity(&pool, &two, "https://issuer-b.example", &email).await;

        let err = dispatch(
            &repo,
            &roles(),
            RbacAction::Grant {
                user: email.clone(),
                role: "lightbridge-admin".to_string(),
                reason: None,
            },
        )
        .await
        .expect_err("an ambiguous email must never be resolved by guessing");
        let message = err.to_string();
        assert!(matches!(err, Error::Conflict(_)), "{err:?}");
        assert!(
            message.contains(&one),
            "the refusal names every candidate: {message}"
        );
        assert!(
            message.contains(&two),
            "the refusal names every candidate: {message}"
        );

        assert!(
            repo.list_platform_role_grants(&PlatformRoleGrantFilter::default())
                .await
                .unwrap()
                .is_empty(),
            "a refused grant must write nothing at all"
        );
    }

    /// An unambiguous email DOES resolve -- the refusal above is about ambiguity, not about emails.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_unique_email_resolves_to_its_person(pool: PgPool) {
        let repo = repo(pool.clone());
        let user = seed_person(&repo, &format!("unique-{}", cuid2())).await;
        let email = format!("only.{}@example.com", cuid2());
        seed_identity(&pool, &user, "https://issuer-a.example", &email).await;

        // Deliberately in a different case from the stored value: an operator types the address by
        // hand, and email is case-insensitive in practice.
        assert_eq!(
            resolve_user(&repo, &email.to_uppercase()).await.unwrap(),
            user
        );

        let err = resolve_user(&repo, "nobody@example.com").await.unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)), "{err:?}");
        let err = resolve_user(&repo, "not-a-real-user-id").await.unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)), "{err:?}");
    }

    /// An unknown role is refused before anything is written. Without this, `--role
    /// lightbridge-admn` writes a row that confers nothing (`permissions_for_roles` maps an
    /// unrecognized role to the empty `default_grants` set) while looking exactly like a successful
    /// grant -- and the operator finds out only when the person it was for cannot do anything.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_role_is_refused_and_names_the_configured_catalogue(pool: PgPool) {
        let repo = repo(pool);
        let user = seed_person(&repo, &format!("typo-{}", cuid2())).await;

        let err = dispatch(
            &repo,
            &roles(),
            RbacAction::Grant {
                user: user.clone(),
                role: "lightbridge-admn".to_string(),
                reason: None,
            },
        )
        .await
        .expect_err("a role absent from the configured catalogue must be refused");
        let message = err.to_string();
        assert!(matches!(err, Error::BadRequest(_)), "{err:?}");
        assert!(message.contains("lightbridge-admn"), "{message}");
        assert!(
            message.contains("lightbridge-admin"),
            "the refusal shows the real options so the operator can retry without reading a values \
             file: {message}"
        );
        assert!(
            repo.active_platform_roles_for_user(&user)
                .await
                .unwrap()
                .is_empty(),
            "nothing may be written on a refused grant"
        );
    }

    /// A deployment that configures its OWN role names accepts those and refuses the built-in ones:
    /// the catalogue is operator configuration, not a hard-coded list.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_catalogue_follows_the_deployments_own_configuration(pool: PgPool) {
        let repo = repo(pool);
        let user = seed_person(&repo, &format!("custom-{}", cuid2())).await;
        let custom = Rbac {
            role_permissions: std::collections::HashMap::from([(
                "platform-owner".to_string(),
                vec!["*".to_string()],
            )]),
            ..Rbac::default()
        };
        let roles = known_platform_roles(&custom);

        dispatch(
            &repo,
            &roles,
            RbacAction::Grant {
                user: user.clone(),
                role: "platform-owner".to_string(),
                reason: None,
            },
        )
        .await
        .expect("a configured role must be grantable");
        assert!(
            dispatch(
                &repo,
                &roles,
                RbacAction::Grant {
                    user,
                    role: "lightbridge-admin".to_string(),
                    reason: None,
                },
            )
            .await
            .is_err(),
            "a built-in name this deployment does NOT configure confers nothing, so it must be \
             refused here too"
        );
    }
}
