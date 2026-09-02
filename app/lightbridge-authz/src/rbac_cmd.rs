//! `lightbridge-authz rbac {grant,revoke,list}` — the operator surface for `platform_role_grants`
//! (ADR-0033), and the ONLY way the first admin can ever exist.
//!
//! That is not a convenience: `grantPlatformRole` requires `rbac:manage`, `rbac:manage` comes from
//! a role, and after the cutover no role is minted by default — so there is no admin to grant the
//! first admin. This command breaks the cycle by writing the row directly, with
//! `granted_by = NULL` recording exactly that ("CLI bootstrap", not "unknown").
//!
//! Runs one-shot against the configured database and exits, exactly like `idp jwk rotate`: no
//! server, no HTTP, no bearer token. Intended for a `kubectl exec` or a k8s Job (see
//! `docs/rbac.md`'s bootstrap runbook). Every failure returns `Err`, which the binary surfaces as a
//! non-zero exit, so a Job that reports success really did write the row.
//!
//! Exposed from the crate's lib target rather than kept bin-private, purely so integration tests
//! can call [`dispatch`] directly instead of spawning the built binary — the same arrangement
//! `jwk_cmd` has.

use std::sync::Arc;

use lightbridge_authz_api_key::entities::platform_role_grant_row::{
    NewPlatformRoleGrant, PlatformRoleGrantFilter,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::platform_role::{known_platform_roles, validate_platform_role};

use crate::rbac_lookup::{format_grants, resolve_user};

/// The three `rbac` operations, decoupled from `cli.rs`'s clap `Subcommand` shape so this module's
/// public API does not depend on how the binary happens to parse its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RbacAction {
    /// `--user` is a `users.id` or an email; see [`resolve_user`].
    Grant {
        user: String,
        role: String,
        reason: Option<String>,
    },
    Revoke {
        user: String,
        role: String,
        reason: Option<String>,
    },
    List {
        user: Option<String>,
        role: Option<String>,
    },
}

/// Entry point: loads config, connects to Postgres (no Redis — grants are DB-only), and dispatches.
pub async fn run(config_path: &str, action: RbacAction) -> Result<()> {
    let config = load_from_path(config_path)?;
    let known_roles = known_platform_roles(&config.oauth2.rbac);
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);
    let repo = StoreRepo::new(pool);
    dispatch(&repo, &known_roles, action).await
}

/// The part of [`run`] that touches the database, taking an already-built [`StoreRepo`] and the
/// already-resolved role catalogue rather than a config path — so integration tests can exercise it
/// against a real test database without a config file on disk.
pub async fn dispatch(repo: &StoreRepo, known_roles: &[String], action: RbacAction) -> Result<()> {
    match action {
        RbacAction::Grant { user, role, reason } => {
            grant(repo, known_roles, &user, &role, reason).await
        }
        RbacAction::Revoke { user, role, reason } => {
            revoke(repo, known_roles, &user, &role, reason).await
        }
        RbacAction::List { user, role } => list(repo, user.as_deref(), role.as_deref()).await,
    }
}

async fn grant(
    repo: &StoreRepo,
    known_roles: &[String],
    user: &str,
    role: &str,
    reason: Option<String>,
) -> Result<()> {
    let user_id = resolve_user(repo, user).await?;
    let role = validate_platform_role(role, known_roles)?;
    let row = repo
        .grant_platform_role(NewPlatformRoleGrant {
            id: cuid2(),
            user_id,
            role,
            // NULL, always, on this path: nobody in `users` made this decision — an operator with
            // database credentials did. That is what distinguishes a bootstrap from a console grant
            // forever after, and it is the honest value even when the operator has a user id.
            granted_by: None,
            reason,
        })
        .await?;
    println!(
        "granted {} to user {} (grant {}, granted_at {})",
        row.role, row.user_id, row.id, row.granted_at
    );
    println!(
        "note: the role reaches this person's token only at the next mint -- bounded by the \
         access-token TTL, see docs/rbac.md"
    );
    Ok(())
}

/// Revokes the ACTIVE grant of `role` for `user`, then closes that person's sessions.
///
/// The session fan-out mirrors `revokePlatformRole`'s, and for the same reason: stamping
/// `revoked_at` alone would leave a still-valid access token carrying the revoked role, and a
/// refresh would keep re-minting it from the same live session. A bootstrap-time revocation that
/// did not bite would be a trap.
async fn revoke(
    repo: &StoreRepo,
    known_roles: &[String],
    user: &str,
    role: &str,
    reason: Option<String>,
) -> Result<()> {
    let user_id = resolve_user(repo, user).await?;
    let role = validate_platform_role(role, known_roles)?;
    let active = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id: Some(user_id.clone()),
            role: Some(role.clone()),
            ..PlatformRoleGrantFilter::default()
        })
        .await?;
    let Some(grant) = active.first() else {
        return Err(Error::BadRequest(format!(
            "user {user_id} holds no active grant for role '{role}'"
        )));
    };
    repo.revoke_platform_role(&grant.id, reason.as_deref())
        .await?;
    let mut revoked_sessions = 0u64;
    for account_id in repo.account_ids_for_user(&user_id).await? {
        revoked_sessions += repo
            .revoke_sessions_and_cascade(&AccountId::assert_already_resolved(&account_id))
            .await?;
    }
    println!(
        "revoked {role} from user {user_id} (grant {}); closed {revoked_sessions} session(s)",
        grant.id
    );
    Ok(())
}

async fn list(repo: &StoreRepo, user: Option<&str>, role: Option<&str>) -> Result<()> {
    let user_id = match user {
        Some(needle) => Some(resolve_user(repo, needle).await?),
        None => None,
    };
    let rows = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id,
            role: role.map(str::to_string),
            ..PlatformRoleGrantFilter::default()
        })
        .await?;
    println!("{}", format_grants(&rows).trim_end());
    Ok(())
}
