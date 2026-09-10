//! `platform_role_grants` reads and writes (ADR-0033): the table that decides who holds a platform
//! role, read at token mint by `ClaimSource::PlatformRoles` and written by `grantPlatformRole` /
//! `revokePlatformRole` / the `lightbridge-authz rbac` CLI.
//!
//! # Why hand-written SQL (ADR-0038)
//!
//! Two independent reasons, either alone disqualifying for the generated model client:
//!
//! 1. The hot read ([`StoreRepo::active_platform_roles_for_user`]) runs on the token-mint path
//!    inside `authz-idp`, which builds no cratestack client at all — the generated client is
//!    wired into `authz-api`/`authz-budget`'s RPC routers, not into the OP store. A model here
//!    would be unreachable from the one caller that matters most.
//! 2. [`StoreRepo::grant_platform_role`]'s idempotency is an `ON CONFLICT … WHERE revoked_at IS
//!    NULL DO NOTHING` against a PARTIAL unique index, and revocation is an `UPDATE … WHERE
//!    revoked_at IS NULL RETURNING` — the same class of single-statement conditional write as
//!    `consume_authorization_code`/`consume_secret_claim`, which generated CRUD cannot express.
//!
//! Recorded in AGENTS.md's Persistence exception list. Lives in its own module rather than in
//! `repo.rs` because that file sits on its committed LoC-gate baseline — same reason as
//! `session_revocation.rs` and `identity_resolution.rs`.
//!
//! # The subject → person hop
//!
//! Grants are keyed on `users.id` (the PERSON, ADR-0024/ADR-0026), while a token's subject is an
//! ACCOUNT id. Callers translate through [`StoreRepo::resolve_user_id_for_account`] (in
//! `platform_role_lookup.rs`) rather than assuming the two are equal — they are byte-identical for
//! every grandfathered account, but ADR-0026 lets one person own several, and a platform role must
//! follow the human across all of them.

use lightbridge_authz_core::error::{Error, Result};
use tracing::instrument;

use crate::db::StoreRepo;
use crate::entities::platform_role_grant_row::{
    NewPlatformRoleGrant, PlatformRoleGrantFilter, PlatformRoleGrantRow,
};

// Every query below spells its column list out in full rather than sharing one `const`: sqlx 0.9
// requires a `&'static str` for query text (`SqlSafeStr`), so a shared fragment would have to be
// `format!`-ed in, which the type system deliberately refuses. The four lists are identical and
// must stay so; `PlatformRoleGrantRow`'s `FromRow` derive is what catches a drift, at compile time
// for a renamed column and at the first test run for a missing one.

impl StoreRepo {
    /// The mint-path read: every ACTIVE role for `user_id`, sorted for a deterministic claim.
    ///
    /// An empty result is a perfectly ordinary answer ("this person was granted nothing"), NOT a
    /// failure — the claim mapper's fail-closed refusal fires only on a database error, never on
    /// an empty grant set. Served by the partial index `idx_platform_role_grants_user_active`.
    #[instrument(skip(self))]
    pub async fn active_platform_roles_for_user(&self, user_id: &str) -> Result<Vec<String>> {
        let roles = sqlx::query_scalar::<_, String>(
            r#"
            SELECT role
            FROM platform_role_grants
            WHERE user_id = $1 AND revoked_at IS NULL
            ORDER BY role
            "#,
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await?;
        Ok(roles)
    }

    /// Grants `role` to a person, IDEMPOTENTLY: a second call while an active grant already exists
    /// returns that existing row untouched rather than minting a duplicate or erroring. The
    /// operator asked for "this person holds this role", and after either outcome they do.
    ///
    /// Idempotency is enforced by the database, not by a read-then-write: the insert conflicts on
    /// the partial unique index `platform_role_grants_active_uidx`, so two concurrent grants
    /// cannot both succeed. The `reason` of an existing grant is deliberately NOT overwritten —
    /// the row records why the grant was originally made, and a repeat call is not a new decision.
    ///
    /// Refuses with [`Error::BadRequest`] when `user_id` names no `users` row, rather than letting
    /// the foreign key surface as an opaque 500. `BadRequest` and not the bare `Error::NotFound`
    /// (which carries no message at all): the caller supplied an id that does not exist, and the
    /// id it supplied is the single most useful thing the error can say.
    #[instrument(skip(self, grant), fields(user_id = %grant.user_id, role = %grant.role))]
    pub async fn grant_platform_role(
        &self,
        grant: NewPlatformRoleGrant,
    ) -> Result<PlatformRoleGrantRow> {
        if !self.user_exists(&grant.user_id).await? {
            return Err(Error::BadRequest(format!(
                "no such user: '{}'",
                grant.user_id
            )));
        }
        let inserted = sqlx::query_as::<_, PlatformRoleGrantRow>(
            r#"
            INSERT INTO platform_role_grants (id, user_id, role, granted_by, reason)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, role) WHERE revoked_at IS NULL DO NOTHING
            RETURNING id, user_id, role, granted_by, granted_at, revoked_at, reason
            "#,
        )
        .bind(&grant.id)
        .bind(&grant.user_id)
        .bind(&grant.role)
        .bind(&grant.granted_by)
        .bind(&grant.reason)
        .fetch_optional(self.pool())
        .await?;
        if let Some(row) = inserted {
            return Ok(row);
        }
        // `DO NOTHING` returned no row, so an active grant already existed. Read it back and
        // return it: that is what makes this idempotent rather than merely conflict-free.
        sqlx::query_as::<_, PlatformRoleGrantRow>(
            r#"
            SELECT id, user_id, role, granted_by, granted_at, revoked_at, reason
            FROM platform_role_grants
            WHERE user_id = $1 AND role = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(&grant.user_id)
        .bind(&grant.role)
        .fetch_optional(self.pool())
        .await?
        .ok_or_else(|| {
            // Reachable only if a concurrent `revoke_platform_role` landed between the two
            // statements above. Surfacing it as a conflict the caller can retry is honest;
            // pretending the grant succeeded would not be.
            Error::Conflict(format!(
                "grant for role '{}' was revoked concurrently; retry",
                grant.role
            ))
        })
    }

    /// Revokes one grant by id, stamping `revoked_at` and (when supplied) replacing `reason` with
    /// the revocation's own reason.
    ///
    /// `WHERE revoked_at IS NULL` makes this a single-statement CAS: a second revoke of the same
    /// grant returns `Ok(None)` — nothing to do — rather than re-stamping a later timestamp over
    /// the real revocation time and destroying the audit trail. `Ok(None)` therefore means "no
    /// such ACTIVE grant", covering both "unknown id" and "already revoked"; the caller decides
    /// whether that is an error for its surface.
    #[instrument(skip(self, reason))]
    pub async fn revoke_platform_role(
        &self,
        grant_id: &str,
        reason: Option<&str>,
    ) -> Result<Option<PlatformRoleGrantRow>> {
        let row = sqlx::query_as::<_, PlatformRoleGrantRow>(
            r#"
            UPDATE platform_role_grants
            SET revoked_at = now(),
                reason = COALESCE($2, reason)
            WHERE id = $1 AND revoked_at IS NULL
            RETURNING id, user_id, role, granted_by, granted_at, revoked_at, reason
            "#,
        )
        .bind(grant_id)
        .bind(reason)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// One page of grants, newest first, filtered per `filter`.
    ///
    /// Ordered by `granted_at DESC` (never by `id` — ADR-0039: CUID2 has no defined ordering), and
    /// cursored on the same column, so `idx_platform_role_grants_granted_at` /
    /// `idx_platform_role_grants_role_granted_at` serve the walk without a sort. The
    /// `include_revoked` half of the filter is what separates the audit view from the "who can do
    /// what right now" view; it defaults to active-only.
    #[instrument(skip(self, filter))]
    pub async fn list_platform_role_grants(
        &self,
        filter: &PlatformRoleGrantFilter,
    ) -> Result<Vec<PlatformRoleGrantRow>> {
        let rows = sqlx::query_as::<_, PlatformRoleGrantRow>(
            r#"
            SELECT id, user_id, role, granted_by, granted_at, revoked_at, reason
            FROM platform_role_grants
            WHERE ($1::text IS NULL OR user_id = $1)
              AND ($2::text IS NULL OR role = $2)
              AND ($3::boolean OR revoked_at IS NULL)
              AND ($4::timestamptz IS NULL OR granted_at < $4)
            ORDER BY granted_at DESC
            LIMIT $5
            "#,
        )
        .bind(filter.user_id.as_deref())
        .bind(filter.role.as_deref())
        .bind(filter.include_revoked)
        .bind(filter.after)
        .bind(filter.page_size())
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}
