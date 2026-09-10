//! The label lookup behind `resolveActorLabels`' fourth kind, `apiKeyIds` (#647, owner feedback
//! 2026-09-03: "can we use names on the 'Spend by API key' panel? API keys do have names").
//!
//! # This query answers WHAT a key is, never WHETHER the caller may see it
//!
//! Unlike its three siblings in [`crate::identity_resolution`], which are estate-wide by design and
//! gated entirely by the admin-only `user:read` permission, this one is reached by ORDINARY
//! members too. It still applies no ownership filter of its own — and that is deliberate, not an
//! oversight: the RPC handler decides visibility BEFORE calling this, and it decides it by reading
//! the ids back through the generated `db.api_key()` delegate, so tenant isolation is the `ApiKey`
//! model's own compiled `@@allow("read", …)` clause rather than a second hand-written ownership
//! join that could drift from it (`actor_api_key_labels.rs` in `lightbridge-authz-rest`, and
//! `listMyExpiringApiKeys`' doc comment for the same idiom).
//!
//! Splitting it that way means one SQL shape serves both callers: an admin passes the requested
//! ids straight through, a member passes the subset the policy already let them read. Any future
//! caller MUST do the same — this function is `pub` because the REST crate needs it, not because
//! it is safe to hand raw user input to.
//!
//! # Why hand-written SQL (ADR-0038)
//!
//! `ApiKey` carries `projectId` and no account edge (the model deliberately has no second relation
//! path to `Account` — see the `ProjectMember` comment in `authz.cstack` for the codegen blowup
//! that rule exists to prevent), so the label's `accountId` needs a join the generated client
//! cannot express. One statement here beats a second scoped `db.project()` round trip that would
//! also have required the caller to hold `project:read` just to be told which account their own
//! key belongs to.
//!
//! Its own file rather than `identity_resolution.rs` because that module sits at 191 of its
//! 200-line ceiling (`.github/loc-baseline.json` grandfathers files, it does not raise the ceiling
//! for new ones), and because the authorization story above is genuinely different from that
//! module's "no ownership filter, on purpose, forever".
//!
//! # Soft-deleted keys
//!
//! This query does NOT filter `deleted_at`: a usage row can name a key that was deleted after the
//! spend was recorded, and "the key you deleted last week" is exactly the label that row needs. The
//! member path reaches it through `db.api_key()`, whose generated `@@soft_delete` filter excludes
//! those rows unconditionally, so in practice a non-admin sees no label for a deleted key and the
//! console renders its own sentinel. That asymmetry is the model policy's answer, not a second
//! rule invented here.

use lightbridge_authz_core::error::Result;
use tracing::instrument;

use crate::db::StoreRepo;
use crate::entities::identity_label_row::{ApiKeyLabelRow, check_batch};

impl StoreRepo {
    /// Labels for `api_key_ids`, with each key's project and account edge. Unknown ids are absent.
    ///
    /// **Callers must have already decided that `api_key_ids` is visible to the caller** — see this
    /// module's doc comment. The cap is enforced here (200, rejected not truncated) so that the
    /// admin path, which passes caller-supplied ids straight through, cannot skip it.
    #[instrument(skip(self, api_key_ids), fields(count = api_key_ids.len()))]
    pub async fn resolve_api_key_labels(
        &self,
        api_key_ids: &[String],
    ) -> Result<Vec<ApiKeyLabelRow>> {
        check_batch("apiKeyIds", api_key_ids)?;
        if api_key_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, ApiKeyLabelRow>(
            r#"
            SELECT k.id         AS api_key_id,
                   k.name       AS name,
                   k.project_id AS project_id,
                   p.account_id AS account_id,
                   (k.revoked_at IS NOT NULL OR k.status <> 'active') AS revoked
            FROM api_keys k
            JOIN projects p ON p.id = k.project_id
            WHERE k.id = ANY($1)
            ORDER BY k.id
            "#,
        )
        .bind(api_key_ids)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}
