//! The two derived views of the RPC permission map that `rpc_authorize.rs` publishes but does not
//! itself consult: [`MAPPED_OP_ID_PERMISSIONS`] (the enumeration of every op-id
//! `rpc_authorize::required_permission` maps to a `Some`) and [`permission_field_name`] (the
//! `auth().perm*` field name each [`Permission`] is baked into).
//!
//! Split out of `rpc_authorize.rs` rather than left beside `required_permission` purely because
//! that file sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be
//! touched but not grown — the same reason `lightbridge-authz-api-key`'s `session_revocation.rs`
//! is separate from its `repo.rs`. Moved verbatim, and `rpc_authorize` re-exports both, so every
//! existing `lightbridge_authz_rest::rpc_authorize::{MAPPED_OP_ID_PERMISSIONS,
//! permission_field_name}` path (`schema_policy_sync_tests.rs`, `auth_provider.rs`) still
//! resolves. The pairing with `required_permission` that
//! `every_mapped_op_id_maps_to_the_documented_permission` enforces is unchanged: that test still
//! walks this list against that match arm-for-arm, so the two cannot drift across the file
//! boundary any more than they could within one file.

use lightbridge_authz_core::Permission;

/// Op-ids that require ONLY a valid, active bearer token -- no permission at all.
///
/// This list is the deliberate, enumerated exception to [`required_permission`]'s fail-closed
/// `None => denied` rule (`rpc_authorize.rs`), and it is a list rather than a "self-service ops are
/// exempt" heuristic precisely so that adding one is a conscious edit somebody reviews.
///
/// [`required_permission`]: crate::rpc_authorize::required_permission
///
/// `getMyAccess` (ADR-0033) returns the caller's OWN already-minted roles and the
/// permission set the server derives from them. Gating it would defeat its purpose: the console
/// calls it to find out what it may render, so a permission requirement would make "you may not
/// ask what you may do" a reachable state, and the natural candidates all make it worse --
/// `rbac:manage` would restrict it to the admins who need it least, and any permission every role
/// happens to hold today is an accident of the default map that an operator's own
/// `role_permissions` can revoke. It discloses nothing new either way: every value it returns is
/// already derivable from the caller's own token, which they are holding.
///
/// `getBuildInfo` (#573) returns the running build's version/commit/image stamp. It is here for a
/// simpler reason: the SAME values are already served unauthenticated at `GET /version` on every
/// listener, beside `/healthz`. Requiring a permission on the RPC transport of a value anyone can
/// curl would be theatre, and it would break the one console screen (`/settings/info`) whose whole
/// job is to answer "what am I running, and what am I talking to" for every signed-in user, not
/// just admins.
pub const AUTHENTICATED_ONLY_OP_IDS: &[&str] = &["procedure.getMyAccess", "procedure.getBuildInfo"];

/// Whether `op_id` is served to any authenticated caller (see [`AUTHENTICATED_ONLY_OP_IDS`]).
pub fn is_authenticated_only_op_id(op_id: &str) -> bool {
    AUTHENTICATED_ONLY_OP_IDS.contains(&op_id)
}

/// Every op-id `required_permission` maps to a `Some`, paired with the expected permission —
/// the single enumeration both `every_mapped_op_id_maps_to_the_documented_permission` (below) and
/// `schema_policy_sync`'s codegen/drift-check walk, so there is exactly one hand-maintained list
/// of "every mapped op-id" in this crate, not two that could silently diverge. Order matches
/// `required_permission`'s own declaration order. `model.AccountSummary.{list,get}` are included
/// even though that view has no live RPC dispatch arm today (see `authz.cstack`'s own doc comment
/// on it) — its `@@allow` clause still exists and still deserves the same generated gate, forward-
/// looking/defensive exactly as the view entry itself already is.
pub const MAPPED_OP_ID_PERMISSIONS: &[(&str, Permission)] = &[
    ("procedure.createAccount", Permission::AccountCreate),
    ("model.Account.list", Permission::AccountRead),
    ("model.Account.get", Permission::AccountRead),
    (
        "procedure.updateAccountDefaultQuota",
        Permission::AccountUpdate,
    ),
    ("procedure.updateAccountName", Permission::AccountUpdate),
    ("procedure.disableAccount", Permission::AccountDisable),
    ("procedure.enableAccount", Permission::AccountDisable),
    (
        "procedure.deleteAccountPermanently",
        Permission::AccountDelete,
    ),
    ("model.Project.create", Permission::ProjectCreate),
    ("model.Project.list", Permission::ProjectRead),
    ("model.Project.get", Permission::ProjectRead),
    ("model.Project.update", Permission::ProjectUpdate),
    ("model.Project.delete", Permission::ProjectDelete),
    ("procedure.disableProject", Permission::ProjectDisable),
    ("procedure.enableProject", Permission::ProjectDisable),
    ("procedure.setDefaultProject", Permission::ProjectUpdate),
    ("procedure.setProjectQuota", Permission::ProjectUpdate),
    (
        "procedure.setProjectAllowedModels",
        Permission::ProjectUpdate,
    ),
    ("procedure.setProjectModelPolicy", Permission::ProjectUpdate),
    ("procedure.addProjectMember", Permission::ProjectMember),
    ("procedure.removeProjectMember", Permission::ProjectMember),
    ("procedure.listProjectRoster", Permission::ProjectMember),
    ("procedure.setProjectMemberRole", Permission::ProjectMember),
    (
        "procedure.setProjectMemberQuotaTier",
        Permission::ProjectMember,
    ),
    ("procedure.createApiKey", Permission::ApiKeyCreate),
    ("procedure.listBillingPlans", Permission::ApiKeyCreate),
    ("procedure.listModelCatalog", Permission::ProjectUpdate),
    ("model.ApiKey.list", Permission::ApiKeyRead),
    ("model.ApiKey.get", Permission::ApiKeyRead),
    ("model.ApiKey.update", Permission::ApiKeyUpdate),
    ("model.ApiKey.delete", Permission::ApiKeyDelete),
    ("procedure.revokeApiKey", Permission::ApiKeyRevoke),
    ("procedure.rotateApiKey", Permission::ApiKeyRotate),
    ("procedure.listMyExpiringApiKeys", Permission::ApiKeyRead),
    ("model.AccountSummary.list", Permission::AccountRead),
    ("model.AccountSummary.get", Permission::AccountRead),
    (
        "procedure.activateBudgetPolicy",
        Permission::BudgetPolicyActivate,
    ),
    (
        "procedure.getBudgetPolicyStatus",
        Permission::BudgetPolicyRead,
    ),
    (
        "procedure.simulateBudgetPolicy",
        Permission::BudgetPolicySimulate,
    ),
    (
        "procedure.requestBudgetRefill",
        Permission::BudgetSelfRefill,
    ),
    (
        "procedure.getMyBudgetRefillLadder",
        Permission::BudgetSelfRefill,
    ),
    (
        "procedure.listPendingAugmentationRequests",
        Permission::BudgetReview,
    ),
    (
        "procedure.approveAugmentationRequest",
        Permission::BudgetReview,
    ),
    (
        "procedure.rejectAugmentationRequest",
        Permission::BudgetReview,
    ),
    ("procedure.querySessions", Permission::SessionReadOwn),
    ("procedure.revokeSession", Permission::SessionRevokeOwn),
    ("procedure.revokeOwnSessions", Permission::SessionRevokeOwn),
    ("procedure.revokeSubjectSessions", Permission::SessionRevoke),
    ("procedure.getMyBudgetBalance", Permission::BudgetReadOwn),
    ("procedure.listMyBudgetGrants", Permission::BudgetReadOwn),
    (
        "procedure.listMyAugmentationRequests",
        Permission::BudgetReadOwn,
    ),
    ("procedure.getBudgetBalance", Permission::BudgetRead),
    ("procedure.listBudgetGrants", Permission::BudgetAuditRead),
    ("procedure.grantBudget", Permission::BudgetGrant),
    ("procedure.revokeBudgetGrant", Permission::BudgetRevoke),
    (
        "procedure.createBudgetPolicyRevision",
        Permission::BudgetPolicyWrite,
    ),
    (
        "procedure.listBudgetResetSchedules",
        Permission::BudgetScheduleManage,
    ),
    (
        "procedure.createBudgetResetSchedule",
        Permission::BudgetScheduleManage,
    ),
    (
        "procedure.updateBudgetResetSchedule",
        Permission::BudgetScheduleManage,
    ),
    (
        "procedure.deleteBudgetResetSchedule",
        Permission::BudgetScheduleManage,
    ),
    (
        "procedure.runBudgetResetScheduleNow",
        Permission::BudgetScheduleManage,
    ),
    (
        "procedure.getEffectiveResetSchedule",
        Permission::BudgetRead,
    ),
    ("procedure.resolveUserProfiles", Permission::UserRead),
    ("procedure.resolveActorLabels", Permission::UserRead),
    ("procedure.searchUsers", Permission::UserRead),
    ("procedure.listPlatformRoleGrants", Permission::RbacManage),
    ("procedure.grantPlatformRole", Permission::RbacManage),
    ("procedure.revokePlatformRole", Permission::RbacManage),
];

/// The `auth().<field>` name `CratestackAuthProvider` bakes each [`Permission`]'s boolean grant
/// into, and every generated `@allow`/`@@allow` clause in `authz.cstack` reads. Mechanically
/// derived from [`Permission::as_str`]'s canonical `resource:action` string (splitting further on
/// `-` for hyphenated actions like `read-own`) rather than a second hand-typed list of 32 names —
/// same single-source-of-truth reasoning as [`MAPPED_OP_ID_PERMISSIONS`] above. E.g.
/// `"account:create"` -> `"permAccountCreate"`, `"budget:read-own"` -> `"permBudgetReadOwn"`.
pub fn permission_field_name(permission: Permission) -> String {
    let mut out = String::from("perm");
    for part in permission.as_str().split([':', '-']) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}
