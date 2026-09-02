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
