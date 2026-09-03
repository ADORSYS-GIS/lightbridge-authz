# Runbooks

| Runbook | Open it when |
|---|---|
| [budget-tier-rekey-cutover.md](./budget-tier-rekey-cutover.md) | Performing the one-time move from per-plan budget rules to the tier ladder |
| [stuck-augmentation-request.md](./stuck-augmentation-request.md) | A user says their refill "did nothing", or a request is stuck pending |
| [roll-back-a-budget-policy.md](./roll-back-a-budget-policy.md) | A policy revision is approving or denying the wrong things |
| [signing-key-management.md](./signing-key-management.md) | Users are suddenly asked to log in again, a refresh returns `400 invalid_grant`, or you need to inspect/create/rotate `authz-idp`'s signing keys |
| [reclaim-usage-events-space.md](./reclaim-usage-events-space.md) | The `usage` database is consuming more volume than the retention window should allow, or you need to physically reclaim the space from the dropped `attributes` column (#549 AC5) |
