# Parallels snapshot retention

SecureSandbox keeps a synchronized, bounded recovery set across its three lab
VMs. The policy avoids long linear snapshot chains while retaining milestones
for clean provisioning, network containment, installed services, accepted
analysis capabilities, and the current stable state.

`./scripts/labctl snapshots` is read-only and reports the proposed action.
`./scripts/labctl snapshots --apply` performs consolidation only when all exact
lab VMs are stopped, the configured free-space floor is met, every named
milestone exists exactly once, the current snapshot is retained, and no VM has
an unexpected snapshot count. It never operates on unrelated Parallels VMs and
does not use recursive child deletion.

Milestone names and VM snapshot identifiers are installation-specific. They
live in ignored `config/snapshot-retention.json`, copied from the public example,
and in private acceptance records. Do not add them to tracked documentation.

Snapshot consolidation is not a substitute for off-host evidence. The external
archive independently retains security telemetry, encrypted conversations,
artifacts, and source-import evidence according to its configured policy.
