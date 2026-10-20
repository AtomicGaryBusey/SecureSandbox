# Implementation overview

This document describes implemented components and deployment acceptance. It
intentionally contains no live installation identifiers, cloud account details,
certificate fingerprints, source inventories, incident records, or run output.
Keep those records in ignored local storage.

## System shape

SecureSandbox uses three isolated Linux guests on an operator-controlled host:

- Gateway is the only guest with Internet access. Independently sandboxed
  services broker model traffic, source acquisition, telemetry, and encrypted
  evidence export.
- Research hosts the restricted agent, immutable source baselines, writable
  analysis worktrees, query-only indexes, and managed research instruments.
- Target executes bounded Python fixtures in a fresh rootless container with no
  network, a read-only root filesystem, a fixed unprivileged identity, and hard
  CPU, memory, process, time, and output limits.

The internal subnet layout in the design is a protocol convention, not a record
of a public installation. Host-facing addresses, interface MACs, SSH routes,
archive recipients, retention names, and secret-store selections live only in
ignored local configuration copied from `config/*.example.*`.

## Host control plane

`scripts/labctl` is the operator entry point. Long-lived agent runs enter a
root-owned, versioned host-controller release whose manifest, payload hashes,
ownership, permissions, and aggregate identity are verified before execution.
Deployment and rollback serialize against launches with a host coordination
lock. Each launch receives a unique run identifier and a bounded lease.

Launch fails closed when trusted guest time is stale, PKI generations disagree,
the Research run marker is occupied, required capture services are unhealthy,
or the requested resumed session is not present in the root-owned registry.

## Network and identity controls

Default guest firewall policy is deny. Gateway exposes only fixed mTLS service
endpoints required by Research. Research can reach only those Gateway endpoints
and the fixed Target service. Target has no Internet route. Service UIDs,
systemd sandboxing, peer certificates, fixed destinations, request bounds, and
root-owned configuration provide independent layers of control.

PKI deployment and rotation are transactional. A rotation stages a complete
generation, temporarily supports dual trust while peers change, verifies the
same manifest on both guests, and commits only after convergence. Private keys
remain on the guest that consumes them.

## Source and analysis path

The operator can plan acquisition of an exact public Git revision or exact
scoped package version. Gateway fetches only through endpoint-specific egress;
Research validates and normalizes the archive without network or lifecycle
execution. Publication produces a root-owned immutable baseline, a separate
agent-writable non-executable worktree, provenance, and a hash-bound registry
entry.

Managed instruments provide source verification, exhaustive literal search,
fixed-profile scanning, bounded exploration, tree inventory, source comparison,
default-configuration static reachability, sealed review-bundle verification,
candidate-finding submission, and memory proposals. Evidence classes remain
explicit: source review, static path evidence, and measured execution do not
imply one another or establish exploitability.

Dependency orchestration assembles only verified, exact, direct runtime
dependencies. It performs no package-manager installation or lifecycle scripts
and does not claim transitive completeness or runtime compatibility.

## Evidence and institutional memory

Conversation journals and agent-authored reports are captured by separate
privileged services, encrypted inside Research, transported over pinned mTLS,
and retained by the configured external archive. Plaintext is not placed on
Gateway. Evidence receipts are minted by identities distinct from the agent and
bind successful managed-tool results to the active run and source identities.

The agent cannot directly change its future instructions. It may submit a
bounded, explicitly untrusted memory proposal for independent review. Candidate
security findings are likewise append-only hypotheses; operator adjudication is
a separate root-owned authority.

## Local configuration

Copy and edit the relevant examples without adding the live copies to Git:

```text
config/ssh_config.example                     -> config/ssh_config
config/netplan-gateway.example.yaml           -> config/netplan-gateway.yaml
config/netplan-research.example.yaml          -> config/netplan-research.yaml
config/netplan-target.example.yaml            -> config/netplan-target.yaml
config/conversation-age-recipient.example.txt -> config/conversation-age-recipient.txt
config/snapshot-retention.example.json        -> config/snapshot-retention.json
config/provider-credential-reference.example.txt -> config/provider-credential-reference.txt
research/glm-persona.example.md                -> research/glm-persona.md
```

Guest bootstrap requires role-appropriate environment values:
`SECURE_SANDBOX_UPLINK_MAC`, `SECURE_SANDBOX_CONTROL_MAC`,
`SECURE_SANDBOX_LAB_MAC`, and, for Gateway,
`SECURE_SANDBOX_ADMIN_SOURCE_IPV4`. Gateway records the admin source in a
root-only local file used whenever its firewall is re-rendered.

Secrets are resolved from the dedicated 1Password vault at use time and piped
directly to their consumer. Secret values must never be written to this tree,
printed, or included in acceptance evidence.

## Acceptance contract

A deployment is ready only after automated tests and syntax checks pass and an
operator verifies, from fresh state:

1. cold boot and trusted time convergence for all guests;
2. deny-by-default boundaries and the exact allowed service paths;
3. consistent PKI and controller release identities;
4. model relay, source acquisition, source verification, and corpus queries;
5. capture, encrypted shipping, recovery, and safe rendering;
6. Target execution isolation and resource bounds;
7. crash recovery for transactional publication paths; and
8. publication checks against the exact Git object set intended for release.

Store identifiers, hashes, logs, incidents, and rollback records outside tracked
source. Documentation of a control is not proof that a live deployment currently
enforces it.
