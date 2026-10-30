# Implementation overview

The native macOS 27 [SecureSandbox Control Center](CONTROL_CENTER_DESIGN.md)
DDD is in progress. The app has a native sidebar, Settings, search, live
Overview, Sessions, Sources, Findings, and Activity catalogs, session labeling,
source planning, and an explicitly started session terminal. Stack lifecycle,
source import and indexing, finding actions, selected evidence exports, and
coordinated backup and restore have UI and versioned bridge paths. A live
encrypted-volume restore reached authenticated `verified` / `accepted`
completion, passed the complete boundary suite with all three replacement VMs
running and reachable, and was followed by a verified stop of all three VMs.
The reviewed host and guest control planes are deployed; action-specific live
acceptance remains for several actions. See the
[command parity inventory](CONTROL_CENTER_COMMAND_PARITY.md) for the current
state of each operation. The validated local app can be installed at
`~/Applications/SecureSandbox.app` with
`macos/ControlCenter/script/install_local.sh` after building its bundle.
Recovery also verifies and separately retires only the terminal journal's
retained failed candidate or previous accepted generation; it requires a
stopped identity-matched stack, a destructive native confirmation, a durable
claim, and authenticated completion readback.
The accepted restore's previous generation remains retained. Its authenticated
preview is ready, but retirement is deliberately pending a separate explicit
operator confirmation.
The main window owns Recovery's transient workflow model, so sidebar
navigation preserves selected inventory, previews, plans, operation readback,
errors, and in-progress controls. A completed backup can reopen its exact
journal-recorded destination through `Use This Verified Backup`, avoiding path
and generation-ID entry.
Settings offers app-only System, Light, and Dark appearance, a shared optional
export-provenance preference, and read-only archive and diagnostic locations.
The Sources view accepts strict public GitHub repository URLs and exact npm
package versions. It requests a time-limited immutable plan, displays the
resolved source identity and plan ID for review, and requires status readback
before a one-time import submission. The protected dispatcher supports that
status readback. Before submission, the bridge and native sheet now compare the
resolved repository and commit against a fresh Sources catalog, reject an exact
duplicate, and offer the existing source for analysis without GUID entry.
The Sessions view can set or remove a private operator label through the
existing `labctl session` path, then reload the catalog. A label does not
grant resume authority.
The session terminal is a separate, explicitly started window. It uses a
revision-pinned SwiftTerm PTY and invokes the installed protected Claude launcher
with a selected UUID as a separate argument. Untrusted terminal output cannot
request OSC 52 clipboard reads or writes or activate links through this view.
The terminal scene does not restore itself into a new run on app relaunch.
Gateway source planning now forwards only stable fetcher error codes through
the control boundary. The app maps known codes to operator guidance without
displaying a raw transient-unit traceback. A live `master` ref plan for the
public example repository succeeded after this change; a `main` ref correctly
reported GitHub status 422.
The source import client checks the plan state before submission, then requires
readback of a completed plan bound to the returned source ID. A failed or
disconnected submission cannot be replayed from the same sheet. Gateway's
`source-status` command is deployed; the UI keeps Import disabled whenever an
independent planned-state readback is unavailable.
An unsubmitted plan can be discarded locally when status readback fails, so it
does not indefinitely block planning a different URL. Once Import is attempted,
the app retains the plan pointer until a terminal outcome is confirmed.
Dependency orchestration accepts the same canonical scoped and unscoped npm
names as source acquisition while continuing to reject ranges, tags, aliases,
URLs, paths, and lifecycle execution. A live unscoped zero-dependency package
passed native plan, independent status, sealed apply, exact set-digest, and
nonempty bundle-catalog readback.
The Activity view displays a bounded projection of the existing metadata-only
Gateway telemetry tail. It excludes request IDs, policy hashes, and any
unrecognized fields from the GUI response.
Selecting a finding and opening its detail explicitly fetches a bounded text
projection, support classification, and history counts. The detail labels
agent-authored claims as untrusted content. Root-authorized adjudication has
separate review sheets and bridge operations, pending protected deployment and
live acceptance.
The Findings list uses severity, state, local submission time, and a stable
ordinal for same-minute entries. The full finding ID remains searchable and
available in detail without occupying each catalog row.
Evidence rows likewise use report filename, version, and local capture time,
with a stable ordinal if those labels collide. The artifact ID remains
searchable and available when a report is opened.
Search selection is limited to visible rows in Sources, Findings, and Evidence.
Filtering out a selection clears it, and a removed record cannot leave an
enabled detail action after catalog refresh.
Maintenance and Recovery show independent read-only guest-clock and snapshot
retention checks. Snapshot changes require the existing stopped-stack safety
gates.
Maintenance can also run the complete existing boundary verifier on demand;
the bridge requires its final success marker and returns only check and gate
counts to the app.
Maintenance's apply-time-sync workflow and explicit control-identity reload
have passed live readback. The exact fixed SSH PTY commands used by its
Research and Target administrator windows have also opened their intended
prompts and exited cleanly.

Run-lease status and renewal passed on a live short-profile zero-request
session. Renewal exposed a cleanup mismatch: the host controller compared the
final renewed lease byte-for-byte with its original issue record. The repair
allows only monotonic bounded `expires_at` and `renewals` changes while keeping
every immutable field equal, with a tamper-rejection fixture. The resulting
latched run was safely recovered through the native reconcile plan, exact
Gateway summary digest review, commit, and separate completed readback. The
repair is committed but still awaits protected host-controller deployment.

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
lock. Host-controller publication, rollback, stable-launcher migration, and host
PKI anchor transitions, protected installer publication, and VM lifecycle
mutations additionally pass through the immutable authorization
broker: a signed native macOS window identifies the declared agent/session,
purpose, operation, nonce, digest, expiry, and operation parameters before an
explicit Touch ID, administrator-password, or cancel choice. A separately
protected root broker revalidates the exact request and signed UI peer; a
root-owned receipt enforces at-most-once execution. Read-only installer verification and VM dry-run
planning do not elevate. The protected VM coordinator starts only through the
broker and permanently drops to the invoking Mac UID before calling Parallels;
`prlctl` is never run as root by the project workflow. Each launch
receives a unique run identifier and a bounded lease. See
`OPERATOR_AUTHORIZATION_PROVENANCE_DESIGN.md`,
`TOUCH_ID_OPERATOR_AUTHORIZATION_DESIGN.md`, and
`UNIVERSAL_HOST_MAINTENANCE_AUTHORIZATION_DESIGN.md`.

Automated guest administration uses a separate `securectl` SSH identity and a
forced, root-owned dispatcher. Routine operations are exact argv allowlist
entries bound to the authenticated guest role. Root-equivalent deployment uses
content-bound bundles extracted into root-private storage and executed behind a
private `/tmp` mount. The staging parent remains `0700`; the request directory
is `01777` only inside the private namespace so deprivileged verifier children
can use normal `/tmp` semantics while secret inputs remain `0600`. Reusable
guest sudo passwords and execution from shared guest `/tmp` are not part of the automated control path. See
`PRIVILEGED_CONTROL_PLANE_DESIGN.md` for the threat model and clean-bootstrap
requirements.

Launch fails closed when trusted guest time is stale, PKI generations disagree,
the Research run marker is occupied, required capture services are unhealthy,
or the requested resumed session is not present in the root-owned registry. Resume
authorization refreshes and checks membership as one locked privileged operation, so
it cannot authorize from a stale registry after a failed or interleaved refresh.
The same bounded journal pass publishes content-free creation, activity,
human-turn, and compaction metadata for operator discovery. The protected host
controller separately records admitted post-DDD run counts immediately before
the fixed Research launcher; historical counts remain unknown rather than
being inferred from agent-owned journal bookkeeping.
Optional operator labels live only in a private Mac-local catalog and never
become resume authority or guest conversation metadata. See
`SESSION_DISCOVERY_AND_LABELS_DESIGN.md`.

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

Fresh VM creation is followed by the serialized, resumable restoration graph
implemented by `scripts/restore-fresh-vms.py`. Its ignored journal binds every
phase to the exact VM UUIDs, bundle paths, and restoration-input digest. It
holds the launch-admission lock through package provisioning, idempotent PKI
bootstrap and rotation, service deployment, hot acceptance, and a real
guest-initiated cold boot. See `FRESH_VM_CONTAINMENT_RESTORATION_DESIGN.md` for
the recovery and acceptance contract.

## Source and analysis path

The operator can plan acquisition of an exact public Git revision or exact
scoped package version. Gateway fetches only through endpoint-specific egress;
Research validates and normalizes the archive without network or lifecycle
execution. Publication produces a root-owned immutable baseline, a separate
agent-writable non-executable worktree, provenance, and a hash-bound registry
entry.

The agent-owned workspace root is `0750`, not `0700`. The agent retains full
control of its mutable workspace, while only service identities deliberately
placed in the `agent` group can traverse to fixed root-owned children such as
the source registry, immutable manifests, and corpus indexes. Those children
remain root-owned and non-writable. Every installer that creates or consumes
these trees reasserts this traversal contract, and live boundary verification
tests the actual corpus, execution, and findings identities against it.

Managed instruments provide source verification, exhaustive literal search,
fixed-profile scanning, bounded exploration, tree inventory, source comparison,
default-configuration static reachability, sealed review-bundle verification,
candidate-finding submission, and memory proposals. Evidence classes remain
explicit: source review, static path evidence, and measured execution do not
imply one another or establish exploitability.

Corpus and CodeGraph publication now expose separate root-routed `status`
operations. The host bridge normalizes only an exact source-bound
`indexed` result with a 64-hex digest and nonnegative item count, or the typed
`not_indexed` state. The native index sheet checks this durable state when it
opens and immediately after an ambiguous build response, so it never needs to
reissue a potentially completed build to discover the outcome. Corpus status
also compares stored document metadata with the SQLite row count. CodeGraph
status reuses the sealed-tree validator and can finish publication of a
missing exact marker; a marker without its graph remains a hard failure.

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
9. control-plane forced-command, role-denial, payload-integrity, audit,
   ownership, and local-admin-negative checks on every guest.

Store identifiers, hashes, logs, incidents, and rollback records outside tracked
source. Documentation of a control is not proof that a live deployment currently
enforces it.
