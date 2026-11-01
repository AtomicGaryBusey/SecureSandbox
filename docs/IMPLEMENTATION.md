# Implementation overview

The implementation's containment baseline includes Anthropic's CVP Defense
[agent-containment guidance](ANTHROPIC_CVP_DEFENSE_CONTAINMENT_FOUNDATION.md),
including dedicated isolation, external credential brokering, post-change
negative validation, 30-day transcript/system-log retention, technical target
scope, human stop authority, segmentation, and exclusion of autonomous
high-consequence production targeting. Canonical source:
<https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants>.

The native macOS 27 [SecureSandbox Control Center](CONTROL_CENTER_DESIGN.md)
DDD is implemented. The app has a native sidebar, Settings, search, live
Overview, Sessions, Sources, Findings, and Activity catalogs, session labeling,
source planning, and an explicitly started session terminal. Stack lifecycle,
source import and indexing, finding actions, selected evidence exports, and
coordinated backup and restore have UI and versioned bridge paths. A live
encrypted-volume restore reached authenticated `verified` / `accepted`
completion, passed the complete boundary suite with all three replacement VMs
running and reachable, and was followed by a verified stop of all three VMs.
The reviewed host and guest control planes are deployed. Actions that require
a legitimate substantive finding, a naturally submitted memory proposal, or
snapshot-policy milestones remain explicitly gated rather than being exercised
against manufactured production state. See the
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
The Models settings surface now confirms profile removal against the exact
display name and profile ID, and confirms Reload whenever it would discard
unsaved draft changes. The same destructive-action audit added confirmation
before removing a persisted session label or forgetting an unsubmitted source,
backup, or restore plan handle. Existing stack, containment, finding, snapshot,
restore, retirement, and update mutations retain their stronger review,
readback, or Touch ID gates.
Its Updates tab implements bounded signed-metadata checking, an optional
metadata-only daily check and notification, exact release review, a separate
manual artifact download, fail-closed Developer ID/notarization admission,
Touch ID installation, atomic replacement, health commitment, and retained
rollback. There is no automatic artifact download or installation mode. The
production channel is visibly unprovisioned until a Developer ID Application
identity, offline manifest key, notarized bootstrap, and approved GitHub
distribution endpoint exist; the development signature is never accepted as a
fallback. See [the In-App Updates DDD](IN_APP_UPDATES_DESIGN.md).

The first protected-harness implementation checkpoint is also source-complete.
`labctl harness` exposes only status, signed-metadata check, explicit exact-
generation acquisition, and quarantine verification. Canonical threshold-
signed metadata, an equivocation-detecting sequence-and-envelope floor, exact
HTTPS/no-redirect bounds, content-derived generation identity, owner-only
non-executable quarantine, typed evidence bindings, and non-admitting receipts
are implemented in `shared/harness_lifecycle.py`. The live policy is absent and
ignored, so no vendor key, metadata channel, or candidate is configured. This
foundation has no Research, protected selector, installation, activation,
automatic-download, or runtime authority. See the
[Harness Lifecycle Foundation and Host Quarantine DDD](HARNESS_LIFECYCLE_FOUNDATION_HOST_QUARANTINE_DESIGN.md).
The second harness-lifecycle checkpoint is source-complete. The neutral
qualification evaluator requires one exact, expiring plan bound to the
generation, artifact, manifest, adapter, suite, fixture corpus, policy, and
runner. Its fixed thirty-case matrix derives pass/fail only from outer-observer
facts. The built-in self-test independently executes a tracked malicious
fixture in fresh temporary working directories and proves denial of hidden
tools, shells, direct MCP, children, dynamic code, packages, hooks,
marketplaces, extensions, subagents, login, model switching, self-update,
peer harnesses, provider networking, ambient project configuration, malformed
events, and hostile session state. The first-party Claude core adapter pins the
existing fixed launch seam and rejects credentials, loader injection, unknown
events, and session mismatch. A successful report remains
`fixture_qualified_not_admitted` with no authority; no vendor artifact or live
Research state is involved. See the
[Harness Conformance and Disposable Qualification DDD](HARNESS_CONFORMANCE_DISPOSABLE_QUALIFICATION_DESIGN.md).
The third harness-lifecycle checkpoint is source-complete. A protected
generation store now validates separately produced provenance, non-synthetic
qualification, and adapter evidence; publishes content-inventoried immutable
release directories; maintains a canonical catalog, selector, and monotonic
admission/revocation floor; consumes exact five-minute Touch ID receipts with
no password fallback; fences run admission; and uses the append-only privileged
workflow engine for activation, rollback, retirement, revocation, and recovery.
Health failure or preactivation process loss restores only the exact
predecessor. Rollback never lowers the floor, retirement requires fresh
zero-reference readback, revocation is monotonic, and no release-deletion API
exists. The only new operator CLI is read-only status/boundary inspection.
No vendor generation, release policy, live Research selector, or session lease
was admitted or changed. See the
[Protected Harness Generation Store DDD](PROTECTED_HARNESS_GENERATION_STORE_DESIGN.md).
The fourth harness-lifecycle checkpoint is source-complete. Session catalog v4,
Gateway lease v2, Research lease v2, and process seed v2 carry one canonical
harness-generation binding alongside the independent model-profile binding.
New sessions use the protected active generation; resume remeasures and uses
the exact recorded active-or-retained generation. Research remeasures before
arming and again before deriving an executable from the immutable protected
release root. The agent launcher no longer supplies an executable path. Legacy
sessions are non-resumable until one exact record is migrated using fresh
executable attestation and a five-minute Touch ID authorization with no
password fallback or selector inference. Deployment is transactionally wired
but intentionally preflight-blocked until a real protected generation exists;
the public migration CLI is plan-only until a protected Host authorization
consumer exists. No live guest or session was changed. See the
[Harness-Bound Sessions DDD](HARNESS_BOUND_SESSIONS_LEASES_RUNTIME_MIGRATION_DESIGN.md).

The Control Center now includes a typed Harnesses settings surface for
floor-bound signed release review, explicit Host quarantine acquisition,
independent evidence re-verification, the non-admitting synthetic containment
self-test, protected-generation inspection, and metadata-only notifications.
Protected mutation controls remain visibly unavailable until their independent
Touch ID-only Host/Research consumer exists; the GUI does not create substitute
authority. See the
[Control Center Harness Lifecycle GUI DDD](CONTROL_CENTER_HARNESS_LIFECYCLE_GUI_DESIGN.md).
The fifth harness-lifecycle checkpoint is source-complete. A bounded
Research-side consumer now stages exactly five reviewed files, creates and
applies protected generation plans, independently rereads active-run state,
runs a credential-free private-network health probe, and exposes only
deterministic journal recovery. The immutable Host authorization broker derives
the exact store receipt after native Touch ID, rejects password fallback, and
the protected Host manager rereads the v4 session catalog before management
and verifies status plus the full boundary after every mutation. Control Center
now creates a short-lived exact plan, displays its digest, generation, expiry,
and session counts, then invokes that same protected ceremony. Capabilities
remain disabled when evidence or protected state is absent. See the
[Protected Harness Lifecycle Authorization Consumer DDD](PROTECTED_HARNESS_LIFECYCLE_AUTHORIZATION_CONSUMER_DESIGN.md).
The sixth harness-lifecycle checkpoint is in progress. A disposable-Mac
campaign contract now binds 91 destructive and negative cases, 198 required
outer-observer facts, one hardware-identity digest, the exact source commit,
and a fixed suite digest. Enrollment rejects known production material and
provider credential markers; the public campaign CLI can catalog, initialize,
verify, assemble, and independently verify evidence but exposes no lifecycle
mutation. A complete export has only acceptance-evidence authority and cannot
admit a generation. Crash review also moved the durable recovery journal before
the admission fence and added non-user-selectable injected checkpoints at each
transaction boundary. A source-complete Host recovery supervisor now stages
only the campaign's exact commit through authenticated Research control,
proves stopped-worker PID/start-time/boot identity, serializes against normal
VM lifecycle operations, and can hard-power only the fixed Research VM after
an exact acknowledgement while preserving Gateway and Target state. It writes
raw fixed-authority evidence only after reserving the destination and grants no
observation or admission authority. Local source tests pass, but no physical
campaign or acceptance verdict exists yet. A separate fixed recovery projector
now revalidates the complete raw checkpoint/fault/reboot/recovery/boundary
chain, snapshots canonical bytes against same-user races, and publishes the
suite-assigned observations without accepting authority, kind, outcome, or
artifact overrides. Partial publication can resume only from exact matching
observations and never overwrites evidence. See the
[Disposable-Mac Harness Lifecycle Acceptance DDD](DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_DESIGN.md).
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
Live resume acceptance filtered the GUI to an unlabeled one-turn registered
session, passed its canonical UUID as a separate `--resume` argument, and
closed the resulting Short run through the native window path. Gateway and
Research read back closed and committed, and the session's v2 run catalog
contained the exact new run ID while preserving unknown historical counts.
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
separate review sheets and deployed bridge operations. Positive live mutation
remains gated on an operator-reviewed substantive finding; the system does not
alter a real candidate solely to manufacture acceptance evidence.
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

Emergency containment has passed live through the versioned bridge. Parallels
keeps the adapter `enabled` flag true while reporting cable disconnect through
an optional `state: disconnected` field, and both cable transitions silently
re-enable automatic gamepad sharing. Panic and Start therefore interpret the
exact asymmetric cable state, reassert gamepad sharing off after a transition,
and require independent readback. Live panic stopped Research and Target and
disconnected Gateway; the following Start reconnected and re-hardened Gateway,
returned all guests to reachable state, and passed all 133 boundary checks.

Run-lease status and renewal passed on a live short-profile zero-request
session. Renewal exposed a cleanup mismatch: the host controller compared the
final renewed lease byte-for-byte with its original issue record. The repair
allows only monotonic bounded `expires_at` and `renewals` changes while keeping
every immutable field equal, with a tamper-rejection fixture. The resulting
latched run was safely recovered through the native reconcile plan, exact
Gateway summary digest review, commit, and separate completed readback. The
repair is deployed. A later native red-X acceptance independently read back a
closed Gateway lease and committed Research completion without reconciliation.

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

The native authorization app is visually distinguished from the Control Center
by a gold padlock layered over the shared SecureSandbox icon. Its Icon Composer
JSON and SVG inputs are covered by the signed UI source manifest; the initial
source-set expansion is admitted only by the exact-predecessor
`bootstrap-authorization-icon-schema` transition.

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

Native terminal windows bind process lifetime to the actual `NSWindow` close
notification rather than relying on SwiftUI representable destruction. A
closed window sends SIGTERM to the reviewed controller and escalates only if
the same child PID remains after 30 seconds. The controller keeps its SSH
session as an explicit child while waiting, allowing HUP/INT/TERM traps to
hang up that child before the existing Research-close, Gateway-finalize, and
digest-bound Research-commit sequence runs. The close path is idempotent before
the first signal because both AppKit close notification and SwiftUI dismantling
can reach it. The coordinator strongly retains the off-window terminal and PTY
until process termination so view deinitialization cannot inject a second HUP;
SwiftTerm's independent force deadline is 35 seconds, after the app-owned
30-second deadline. Live acceptance proved the local tree exited and both
durable authorities closed and committed with no manual recovery.

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

Successful static reachability now publishes an immutable, producer-owned
analysis record and returns a three-field findings pointer containing the
evidence class, source UUID, and opaque analysis UUID. The findings broker
resolves that record and imports the graph digest and fixed evidence semantics;
legacy full projections remain accepted only on an exact field-for-field
match. Canonical structured digests remain ungrouped, while CodeGraph and MCP
display text groups them into eight-character chunks for comparison. The
idle-gated DDD deployment performs a fresh analysis, verifies exact pointer
resolution and fixed mismatch diagnostics, and then runs the complete
containment boundary.

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
config/model-profiles.example.json                -> config/model-profiles.json
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

The ignored model-profile catalog stores only bounded non-secret provider,
model, adapter, inference, pricing, lease, and `op://Agents/...` credential
references. Saving it is inert. Live authority changes only through an exact,
expiring Touch ID activation plan; each session and run lease remains bound to
one profile revision.

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

## Attested model profile configuration

`config/model-profiles.json` is ignored, owner-controlled mode 0600, bounded to
64 KiB and 16 profiles, and validated with closed adapter-specific schemas.
Tracked example data contains the existing Abliteration profile. Supported
protocol boundaries are fixed to Anthropic Messages, OpenAI Responses, and the
Google OpenAI-compatible chat endpoint; a profile cannot supply code or select
an arbitrary adapter.

Saving settings is inert. Activation creates a canonical five-minute plan that
binds the profile revision, adapter, vendor/model, inference settings, pricing,
lease limits, HTTPS origin, and resolved global IPv4 pins. The native review
sheet displays that authority, the independently agreed current-generation
digest, credential reference, OAuth pins, settings, ceilings, pricing, and
lease bounds, then submits the exact plan digest to the protected authorization
broker. The Touch ID ceremony repeats the security-relevant projection.
`model-profile-activate` forbids password fallback.

The protected Host coordinator durably records its transaction before the
first mutation. Gateway lease admission and Research run admission are fenced
under their existing lifecycle locks; the coordinator records mutation intent
before each guest transition, restores the prior guest and Host receipts on
failure, and leaves both fences closed if rollback cannot be proved. It commits
the Host receipt only after exact independent Gateway/Research readback, then
reopens Research first and Gateway last so a partially reopened transaction
cannot issue usable new authority. A later invocation recovers any nonterminal
transaction before accepting a new activation.

An upgraded legacy lab may have a reviewed Gateway broker identity but no
Research active-profile record. Research reports that condition as the bounded
`legacy_unbound` state instead of inferring authority. The state and Gateway
identity are both part of the reviewed current-generation digest; only the
exact Touch ID activation creates the first Research binding. Historical
sessions remain unbound and cannot resume implicitly.

Production credentials are read only through `op-agents`, streamed directly to
Gateway, encrypted with the guest host key, and bound by profile and reference
digests before activation. The Google adapter mints a short-lived service-
account assertion in memory and exchanges it only with pinned
`oauth2.googleapis.com`; the provider and OAuth addresses share the broker's
deny-by-default firewall identity. Safe mock activation requires no provider
credential or outbound provider path.

Gateway leases now contain adapter, vendor, model, profile ID, and profile
revision. The Host session catalog v3 records the same immutable identity and
rejects a legacy or cross-profile resume before requesting a lease. Research's
root watchdog state and process supervisor validate the binding before Claude
Code starts. A model in a running session therefore cannot select another
configured profile, credential, adapter, or endpoint.

Live acceptance activated the reviewed profile in safe-mock mode to create the
first explicit Research binding, then restored production in a separate exact
Touch ID ceremony. Gateway, Research, and Host receipts agree on the active
revision; the provider credential is encrypted and readable only through the
broker service; production address pins and profile-bound lease policy pass;
and the complete boundary suite passes with the source-matching protected Host
release. A subsequent verified whole-stack Stop/Start preserved the same
production authority; all three VMs returned reachable and the complete
post-boot boundary suite passed.
