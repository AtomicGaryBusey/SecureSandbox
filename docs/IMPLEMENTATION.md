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

The Native Vendor Harness + Model Stack Mode DDD now has a source implementation
candidate. Its closed registry admits exactly two vendor tuples: unmodified
Claude Code + Anthropic subscription OAuth + the operator's CVP Defense
declaration + Mythos 5.1, and exact Codex + OpenAI Sign in with ChatGPT +
Daybreak Blue + `gpt-6-sol`, `gpt-6-luna`, or `gpt-6.1-sol`. The tuples retain
different credential-custody contracts rather than treating OAuth tokens as
interchangeable. Cross-vendor composition, arbitrary adapters, alternate
program tiers, unreviewed models/settings, weakened custody, and fallback are
rejected. The ignored owner-only catalog remains inert: saving reports only
`configuration-required`, `login-required`, or `content-ready` and never opens
egress, authenticates, activates, or launches a harness.

`gpt-6.1-sol` was added explicitly because OpenAI's current SIWC Models and
inference Responses example names it. It is a separately bound reviewed model, not an
alias, wildcard, fallback, or automatic upgrade from either earlier entry.

The complete native binding now flows through the mutually exclusive
brokered/native runtime union, canonical session plan, runtime authority,
Host/Gateway/Research leases, exact process generation, egress grant, UI
handle, journal, final summary, and teardown readback. It binds the session,
source and source manifest, persona, outer-tool catalog, extension set, vendor,
harness generation/adapter, custody, opaque account/workspace, program/tier,
model/settings, network policy, and lease profile. Every consumer repeats the
comparison; catalog-current inference, cross-mode resume, cross-account reuse,
and expired authority fail closed. Activation is projection-free and remains a
different Touch ID action from session start.

The source candidate implements phase-scoped native egress with exact
destination and resource ceilings, timed kernel sets, UID/mark rules,
structural nftables verification, durable deny recovery, independent Gateway
and Research watchdogs, process termination, conntrack purge, and closed-state
readback. Installer promotion, recovery, and rollback serialize on the exact
admission and actuator locks. An ambiguous controller or watchdog transition
leaves the provider path closed.

Claude uses its own unmodified subscription login and credential store through
an opaque no-capture channel; SecureSandbox never asks for or intermediates its
token. The Research adapter derives only purpose-separated opaque
account/workspace/subscription bindings from bounded native status, applies the
single-model/no-tools policy, and runs each vendor command in an exact
stopped-child systemd scope. Session and qualification admission require Claude
Code 2.1.248 or later, `--restricted`, an empty built-in tool set, blanket/MCP
tool denial, managed plus explicit settings only, no permission bypass, and no
cloud session. Login, status, qualification, logout, cancellation, UI loss, and
expiry all converge on exact process and egress teardown. CVP
Defense remains an `operator-external` declaration unless Anthropic exposes an
independent tier attestation; this DDD does not replace the separate CVP
conformance review.

OpenAI SIWC uses a stable Secure Enclave host identity and a Developer
ID-restricted per-user credential helper. Rotating refresh custody remains in
the Host Keychain contract. A one-shot signed consumer projects one access
token through a non-PTY stream to one exact Research launcher. Its projection
permit expires no later than the exact session lease. The fixed C launcher
emits a content-free receipt for its fresh PID/start generation, token digest,
environment proof, permit, runtime authority, and session, then waits at a
private fd-7 gate before vendor execution. The controller independently binds
that receipt to the live generation and releases the gate only while both
permit and lease remain current.

The process namespace, restricted `/proc`, core/dump denial, exact descriptor
inventory, app-server configuration, schema-pinned protocol firewall, run
journal, and global token-reflection quarantine reject raw JSON, unknown
methods, process escape, credential reflection, and Daybreak omission. The
Codex environment is a closed inventory with only the reviewed uppercase
`HTTP_PROXY` and `HTTPS_PROXY`; direct provider routing, `NO_PROXY`,
`ALL_PROXY`, lowercase proxy aliases, and ambient inheritance are absent. Every
session performs a new hostile qualification against its own PID/start,
receipt, environment, descriptors, namespace, and cgroup. Qualification
reserves and then device/inode-binds scratch state in a durable journal before
use, removes the exact empty inode before a terminal pass, and reconciles
interruption. The complete transient cgroup stays frozen across the final
quiet drain and typed READY write, and thaws only after READY succeeds. Every
qualified turn explicitly carries `daybreakBlue`; catalog availability alone
grants nothing.

Claude login, Claude sessions, and Codex sessions now share one controller
lifetime contract. The root controller captures its PID before fork, and the
vendor child arms `PR_SET_PDEATHSIG(SIGKILL)` with an immediate parent check
both before and after `setgid`/`setuid`; the second arm restores the setting
Linux clears during credential changes. A separate descriptor-minimal root
watcher keeps only a pidfd for the exact controller and occupies
`secure-sandbox-native-owner-<id>.scope`. The vendor run scope binds with
`BindsTo`, `After`, and `PartOf` to that exact owner and
`native-harness-supervisor.service`, with group-wide `SIGKILL` teardown.

Admission also proves resource enforcement rather than trusting configured
properties. Each vendor scope has an explicit 256-task, 4-GiB, zero-swap, 300%
CPU/100-ms ceiling and exact transient fragment identity. The controller opens
the exact cgroup through descriptor-relative, no-follow traversal and requires
canonical `memory.max`, `memory.swap.max`, `pids.max`, and `cpu.max` values
before resume. Cleanup retries exact owner custody only while the watcher
remains live and requires two stable absence reads. Lifecycle stop terminates
the supervisor, vendor run scopes and bounded Claude services, then owner
scopes; installation and recovery reject any remaining unit in those three
namespaces. These are source guarantees until real Research Linux/systemd
tests exercise controller death, fork/`setsid` descendants, post-UID-drop
parent death, dependency teardown, transient rendering, and kernel ceilings.

Native Host packaging now treats Developer ID as a monotonic installed floor,
not merely a build option. The authorization UI, credential helper, protected
backend, and projection consumer are content-bound release members and must
share an Apple Team ID, exact identifiers, hardened runtime, and Developer ID
Application requirements. A root-owned canonical floor permits certificate
rotation only within that team. The one-time Development-to-Developer-ID
migration binds the exact predecessor and candidate releases, both UI manifest
digests, launcher hashes, and team; it stops Host services, records a
non-launchable predecessor recovery marker, removes `current`, and only then
publishes the floor. Any later failure remains selector-fenced and resumable
without ever restoring the below-floor release. The floor's fsynced hard-link
publisher also recognizes only its exact same-inode post-link crash state.

Protected native deployment adds a separate, irreversible coordination floor.
A private root-owned mode-0600 record is the authoritative epoch and feature
minimum; a root-owned mode-0444 enforcement projection cross-binds its exact
digest so the unprivileged stable launcher can reject a below-floor Host
release before execution. The launch path takes the Host shared lock before
the controller lock, verifies the exact selected release and coordination
contract, and only then publishes an active marker. The historical bootstrap
migration takes the Host exclusive lock, fences Host services, retains the exact
predecessor and an immutable digest-named copy of the old launcher, unlinks and
fsyncs `current`, and replaces the stable launcher only within that fenced
transition. This is
the bounded one-time pre-pair coordination-floor bootstrap, not the ordinary
update protocol. A crash can resume from those exact retained identities; an
operator cannot clear the floor, projection, selector, marker, or backup to
force an older release back into service.

The coordination migration has one deliberately narrow compatibility case.
Only the complete `d8653cb` pre-floor release with all seven pinned payload
digests is eligible. The manager freezes the exact historical launchd broker,
revalidates its PID, start generation, stopped status, and empty direct-child
census, and resumes that same generation if an operation is active. After
bootout, two system-wide UID inventories reject any old-release or detached
orphan process. The historical manager and promotion locks then remain held
across selector removal, floor publication, and candidate installation. This
authority is exposed only to schema bootstrap; a mixed inventory, digest near
match, active child, orphan, or ordinary mutation fails closed.

Those inventories also cover interpreter-backed stable-launcher processes when
Darwin preserves a relative argv spelling such as
`./secure-sandbox-claude`. Only the basename of the explicitly supplied
absolute launcher alias receives this treatment; historical release paths keep
their absolute containment rule. The two independent snapshots both apply the
same predicate.

Ordinary Host installation and rollback now treat the immutable release and
stable launcher as one fenced generation. The coordination contract requires
`host-release-launcher-pair-fence-v1`; its mode-0444
`host-release-launcher-pair.json` PENDING form denies every launch before
physical mutation, while STABLE binds the release, v2 candidate authority,
complete release-tree identity, launcher hash and installed file identity, and
the committed terminal. The launcher validates that public chain, independently
remeasures the physical release tree and launcher, and brackets validation with
a second unchanged public-record read.

An ordinary Touch ID install binds a deterministic pre-install target plan with
the source STABLE digest, exact payload map and release ID, candidate-record
digest, and target launcher digest. Installed authority and tree identity are
derived only after authorization. Rollback has a separate plan binding the
already-installed target release, launcher, authority, tree identity, and source
STABLE digest. There is no standalone ordinary launcher migration; the low-level
command is retained only for pre-pair bootstraps and rejects an established pair
record.

The private mode-0600 `secure-sandbox-host-pair-transition-v2` journal drives
service fencing, launcher-first selection, selector and service replacement,
and exact crash replay. Its receipt-free first-pair form includes a digest-bound
`bootstrap_admission` naming the establishment mode, target and immutable
predecessor release IDs, candidate-record digest, and candidate-floor digest.
Every initial execution and generic or named replay revalidates that admission
against the irreversible floor, cross-binds the installed target authority,
tree and launcher, verifies the exact predecessor inventory, and derives the
mandatory final predecessor process census from the journal rather than a
caller. A public mode-0444 terminal records only
`target_committed` or `source_restored` and embeds digest-bound selector and
service evidence. The terminal is durable before STABLE, and the private journal
is removed only after STABLE readback. Broker/child loss may produce
`host_pair_transition_pending`; recovery and the wrapper use the terminal plus
STABLE cross-binding rather than transport success. These source controls have
focused test evidence but no protected live pair-transition evidence yet.

Ordinary pair activation now consumes Touch ID authority only while
`created_at <= now < expires_at`: the manager checks before public PENDING,
after source-prefix authentication, and directly before launcher replacement;
the broker rejects an expired pristine PREPARED journal and validates a child
PENDING result at completion rather than operation start. Already durable
launcher/selector prefixes and finalization/terminal records remain exactly
replayable after expiry, as does the floor-authorized receipt-free bootstrap.
Capacity recovery uses schema-agnostic `lstat` presence of any private install
journal as a veto in both planning and locked recomputation, preventing a
prepared candidate from being archived before its transition converges.

The distribution source is designed to package those four Host products in one
exact Developer-ID-signed, notarized, stapled DMG. Its canonical inner and
outer inventory binds every path, mode, size, and hash. Root installation
treats the content-free notarization receipt as audit metadata only and
independently rechecks the exact DMG signature, ticket, Gatekeeper result,
image integrity, closed mounted inventory, individual member hashes,
entitlements, identifiers, and common Team ID before admitting the release.
That workflow is an implemented admission contract, not evidence that the
current source candidate has been notarized, stapled, assessed, or installed.

A bounded 2026-11-05 preflight established one real Host Developer ID and
coordination-floor migration for the exact installed release retained in
protected local evidence under Team `389K3H8Y32`. A separately installed
Control Center `0.2.0` build
`2` is notarized, stapled, Gatekeeper-accepted, hardened-runtime code from the
same team. This proves neither the exact current four-product carrier nor the
current source descendant: the preflight exposed a fail-closed broker peer
validation defect before query classification. The tested source repair
separates audit-token-bound dynamic validation from supplemental
all-architecture static validation, and the responsive Models selector source
repair passed a separate ad-hoc current-source visual inspection without text
overflow. A separate exact-archive build of checkpoint `6519676` produced the
planned `0.2.1` build `3`, sequence `3` ad-hoc bundle in fresh resolved-only
SwiftPM state, preserved the disabled updater policy and release-commit
binding, and produced no update-signer executable. The exact Developer ID,
notarized app reinstall and installed visual/readback acceptance remain
pending. The same preflight recovered the exact interrupted
PKI generation and retained its
manifest and anchor identities in local evidence; PKI success clears an
identity/transport dependency but grants no native-stack authority.

Projected OpenAI token custody now has an explicit terminal protocol. The
helper records the exact signed consumer process generation before credential
delivery, owns and reaps that child without PID-only cleanup, and terminalizes
only after the fixed completion frame binds the same operation and session
authority. Research emits that frame only after exact process absence and
Gateway egress closure. A missing frame remains durable ambiguity. A separate
fresh Touch ID reconciliation plan binds the original process generation and
independent closure evidence; timeout, PID disappearance, or a normal session
receipt cannot substitute for that recovery authority.

Control Center source separates inert settings, provider login, program
attestation, activation, change/logout/recovery, and session start/stop into
distinct plans and Touch ID receipts. It displays independent assurance facts,
opens Claude only as an opaque terminal, and opens Codex only through a typed
schema-pinned surface. Closing either view deterministically requests exact
session teardown. The source, focused tests, and build contracts do not prove a
signed installation or live provider use. Exact Developer ID packaging,
protected three-plane deployment, admitted harness generations, provider
login/entitlement, hostile credential probes, cold boot, disposable fault
campaign, and production activation remain `unverified` in the
[acceptance matrix](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_ACCEPTANCE_EVIDENCE.md).
See also the
[operator guide](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_OPERATOR.md).

Touch ID mutation sheets require an explicit button click; Return is never an
authorization action and Cancel remains the safe keyboard shortcut. The root
broker holds the exact request-directory and request-file inodes across review
and its final commit reread, so cancellation or pathname substitution revokes
rather than retargets authority. Swift-parent and Python-supervisor liveness
pipes propagate window/process loss through bounded cancellation and complete
process-group cleanup. The longest sign-in deadline chain is strictly nested as
`1440 < 1500 < 1560 < 1620` seconds from broker to wrapper, API, and Swift.
Privileged streaming uses an exact unbuffered readiness handshake before
request delivery; cancellation reaps the nested SSH child. Missing results are
resolved from durable status and are never inferred from transport closure.

The native-mode source was hardened through focused, reviewable checkpoints.
`2d1bc3c` closed the isolated Research package's exact import dependency;
`5e9f68b` added content-free projection-identity recovery; and `678325e`
completed the Control Center identity-import and closure-reconciliation
ceremonies with a complete-row-only v2 custody ledger. `65559ec` added Host
activation recovery, exact release payload parity, zero-custody preflight, and
the fail-closed legacy-ledger gate. `36821e2` made catalog publication a
Research-first, exact-readback, release-last Host/Research transaction.
`a411001` made signed component build cleanup deterministic. `cb05b64` added
the canonical guest deployment package/plan/status contracts, package-bound
Gateway and Research releases, Research deployment fencing, and the protected
probe. `4a2953a` then made the Host activation commit point irrevocable across
process replacement, serialized exact pending retirement, preserved a
launchable fallback, and fenced same-release failure. These commit identifiers
are source checkpoints, not protected-installation or provider evidence.

`d7f6e87` added the bounded ephemeral legacy/absent Research fence bootstrap
and rollback-only release path using the same shared lifecycle transaction as
the installed controller. `3617a60` closed guest installer/probe races, exact
predecessor admission, watchdog process-generation proof, strict closed-state
validation, deterministic payload dependency closure, and lock-held Gateway
compensation. Both checkpoints retain unknown or partially converged state as
recovery-only authority.

`8483297` bound the native deployment modes and exact predecessor state across
payload construction, guest installation, probes, and lifecycle validation.
`3582fed` added the crash-safe Host deployment coordinator, durable journal,
exact two-plane readback, and compensation recovery. `d8653cb` integrated that
transaction and its payloads into the protected Host release and authorization
surface. `fab2d7b` added the fail-closed Control Center deployment/recovery
panel, root-peer-authenticated broker protocol, current-versus-historical Host
authority distinction, bounded bridge termination, and exact Touch ID review.
`c0a72f9` added the irreversible coordination floor and its exact one-time
`d8653cb` predecessor admission, including historical broker/child/orphan
fencing and lock-held transition. `8174791` replaced a racy concurrent
file-descriptor pressure assumption in the inheritance test with an atomic
high-descriptor duplicate, proving both the original broker socket and an
FD-128-or-higher duplicate are absent after exec.

The immutable changed-boundary scan of `c8a67ee..459b10a` then confirmed five
findings: one high, three medium, and one low. `51f4205` hardened the Control
Center inspect socket and removed Return-key authorization from Touch ID
actions. `2f9493b` bound the authorization subtree to Control Center parent
liveness and established the 1,620-second outer deadline. `9eb755c` added
request-inode custody, cancellation domains, exact privileged-stream readiness,
and projection/descendant cleanup. Guest checkpoint `05229db` bound each Codex
session to a fresh PID/start receipt and fd-7 gate, session-capped temporal
authority, an exact proxy-only environment, journaled scratch identity, and a
whole-cgroup freeze through READY. These fixes are source-remediated pending an
exact-tip remediation scan. A subsequent immutable scan
`75f30fe9` of `c8a67ee..133d1a5` reviewed 234 of
234 items and found one high controller-lifetime escape plus one medium absence
of per-session resource ceilings. Executable checkpoint `d5393bf` adds the
owner-bound lifetime, post-credential parent-death, group-wide SIGKILL, and
kernel-enforcement contract. Final immutable scan
`e0e3cb96` of `c8a67ee..d5393bf` closed all 235
review items with zero findings. The complete scan records are retained in the
DDD acceptance evidence; none of these source results is installed Linux
evidence.

Through executable checkpoint `d5393bf`, the clean hermetic Host suite passed
167 tests with two
intentional superseded-bootstrap skips; affected Host script suites passed 358
of 358; Swift passed 118 of 118; affected guest suites collected 234 tests with
233 passes and one pre-existing macOS `SO_PEERCRED` skip; Gateway lease tests
passed 21 of 21; and Research lease/watchdog tests passed 56 of 56. Changed
Python compilation and diff validation passed. The final remediation selection
passed 99 tests with one macOS skip; canonical discovery passed 1,331 Scripts
tests with two skips, 553 Research tests with one macOS skip, 274 Shared tests,
113 Gateway tests, and five Target tests. These are source results, not
installation evidence. Executable checkpoint `c7029a4` subsequently passed the
complete canonical gate—2,524 tests with three expected skips—and its exact
`4937d57..c7029a4` changed-boundary scan covered all 34 changed-file receipts
across five threat surfaces with zero candidates and zero findings. The
publication/secret gate is rerun on the final documentation-only descendant
before the same exact commit is published to both configured remotes.
Signed/notarized packaging,
protected deployment, admitted live harnesses, provider login/qualification,
real Linux/systemd behavior, physical/disposable testing, and production
activation all remain `unverified`.
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
lock. Host-controller paired install and rollback, host PKI anchor transitions,
protected installer publication, and VM lifecycle mutations additionally pass
through the immutable authorization broker: a signed native macOS window
identifies the declared agent/session, purpose, operation, nonce, digest, expiry,
and operation parameters. Host pair install and rollback require Touch ID with
no password fallback; other operation policies may offer an explicit
administrator-password or cancel choice. A separately protected root broker
revalidates the exact request and signed UI peer. The root-owned receipt enforces
one authorization while permitting only exact journal replay of the same Host
pair plan after child or broker loss. Read-only installer verification and VM
dry-run planning do not elevate. The protected VM coordinator starts only
through the broker and permanently drops to the invoking Mac UID before calling
Parallels; `prlctl` is never run as root by the project workflow. Each launch
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
