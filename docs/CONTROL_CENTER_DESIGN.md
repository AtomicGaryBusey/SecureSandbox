# SecureSandbox Control Center DDD

## Decision and scope

Build a signed, native SwiftUI macOS 27 operator app for the existing three-VM
SecureSandbox installation. The app is a desktop front end to reviewed host
operations, with readable names, progress, evidence, and recovery guidance in
place of copied commands and UUIDs. This document is the design and delivery
plan. A first read-only app checkpoint is implemented in
`macos/ControlCenter`, followed by session labeling and an explicit-start
terminal window. A source-plan readback and one-time import client are built
but need the protected dispatcher update before live activation. Backup and
export services remain planned. The Activity view now reads a bounded,
content-free telemetry projection. Maintenance and Recovery show read-only
clock and snapshot-policy checks.
Findings now have an explicit, bounded detail view for claims, support,
limitations, and history counts.
Maintenance offers the existing full boundary verifier as an explicit action.
Evidence now loads its bounded archived-artifact catalog on demand, with
explicit verified text preview and a native selected-file export. Start and Stop have operator review,
GUI-closed preflight, existing lifecycle-lock enforcement, and independent
three-VM readback; live transition acceptance is pending.
An opened artifact can also open its run's verified conversation transcript.
The bridge checks each JSONL record and escapes control characters before the
app renders or exports the selected transcript. A selected run also exposes a
tool-result catalog derived from the verified archive: assistant tool-use IDs
are paired with user result blocks, each result has an exact JSON digest, and
the app rechecks that digest before showing or exporting one result. A
run-to-session catalog remains to be built.
The live artifact archive includes records captured before a run was active;
these carry the collector's `preflight` marker. The catalog accepts that exact
marker, and the transcript action is shown only for artifacts bound to a run.
Live readback found 73 archived artifacts, including 49 run-linked records and
24 `preflight` records. `labctl transcript` now suppresses Azure download
metadata on stdout, so a linked run rendered 145 verified JSONL records through
the bounded bridge without exposing conversation content in diagnostics.
That run yielded 10 matched archived tool results; a selected result's digest
was verified through the detail endpoint without printing its content.
The host session-run catalog now has a v2 writer and reader for bounded run IDs.
The Sessions view can open a selected session's linked transcripts and tool
results. The installed controller still has the v1 count-only format; live
readback found one session with eight historical runs and no run links. A future
approved controller deployment and run will migrate it without inventing old
run IDs.
Selected runs now have a bounded Gateway lease view and explicit five or
fifteen minute renewal controls. The bridge requires an active lease within its
maximum expiry, invokes the existing two-VM renewal command, and independently
reads back lease identity, expiry, and renewal count. A failed or unclear
renewal requires refresh before the app enables another attempt. Reconciliation
remains separate until Research completion readback is available.
Sources now offers exact npm package planning through the same reviewed plan
status and one-time import flow.
An imported npm source can open a direct-runtime-dependency plan, refresh which
exact package versions are present, and assemble a sealed bundle once all are
ready. The bundle is read back by ID and dependency-set digest. This requires
live acceptance; the UI does not claim transitive completeness or enable
package lifecycle scripts.
Selected imported sources now expose explicit corpus and CodeGraph index
builds. The bridge accepts only a matching sealed index result, and the UI
does not repeat an ambiguous attempt from the same sheet.
Recovery now has an operator-selected encrypted APFS destination preflight.
It inventories the exact three VM bundles, checks destination capacity with a
10 GiB minimum reserve, and requires verified stopped VM state. Insufficient
free capacity or a running VM prevents readiness. A ready destination can now
become a one-time, 15-minute backup plan. Recovery presents its volume and
size before submission, then monitors a durable operation ID. Reopening the
app recovers the plan or verifies the published generation by the same ID.
Recovery can also browse generations on a selected encrypted APFS volume.
Selecting one verifies its authenticated manifest and every archived file,
then shows host space and stopped-stack readiness for a future restore.
Incomplete generations remain visible and cannot be selected for restore.
Live cold-backup acceptance and the restore transaction remain pending.
The volume check was exercised against disposable encrypted APFS disk images:
an encrypted image containing an unencrypted APFS volume is rejected, while
APFS volume encryption reports the required diskutil fields.
Maintenance now offers reviewed clock synchronization with the existing
active-run refusal and a separate readback of all three clocks.
Maintenance now projects a bounded safety audit summary. The installed
controller currently differs from reviewed source, so the live audit correctly
reports attention until the protected deployment is completed.
Maintenance can read bounded memory proposal metadata (title, category, status,
creation time, ID, and content digest) without loading proposed content.
Maintenance now opens separate Research and Target administrator terminal
windows with destination-specific warnings. Each launches `/usr/bin/ssh` with
the fixed installed host SSH config and an exact alias; live terminal
acceptance remains pending.
Maintenance also exposes emergency containment behind a destructive confirmation.
The bridge invokes the existing fixed panic action once, checks its lifecycle
record, and independently reads Research, Target, and Gateway net0 state. It
marks the outcome incomplete when any observed boundary disagrees. The live
emergency action has not been exercised.
Maintenance can reload the two host SSH identities from the Agents vault after
an explicit confirmation. The bridge checks both dedicated agent sockets and
returns only loaded state; no key data or raw command output enters the UI.
Live post-reboot acceptance remains pending.
Finding detail now projects candidate and amendment evidence with a digest of
each archived evidence object, plus bounded adjudication event summaries. The
UI groups digests for reading and keeps evidence references separate from the
untrusted claim text. A live finding with amendment evidence rendered seven
entries through the typed bridge.
The native transition form offers only allowed next states and selects
consulted evidence from the verified detail. It gathers the adjudicator role,
rationale, and conflict note, then sends a bounded typed request on stdin to
the bridge. The bridge stages it in a 0600 private file for the existing
root-authorized CLI path and requires the append-only journal receipt to
appear in a fresh finding readback before showing success. A failed or lost
response requires refresh before a new attempt. All four finding action forms
need live acceptance.
The relation form selects a target from the findings catalog and records one
of duplicate, supersedes, or disputes with the actor and rationale. The bridge
rechecks both finding identities and requires the exact relation event in the
fresh journal readback. Live relation acceptance remains pending.
The reopen preview compares available evidence with the terminal event's
frozen evidence inventory, including the legacy timestamp fallback. It offers
only new digests and excludes report content already frozen at terminal state.
The bridge rechecks the selected evidence before submission and requires a
matching reopened journal event and Needs Evidence state in fresh readback.
Terminal disposition now has a destructive native review. The root action
archives the candidate and writes a digest-bound root-owned disposition marker. A new
read-only protected command verifies that marker and archived candidate; the
bridge requires its marker digest, terminal state, and candidate digest to
match the reviewed request. Protected deployment and live acceptance remain.
The selected run lease sheet can prepare reconciliation after Gateway closes.
The plan proves Research is locally closed and binds the final Gateway summary
digest to the same run and lease. Confirmation recomputes that material before
commit, then reads the durable Research completed record even if the command
response was lost. The digest is grouped in the UI for review; the exact bytes
are submitted without transcription. The new completed-record control command
requires protected deployment before live acceptance.
Recovery also shows a bounded snapshot-policy diagnostic and a typed
consolidation preview with per-VM counts, host free space, stopped-stack state,
and Parallels GUI state. The bridge validates the exact policy VM set and
retained milestone list before interpreting the dry-run output. Live preview
reports unavailable: the stack is running, free space is below the 50 GiB
policy floor, and required retained milestones are missing. Consolidation
requires those conditions before it can be offered as an action.
Snapshot apply now uses a Python implementation under the host lifecycle lock.
It verifies all three stopped VMs and all retained milestones before deleting
anything, then compares the exact retained snapshot IDs after each VM. The
app rechecks readiness before apply and performs an independent post-apply
inventory readback. A failed or lost response is shown as incomplete unless
the retained set is independently verified. The current live prerequisites do
not permit a deletion acceptance test.
The backup transaction engine now stages copies of the exact three VM bundles
and a fixed set of eight non-secret deployment configuration files, compares
source and copy inventories, authenticates a content and metadata
manifest with an injected secret, verifies the staged generation, and publishes
it atomically. Disposable fixtures cover success, tampering, wrong key, and an
interrupted copy that remains visibly incomplete. The app now exposes this
engine through a one-time plan and worker; live cold backup acceptance remains.
The engine accepts a caller-owned generation ID and
readback by that ID, refusing to replay an incomplete generation. A dedicated
64-character authentication key was created in the Agents vault as
`SecureSandbox-VM-Backup`; its value is never placed in command arguments or
the repository.
Backup plans now persist under a private operator-owned directory with a
15-minute expiry, authenticated destination, volume and VM identities, and a
one-time claim marker. Submission starts a detached worker under the host
lifecycle lock after rechecking the encrypted volume, stopped stack, and VM
identities. The worker stages, verifies, and publishes one generation. An
authenticated status file and generation readback distinguish a running,
failed, incomplete, or verified operation. The app never retries submission
automatically after an unclear outcome. The private backup authentication key
is read from the Agents vault inside the bridge and worker; its value is never
passed in process arguments. No backup has yet run against the live VM bundles,
because the current stack is running and an encrypted destination with enough
free space has not been mounted.
The v2 backup manifest binds `ssh_config`, the three netplan files,
`external-containment.json`, `snapshot-retention.json`, the conversation age
recipient, and the provider credential reference. It excludes private keys,
tokens, credential values, and the off-host evidence archive. Restore must
reconcile these files with the target host rather than silently overwrite live
configuration.
A restore staging component now verifies an archived generation, copies its VM
bundles and host configuration into a private candidate on the same filesystem
as the live bundles, compares both inventories, and publishes only a fully
verified candidate. Interrupted copies remain incomplete and leave the live
bundles untouched. A transaction component now journals the original and
candidate directory identities, unregisters and quarantines the stopped old
bundles, installs and registers the candidate, and delegates cold acceptance
to an adapter. Failure invokes rollback; an authenticated journal supports
resuming rollback after an interruption. Disposable fixtures cover success,
acceptance failure, interrupted rollback, and journal tampering.
The production adapter now binds Parallels registration and the existing
start/stop verifier to an inherited lifecycle lock. A one-time restore plan
and detached worker recheck the encrypted source, authenticated generation,
current VM bundle identities, host configuration, and free space under that
lock before staging or registration changes. The app presents the reviewed
plan, requires explicit confirmation, and reattaches to its durable operation
ID. A successful swap retains the prior VM directory in quarantine; failed
acceptance triggers rollback. A nonterminal journal with no active worker
exposes an explicit prior-VM recovery action, which reuses the lifecycle lock
and resumes journaled rollback. The inherited-lock and recovery paths are
covered by fixtures, but they have not been exercised against live VMs. Live
cold backup, restore, and recovery acceptance remain before DDD release.

The installed Xcode 27.1 and macOS 27 SDK are the development baseline. Follow
[Apple's macOS design guidance](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/)
and [macOS 27 design resources](https://developer.apple.com/design/resources/):
native sidebar, toolbar, menus, sheets, search, keyboard access, window
restoration, semantic colors, and system Liquid Glass. Use standard SwiftUI
controls and materials, with no custom translucent shell around the app. Test
light, dark, increased contrast, reduced transparency, VoiceOver, full keyboard
access, and narrow and wide windows on macOS 27.
The app now includes vector background and foreground icon artwork and builds
a static `.icns` fallback into its SwiftPM bundle. A layered Icon Composer
document and appearance review remain for final macOS 27 packaging.

## Operator model

The launch window has a stable sidebar: Overview, Sessions, Sources, Findings,
Evidence, Recovery, and Activity. A selected item opens a detail pane; an
inspector presents provenance, IDs, digests, and exact operation receipts when
needed. The toolbar exposes the current context's primary action and search.
The menu bar offers all actions, with shortcuts for refresh, new analysis,
session search, and opening a session terminal. A small optional menu bar status
item may show verified stack health, but the main window remains a normal Dock
app. Settings contains archive location, display preferences, and diagnostic
paths; it never stores secrets.

| Surface | Operator task | Existing foundation / required work |
| --- | --- | --- |
| Overview | See each VM, reachability, current run, capture and boundary status; start or stop the stack | `labctl status`, `start`, `stop`, `verify`, `safety-audit`; add typed progress and last-known-state responses |
| Sessions | Browse content-free metadata, private labels, associated runs and artifacts; resume in a terminal | `sessions`, `session label`, `claude --resume`, `transcript`; add typed catalog and run linkage |
| Sources | Paste a supported repository URL, inspect resolved owner/repo/ref and immutable commit, approve import, index and start analysis | `source plan`, `source apply`, `sources`, `corpus index`, `codegraph index`; add bounded URL normalization and typed plan response |
| Findings | Browse candidates and adjudication history; inspect support and evidence | `findings`, `finding show`; preserve explicit root-only adjudication |
| Evidence | Browse reports, transcripts, artifact revisions and tool evidence; preview and export selected items | `artifacts`, `artifact`, `transcript`, findings; add verified file export and a bounded tool-result catalog |
| Recovery | Inspect snapshot policy, create and verify a full backup, preview and execute restore | `snapshots` is retention only; add coordinated backup and restore operations |
| Activity | See content-free operation progress, failures, audit receipts and retry guidance | host lifecycle records, control audit, leases; add typed event stream |
| Maintenance | Check time sync, renew or reconcile leases, manage dependencies and indexes, review memory proposals, run boundary checks, and reach break-glass tools | `time-sync`, `lease`, `dependencies`, `memory`, `verify`, `logs`, `admin`, `target`, `panic`; preserve their distinct authorization and warning flows |

The default view shows human labels and concise timestamps. UUIDs, hashes, VM
bundle paths, and request digests stay in the inspector and copy menus. Search
matches labels, imported source names, and safe metadata. Transcript and report
contents appear only after an explicit open action and are marked as untrusted
agent output.

## Trust and process architecture

Use a multi-file SwiftUI app with `WindowGroup` for the primary browser,
`Settings` for preferences, and separate windows for session terminals and
verified evidence previews. `NavigationSplitView` owns the sidebar and detail
selection. App-wide stores hold the read-only catalog and operation state;
window-scoped state holds selection, filter, scroll, and terminal context.
Services own protocol decoding and host operation calls. AppKit is limited to
PTY, terminal text input, save panels, and any window behavior SwiftUI cannot
express reliably.
The host bridge now enforces its 8 MB response ceiling while reading child
output, retains only a bounded diagnostic tail, and stops a child at its
operation deadline. An uncertain mutation outcome must be inspected before
another attempt.
The Swift client also reads bridge output in 64 KiB chunks, stops at 8 MB,
and terminates a bridge that exceeds its deadline. A timeout reports an
unclear outcome so the operator can inspect the operation before retrying.

The UI process runs as the Mac operator. It never gains root privileges, reads
guest control keys, or calls `prlctl` directly. Guest control and analysis
mutations continue through the protected host controller and authorization
broker. VM lifecycle, backup, restore, and snapshot operations run under the
local operator identity through their reviewed host workers; the lifecycle
lock, fixed paths, exact identities, encrypted volume checks, and one-time
plans bound their scope. First add a
versioned, bounded, structured `control-center` host API for read-only catalogs,
preflight plans, operation submission, operation status, and receipts. Its
implementation maps typed operation names to fixed argv or reviewed internal
functions; it does not evaluate shell text. The app must validate schema,
size, type, and version of every response and treat guest and agent content as
data. A cancelled or disconnected UI must reattach to the original operation
identity and inspect its receipt before a new attempt; ambiguous outcomes are
never blindly retried.

The signed Touch ID or password authorization window continues to identify
each protected guest operation. Present the same purpose and scope in the app
before invoking it. Local recovery operations receive separate confirmation
with the exact VM set and backup generation; their one-time plan is checked
again by the detached worker. The GUI cannot approve a different protected
request or silently replace the existing ceremony. The app supports
read-only use while the lab is down and explains stale observations rather
than showing cached state as live.

## Core workflows

1. **Start and stop.** Show a preflight summary and live phase progress. The
   stop view instructs the operator to quit the Parallels Desktop GUI first.
   The app independently checks that it is closed before lifecycle mutation.
   A stopped state is complete only when the final lifecycle record is
   `verified` and Gateway, Research, and Target all read back as stopped.
   Guest SSH status 255 during poweroff is not by itself failure. On start,
   show VM reachability, adapter state, clock convergence, and boundary result.
2. **Sessions.** List only registry-admitted session IDs with content-free
   metadata and private labels. Selecting one opens a dedicated terminal
   window that launches the fixed `labctl claude --resume` path with the
   selected canonical UUID as a separate argument. New sessions use the same
   fixed launcher without a resume ID. The terminal binds one window to one
   run, exposes lease status and graceful close, and does not invoke a shell
   string. A session detail can open a verified historical transcript by run
   ID; a session UUID alone is not treated as a transcript ID.
3. **Import a repository.** Accept a pasted HTTPS GitHub repository URL and
   optional ref through a narrow parser. Normalize to the supported
   `OWNER/REPOSITORY` and ref grammar, show the resolved immutable commit and
   provenance returned by `source plan`, then apply the exact plan ID. Other
   hosts, redirects, credentials, fragments, and ambiguous URL forms receive
   a clear unsupported-source explanation. Show import and indexing as
   separate operations. A successful import can open a new analysis terminal
   with the source selected through an approved launcher context; this
   selection must not become arbitrary agent command input.
4. **Export.** The operator chooses a report revision, transcript, finding,
   or retained tool result. A privileged reader verifies the archived object
   and streams a bounded typed payload to a private host staging file. The app
   uses a native save panel, writes atomically to the selected destination,
   records provenance beside the export when requested, and deletes staging
   plaintext on close or error. Export is explicit; browsing metadata does not
   bulk decrypt evidence. Tool output not already retained needs its own
   content-bound catalog before the UI can promise a historical export.
5. **Backup and restore.** A backup is a coordinated, stopped-stack copy of
   the three exact VM bundles and the required non-secret host configuration,
   with an authenticated manifest, version, VM identities, file inventory,
   completion marker, and verification read-back. Backups write to an
   operator-selected encrypted destination through a temporary generation and publish
   atomically; interrupted generations remain visibly incomplete. Secrets
   remain in 1Password and are referenced, not copied. The external evidence
   archive has its own retention and is identified in the recovery plan rather
   than silently included in a VM copy. Restore first validates
   every byte, target identity, disk capacity, required secrets, and current
   stack state. It stages the candidate bundles, preserves the prior bundles
   in quarantine, swaps registration under the host lifecycle lock, runs cold
   start and full boundary acceptance, and only then offers separate retirement
   of the old generation. A failed acceptance restores the previous registration
   and reports both the failed and recovery outcomes. Snapshot retention stays
   a distinct Recovery action with its own stopped-stack and free-space gates.

## Delivery sequence

The [command parity inventory](CONTROL_CENTER_COMMAND_PARITY.md) tracks each
existing `labctl` action to its GUI surface and acceptance state.

1. **Contract and safety fixtures.** Inventory every `labctl` action, define
   typed request/response schemas, operation IDs, privacy classification,
   error taxonomy, and authorization mapping. Every existing CLI capability
   must have a GUI home or an explicit break-glass-only rationale; the
   Maintenance surface tracks this parity. Add read-only adapters first.
2. **App shell.** Create the Swift project, signing configuration, app icon,
   scenes, sidebar, menus, search, accessibility labels, and simulated data
   previews using the macOS 27 SDK. Build a foreground `.app` bundle.
3. **Live observability.** Wire Overview, Activity, Sessions, Sources,
   Findings, and Evidence catalogs; verify stale/offline/error states.
4. **Safe actions.** Wire start/stop, labeling, source plan/apply/index, new
   and resumed session terminals, lease controls, and explicit exports through
   the typed host API and existing authorization ceremony.
5. **Recovery.** Implement backup creation, manifest verification, restore
   preview, transaction, rollback, and snapshot-retention UI.
6. **Acceptance and release.** Exercise cold start/stop, disconnected guest,
   closed terminal, duplicate request, interrupted backup, failed restore,
   wrong VM identity, malicious source URL, oversized evidence, cancelled
   authorization, and successful recovery on the real stack. Run the full
   boundary suite after mutations, compare deployed host components with
   reviewed source, run publication and secret checks, then publish the same
   reviewed `public-release` commit to both remotes.

The first usable vertical slice is Overview, Sessions, and Sources with the
typed read-only API; later checkpoints add mutation and recovery. Completion
of this DDD requires every workflow above, including a verified restore and
safe export, rather than a decorative app over a subset of commands.
