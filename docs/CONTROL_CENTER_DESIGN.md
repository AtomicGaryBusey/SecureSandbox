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
Evidence now has a bounded archived-artifact catalog, explicit verified text
preview, and a native selected-file export. Start and Stop have operator review,
GUI-closed preflight, existing lifecycle-lock enforcement, and independent
three-VM readback; live transition acceptance is pending.

The installed Xcode 27.1 and macOS 27 SDK are the development baseline. Follow
[Apple's macOS design guidance](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/)
and [macOS 27 design resources](https://developer.apple.com/design/resources/):
native sidebar, toolbar, menus, sheets, search, keyboard access, window
restoration, semantic colors, and system Liquid Glass. Use standard SwiftUI
controls and materials, with no custom translucent shell around the app. Test
light, dark, increased contrast, reduced transparency, VoiceOver, full keyboard
access, and narrow and wide windows on macOS 27.

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

The UI process runs as the Mac operator. It never gains root privileges, reads
guest control keys, or calls `prlctl` directly. The existing protected host
controller and authorization broker remain the mutation boundary. First add a
versioned, bounded, structured `control-center` host API for read-only catalogs,
preflight plans, operation submission, operation status, and receipts. Its
implementation maps typed operation names to fixed argv or reviewed internal
functions; it does not evaluate shell text. The app must validate schema,
size, type, and version of every response and treat guest and agent content as
data. A cancelled or disconnected UI must reattach to the original operation
identity and inspect its receipt before a new attempt; ambiguous outcomes are
never blindly retried.

The signed Touch ID or password authorization window continues to identify
the exact protected operation. Present the same purpose, scope, affected VMs,
and backup generation in the app before invoking it. The GUI cannot approve a
different request or silently replace the existing ceremony. The app supports
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
