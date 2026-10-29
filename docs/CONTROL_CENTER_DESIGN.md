# SecureSandbox Control Center DDD

## Decision and scope

Build a signed, native SwiftUI macOS 27 operator app for the existing three-VM
SecureSandbox installation. The app is a desktop front end to reviewed host
operations, with readable names, progress, evidence, and recovery guidance in
place of copied commands and UUIDs. This document is the design and delivery
plan. The SwiftPM app in `macos/ControlCenter` now covers the operator surfaces
and command inventory; protected deployment and live acceptance remain for
prepared actions. The Activity view reads a bounded,
content-free telemetry projection. Maintenance and Recovery show read-only
clock and snapshot-policy checks.
Findings now have an explicit, bounded detail view for claims, support,
limitations, and history counts.
Maintenance offers the existing full boundary verifier as an explicit action.
Its typed result now carries bounded failed-check names as well as passed and
gate counts. A rejected boundary run stays visible in Maintenance with the
specific check names, while malformed or incomplete verifier output is treated
as a bridge error. This makes deployed-source drift diagnosable in the app.
Evidence now loads its bounded archived-artifact catalog on demand, with
explicit verified text preview and a native selected-file export. Start and Stop have operator review,
GUI-closed preflight, existing lifecycle-lock enforcement, and independent
three-VM readback; live transition acceptance is pending.
While a lifecycle action runs, Overview polls fresh read-only host status and
a bounded phase record written under the lifecycle lock. It shows the current
host step alongside timestamped VM and Gateway uplink observations. The phase
record is replaced atomically, cleared on lock acquisition and completion,
and reads as idle once the lock is released. The UI does not treat a phase or
intermediate VM observation as completion; only the final lifecycle record and
independent post-action readback can do that. A real cold Stop passed; the
following Start reached running guests but failed the boundary gate, as
recorded below. Full cold transition acceptance remains.
When Start reaches running guests but fails that gate, the bridge directs the
operator to refresh live VM status and inspect the named failures in
Maintenance; it does not present the transition as successful.
On a verified Start result, Overview separately names the confirmed Gateway
uplink, guest reachability, clock synchronization, and boundary verification.
An opened artifact can also open its run's verified conversation transcript.
The bridge checks each JSONL record and escapes control characters before the
app renders or exports the selected transcript. A selected run also exposes a
tool-result catalog derived from the verified archive: assistant tool-use IDs
are paired with user result blocks, each result has an exact JSON digest, and
the app rechecks that digest before showing or exporting one result. A
run-to-session catalog is implemented for future runs.
The live artifact archive includes records captured before a run was active;
these carry the collector's `preflight` marker. The catalog accepts that exact
marker, and the transcript action is shown only for artifacts bound to a run.
Live readback found 73 archived artifacts, including 49 run-linked records and
24 `preflight` records. `labctl transcript` now suppresses Azure download
metadata on stdout, so a linked run rendered 145 verified JSONL records through
the bounded bridge without exposing conversation content in diagnostics.
That run yielded 10 matched archived tool results; a selected result's digest
was verified through the detail endpoint without printing its content.
Tool-result catalog and detail now read a private, bounded verified transcript
file, so they no longer depend on the 8 MiB preview response. The catalog
retains only identities, names, lengths, and digests; detail retains only the
selected bounded result. The same live run returned 10 results and an
independent selected digest match after this change.
The transcript CLI now reads the archive identity once per run. Its verifier
checks each downloaded ciphertext digest, exact chunk sequence, run-bound
header, previous-cipher chain, and declared record length before streaming
the existing `jq`-validated JSONL. A live 286-record run completed in about
6 seconds; the former repeated identity lookup made the native tool-result
browser take roughly a minute for this class of run.
The installed app's archived tool-result catalog then reopened in about
5.5 seconds; selecting and digest-checking one result took about 5.3 seconds.
The Swift app client, compiled from its actual model and service files, decoded
the six primary live catalogs. A second smoke run decoded the empty bundle and
proposal catalogs plus snapshot and safety summaries. A selected archive run
decoded 73 artifact rows, one artifact detail, 145 transcript records, 10 tool
results, and a selected tool-result digest match. These checks exercise the
Swift decoding boundary; the native visual interaction still needs review.
The macOS app now has debug SwiftUI previews for healthy, degraded, and
unavailable Overview states. They use fixture status data in the production
Overview view and compile under the macOS 27 SDK; interactive window review on
the unlocked desktop remains pending.
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
The terminal's pre-launch review now offers the controller's short, standard,
and extended initial run-lease profiles for new, resumed, and source-bound
analysis. It passes the selected allowlisted profile as a separate argument to
the fixed launcher; the Gateway remains the authority for actual limits.
Terminal windows also require the selected resume or source ID to be a
canonical lowercase UUIDv4, matching the fixed launcher's accepted argument
grammar before a PTY is created.
Sources now offers exact npm package planning through the same reviewed plan
status and one-time import flow.
Live negative bridge checks rejected a GitHub URL with a query, a repository
subpath, and a non-GitHub host before any source acquisition. The finding
transition bridge also rejected a 16,385-byte stdin request at its 16 KiB
limit before reaching the findings broker. Positive source import and finding
mutation acceptance remain separate.
The live Gateway source plan for `https://github.com/octocat/Hello-World` at
`master` returned a one-time plan, a 40-character resolved commit, and an
expiry through the typed app bridge. The plan was not applied; branch
resolution is accepted. Later live bridge checks resolved a public GitHub
release tag to a 40-character commit and an exact npm version to a
40-character package shasum; both returned expiring plans. Neither plan was
applied; one-time import still needs live review.
The source sheet now retains one GitHub and one npm plan pointer across app
restarts. It rebuilds the review from fresh Gateway plan status, preserves a
durable “import attempted” latch before submission, and will not replay an
unclear plan. A completed status can recover the published source ID and offer
analysis even when the original import response was lost, after the fresh
Research source catalog confirms the same ID and repository. Expired plans
cannot be submitted; only an unsubmitted or terminal plan can be cleared in
the UI.
Live plan/readback acceptance found that the currently installed controller
rejects `source-status` with `operation_invalid` after a successful public
GitHub plan. The GUI leaves Import disabled in this state and now explains that
the installed controller lacks the operation. Protected deployment of the
reviewed dispatcher is required before source-plan recovery can be accepted.
An imported npm source can open a direct-runtime-dependency plan, refresh which
exact package versions are present, and assemble a sealed bundle once all are
ready. The bundle is read back by ID and dependency-set digest. This requires
live acceptance; the UI does not claim transitive completeness or enable
package lifecycle scripts.
Sources now also has a native browser for previously sealed dependency bundles,
showing root package, direct package count, creation time, bundle ID, and
grouped set digest. The live list is empty and decodes successfully; nonempty
bundle acceptance remains after assembly.
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
Maintenance can read bounded memory proposal metadata without loading proposed
content. A selected proposal opens an inspector with its originating run ID,
proposal ID, explicit untrusted authority, status, creation time, and grouped
content digest. The protected reader checks the file identity and recomputes
the digest from the submitted fields before projecting metadata. The live
proposal list is currently empty, so a nonempty live inspector review remains.
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
Finding detail now offers a native selected-file JSON export. Before opening
the save panel, the app fetches the finding again and requires its candidate
digest, state, amendment count, and history count to match the displayed
review. The exported projection includes the bounded evidence and adjudication
history, its candidate digest, export time, and an explicit schema. A live
native save produced valid JSON and a matching provenance digest; both files
were mode 0600.
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
The sheet now persists a per-run reconciliation-attempt latch before commit.
After an unclear outcome it offers completed-record inspection but cannot
repeat the mutation, including after app restart. When a closed run is opened,
it checks for an existing Research completion before offering a new plan.
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
The disposable restore tests now compare the full three-bundle file inventory
before and after failed acceptance, resumed rollback, and wrong-current-VM
identity rejection. They also compare the accepted candidate against the
archived generation and the quarantined prior stack against the original.
These are local transaction fixtures; they do not substitute for a real
Parallels restore on an encrypted backup volume.
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
After an unclear backup or restore submission, Recovery removes the local
submit button, retains the operation ID, and reads back its durable status.
It offers an explicit status refresh; an unsubmitted plan can be forgotten
without changing host state, while a running or unread operation keeps its
identity in focus. Expired plans cannot be submitted. Once rollback recovery
is claimed, the host status no longer offers a second recovery submission;
it distinguishes a still-starting recovery from an incomplete or failed one.
These paths have focused fixtures and a Swift build, pending live recovery
acceptance with a suitable encrypted backup volume.

The installed Xcode 27.1 and macOS 27 SDK are the development baseline. Follow
[Apple's macOS design guidance](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/)
and [macOS 27 design resources](https://developer.apple.com/design/resources/):
native sidebar, toolbar, menus, sheets, search, keyboard access, window
restoration, semantic colors, and system Liquid Glass. Use standard SwiftUI
controls and materials, with no custom translucent shell around the app. Test
light, dark, increased contrast, reduced transparency, VoiceOver, full keyboard
access, and narrow and wide windows on macOS 27.
The app now has a two-group Icon Composer document with vector artwork in
`macos/ControlCenter/Artwork/AppIcon.icon`. Xcode 27.1's `actool` compiles it
into the app's `Assets.car` and `AppIcon.icns`, and the bundle names `AppIcon`
as its icon asset. The Icon Composer renderer produced reviewed Default, Dark,
and Mono macOS 27 previews. A live dark-mode desktop review now covers the
installed app's eight main surfaces at a wide window size. Their sidebar,
toolbar, list selection, and status presentation render cleanly. The Sessions,
Sources, Findings, Evidence, and Activity catalogs now show local dates rather than raw UTC strings;
the session list also uses singular “turn” for a count of one. Light mode,
increased contrast, reduced transparency, VoiceOver, keyboard, narrow-window,
and Dock review remain.
The live Evidence view displayed a loading state while its 73-item verified
archive catalog was fetched. Its first load took over a minute because the
CLI fetched the archive identity separately for each artifact. The catalog
path now receives that identity once through stdin and still checks every
ciphertext hash and decrypted envelope. A subsequent live CLI read took about
7 seconds, the versioned bridge about 14 seconds, and the app displayed the
same 73 rows after its loading state. Recovery correctly showed snapshot policy
attention while the current retained set was incomplete, without offering an
apply action.
The Sessions keyboard shortcut, Command-F search focus, and live filtering of
a selected session also passed a desktop check.
The bundle builder now verifies its identity, minimum OS, icon, SwiftTerm
license, and strict code signature on every local build. The separate
`script/validate_bundle.sh APP --distribution` gate requires a Developer ID
Application signature, hardened runtime, and Gatekeeper acceptance. An
operator can set `SECURE_SANDBOX_DEVELOPER_ID` to an installed certificate name
when building for distribution. The current app passes the local gate but the
distribution gate correctly rejects its ad hoc signature; this Mac currently
has an Apple Development identity and no Developer ID Application identity.
For local operation, build with `macos/ControlCenter/script/build_and_run.sh --build-only`
and run `macos/ControlCenter/script/install_local.sh`. The latter validates the
bundle, copies it into `~/Applications/SecureSandbox.app`, validates the copy,
and restores the previous installation if replacement fails. It recovers a
previous bundle left by an interrupted replacement before installing again.
This is a user-local install; it does not satisfy the distribution signature
gate.

### Read-only live acceptance, 2026-10-29

The current bridge returned valid versioned envelopes for Overview, Sessions,
Sources, Findings, Activity, Maintenance, Evidence, snapshot policy and
preview, memory proposals, dependency bundles, and safety audit. The catalogs
contained 36 sessions, 11 sources, 13 findings, 100 activity records, and 73
archived artifacts; the proposal and bundle catalogs were valid empty lists.
The three VMs read back running and reachable with Gateway uplink connected.
The snapshot preview correctly refused apply with the stack running and about
32.7 GB free against its 50 GiB floor. The safety audit correctly reported an
installed protected-controller source mismatch pending deployment. These
checks exercise read-only bridge output, not visual UI or mutation acceptance.

### Cold lifecycle acceptance, 2026-10-29

With GLM closed, Research `lifecycle-idle` verified, and Parallels Desktop
closed, `labctl stop` returned a final `verified` record. Target, Research,
and Gateway poweroff controls each lost their SSH response, but the independent
Parallels readback found all three VMs stopped. The phase feed then read idle.

`labctl start` powered on all three VMs and synchronized their clocks within
one second, but its full boundary verifier reported six failures: the host
controller source match, the Gateway/Research/Target control-file matches,
the Research lease watchdog posture, and the candidate findings broker
posture. The final Start record was `rejected` at
`boundary_verification_failed`. A separate readback found all three VMs
running and reachable, with Gateway uplink connected; the phase feed was
idle. The UI now keeps a separate post-action VM readback visible after a
rejected lifecycle result, without implying that running VMs satisfy the
boundary gate. Protected deployment and a clean full boundary pass are
required before Start acceptance can be recorded.

## Operator model

The launch window has a stable sidebar: Overview, Sessions, Sources, Findings,
Evidence, Recovery, and Activity. A selected item opens a detail pane; an
inspector presents provenance, IDs, digests, and exact operation receipts when
needed. The toolbar exposes the current context's primary action and search.
The menu bar exposes navigation and primary session actions, with shortcuts for
refresh, new analysis, session search, and opening a session terminal. A small optional menu bar status
item may show verified stack health, but the main window remains a normal Dock
app. Settings contains archive location, display preferences, and diagnostic
paths; it never stores secrets.
The native Navigate menu now opens a new analysis (Command-N), searches Sessions
(Command-F), and opens the selected registered session terminal
(Command-Shift-T). Its selection is shared with the Sessions list, and a stale
or absent selection disables the terminal command. Command-R refreshes catalogs.

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
Each main window now owns its own navigation and search state. Menu commands
read the focused scene's navigation model, so they act on the front window's
session selection. Shared catalogs remain app scoped. Multiwindow visual
acceptance remains pending on the unlocked desktop.
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
The bridge and terminal now use the fixed `~/SecureSandbox` installation.
Settings displays that path without offering a command-source override. Before
launching the bridge, the Swift client checks the operator-owned home,
repository, scripts directory, bridge file, and `labctl` file for expected
types and modes without following symlinks. An alternate path is rejected;
a direct Swift smoke run loaded the live Overview catalog from the fixed path.

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
   The Sources list and successful import sheet now open a source-bound terminal
   with only a canonical source UUID. The host controller accepts `--source`
   only for a new session, the Research forced SSH command admits only the
   exact launcher shape, and the root run supervisor verifies the registered
   worktree against its source manifest before setting the scoped Claude
   working directory. The source UUID is never forwarded as a Claude prompt
   or option. Protected host and Research deployment plus live acceptance
   remain.
4. **Export.** The operator chooses a report revision, transcript, finding,
   or retained tool result. A privileged reader verifies the archived object
   and streams a bounded typed payload to a private temporary file. The app
   uses a native save panel, writes atomically to the selected destination,
   records provenance beside the export when requested, and deletes staging
   plaintext on close or error. Export is explicit; browsing metadata does not
   bulk decrypt evidence. Tool output not already retained needs its own
   content-bound catalog before the UI can promise a historical export.
   Artifact text, selected tool result, finding JSON, and transcript exports
   now offer an optional provenance sidecar after a successful native save.
   The sidecar records the selected archive identity and digest, or the
   rendered-file digest where escaped text differs from original content.
   It is bounded, mode 0600, and created without replacing an existing
   sidecar. A direct smoke check confirmed mode, replacement refusal, and
   unchanged content. The native artifact panel opened a selected archived
   report and exported its verified text with a provenance sidecar. The
   sidecar's original digest matched independent `labctl artifact` readback,
   and its rendered digest matched the saved bytes. The first live save showed
   that the system document exporter used mode 0644. The app now opens the
   returned regular file without following symlinks and restricts it to mode
   0600 before writing provenance; a second live save verified mode 0600 for
   both files. A direct Swift probe verified regular-file protection and
   symlink refusal. Live finding JSON and selected tool-result saves also
   produced valid JSON with matching provenance digests and mode-0600 files.
   The tool-result browser verified a linked archived transcript and the exact
   selected result digest before offering its export.
   Selected transcript export now streams canonical JSONL to a mode-0600
   temporary file beside the chosen destination and replaces it only after
   archive chain verification and a successful process exit. The response
   carries record count, byte count, and SHA-256; the export is bounded to
   512 MiB and one million records. The in-app preview remains limited to 8 MiB.
   The underlying CLI now decrypts each archive chunk to a private temporary
   file and checks the entire ciphertext chain before rendering records, so
   chunk size no longer dictates shell memory use. A live 145-record run passed
   CLI readback and bridge export; the exported count, byte size, SHA-256, and
   mode 0600 matched independent checks. A live export above 8 MiB remains.
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
