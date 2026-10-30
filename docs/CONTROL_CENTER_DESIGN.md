# SecureSandbox Control Center DDD

## Decision and scope

Build a signed, native SwiftUI macOS 27 operator app for the existing three-VM
SecureSandbox installation. The app is a desktop front end to reviewed host
operations, with readable names, progress, evidence, and recovery guidance in
place of copied commands and UUIDs. This document is the design and delivery
plan. The SwiftPM app in `macos/ControlCenter` now covers the operator surfaces
and command inventory. The reviewed host and guest control planes have been
deployed; action-specific live acceptance remains for prepared actions. The
Activity view reads a bounded,
content-free telemetry projection. Maintenance and Recovery show read-only
clock and snapshot-policy checks.
Findings now have an explicit, bounded detail view for claims, support,
limitations, and history counts.
The Findings catalog keeps agent-authored claims behind explicit detail open.
Rows use severity, state, local submission date, and a stable ordinal when
several findings share the displayed minute; full IDs remain in detail and
search without occupying the list label.
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
Swift decoding boundary; native visual review is described below.
The macOS app now has debug SwiftUI previews for healthy, degraded, stopped,
and unavailable Overview states. The stopped-stack fixture covers the expected
unreachable guests after a verified Stop. The reachability warning applies
only to running guests, so an intentionally stopped VM does not suggest a
control-identity fault. These previews use fixture status data in the production
Overview view and compile under the macOS 27 SDK. The installed dark-mode
window has since been reviewed on the unlocked desktop.
The host session-run catalog now has a v2 writer and reader for bounded run IDs.
The Sessions view can open a selected session's linked transcripts and tool
results. The installed controller still has the v1 count-only format; live
readback found one session with eight historical runs and no run links. A future
approved controller deployment and run will migrate it without inventing old
run IDs.
Linked runs display their ordinal in the session history list. Their UUID is
available through Copy Run ID in the row's context menu, so operators can
choose transcripts, tool results, or leases without reading a GUID. The row
layout compiles and is installed; nonempty live history acceptance still
requires a linked run from the v2 writer.
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
SwiftTerm reports fork and PTY input-channel launch failures separately from
normal process termination. The terminal delegate now shows those failures as
a final message in the window, including for direct administrator shells. The
updated app built and relaunched locally; an actual failed launch and an
approved session's window-close lease finalization still need live acceptance.
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
cannot be submitted. An unsubmitted plan can be discarded locally even when
status readback is unavailable, so a stale pointer cannot block another URL;
the Gateway plan expires on its own. A submitted plan remains latched until a
terminal status is read back. Terminal plans can be cleared in the UI.
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
One live cold backup passed; the restore transaction remains pending.
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
engine through a one-time plan and worker. A live cold backup later passed.
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
passed in process arguments. A live three-VM backup later ran to a signed
verified terminal record on an encrypted external APFS volume.
A disposable 128 MiB APFS volume was encrypted with a disk user and mounted for
live preflight. `diskutil` reported APFS with `Encryption`,
`EncryptionThisVolumeProper`, and `FileVault` all true. The bridge returned
`encrypted: true`, `stack_stopped: false`, `ready: false`, and insufficient
capacity. The installed Recovery view showed encrypted APFS verified, stack
stopped required, and a disabled Prepare Backup action. The probe was then
detached and deleted, and revisiting Recovery cleared its temporary preflight.
This validates the failure path and volume-encryption detection; it does not
verify a full backup or restore.
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
Restore and recovery acceptance remain before DDD release.
After an unclear backup or restore submission, Recovery removes the local
submit button, retains the operation ID, and reads back its durable status.
It offers an explicit status refresh; an unsubmitted plan can be forgotten
without changing host state, while a running or unread operation keeps its
identity in focus. Expired plans cannot be submitted. Once rollback recovery
is claimed, the host status no longer offers a second recovery submission;
it distinguishes a still-starting recovery from an incomplete or failed one.
These paths have focused fixtures and a Swift build, pending live recovery
acceptance with a suitable encrypted backup volume.
Earlier on 2026-10-29 the host had 29 GiB free and no external physical disk
attached. The operator then mounted an encrypted external APFS volume with
about 1 TB free, enabling live cold-backup acceptance. Restore still needs
its separate host-space preflight; generated data outside this project
includes large shared application caches, which remain untouched pending an
operator choice.

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
the session list also uses singular “turn” for a count of one. Full review in
Light, increased contrast, reduced transparency, VoiceOver, keyboard, narrow
windows, and the Dock remains.
Settings now offers a system/light/dark app appearance choice. The installed
app's Settings and Overview windows rendered in Light and returned to System
without changing the Mac's global appearance. A shared export-provenance
preference reached the selected finding's export sheet; it was returned to off
after the check. The installed app subsequently rendered Sessions, Sources,
Findings, Evidence, Recovery, Activity, and Maintenance in Light at the
standard window size. Catalog rows, toolbar actions, status colors, and
scrollable content remained readable; System appearance was restored. Evidence
rows now use filename, version, local capture time, and a stable ordinal for
any identical display labels; artifact IDs remain in detail and search.
The live Evidence view displayed a loading state while its 73-item verified
archive catalog was fetched. Its first load took over a minute because the
CLI fetched the archive identity separately for each artifact. The catalog
path now receives that identity once through stdin and still checks every
ciphertext hash and decrypted envelope. A subsequent live CLI read took about
7 seconds, the versioned bridge about 14 seconds, and the app displayed the
same 73 rows after its loading state. Recovery correctly showed snapshot policy
attention while the current retained set was incomplete, without offering an
apply action.
The six independent startup catalogs now begin concurrently, retaining
separate success and error state for each screen. Sequential live bridge calls
took about 4.4 seconds; the same six calls dispatched concurrently took about
1.8 seconds. The installed app loaded Overview, Sessions, Sources, Findings,
and Activity after the change with current catalog rows and no load errors.
The Sessions keyboard shortcut, Command-F search focus, and live filtering of
a selected session also passed a desktop check.
In a further live check, selecting a session and searching for an absent row
cleared the selection and disabled Label Session, Browse Session Runs, and Open
Session Terminal. Clearing the search restored the catalog without selecting
an unrelated session.
Sources, Findings, and Evidence now bind their detail actions to the currently
visible filtered selection. Search clears a selection that no longer matches;
catalog refresh also disables detail actions for removed records. A live
Evidence check first reproduced an enabled Open Artifact action after the
selected row disappeared under an empty-result search. With the updated app,
the same empty-result filter disabled Open Artifact; Findings also disabled
Open Finding, and Sources removed the hidden source's analysis, index, and
dependency actions.
The native label sheet saved a temporary private label, the Sessions catalog
read it back, and explicit removal restored the original unlabeled state.
Unlabeled sessions now show their local start date rather than a truncated
UUID. Same-minute sessions receive a stable ordinal suffix; the live catalog
contains one exact same-second pair, and the installed app displayed distinct
“1 of 2” and “2 of 2” rows. The “2 of 2” name also appeared in its native
resume-window title and preflight heading before any launcher started. Names
are computed once when the catalog changes,
so long lists avoid a per-row scan of all sessions. The selected detail view
has session identity so VoiceOver's combined
accessibility value follows selection; a live switch between two unlabeled
rows returned the matching full ID for each.
The native Settings scene opened with Command-comma and closed back to the
main window. New Analysis and selected Resume Session each opened a separate
window with a lease picker and explicit start button; closing either before
start left the launcher uninvoked. Resume windows now resolve the selected
session's label or local start date for their title and preflight heading. A
live unlabelled resume window changed from the generic loading title to its
date-based title without exposing a UUID fragment.
The bundle builder now verifies its identity, minimum OS, icon, SwiftTerm
license, and strict code signature on every local build. The separate
`script/validate_bundle.sh APP --distribution` gate requires a Developer ID
Application signature, hardened runtime, and Gatekeeper acceptance. An
operator can set `SECURE_SANDBOX_DEVELOPER_ID` to an installed certificate name
when building for distribution. The current app passes the local gate with an
ad hoc signature, but the distribution gate correctly rejects it. Xcode's
Personal Team offers Apple Development only; this Mac currently has no
Developer ID Application identity.
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

### Protected deployment and Control Center Stop, 2026-10-29

With the operator present for Touch ID and GLM lifecycle idle, the reviewed
host-controller release was deployed, the typed control plane was republished
to all three guests, and aged control receipts were archived losslessly. The
Gateway and Research run-lease package and focused Research findings package
were installed. The next complete boundary run passed 133 checks with no
failures or gate notices. The app's Stop sheet then showed the live three-VM
preflight, transition phase, verified final result, and independent readback
of all three stopped VMs. Overview showed the stopped guests as unreachable
without a false control-identity warning. Parallels Desktop's GUI remained
closed throughout the lifecycle change.
The first app-submitted backup plan failed before copying: Finder had created
one `.DS_Store` file beside the three VM bundles, and the exact-root inventory
rejected it. The backup inventory now permits only a bounded, regular,
single-link, owner-controlled `.DS_Store` entry while still rejecting unknown
root entries and symlinks. Focused fixtures passed. A fresh app-submitted
one-time plan copied and published all three VMs and the fixed host
configuration on the encrypted external volume. The worker's authenticated
terminal record reported `verified`, 64 files, and 27.73 GB, after an
independent full readback. The app displayed the same verified result. Status
polling was then bounded so it reports a running worker's verification phase
without starting competing full-file reads. After completion, status checks
the authenticated worker result, manifest, and completion marker quickly;
the explicit Verify & Preview action still rehashes every archived file.
Finder later added `.DS_Store` to the published generation root when the
operator browsed the encrypted volume. Generation verification now permits
only a bounded, single-link, owner-controlled regular Finder metadata file
at that location. Unexpected entries and symlinks still fail. Focused tests
and live authenticated backup-status readback passed after this correction.
That separate live preview rehashed all 64 archived files successfully,
confirmed the stopped stack and matching host configuration, and reported
`ready: false` solely because the Mac had 31.2 GB free versus about 38.5 GB
required for restore data plus reserve. No restore plan or transaction was
submitted. The updated app was installed locally, relaunched, and read back
the same signed backup completion quickly; it labels that status "Verified
at completion" and directs the operator to the explicit current-content
preview.

### Cold Start and source workflow, 2026-10-29

From the stopped state, the app's Start sheet read back all three stopped VMs,
then showed the Gateway-reachability and containment-verification phases.
Its final record and independent `labctl status` readback found all three VMs
running and reachable. A separate full boundary run passed 133 checks with no
failures or gate notices.

The Sources GUI resolved `https://github.com/octocat/Spoon-Knife` at `main`
to an immutable commit. Its first `source-status` readback failed because the
Gateway still had an older source controller. After deploying the reviewed
source-acquisition package, the same plan read back as planned; the GUI
submitted it once, received a completed source identity, and displayed the
new catalog row. From that row, the app built a three-document corpus index
and a CodeGraph index with zero code nodes for its HTML/CSS/Markdown files.
The source-bound terminal launched Claude in the imported worktree, returned
a run and lease identity, and exited cleanly via `/quit` with zero model
requests. Research `lifecycle-idle` then passed.

Session run browsing exposed a mixed-schema migration bug: two historical
records in the v2 private catalog retained their old two-field shape. The
reader now preserves their counts with no invented run links, and the writer
normalizes such records on its next run. The live Sessions view then showed
the selected historical session's eight recorded runs and zero linked runs
without failing the entire catalog.
The reviewed writer fix is committed and passes focused tests. An initial
protected deployment request expired; a fresh Touch ID approval installed
the reviewed host-controller release, and the installed controller's digest
matched its source. Next-run normalization of the existing private catalog
still needs live acceptance. The app subsequently stopped all three VMs
again, with a verified final host record and independent status readback.
The full publication and secret checks passed for the committed
implementation checkpoint.

For restore testing, the operator approved temporarily offloading the uv and
Xcode DerivedData caches to the encrypted external volume. Each copied tree
passed a content-and-link checksum comparison before its local original was
removed. The project Swift build output was preserved the same way. APFS free
space initially remained 48 MB below the restore threshold. Automatic
approval review rejected removing the project's `artifacts` directory
without a specific operator instruction. The operator then explicitly
approved that third offload; its external copy passed the same content check
before local removal. A private return manifest on the encrypted volume
records all four original locations. Host free space then exceeded the
restore data-plus-reserve requirement by about 288 MB.

### First live restore and automatic rollback, 2026-10-29

The app's full backup preview passed all 64 archived files, stopped-stack
state, matching host configuration, and host-space threshold. It created and
submitted one restore plan. The detached worker reverified the source,
copied and verified a three-VM candidate, quarantined the original bundles,
registered the candidate, and started all three guests. Its cold acceptance
failed one boundary check, so the journaled transaction automatically rolled
back. The authenticated journal ended `rolled_back`; the live VM directory
and all three bundle inodes matched their original recorded identities.

An independent normal Start of those originals reproduced the same failing
check: the host controller release could not be verified against approved
source while the project's local `artifacts` output was offloaded for space.
Restoring that directory from its checksum-verified external copy made the
complete 133-check boundary suite pass again. The failed candidate remains
retained separately for diagnosis, while the original VMs are running and
reachable. The restore worker now checks this host-release prerequisite
before any archive hashing or candidate copy. Rolled-back status also includes
an authenticated bounded failure code instead of discarding the reason.

### Second live restore and signing-validity boundary, 2026-10-29

After the local failed candidate was copied to the encrypted external drive
and removed from the host, the app again verified all 64 archived files and
reported 46.27 GB free against the 38.76 GB data-plus-reserve requirement. It
created and submitted one new restore plan. The worker completed independent
preflight hashing, copied all three bundles, verified the candidate, swapped
registrations, and entered cold acceptance. Acceptance failed and the
transaction again restored the original bundle directory and exact three VM
UUIDs. An independent unrestricted readback found all three originals stopped
and registered after rollback.

The single failing boundary was again the immutable host release. This time
the signed Touch ID UI was intact and its entitlements, designated
requirement, hardened runtime, and signing team all verified. Its embedded
development provisioning profile expired at 2026-11-01 03:01:46 UTC. The
restore began with slightly more than the boundary verifier's required 48
hours remaining, then crossed that floor during its repeated hashing, copy,
and candidate-verification passes. Xcode rebuilt the helper but reused the
same cached profile. With that exact profile temporarily removed, automatic
signing reported that Xcode has no developer account configured, so it could
not obtain a replacement; the cached profile was restored to its original
location.

Restore admission now requires at least 52 hours of helper-profile validity,
leaving four hours of transaction headroom before the 48-hour boundary floor.
It rejects insufficient headroom before reading the archive. Cold acceptance
also captures the lifecycle's final typed record and projects its first
bounded action failure into the authenticated restore error. Focused restore
fixtures cover both behaviors. The Touch ID helper build now applies the same
headroom floor before replacing the reviewed artifact, so reuse of a nearly
expired cached profile is an explicit build failure.

A fresh Apple development profile was subsequently issued with sufficient
headroom, and the rebuilt helper and reviewed host controller were deployed
through an attributed Touch ID approval. A normal cold Start then passed all
133 boundary checks, and a verified Stop returned all three original VMs to
the required stopped state. The app created a fresh aligned generation on the
encrypted external volume; its authenticated completion covered 64 files and
27.88 GB. A separate full-file preview rehashed that generation, confirmed the
stopped stack and matching host configuration, and refused to prepare a
restore only because retained diagnostic data left 9.55 GB free against the
approximately 38.6 GB data-plus-reserve threshold. The prior failed candidate
has a byte-identical copy on the encrypted external volume. After explicit
operator approval, the native retirement workflow removed the exact local
candidate and authenticated readback reported `retired`; the registered VM
stack remained stopped and untouched.

Recovery operation status survives app relaunch through its persisted
operation identity and authenticated readback. A live long-running backup also
exposed a transient 1Password CLI read failure during status polling. Backup
key acquisition now makes three bounded attempts within the original overall
timeout envelope, never returns or logs vault diagnostics, and has focused
failure and timeout recovery tests.

Recovery's in-window workflow state is owned by the main window rather than
the conditionally rendered sidebar detail. Selected backup inventory,
preflights, plans, authenticated operation status, errors, busy flags, and
monitor generations therefore survive navigation away from Recovery and back.
A live acceptance check preserved both the selected encrypted backup inventory
and an active 27.88 GB integrity pass across a Recovery → Overview → Recovery
round trip. A verified backup also exposes `Use This Verified Backup`, which
resolves the exact journal-recorded destination without making the operator
browse a mounted volume or re-enter a path.

Recovery now exposes retained-generation retirement as an explicit native
workflow instead of requiring a path or restore UUID at the command line. It
accepts only an authenticated terminal `accepted` or `rolled_back` journal,
binds the exact retained directory and inode identity, verifies the current
stopped VM directory and registered UUIDs, rejects links, special files,
cross-device entries, and oversized trees, and shows the verified item count
and reclaimable space before enabling a destructive confirmation. Submission
uses a durable claim, the host lifecycle lock, authenticated status readback,
and restart-safe reconciliation when deletion completes before the terminal
status write. The installed app's live preview bound the retained failed
candidate as 76 entries and 27.76 GB; the explicitly confirmed live retirement
then completed with authenticated terminal readback. Accepted restore and the
separate live retirement of its previous generation remain before release.

## Operator model

The launch window has a stable sidebar: Overview, Sessions, Sources, Findings,
Evidence, Recovery, and Activity. A selected item opens a detail pane; an
inspector presents provenance, IDs, digests, and exact operation receipts when
needed. The toolbar exposes the current context's primary action and search.
The menu bar exposes navigation and primary session actions, with shortcuts for
refresh, new analysis, session search, and opening a session terminal. A small optional menu bar status
item may show verified stack health, but the main window remains a normal Dock
app. Settings identifies the host-configured encrypted evidence archive,
offers an app-only appearance choice and shared export-provenance preference,
and shows fixed installation and bridge paths with diagnostic guidance. It
never stores secrets or accepts a command-source override.
The native Navigate menu now opens a new analysis (Command-N), searches Sessions
(Command-F), and opens the selected registered session terminal
(Command-Shift-T). Its selection is shared with the Sessions list, and a stale
or absent selection disables the terminal command. Command-R refreshes catalogs.
The File menu offers only a new main browser window. Parameterized session and
direct administrator windows remove SwiftUI's automatic New menu commands;
their context-specific entry points remain. The installed app's File menu
showed only New SecureSandbox Window, and Command-N still opened the explicit
New Analysis preflight without starting a launcher.

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
session selection. Shared catalogs remain app scoped. On the unlocked desktop,
a second main window opened on Overview and navigated to Sessions while the
first retained Sources; closing the second returned to the first window.
Focused command selection across two distinct session selections still needs
live acceptance.
The host bridge now enforces its 8 MB response ceiling while reading child
output, retains only a bounded diagnostic tail, and starts each bounded CLI
call in a private process group. On a deadline or oversized response it kills
that local group before reaping the command. A disposable timeout test verified
that a child process did not remain active. An uncertain mutation outcome must
be inspected before
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
