# Disposable-Mac Harness Lifecycle Acceptance DDD

Status: campaign contract, bootstrap/recovery/cold-boot drivers, protected Host
provenance and production-bound archive rejection, protected Research
qualification, Touch ID authorization, runtime and management scenarios,
independent export, and crash-boundary hardening are implemented. All ten
driver classes are source-complete, and none is considered physically
available until an exact
commit is installed under a protected self-digested manifest.
Physical disposable-Mac execution remains pending. No live acceptance verdict exists yet.
The ordered root-password and 11-case Touch ID handoff is retained in
`docs/DISPOSABLE_MAC_OPERATOR_CEREMONY_QUEUE.md`; it explicitly forbids using
the development Mac or requesting credentials before a ceremony is runnable.

## Decision

Harness lifecycle acceptance is a destructive, machine-bound campaign, not a
unit-test label and not an admission shortcut. A campaign can begin only from a
fresh macOS enrollment receipt that declares the machine disposable, finds no
known production-material paths or provider credential environment, and finds
no Agents-vault service credential in the login Keychain. The receipt exports
only a digest of hardware identity; it never exports the platform UUID or
serial number.

The fixed suite contains 91 cases and 198 required observations. It covers
fresh bootstrap, provenance and archive rejection, candidate isolation, all
Touch ID outcomes, new/old/legacy session behavior, rollback, retirement,
reclamation, revocation, containment, cold boot, and paired process-loss and
power-loss cases at fifteen durable lifecycle transitions. The suite digest
binds every case, expected result, observation kind, Touch ID requirement,
reboot requirement, and destructive flag.

A complete export has only `acceptance-evidence-only` authority. Passing it
means the evidence is eligible for a separately reviewed exact-generation
admission decision. It cannot install, select, activate, admit, migrate,
download, or authorize a harness.

## Trust model

Protected facts are the campaign identity, machine digest, exact source commit,
suite digest, observation set, receipt order, final export, and the negative
claim that production material was absent. Relevant adversaries include a
candidate harness fabricating its own success, an agent omitting negative
cases, observations copied from another machine or source revision, an
operator accidentally using production credentials, and a crash that leaves
admission fenced without a recoverable transaction.

The candidate is never an accepted collector. Observations must name one of
the fixed outer collectors: protected Host, Research, privileged-control,
Touch ID broker, disposable supervisor, cold-boot supervisor, or evidence
exporter. Each observation binds the campaign, machine, source commit, case,
kind, expected outcome, subject and detail digests, time window, and an explicit
`candidate_statement_used: false`. Mixed-machine, mixed-commit, duplicated,
missing, reordered, expired, oversized, or candidate-derived evidence rejects.

The v4 campaign format does not pretend that a JSON digest proves physical
reality by itself. Collector authenticity comes from the already protected
Host/Research release and its independently read-back receipts. The export
preserves those facts so a verifier need not trust the candidate narrative.
The immutable external evidence archive remains the retention boundary.

Each v4 observation embeds a canonical evidence projection rather than only a
digest-only success claim. The projection binds the source schema and normalized
source outcome, source and subject digests, exact collector, machine, source
commit, and a bounded inventory of underlying protected artifacts. Every
artifact declares one closed outer authority; `candidate` is not an allowed
authority. The observation must bind the same subject, collector, kind, and
outcome as its embedded projection. Empty artifacts, detached subjects, and
otherwise self-consistent candidate-authored projections reject.

The export is self-contained: each protected readback's exact bytes are
canonical-base64 embedded with size and SHA-256 readback, not merely referenced
by a digest. Each artifact is capped at 64 KiB and each observation at sixteen
artifacts; the complete export reader is capped at 32 MiB. Because the campaign
is synthetic-only, a protected readback containing production material is a
campaign failure, not material to preserve in this bundle.

## Enrollment and production-material exclusion

`scripts/enroll-disposable-mac-harness-lifecycle.py` is intentionally separate
from lifecycle mutation. It requires an exact destructive-test acknowledgement,
Darwin hardware, absence of known provider credential environment variables,
absence of SecureSandbox/provider state paths, an unambiguous Keychain probe,
and no `op-service-account-agents` entry. It emits no secret and never calls
1Password. Enrollment owns the single provider-state path inventory used by
bootstrap, qualification, runtime, and management Host scans. That inventory
includes the Google credential database and Azure MSAL cache; source tests
reject either marker and prevent per-driver copies from drifting.

This preflight is a lower bound, not a forensic proof that a reused Mac is
clean. The physical campaign therefore requires a factory-reset or freshly
erased dedicated Mac, a new local test account, synthetic credentials only,
and no sign-in to the operator's production 1Password, provider, cloud, or
research accounts. Any uncertainty aborts the campaign.

## Clean-destination product bootstrap

Physical execution exposed a prerequisite that source-only review had not:
the disposable Mac needs the ordinary protected SecureSandbox Host controller
and exact three-VM lab before the campaign's clean-install collector can read
them back. The former first-install path rebuilt and notarized native Host
products on the destination. That would require the release operator's
Developer ID private key and Apple notarization credential on the disposable
Mac, contradicting the production-material exclusion boundary.

First install therefore accepts a transferable native-Host candidate built on
the trusted release Mac. The transfer contains public signed/notarized product
bytes, their detached Developer ID receipt, bounded notarization result and
log, source archive, and signed-release preimage. It contains no signing key,
notarization password, provider credential, or 1Password service credential.
`deploy-host-controller.py stage-native-host-candidate` never executes transfer
content. It requires an absolute owner-controlled candidate directory, rejects
links, special files, unsafe modes, unexpected top-level entries, excessive
depth, count, or size, and copies without extended metadata into a private
destination-local staging identity. It holds the retained-parent descriptor
through reservation and publication. Interrupted or rejected copies remain
under the inert `.candidate.*` class; cleanup never recursively removes a
pathname that another process could substitute.

The existing release verifier remains authoritative. Before an imported
candidate can become first-install or ordinary-upgrade authority it must
independently verify the
v3 detached Developer ID receipt, expected Apple team, notarized and stapled
carrier, product manifests and signatures, source archive, Host-release
preimage, complete destination tree, and an exact match between its signed
commit/archive/tree/signing provenance and the current clean source checkout.
On a clean destination the signed candidate supplies only its authenticated
signing-configuration digest; the destination independently derives the public
commit and deterministic Git archive without recreating the ignored local
signing file.
Bootstrap and ordinary deployment accept exactly one eligible
candidate. Zero
eligible candidates falls back to the trusted release-Mac build path; multiple
eligible candidates or any malformed inventory fail closed. The displayed and
privileged deployment plan then binds the destination device, inode, whole-tree
digest, certificate, source, preimage, and release identity exactly as it does
for a locally built candidate.

The first exact-provenance ordinary-upgrade ceremony reached a real, centered
authorization window on the Neo and expired without mutation when the operator
did not act. A second deliberately unapproved diagnostic run proved the window
was on screen, then failed closed because the installed broker tried to open
the root-owned mode-0600 candidate-floor marker before inspecting its ACL. That
assumption is invalid on macOS: even `O_EVTONLY` does not grant an unprivileged
process access to that private file. The repaired broker instead brackets a
pathname ACL query with stable `lstat` identities. It never opens or reads the
marker; the independently verified root-owned, non-writable parent prevents an
operator process from substituting its name.

Because the defective immutable broker cannot authorize its own replacement,
one narrowly bound two-gate recovery exists for that exact predecessor release
and broker digest. The administrator-password phase may only materialize the
exact signed/notarized successor release and candidate authority as root-owned,
non-selected objects. It independently proves that `current`, `previous`, the
stable launcher, and the stable launcher/release pair did not change. The
staged successor must contain the reviewed pathname-ACL repair and must not
contain the defective open-based check. The ordinary operator broker then runs
from that exact staged release and still requires a fresh Touch ID ceremony for
the normal atomic Host-pair transition. Recovery cannot authorize selection,
cannot accept a different predecessor, and becomes unavailable after the
successor is selected.

The first recovery launch also failed closed before displaying its notice: its
login-user preflight reused a full release verifier that attempted to read the
root-private native-stack coordination floor. Recovery preflight now identifies
the exact predecessor only through the canonical public enforcement
projections, stable Host pair, immutable payloads, candidate authority, and
launcher identity, then separately pins the observed broker digest. The
sudo-isolated staging manager remains the first component permitted to read and
cross-check the private floors. Thus the notice is based on strong public
readback without silently granting the login user private-floor content
authority.

Physical recovery then exposed the same invalid content-authority assumption
in the staged broker's native-stack coordination-floor check. The broker now
verifies that private marker's stable root-owned mode-0600 metadata and ACL,
then treats the canonical root-owned mode-0444 enforcement projection as its
minimum-epoch and feature authority. It never opens the private marker. The
privileged release manager still reads the private canonical bytes and requires
their digest to match the public projection before mutation, so moving the
login-user check to the projection does not move final authority out of root.

The operator password ceremony must run in a Terminal window on the disposable
Mac. An SSH pseudo-terminal owned by the controller is not an operator-visible
prompt even when the preceding graphical notice is visible. Remote orchestration
therefore opens a local Terminal tab and retains output through `tee` while
leaving stdin attached to that local terminal. Touch ID must be enrolled in the
Mac's Secure Enclave before the subsequent biometric-only gate; no password
fallback is permitted.

The first enrolled-Touch-ID transition retained an exact failed broker receipt
and left the stable Host pair and selectors unchanged. The terminal receipt's
stdout digest resolved to
`native_host_release_tree_identity_inventory_invalid`; immediate independent
readback then proved complete, byte-consistent inventories for both the stable
source and staged target, with no transition record. Receipt recovery therefore
admits this one additional exact canonical error digest alongside the already
enumerated signed-app tree-identity mismatch. It still requires the original
Touch ID receipt, request digest, target-plan digest, empty stderr, exit status
1, unchanged independently verified source pair, exact candidate and rederived
plan, and no pending transition. The failed receipt is archived root-only
before reconstruction. Every other failure remains terminal, and an active
transition prevents reconstruction.

The next physical recovery consumed a fresh Touch ID request and reached the
atomic Host-pair transition, but failed closed while activating the target
authorization daemon. The protected transition record is terminal
`source_restored`: the source release, pair, launcher, and daemon were restored;
the target remains an inert staged release; the failed request is spent. Unified
launchd evidence showed a post-`bootout` same-label cleanup window after exact
job absence and before the target label became reusable.

Authorization-service installation therefore has a bounded admission barrier.
It retries the identical fsynced plist after a nonzero `bootstrap` only when two
separated exact readbacks both prove absence. Before the first bootstrap, the
same two-readback barrier may wait through launchd's specific temporary
state-unproven cleanup observation without treating it as absence. A registered
state fails closed. Once `bootstrap` returns zero it is never issued again:
scheduled or inactive states may progress only to two matching running
readbacks with one stable PID. Absence, unexpected state, PID change, oversized
output, or timeout fails closed. This adds no executable, selector, or release
authority.

A physically clean destination has no stable Host launcher or immutable
pre-authorization release to bind. The first Neo execution exposed that the
former path nevertheless tried to read `/usr/local/bin/secure-sandbox-claude`
before presenting the authorization ceremony. Clean bootstrap now derives a
real six-payload predecessor from the already verified candidate preimage,
binds its deterministic release ID and candidate launcher digest in the public
operator plan, and independently rederives both as root. Under the Host and
controller locks, root may materialize only that immutable predecessor,
selector, and launcher. A partial or unrelated install-root/launcher state
fails closed. Each publication boundary is replayable to the same identities;
tests inject interruption after release, selector, and launcher publication.
The next logged Neo attempt reached the administrator boundary and then failed
closed before publication because the wrapper had overloaded one digest: it
derived the candidate release manager digest but asked the privileged loader to
execute the newer reviewed bootstrap manager. These identities are now kept
separate. The loader digest binds the exact current manager bytes it opens and
executes; the older transferable candidate remains bound by its independently
rederived release ID, complete payload closure, candidate record, launcher,
Developer ID identity, notarization evidence, and preimage. A mismatch in
either identity still rejects before protected publication.

Every physical bootstrap attempt now runs through a fixed diagnostic launcher
instead of an ad hoc terminal pipeline. The launcher creates one private,
non-overwritten log per attempt and records UTC launcher, command, signal, and
exit events together with the source commit, PID, and terminal identity. The
deployment command retains the terminal as stdin, so administrator input is
never copied into the log. A dedicated append descriptor records terminal
closure and final status independently of the command-output `tee`; that
output is also copied through the pinned descriptor rather than by reopening a
mutable pathname. Dirty/non-public source, an ACL-bearing or non-private log
root, and log-identity substitution fail closed. Terminal scrollback is not
evidence.

The corrected bootstrap subsequently completed on the erased Neo. Independent
unprivileged verification from the installed immutable manager—not the
bootstrap success response—validated the selected release, stable launcher,
launcher/release pair, complete payload closure, native candidate authority,
and established Developer ID team floor. This establishes the ordinary Host
prerequisite only. Installer acquisition, exact three-VM creation, resource and
boundary qualification, protected acceptance-driver installation, and the
ordered physical campaign remain required.

The first clean-machine installer acquisition downloaded the complete pinned
Canonical ISO and independently matched its expected SHA-256, but the protected
verifier rejected before authorization because the clean public checkout did
not contain ignored binary `.gpg` files. The acquisition path had assumed that
the release signature and Ubuntu archive keyring already existed even though
the publication policy deliberately excludes them. The repaired path downloads
those two public inputs from fixed official HTTPS endpoints, pins their exact
reviewed whole-file digests and size bounds, rejects unsafe or divergent
existing paths without replacement, and publishes new inputs with an exclusive
macOS rename plus file and directory durability. The protected verifier remains
authoritative: it must authenticate the tracked manifest under the exact pinned
Canonical fingerprint before the retained ISO can be promoted. The rejected
attempt and its mode-0600 diagnostic log remain physical failure evidence.

This transfer is a release artifact, not production identity. The destination
must still run Gatekeeper and project verification, establish the immutable
Developer ID team floor through the one-time attributed bootstrap, provision
the reviewed VM layout, and independently read back the complete Host/Research
boundary before campaign initialization.

## Crash-boundary repair

The acceptance review found that activation and management previously wrote
the run-admission fence before the recovery journal. Power loss in that narrow
window could leave admission closed with no journal describing the exact
predecessor. The transaction now durably writes a `prepared` recovery journal
first, then writes the fence, checks runtime idleness, and advances the journal.
If runtime is not idle it removes both records durably.

Internal constructor-injected checkpoints now exist after:

1. candidate staging and plan publication;
2. prepared journal and admission fence;
3. workflow authorization and immutable release publication;
4. catalog, floor, and selector writes;
5. health evidence;
6. activated, verified, and committed workflow records; and
7. fence and journal removal.

They are not command-line arguments, protected-control operations, environment
variables, files, or model-visible knobs. Production managers use a no-op
callback. Source tests inject process loss without adding a runtime bypass.
The journal records `committed` before fence removal, allowing recovery to
distinguish a safe pre-fence crash from a committed response-loss window while
still rejecting an unexplained missing fence.

## Campaign and export protocol

The public operator CLI exposes only:

- `catalog`: render the immutable suite and its digest;
- `readiness`: separately report source completeness and exact-commit protected
  installation under a root-owned self-digested manifest, with no execution or
  mutation authority;
- `initialize`: consume one canonical owner-controlled enrollment receipt and
  create a bounded campaign for an exact source commit, but only when every
  suite-declared driver source is complete and every driver is present in the
  exact protected installation;
- `verify-campaign`: validate policy, identity, time, and self-digest;
- `status`: validate every present observation and report the next incomplete
  fixed case without creating evidence;
- `next`: return the immutable protocol, interaction, interruption checkpoint,
  reset rule, and exact missing collector assignments for only the next
  incomplete case;
- `scripts/harness-lifecycle-acceptance-observe.py`: project one or more stable,
  owner-controlled protected readback files into the exact case/kind filename;
  it derives the primary schema, source status, subject digest, artifact sizes,
  artifact digests, and bounded embedded bytes rather than accepting a
  caller-supplied outcome;
- `assemble`: require the exact observation filename and case/kind inventory,
  validate every observation, and create a chained receipt export; and
- `verify-export`: independently revalidate the complete export and return the
  non-admitting verdict.

There is no activate, rollback, retire, revoke, recover, poweroff, download, or
credential command. Existing protected ceremonies remain the only mutation
path. Files must be regular, single-link, owner-controlled, bounded, and
canonical. Output creation uses `O_EXCL|O_NOFOLLOW` and never overwrites prior
evidence.

The fixed readiness inventory currently reports ten source-complete and zero
physically available drivers on a source checkout. Checkout ownership or filenames
are never protected-Host authority. Availability additionally requires the campaign source commit in a
closed root-owned release directory, a canonical mode-0444 manifest whose
self-digest binds the suite and exact payload inventory, and byte-for-byte
payload verification. Runtime and management use the same exact-commit gate.
This is a release gate, not a bypass flag: there is no command-line option to
initialize an incomplete or unprotected campaign.

Before any operator authorization, the read-only morning preflight requires a
fresh enrollment bound to the current hardware, a clean `public-release`
checkout at the exact commit returned by the credential-free public GitHub
release authority. Remote lookup uses its literal pinned HTTPS endpoint from `/`, with repository,
global, and system Git configuration excluded, so an operator-writable remote
name or URL rewrite cannot substitute the publication authority. The private
Hobby mirror remains mandatory at publication time on the trusted development
Mac, but is deliberately not queried from the disposable Mac because doing so
would import a forbidden production credential. The root installer repeats
the isolated exact-tip check, fetches that tip into a fresh root-owned bare
repository, and reads payloads only from that store. It never evaluates Git
configuration, hooks, indexes, objects, or payload paths from the
operator-writable checkout. The operator ceremony first clones the pinned
public branch into a new root-owned, non-overwritable bootstrap directory
directly beneath the fixed macOS `/private/var/db` system hierarchy, and
verifies the clone resolves to the preflight commit before executing any file
from it. Every sudo subprocess starts with an empty allowlisted environment,
and every privileged Python verifier uses isolated mode. The installer rejects
execution unless its resolved file and the complete fixed hierarchy are the
exact root-owned, non-symlink, non-group/other-writable path for the requested
commit. Before it can queue that root ceremony, the read-only gate independently
requires every fixed system ancestor to exist as a root-owned, non-symlinked,
non-group/other-writable directory with no extended ACL, rejects an object that
changes identity across the ACL probe, and binds each accepted object's device,
inode, UID, GID, mode, and explicit ACL absence into the canonical preflight
receipt. A rejected clean-machine Host bootstrap may leave only its empty
coordination hierarchy. The gate classifies that state as
`empty-coordination-residue` instead of deleting it: it pins the user-owned
directory chain with descriptors, requires the exact 0755 `SecureSandbox`
directory and sole empty 0700 `controller-state` child, checks ownership and
extended ACL absence through those descriptors, and repeats named identity and
content readback before recording the classification. Every additional entry,
wrong mode or owner, link, ACL, identity change, or nonempty state remains
production material and fails closed. Enrollment remains stricter and accepts
no such pre-existing path. The gate also requires the complete source closure, absence of known
provider/production material and
the Agents service credential, a closed Parallels GUI, and readable fixed VM
states. It distinguishes the expected complete absence of a protected release
from any partial or invalid installation. Only the former may name the exact
root installation as the next ceremony. A complete protected ten-driver
release instead names unauthenticated campaign initialization; the preflight
always reports Touch ID unavailable and cannot invoke `sudo`, the broker, an
installer, or a VM transition. It rejects execution as root so the inspection
cannot accidentally become a privileged ceremony. File output requires an
expected transition and uses descriptor-relative, no-overwrite mode-0600
publication beneath a real operator-owned mode-0700 directory with no extended
ACL; both file and directory are fsynced. The consumer rereads canonical stable
receipt bytes, verifies the self-digest, operator, authority, transition,
protected-install state, remote tip, and source commit, then emits only that
bound commit. It also requires the producer's complete closed field set and
revalidates every retained absence, bootstrap-hierarchy, VM-boundary, driver,
and Touch-ID-unavailability fact; a correctly re-digested receipt with an
omitted, added, or inconsistent fact is still invalid. Root installation and
campaign initialization therefore consume
the distinct pre-install and post-install receipts instead of recomputing a
potentially changed checkout commit or relying on terminal scrollback.

The Host provenance fixture core and the protected Host installer are
now source-complete, but no live protected installation has been made on the
disposable Mac. The fixture executes all sixteen fixed provenance cases
against an isolated instance of the production `HarnessStore`, including exact
carrier acquisition, redirect/oversize/substitution rejection, delegated
signer validity/revocation/chain rejection, metadata time, rollback, freeze,
fast-forward, equivocation, and inconsistent evidence binding. Every rejection
proves an unchanged protected-state digest; successful acquisition retains only
an inert mode-0600 quarantine generation. The outer driver rebinds the current
machine and verifies its own exact-commit protected manifest, accepts only the
next provenance case, reserves raw evidence before execution, and supports
non-overwriting projection resume from one validated canonical raw result. The
installer requires root, a clean checkout at the requested commit, fixed
root-owned paths, immutable payload modes, and a self-digested manifest. Payload
bytes come from immutable objects of the exact requested commit rather than
mutable checkout paths. A root-owned installation lock serializes the
absence-check and publication rename, and the installed verifier rereads the
published release before success. The manifest constructor and that final
readback both enumerate all ten drivers, including the clean-machine bootstrap
and its dynamically loaded Host-release verifier; a source test requires the
installer payload list to equal the union of every contract-declared closure.
It refuses collisions. Privileged driver
execution rejects any path outside the exact protected release before local
imports. Installed execution also disables Python bytecode writes, preserving
the closed manifest inventory. Until
that installation and its root invocation occur on the disposable Mac,
readiness remains unavailable; owner-run source tests cannot become physical
protected-Host evidence.

The archive preflight and protected Host wrapper are source-complete and remain
non-admitting. The production `HarnessStore.acquire` boundary invokes the
bounded preflight only after the signed carrier length and digest are verified
and before any quarantine generation is created. The preflight
parses a closed, bounded ustar subset without extracting or executing any
member, validates the whole header/data/terminator framing, and rejects absolute
or traversing paths, links and special entries, sparse members,
duplicate/case-fold/Unicode path collisions, expansion limits, alternate
streams, and trailing data. The wrapper accepts only the next
suite archive case, verifies its exact-commit protected manifest and current
machine, reserves raw evidence first, and publishes only root-owned mode-0444
`protected-host` rejection observations. Each of its twelve signed synthetic
carriers enters that real acquisition boundary through an isolated root-owned
production store. The fixture independently inventories and hashes the store
before and after rejection, requires an empty quarantine, and proves
`extracted: false`, `executed: false`, and authority `none`. The shared Host
installer binds both provenance and archive payload inventories into the same
exact-commit manifest and post-verifies both before success. Live installation
and root invocation on the disposable Mac are still required for physical
evidence. Existing quarantine generations are not grandfathered: the common
descriptor-relative verification path rereads exact artifact bytes, verifies
their signed digest, and applies the same bounded archive policy before either
`already_acquired` or `artifact_and_evidence_bindings_verified` can be emitted.
This closes upgrades over legacy quarantines that predate the archive control.

The Research qualification driver is source-complete. Its non-admitting
fixture projection core and protected Research execution wrapper are
implemented in
`shared/harness_lifecycle_qualification_fixture.py`. It binds each of the ten
acceptance qualification cases to one exact case in the complete ordered
thirty-case qualification plan, retains the complete plan and report, requires
the selected case to pass without semantic loss or side effects, and emits a
self-digested result with candidate authority `none`. The core accepts neither
a caller-selected fixture path nor caller-supplied observation faults. It pins
the repository fixture as a regular, single-link, owner-controlled bounded
file before execution.

That inner projection explicitly records `observer_scope:
synthetic-contract-only`, `physical_evidence_eligible: false`, and the blocker
`independent_research_observer_required`. The existing synthetic supervisor
constructs several denial facts to test evaluator semantics; those facts are
not process, network, filesystem, credential, or lifecycle telemetry.

The root-only Research wrapper runs that unchanged core in a transient
dynamic-user systemd unit with a private network, `AF_UNIX`-only address-family
policy, deny-all IP policy, strict protected filesystem, private home and tmp,
no-new-privileges, a two-task ceiling, and an explicit credential-environment
deny list. It independently reads back the complete unit policy, successful
main-process result, zero restarts, empty post-run cgroup, and Research boot
identity before it can label its outer result physically eligible. The inner
result must still say that it is ineligible; a caller cannot upgrade it by
editing a field. An exact-commit Research installer publishes the fixed seven
file dependency closure beneath a root-owned immutable release and campaign
state root, refuses active or unreconciled agent runs, and never admits a
generation.

The protected Host supervisor and fixed projector close the source path. The
supervisor accepts only the next qualification case, rebinds the enrolled Mac
and exact root-owned Host manifest, reserves raw evidence before remote
mutation, repeats the production-material and Keychain scan, proves the Host
fixture remained a non-executable unchanged payload, deploys only manifest
bytes through authenticated Research control, and binds the Research result to
explicit no-admission, no-activation, no-selector-change, and no-session-
migration facts. The projector requires the complete four-record raw set,
revalidates every digest and cross-record binding, and assigns the suite's
fixed protected-Research, protected-Host, and disposable-supervisor authorities
without caller-selected evidence fields. It supports only non-overwriting,
validated resume. Source completion still grants no physical availability:
the exact commit must be installed and run on the disposable Mac.

Control Center exposes only a verified read-only projection from the fixed
`~/Library/Application Support/SecureSandbox/harness-acceptance` campaign
root. It reports enrollment availability, immutable suite identity, completion
count, next case, the exact next procedure and procedure digest, and assembly
readiness with authority `none`. It cannot
enroll the Mac, execute a case, create or edit an observation, assemble an
export, issue a verdict, or admit a generation. An untrusted root, invalid
catalog, or invalid campaign status is displayed as rejected rather than
silently treated as incomplete.

Every evidence kind is suite-bound to exactly one outer collector; this mapping
is included in the suite digest. The observation projector derives that
collector and offers no command-line collector override. It requires the
primary artifact authority to match the fixed collector, binds both source and
subject digests to the primary artifact's exact bytes, requires an actual
nonempty bounded artifact, and
accepts only closed source-status sets. A passing observation cannot be made
from a rejected source record, or vice versa. The exact observation output
directory is operator-owned private mode 0700. A protected driver creates each
case/kind record once as root-owned mode 0444 with a directory fsync; ordinary
source invocation creates only owner-run mode 0600 output, which the production
status and assembly paths reject as physical evidence. Status validation binds
the directory to the operator UID separately from the root-owned observation
files, so neither ownership class is silently conflated with the other.

Every case also carries a self-digested physical operator protocol. The suite
digest therefore binds its driver class, required baseline, exact action,
human or supervisor interaction, egress posture, optional durable interruption
checkpoint, required postcondition, and reset boundary. Recovery cases name the
same fifteen durable checkpoints used by the implementation. `next` is
read-only and cannot skip ahead, mark a step complete, invoke a driver, or
manufacture evidence. A protocol change creates a new suite identity before a
campaign can enroll.

## Clean-machine bootstrap driver

`scripts/harness-lifecycle-acceptance-bootstrap.py` supplies the fixed,
read-only collector and projector for the first two physical cases:
`bootstrap-clean-install` and `bootstrap-no-production-material`. Installation,
enrollment, and authorization remain separate reviewed operator ceremonies;
the driver cannot perform or repair any of them. It accepts only the current
`next` bootstrap case, rebinds the current Mac and exact clean source checkout,
and reserves a private raw case directory before it reads protected state.

For clean-install evidence it verifies the root-owned Host release, reads the
protected Research control and generation status, and requires open admission,
no pending recovery, and exact agreement with the independently verified
boundary. For no-production-material evidence it revalidates the original
machine enrollment and repeats a metadata-only scan of the fixed provider
environment names, credential-path markers, and Agents Keychain service. It
does not read, export, or hash credential values. SecureSandbox's deliberately
installed synthetic acceptance state is not mislabeled as production material.

Raw filenames, evidence kinds, authorities, and supporting-artifact
relationships are suite-fixed. Projection revalidates the exact raw inventory,
copies canonical bytes into a private snapshot, and offers no collector,
authority, artifact, kind, outcome, install, or authorization override.
Publication is non-overwriting and crash-resumable only when every existing
observation still validates and binds the same primary and supporting raw
digests. A rejected collection leaves its reserved raw directory intact for
failure retention and cannot be silently reused.

## Disposable recovery fixture driver

`scripts/harness-lifecycle-acceptance-recovery.py` implements the recovery
protocol class without adding a checkpoint option to any production manager.
It derives the transition only from a suite-bound process-loss or power-loss
case and runs the production `GenerationStore` implementation against a fixed,
private `recovery-fixtures/<case-id>` directory beneath the campaign root. Its
candidate, evidence, authorization, and health material are synthetic and have
no production store, credential, network, selector, or admission authority.

At the exact durable callback, the worker fsyncs a campaign/case/checkpoint
record, emits it to its outer supervisor, sends itself `SIGSTOP`, and exits with
status 125 if it is ever resumed. The external supervisor must then either kill
the stopped worker for a process-loss case or hard-power only the Research VM
for a power-loss case. After restart, `recover` verifies the exact immutable
checkpoint record, invokes deterministic recovery when a journal exists, and
requires open admission, no pending recovery, and an independently verified
boundary. Pre-transaction stage/plan loss and post-journal committed loss are
reported explicitly rather than fabricated as journal recovery.

Source tests exercise all fifteen checkpoints and both process/power case
bindings. This fixture is not physical evidence until the Host supervisor
actually invokes it inside the disposable Research VM and records the external
kill or VM-power receipt on the dedicated Mac.

## Host recovery supervisor

`scripts/harness-lifecycle-acceptance-supervisor.py` implements the outer
process-loss and Research-VM power-loss boundary. It accepts only the current
`next` suite case, only when that case is a fixed recovery case, and recomputes
the enrolled hardware digest from the current Mac before it performs any
remote mutation. It also requires the repository's checked-out `HEAD` to equal
the campaign source commit and every tracked byte to match that commit under a
minimal Git environment with replacement objects disabled. The running Python
modules are loaded before that check; a later on-disk edit cannot change the
already loaded supervisor. It reserves a new private raw-evidence directory first. An
invalid, reused, missing, wrong-mode, symlinked, or differently owned evidence
root therefore rejects before deployment, worker interruption, or VM power.

The supervisor stages the worker, acceptance contract, production generation
store, archive-preflight dependency, and required support modules from the
campaign's exact Git commit—not from mutable working-tree bytes. The complete
dependency closure is also bound into the protected recovery-driver payload.
The authenticated Research control channel
runs `scripts/install-harness-lifecycle-acceptance-recovery.sh`, which installs
that source under a root-owned commit directory, binds an immutable campaign
copy to its UUID and source commit, and refuses an existing release or campaign
whose content, owner, type, or mode differs.

The worker checkpoint binds the campaign, current Research boot digest, PID,
Linux process start time, case, and durable transition. A separate root worker
operation rereads `/proc`, requires the same start time and a stopped state,
and only then sends `SIGKILL`. PID reuse, a resumed worker, a different boot,
or a caller-selected PID rejects. Cleanup after a partial supervisor failure
uses a separate bounded abort operation that can kill only that same stopped,
campaign-bound worker and never yields acceptance evidence.

For power-loss cases the VM name is a source constant:
`SecureSandbox-Research`. There is no VM, PID, checkpoint, executable, remote
path, or power-operation argument. The supervisor requires the exact
`HARD POWER ONLY THE DISPOSABLE RESEARCH VM` acknowledgement, shares the normal
Host lifecycle lock with `labctl start` and `labctl stop`, checks that Parallels
Desktop's GUI is closed immediately before both stop and start, and compares
Gateway, Research, and Target states before stop, after stop, after restart,
and after recovery. It also requires the Research boot digest to change while
Gateway and Target remain unchanged.

Every protected readback is schema-, campaign-, case-, checkpoint-, authority-,
and self-digest-validated. Successful execution creates raw
`fault-injection-receipt.json`, `recovery-receipt.json`, and
`boundary-readback.json` files; power cases additionally create
`cold-boot-readback.json`. These are immutable inputs to the separate
observation projector. The supervisor neither creates observations nor admits,
selects, activates, downloads, or authorizes a harness.

The raw artifact authorities are fixed:

- fault injection: `disposable-supervisor`;
- cold boot: `cold-boot-supervisor`;
- recovery: `protected-research`; and
- boundary: `privileged-control`.

An interrupted or rejected run leaves its case evidence directory reserved.
The operator must archive that failed attempt and restore the suite-declared
disposable baseline; the supervisor never overwrites or silently resumes raw
evidence.

## Recovery observation projection

`scripts/harness-lifecycle-acceptance-recovery-observe.py` is the fixed bridge
between one successful recovery-supervisor directory and the campaign's three
or four required observations. It accepts no collector, authority, artifact,
kind, outcome, checkpoint, PID, VM, or executable override. The suite fixes the
raw filenames, primary authorities, supporting-artifact relationships, and
observation names.

Before it creates any observation, the projector rebinds the current Mac to
the campaign, requires the same exact clean source checkout, requires the exact
current `next` recovery case, rejects any
missing or extra raw file, and independently revalidates the full fault,
stopped-worker, termination or Research-only power transition, cold-boot,
recovery, and generation-boundary records. The fault receipt now embeds the
complete self-digested worker checkpoint, rather than only its digest, so the
projection can independently verify the PID, process start time, Research boot,
campaign, source commit, case, and durable transition.

Validated raw records are canonicalized into a private snapshot before the
generic observation projector reads them. A same-user process therefore cannot
change a raw file between receipt validation and observation construction.
All missing observations are constructed and validated in a private staging
directory before any is published. Publication remains `O_EXCL|O_NOFOLLOW`.
If the Host stops between observation writes, a retry accepts only already
published observations whose full contract and primary source digest match
the same raw artifact, then publishes only the remaining fixed kinds. It never
overwrites or repairs a changed observation.

Receipts are emitted in immutable suite order. Each binds the ordered
observation digests and predecessor receipt. The final export embeds the exact
campaign, all observations, all receipts, final chain head, source commit,
machine digest, suite digest, completion time, `candidate_authority: none`, and
`production_material_used: false`. Any omission prevents assembly; any later
change breaks the export digest or chain.

## Research-only cold-boot readback driver

`scripts/harness-lifecycle-acceptance-cold-boot.py` supplies the four fixed
post-commit persistence cases. It accepts only the current suite case and exact
acknowledgement, verifies the enrolled Mac and root-owned exact-commit driver
manifest, acquires the shared lifecycle lock, requires the Parallels GUI to be
closed, and reserves the raw evidence directory before any power transition.
It has no VM-name input: the only stop/start target is the constant
`SecureSandbox-Research`.

The driver uses the already installed campaign-bound recovery worker only for
canonical Research boot-identity readback. It records the pre-boot identity,
hard-stops Research, verifies Gateway and Target did not change, restarts
Research, waits for protected control, and requires a different post-boot
identity and a final VM inventory equal to the initial inventory. It then
independently reads the protected generation status, boundary, active runtime
binding, catalog/selector digests, active policy binding, and Host protected
manifest. No admission, activation, selection, download, session, or policy
mutation is exposed.

Every raw record has a closed schema, campaign/case/procedure binding, bounded
observation time, self-digest, candidate authority `none`, and production
material `false`. Projection revalidates the exact raw inventory, boot
transition, VM-state invariants, runtime/policy relationship, fixed primary
authorities, and supporting-artifact relationships before non-overwriting,
crash-resumable publication. This source completion is not physical evidence;
the exact Host and Research releases and the committed synthetic generation
must exist on the disposable Mac.

## Independent evidence export driver

`scripts/harness-lifecycle-acceptance-export.py` supplies the final evidence
case and the only protected assembly path. It runs from the root-owned exact-
commit release, accepts an explicit operator UID, and proceeds only when the
two exporter observations are the sole missing records. Before it creates
them, it independently rereads every prior root-owned mode-0444 observation in
immutable suite order and binds the exact filename, observation digest, and
canonical file digest into a self-digested export-readback record.

The paired candidate-independence record binds the installed exporter payload
and manifest and states closed, validator-enforced facts: no candidate
statement was used, no candidate executable was invoked, no candidate network
was used, no provider credential was read, and no lifecycle mutation was
performed. Both observations use the fixed evidence-exporter authority. The
driver then assembles the complete v4 export with the shared validator,
immediately derives the non-admitting verdict, and writes both once as
operator-owned read-only files. The destination must be an empty private
operator directory on a different filesystem device from the disposable-Mac
observation store; same-volume export fails closed.

The export cannot cryptographically contain its own final digest in an
observation without a self-reference. Instead, the final external verdict
binds the completed export digest after both exporter observations exist.
Independent verification on a second machine remains a physical exit
criterion; the locally derived verdict is a consistency check, not that
independent act.

## Interactive fixture boundary

The authorization, runtime, and management drivers do not populate
the real production generation store with a synthetic candidate. The
production store deliberately accepts only a qualification record whose
`synthetic` field is false; changing that rule or falsely labeling an
acceptance artifact would invalidate the campaign rather than test it.

Their implementation therefore uses an acceptance-only interactive boundary.
The real signed Host authorization broker and native Touch ID UI authorize an
exact campaign plan, but the broker dispatches that plan only to a root-owned,
exact-commit acceptance consumer. That consumer validates the same plan,
transaction, generation, requesting-agent/session, expiry, replay, and
password-fallback fields as the production consumer while operating on an
isolated campaign store built from the production `GenerationStore` code. It
has no path to the production release, state, selector, session catalog, or
Research lifecycle control operations.

This preserves the properties the physical cases are intended to test:
approve, cancel, expiry, replay, changed-plan, wrong-generation, session
pinning/migration, rollback, retirement, reclamation, revocation, and
containment. It also preserves the stronger fact that a test campaign cannot
grant admission authority. The broker extension must be a separately named,
closed-schema acceptance operation; it must reject ordinary lifecycle
resources, arbitrary executable paths, caller-selected store roots, and any
request whose campaign source commit does not identify its installed protected
consumer. No password fallback or synthetic-to-production promotion exists.

The shared interactive core and protected authorization consumer now implement
the first complete enforcement layer of that boundary in
`shared/harness_lifecycle_acceptance_interactive.py`. Its closed five-minute
plan binds campaign, enrolled machine, exact source commit, suite case and
procedure, invoking operator UID, operation, generation, plan, and transaction.
It delegates Touch ID
receipt validation to the production generation-store authorization validator,
requires an exact byte-equivalent stored plan, consumes each authorization
digest once through a self-digested monotonic ledger, and returns only
`authorized-for-acceptance-only` with production-store access and lifecycle
mutation both false. The signed Host broker has a separately named Touch-ID-
only route to the exact campaign commit; it rejects a different local UID and
cannot accept a caller-selected executable or state root. The protected
consumer uses per-case root-owned state, an isolated empty instance of the
production `GenerationStore`, a journaled ledger/result transaction, and
deterministic recovery. It proves the isolated store remains empty before and
after every accepted or rejected consumption. The replay case consumes one
authorization exactly once and then rejects the protected second use without a
second prompt. An approval that crosses the plan expiry boundary now produces
a final failed broker receipt rather than leaving an `executing` receipt.
Tests cover exact approval, replay, changed plan, wrong generation, expiry,
password fallback, noninteractive cases, cross-UID use, crash recovery, and
forged production access. The protected prepare/finalize wrapper accepts only
the campaign's exact next case from the fixed operator campaign root, verifies
the installed manifest and enrolled machine, and captures the protected
Research generation status before and after the ceremony. Finalization binds
the exact Host release, broker plan/campaign/generation fields, terminal output
digests, isolated-store state, and unchanged Research selector. The fixed
projector revalidates that complete chain and publishes only the suite-assigned
Touch ID, privileged-control, and protected-Research observations in mode 0444
with non-overwriting resume. For every rejected selector case, the primary
protected-Research artifact is the exact authenticated Research generation
status response. The locally composed selector summary remains supporting
privileged-control evidence and is never relabeled as Research output. The Host
installer now includes and post-verifies the complete authorization closure.
The driver is source-complete but has no physical
authority until the exact commit is installed and exercised on the disposable
Mac.

The runtime and management implementation now also has a shared closed-scenario
core in `shared/harness_lifecycle_acceptance_scenarios.py`. It constructs two
deterministic campaign-only generations and synthetic session records, reuses
the production runtime-binding and Touch ID authorization validators, and
implements all four runtime and six management outcomes without creating a
production qualification, release, selector, session, or admission record.
Every result carries `candidate_authority: none`, preserves evidence after
reclamation, leaves rejected state byte-equivalent, and exposes neither a
production store path nor a caller-selected executable. The root-only protected
driver entrypoints, fixed evidence projector, broker routing, and installed
payload closures now complete both source classes. They remain physically
ineligible until the exact reviewed commit is installed and exercised on the
disposable Mac.

The shared core now has a Research-side protected executor and exact-release
installer. The installer refuses active or unreconciled runs, accepts only the
campaign-bound seven-file closure, publishes it without overwrite beneath the
exact source commit, and maintains a root-owned campaign-only `scenarios`
store. The executor accepts only the fixed runtime or management case catalog,
validates Touch ID plans with the production authorization validator, publishes
immutable before/after/result records with interrupted-link cleanup recovery,
and resumes only an exact previously validated result. It has no production
generation-store path, release input, session catalog, provider credential, or
network client. The fixed Host supervisor scans for production material before
deployment, installs only the exact campaign closure through authenticated
control, binds the campaign's exact next case and immutable plan, and retains a
failed-closed record if deployment fails. Finalization binds successful Touch
ID broker receipts to the exact Research result and publishes separate Host
and privileged-control projections. The projector keeps authenticated Research
results primary for Research-assigned evidence, uses Host-authored session
readbacks only for Host-assigned evidence, and never relabels a Host composite
as Research authority. Response-loss retries preserve the first durable
timestamp and accept only byte-equivalent existing records.

## Physical campaign boundary

The current development Mac must not be used to manufacture the destructive
evidence. The dedicated disposable Mac must run every case with synthetic
sessions and credentials. Touch ID approve/cancel cases require the operator
at the keyboard. Research-VM hard-power cases must keep Parallels Desktop's GUI
closed and operate only on the disposable campaign. They do not authorize an
abrupt shutdown of the macOS host; ordinary host restart safety remains in
force.

No production data, provider credential, active research session, vendor
admission, or selector change is in scope. A source test pass proves the
campaign machinery and deterministic recovery model, not the still-pending
physical observations.

## Exit criteria

This DDD is complete only when the dedicated Mac has:

1. produced a valid clean enrollment and exact-commit campaign;
2. run all 91 cases and retained all 198 fixed-collector observations;
3. completed every process-loss and Research-VM power-loss transition with
   deterministic recovery or an unambiguous committed readback;
4. passed cold-boot Host/Research/catalog/executable/policy readback;
5. assembled and independently verified the complete non-admitting export;
6. archived that export outside the candidate and disposable machine; and
7. been erased or quarantined after evidence export.

Until then the next First Exact Claude Generation Admission DDD remains
blocked by design.
