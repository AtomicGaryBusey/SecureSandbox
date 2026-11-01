# Disposable-Mac Harness Lifecycle Acceptance DDD

Status: campaign contract, bootstrap/recovery drivers, provenance fixture and
protected provenance installer, archive preflight core, and crash-boundary
hardening are implemented. Seven driver classes still lack source entrypoints,
and none of the ten drivers is considered physically available until an exact
commit is installed under a protected self-digested manifest.
Physical disposable-Mac execution remains pending. No live acceptance verdict exists yet.

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
1Password.

This preflight is a lower bound, not a forensic proof that a reused Mac is
clean. The physical campaign therefore requires a factory-reset or freshly
erased dedicated Mac, a new local test account, synthetic credentials only,
and no sign-in to the operator's production 1Password, provider, cloud, or
research accounts. Any uncertainty aborts the campaign.

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

The fixed readiness inventory currently reports zero physically available
drivers on a source checkout. Bootstrap, provenance, and Research recovery are
source-complete, but checkout ownership or filenames are never protected-Host
authority. Availability additionally requires the campaign source commit in a
closed root-owned release directory, a canonical mode-0444 manifest whose
self-digest binds the suite and exact payload inventory, and byte-for-byte
payload verification. The other seven driver classes remain source-incomplete.
This is a release gate, not a bypass flag: there is no command-line option to
initialize an incomplete or unprotected campaign.

The Host provenance fixture core and its collision-closed root installer are
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
root-owned paths, immutable payload modes, and a self-digested manifest. It
refuses collisions. Installed execution disables Python bytecode writes before
any protected local import, preserving the closed manifest inventory. Until
that installation and its root invocation occur on the disposable Mac,
readiness remains unavailable; owner-run source tests cannot become physical
protected-Host evidence.

The archive preflight core is also source-complete but non-admitting and does
not yet satisfy the `host-archive-fixture` readiness entry. It parses a closed,
bounded ustar subset without extracting or executing any member, validates the
whole header/data/terminator framing, and rejects absolute or traversing paths,
links and special entries, sparse members, duplicate/case-fold/Unicode path
collisions, expansion limits, alternate streams, and trailing data. Its twelve
fixed synthetic cases prove identical before/after protected-state digests and
authority `none`. A protected Host wrapper, installed identity, and observation
projection remain required before these source checks can become physical
archive-rejection evidence.

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
store, and required support modules from the campaign's exact Git commit—not
from mutable working-tree bytes. The authenticated Research control channel
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
