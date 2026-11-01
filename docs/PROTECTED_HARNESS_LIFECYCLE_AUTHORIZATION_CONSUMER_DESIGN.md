# Protected Harness Lifecycle Authorization Consumer DDD

Status: source implementation complete; live Host/Research deployment and first
vendor admission remain separately authorized

## Decision

SecureSandbox now has the fixed Host/Research consumer for the protected
harness generation store. It supports exact activation, explicit rollback,
zero-reference retirement, monotonic revocation, and deterministic recovery.
Every ordinary mutation is created as a five-minute Research plan, reviewed in
Control Center or the CLI, and consumed only after native Touch ID. Password
fallback is rejected by the UI path, Host broker, authorization receipt, and
Research store.

The implementation does not manufacture provenance or qualification. Real
activation remains unavailable unless one Host admission-staging generation contains
the exact artifact, canonical manifest, provenance-verification receipt,
non-synthetic disposable-supervisor qualification receipt, and reviewed
adapter projection required by the protected store. The existing synthetic
fixture still has `authority: none` and cannot satisfy this gate.

## Threat model and trust boundaries

Protected assets are the Research release inventory, catalog, selector,
admission/revocation floor, recovery journal, workflow chain, session
references, and Host authorization receipts. Relevant adversaries include a
compromised harness or model session, a malicious candidate artifact, a
mutable repository process, a stale or tampered GUI plan, a local process
racing session state, and transport loss between Host and Research.

Trust crosses four narrow boundaries:

1. The unprivileged Host planner may submit only one canonical framed candidate
   or exact lifecycle arguments through the role-bound protected control
   client. It has no selector primitive.
2. Research owns root-only staging, plan creation, source remeasurement,
   active-run readback, immutable publication, health probing, transaction
   application, and recovery.
3. The immutable Host release owns request validation, native Touch ID
   consumption, authorization-receipt derivation, a second Host session-catalog
   read, and post-mutation status/boundary readback.
4. Control Center displays typed summaries and invokes the same planner and
   immutable broker. It creates no authorization and has no direct Research
   mutation API.

The protected control allowlist exposes only `stage-activate`,
`prepare-rollback`, `plan-management`, `apply`, `recovery-status`, and
`recover`. Arguments are exact UUID, SHA-256, bounded integer, or fixed enum
values. The two stdin operations remain content-bound and bounded by the
existing 256 MiB control-plane limit; the DDD does not widen that global
limit. Consequently, the current activation carrier accepts candidates below
approximately 254 MiB even though the underlying store supports larger
artifacts.

## Exact planning and authorization

Activation framing fixes the ordered inventory to `artifact`, `manifest.json`,
`verification.json`, `qualification.json`, and `adapter.json`. The header binds
every file name, size, digest, stage UUID, and content-derived generation ID.
Research writes new owner-only files with `O_EXCL|O_NOFOLLOW`, fsyncs them,
rejects trailing bytes, and deletes only a stage created by that invocation.
A colliding pre-existing directory is never removed.

Rollback copies and remeasures an already immutable retained Research release.
Retirement and revocation bind a reason digest plus a fresh reference receipt.
Planning reads the Host v4 session catalog and Research active run. Application
rereads both independently after Touch ID. A changed count, malformed catalog,
different active run, protected-state digest, plan, stage, request, expiry, or
authorization rejects before mutation.

The immutable Host broker derives the store authorization receipt itself; the
requestor cannot supply it. It binds the exact plan and transaction, operation,
Touch ID method, `password_fallback: false`, authorization window, and SHA-256
identities of the declared agent and conversation. The protected Host manager
accepts only that receipt and exact wrapper, then sends a canonical apply
request to Research. The Research store revalidates the entire receipt and
plan again.

## Health, recovery, and postconditions

After immutable publication and selector readback, Research runs only the
published executable's fixed `--version` probe through a transient systemd
service. The service has a dynamic user, private network and temporary
directory, protected system/home/devices/kernel/control-group surfaces, no new
privileges, address denial, resource and time caps, a minimal environment, and
no production credentials. Candidate-selected commands, environment, network,
or health criteria are not accepted.

Recovery first returns the one pending journal digest. The Touch ID request
binds that digest. The Host manager rereads it immediately before invoking
Research recovery. Recovery cannot choose a generation or infer a preferred
selector; the protected store restores or completes only the transaction
encoded in the journal.

Every successful Host operation independently reads protected generation
status and verifies the complete boundary after the Research result. Control
Center reports success only from that composite result. Lost or ambiguous
responses do not authorize retry by inference; a new status read and, where
necessary, exact recovery ceremony is required.

## Deployment and rollback

`install-harness-lifecycle-consumer.sh` transactionally installs the Research
manager, read-only inspector, generation store, workflow engine, runtime
binding, and rollback helper. It refuses active or unreconciled runs and a live
Claude process, compiles every Python payload, backs up each prior file, and
initializes only canonical protected state. Rollback restores exact code
backups and refuses to remove lifecycle code underneath a published
generation. It never deletes release or state data.

The Host manager is an immutable host-controller payload. Historical release
schemas remain explicitly enumerated; the stable launcher accepts the exact
pre-consumer release only as a predecessor. The broker's protected-release
manifest requires the new payload before any new harness operation can execute.

## Control Center behavior

The Harnesses settings surface enables actions only from verified capability
state:

- activation requires a complete real-evidence candidate directory;
- rollback requires a verified predecessor and open admission;
- retirement and revocation require an eligible retained generation;
- recovery requires a pending protected journal; and
- every action first shows its operation, generation, digest, expiry, and
  available active/resumable reference counts.

The final button explicitly says “Authorize Exact Plan with Touch ID.” There is
no automatic mutation path. Scheduled work remains metadata-check and
notification only.

## Residual risk and next gate

This checkpoint has not deployed the new Host or Research payloads live, has
not admitted vendor bytes, and has not changed the Research selector. The
fixed health probe is a bounded startup/readback check, not a substitute for
the full disposable qualification matrix. The next DDD is the Disposable-Mac
Harness Lifecycle Acceptance DDD, which must exercise installation, Touch ID
approve/cancel/expiry/replay, process and power loss, hostile archives,
signature/chain failures, cold boot, rollback, revocation, legacy sessions,
and independent evidence export before production admission.

