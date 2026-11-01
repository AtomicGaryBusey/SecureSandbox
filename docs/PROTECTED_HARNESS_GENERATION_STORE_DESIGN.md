# Protected Harness Generation Store and Transactional Activation DDD

Status: source implementation complete; no vendor generation admitted or live
Research selector activated

## Decision

SecureSandbox now has a component implementation for root-owned immutable
harness generations, a canonical catalog and selector, a monotonic admission
floor, exact Touch ID authorization receipts, run-admission fencing,
transactional selection, independent readback, predecessor restoration,
retention, retirement, revocation, and crash recovery.

No vendor generation is admitted by this checkpoint. The release policy is
still unprovisioned, no real non-synthetic disposable-supervisor qualification
receipt exists, and the direct Claude bootstrap remains the live legacy path.
The read-only CLI exposes only `status` and `verify-boundary`. It cannot stage,
activate, roll back, retire, revoke, reclaim, download, or install anything.

## Authority boundaries

The generation store consumes evidence; it does not manufacture it. A candidate
must bind all of the following to one exact generation:

- the canonical vendor release manifest and inert artifact from Host
  quarantine;
- the foundation verifier's exact artifact/evidence receipt;
- a non-synthetic disposable-supervisor qualification receipt;
- the reviewed adapter projection and policy generation; and
- a five-minute activation plan plus request-bound Touch ID authorization.

The completed conformance DDD's built-in
`fixture_qualified_not_admitted` report remains `authority: none`. Its
synthetic fixture report is categorically rejected as activation evidence.
Qualification evidence must instead declare `synthetic: false`, bind the full
observer result set, and carry only `qualification-evidence-only` authority.
That evidence still cannot select a generation by itself.

The model, harness, project, session, provider, release carrier, GUI, and
read-only CLI have no mutation API. The protected authorization consumer is the
only intended caller of the mutation methods. Password fallback is explicitly
rejected for harness activation and management.

## Protected state

The implementation fixes these production paths:

- releases: `/usr/local/libexec/secure-sandbox-harnesses/releases/<generation-id>/`;
- state: `/var/lib/secure-sandbox/harnesses/`;
- catalog: `catalog.json`;
- selector: `selector.json`;
- monotonic floor: `admission-floor.json`;
- fence: `activation-fence.json`;
- component recovery journals: `journals/`; and
- append-only generic workflow state: `workflow/`.

The store and state directories reject symlinks, incorrect owner, mode drift,
links, noncanonical JSON, unknown fields, duplicate identities, excess entries,
and inconsistent catalog/selector/floor state. Published release directories
are mode `0555`; the executable is `0555`, evidence is `0444`, and every file
is named, sized, mode-bound, and hashed by a canonical inventory. Publication
uses a fresh private directory, file and directory fsync, a final mode change,
an atomic rename under a global lock, and full readback.

There is intentionally no deletion API. Retired, revoked, rejected, active,
and predecessor bytes remain retained. A future separately authorized
reclamation DDD may delete only after proving zero references and a durable
evidence archive.

## Activation plan and ceremony

An activation or explicit rollback plan binds:

- plan, transaction, and one-time transition action IDs;
- operation and five-minute expiry;
- exact generation, harness, vendor, version, platform, release sequence,
  artifact size/digest, manifest, policy, adapter, and suite identities;
- verification, qualification, and adapter-projection receipts;
- the complete current catalog, selector, and floor digests; and
- the current generation and selector epoch.

The authorization receipt repeats the plan ID/digest, transaction, operation,
requesting conversation hashes, authorization and expiry times, and
`method: touch-id`. `password_fallback` must be false. Changed state, changed
bytes, replay, expiry, a wrong operation, or a wrong conversation-bound receipt
fails before publication or selector mutation.

Rollback is not a floor rollback. It may target only an already retained,
non-revoked generation; selecting it leaves `highest_release_sequence` at its
existing maximum.

## Transaction ordering

Activation proceeds under the store lock:

1. prove Research is idle and no recovery is pending;
2. revalidate plan, authorization, source evidence, and current protected state;
3. publish the exact admission fence consumed by Research run admission;
4. create and authorize the append-only `harness-activation` workflow;
5. publish or remeasure the immutable release;
6. make the predecessor retained and atomically write catalog, monotonic floor,
   and future-session selector;
7. independently read back every protected file and release inventory;
8. require a fixed synthetic, credential-free health receipt from the
   production adapter path; and
9. record `activated`, `verified`, and `committed`, remove the fence, and emit a
   bounded receipt.

The health interface accepts no candidate-selected command or executable. Its
receipt must prove the exact plan/generation/artifact/adapter binding, synthetic
input, absence of production credentials, no network attempt, and success.

If publication, selector readback, or health fails while the generic workflow
is still preactivation, the component journal restores the exact old catalog,
selector, and floor, records the published candidate as rejected when present,
reads the predecessor back, records `rolled_back`, and only then removes the
fence. This is restoration inside one already-authorized transaction, not a new
automatic rollback choice.

## Crash recovery

The component journal contains the content-bound plan and exact old protected
state. A process loss leaves admission fenced. Recovery accepts exactly one
journal and never searches for the newest, closest, or highest generation.

- Before generic `activated`, recovery restores the exact old state, retains a
  published interrupted candidate as rejected, records `rolled_back`, and
  removes the exact fence. If process loss occurred before workflow creation or
  publication rename, recovery removes only exact generation-bound,
  owner-validated publication temporaries; unknown debris remains fail-closed.
- At or after generic `activated`, recovery requires the selected generation,
  full boundary readback, and retained health digest, then completes only the
  missing `verified` and `committed` transitions.
- Missing, forked, tampered, or ambiguous state keeps admission closed.

Exact repeated action IDs make lost responses idempotent in the generic
transaction engine.

## Retirement and revocation

Retirement and revocation are separate five-minute Touch ID transactions. Both
bind an exact reason digest and fresh independent session-reference readback.
Retirement rejects the active generation and any generation with an active run
or resumable session. It changes only catalog eligibility and never deletes
bytes or evidence.

Revocation is monotonic. It may mark a generation even when references remain,
but a revoked active generation is immediately removed from the future-session
selector. The revocation ID remains in the monotonic floor and cannot become a
rollback target. Remote metadata alone cannot invoke this operation.

## Admission fence

`research/run_lease_watchdog.py` now treats the exact harness activation fence
like the existing model-profile fence: a new Research run cannot arm while it
exists. The store independently refuses mutation unless its caller proves the
runtime is idle. The next DDD will add immutable harness-generation fields to
sessions and leases; this DDD does not silently infer those bindings.

## Explicit non-goals and next dependencies

This checkpoint does not:

- configure a vendor key, release channel, carrier, or candidate;
- accept the tracked malicious fixture as a real qualification;
- change `/usr/local/bin/claude` or launch a new live Research harness;
- migrate legacy sessions or alter session/run-lease schemas;
- add a Control Center Harnesses surface;
- add automatic checking, downloading, installation, activation, rollback,
  retirement, or revocation; or
- reclaim retained release bytes.

The **Harness-Bound Sessions, Leases, and Runtime Migration** DDD is now
source-complete. The next DDD is **Control Center Harness Lifecycle GUI**,
which will expose these protected operations through typed review surfaces; it
will not create new authority.

## Acceptance evidence

`shared/test_harness_generation_store.py` covers exact publication and modes,
two-generation activation, explicit rollback with a nondecreasing floor,
health failure, predecessor restoration, simulated process loss and recovery,
synthetic-fixture rejection, password-fallback rejection, source/state drift,
active-runtime refusal, immutable-file tampering, zero-reference retirement,
retention, active revocation, management crash recovery, loss before workflow
creation, and loss during immutable publication.

`research/test_run_lease_watchdog.py` proves that the activation fence blocks a
new run. `scripts/test_harness_generation_store_ddd.py` protects the source and
authority boundary, including the read-only CLI command set.

Production acceptance still requires a separately reviewed deployment, a real
non-synthetic disposable supervisor, a provenance-verified vendor candidate,
the disposable-Mac destructive/crash matrix, and an explicit operator decision
to admit one exact generation.
