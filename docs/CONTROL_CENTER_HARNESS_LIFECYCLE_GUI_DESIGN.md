# Control Center Harness Lifecycle GUI DDD

Status: source-complete; no production release policy configured; no vendor
artifact downloaded; no harness generation admitted or activated.

## Decision

Control Center has a dedicated **Harnesses** settings surface. It projects the
existing Host quarantine, signed release metadata, synthetic containment
self-test, and protected Research generation inspector through typed,
versioned models. It creates no lifecycle authority of its own.

The surface deliberately distinguishes four fact classes:

1. signed vendor/project metadata is an authenticated claim only;
2. Host quarantine is inert storage only;
3. the built-in malicious fixture is a diagnostic with `authority: none`; and
4. the protected Research catalog is the only runtime selector authority.

No success label collapses these classes into “trusted.”

## Manual flow

`Check for Releases` fetches only bounded signed metadata, verifies the
threshold signatures and monotonic floor, and stores a receipt. The GUI reads
the candidate catalog only through a second verification of the retained
envelope, policy, and exact floor binding. It shows vendor, version, platform,
release sequence, generation and artifact digests, adapter compatibility, and
every declared evidence digest before acquisition is offered.

`Download to Quarantine` requires an explicit confirmation naming the exact
candidate. It downloads only that generation into the inert Host quarantine.
`Verify Bytes and Evidence` is a separate confirmed operation and ends with
`not_admitted_not_executable`. Neither operation can stage Research bytes,
change a selector, start a harness, or create a session.

`Run Synthetic Containment Self-Test` is also confirmed. Its bridge accepts
only the fixed `qualify-self-test` command, which invokes the tracked fixture
with no candidate path or selector. The GUI repeats that the result cannot
qualify vendor bytes.

## Automatic checks

`Automatically check signed harness metadata` is off by default. When enabled,
at most one check per day fetches the same bounded metadata as the manual
check. A notification may report a newly verified metadata sequence. The
scheduled path has no artifact, qualification, staging, installation,
activation, rollback, retirement, or revocation capability.

There is no automatic-download or automatic-install setting, hidden default,
background task, or authority mapping.

## Protected actions and the discovered boundary

The protected generation store already implements exact five-minute plans,
Touch ID-only authorization validation, transactional activation/rollback,
retirement, revocation, recovery, and readback. Its installed public CLI is
intentionally inspection-only. During this DDD, review confirmed that no
protected Host authorization consumer yet transports candidate evidence,
obtains the native receipt, and invokes those mutation primitives on Research.

Control Center therefore shows `Activate with Touch ID`, `Roll Back with Touch
ID`, `Retire`, and `Revoke` as visibly disabled capabilities with the missing
prerequisite. It does not fake a Touch ID ceremony, invoke a root primitive
directly, or reinterpret an ordinary confirmation as authorization. The typed
status contract fixes `requires_touch_id: true`, `password_fallback: false`,
and all mutation capability flags to false.

Implementing that consumer changes the protected Host and Research release
boundary and became the discrete **Protected Harness Lifecycle Authorization
Consumer DDD**. It must land before disposable-Mac lifecycle acceptance. This
decomposition is fail-closed: absence of the consumer prevents mutation rather
than weakening the ceremony.

## Bridge and validation

`control-center-api.py` invokes fixed `labctl harness` subcommands without a
shell and validates bounded schemas before returning a Control Center envelope.
Variable generation IDs must be lowercase SHA-256 values. Receipts must bind
the requested action and generation. The release catalog is independently
signature- and floor-verified by `HarnessStore.releases()` before projection.

Protected status and boundary verification are read-only allowlisted Research
operations. An older deployed controller that lacks them is reported as
`protected_generation_consumer_not_deployed`; it is not treated as an empty or
healthy catalog.

## Confirmation and error policy

Acquisition, byte/evidence verification, and the synthetic self-test use
native confirmation alerts. Security or schema rejection is persistent and
red until another explicit operation or refresh. There is no bypass action.
Candidate evidence review is read-only and digest-bearing.

## Non-goals

This DDD does not:

- configure a release policy or remote;
- download a real vendor artifact;
- qualify vendor bytes;
- stage or publish Research executable bytes;
- implement the missing protected mutation consumer;
- activate, roll back, retire, revoke, or recover a generation;
- migrate a legacy session; or
- change the active harness selector.

## Acceptance

The Swift package builds with the Harnesses settings tab, typed models, client,
store, confirmation flows, review sheet, and metadata-only notification path.
Python tests cover zero authority, floor-bound release projection, fail-closed
consumer absence, synthetic-fixture authority, and existing lifecycle crypto
and quarantine behavior. The evidence matrix records the exact boundaries.

