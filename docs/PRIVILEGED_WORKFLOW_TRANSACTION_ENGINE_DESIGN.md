# Privileged Workflow Transaction Engine

## Status

Implementation and acceptance contract. Deployment-specific identifiers and
live evidence remain in ignored local records.

## Decision

SecureSandbox uses one small transaction-state library for the durable control
logic shared by privileged workflows. The engine records authorization
decisions and verified postconditions; it never performs a privileged side
effect and never replaces a component's authorization policy, verifier, or
recovery procedure.

The fixed lifecycle is `prepared`, `authorized`, `activated`, `verified`, and
`committed`. Before activation a transaction may instead become `rolled_back`
or `expired`. Activation is the irreversible boundary: the generic engine does
not permit rollback, expiry, or replacement afterward. A component that needs
a more detailed safe ordering keeps those subphases in its own implementation
and records only the common control milestones here.

## Append-only event chain

Each transaction has an append-only directory of canonical JSON events. Every
event binds the workflow name, UUIDv4 transaction and action identifiers,
sequence number, prior-event digest, exact component identities, transaction
expiry, phase-specific authorization or evidence digest, and its own SHA-256.
Event bytes are written and fsynced under a distinct unpublished name, then
published through a same-directory no-overwrite hard link. The event directory
is fsynced before the unpublished name is removed and before the replaceable
head pointer advances. Strictly named abandoned unpublished files are removed
only while holding the workflow lock.

The head is only an index. Recovery reconstructs truth from the complete event
chain. A missing or lagging head is repaired from a unique valid successor. A
fork, gap, substituted event, changed identity set, invalid transition, or head
that claims an event outside the chain fails closed. State counts, JSON sizes,
identity counts, names, values, lifetimes, and event counts are bounded.

## Authorization boundary

The `authorized` event requires a digest of a component-produced authorization
artifact and a bounded expiry. The engine does not mint or interpret that
artifact. `activated` is accepted only while the immediately preceding
authorization remains live, and it requires a digest of the caller's verified
activation postcondition. Thus a caller cannot use the state engine itself as
authority and cannot silently turn an expired approval into activation.

## Irreversible activation

After `activated`, the only valid path is `verified` then `committed`. Both
transitions require component-produced evidence digests. A workflow whose
activation changes a monotonic floor, key generation, trust root, admission
state, or protected selector must supply the exact observed postcondition. The
engine deliberately offers no generic abandon or rewind operation after this
point.

## Lost-response recovery

Every action has a UUIDv4 idempotency key. Repeating the exact action returns
its recorded result without appending another event. Reusing the key with a
different phase, digest, or expiry is rejected. If a process is lost after an
event is durable but before its head update or response, the next locked open
repairs the head and the exact retry returns the durable event.

The engine cannot decide whether an external side effect happened before its
evidence was recorded. Callers must use an exact idempotent operation and
revalidate its postcondition before submitting the same action. This keeps
side-effect ownership and recovery semantics with the component that can
actually observe them.

## Mixed-state rejection

Creation binds a nonempty, bounded map of component identities such as Host,
Gateway, Research, Target, release, generation, manifest, or policy digests.
Every event repeats that exact map, and every inspect or advance operation may
require the caller's freshly observed map. Any difference rejects the
operation. The engine never selects a familiar pathname or guesses which
component is authoritative when identities disagree.

## Expiry and rollback

Transaction expiry is fixed at creation and capped at seven days. An
authorization expiry must be earlier. A transaction may expire only after its
deadline and only while prepared or authorized. Rollback requires an evidence
digest and is permitted only in those same preactivation phases. Both are
terminal append-only events, not deletion of history.

## Trust and storage

Each role stores engine state in an owner-only directory with an owner-only
lock, transaction directories, event directories, and records. Directories,
regular files, ownership, modes, link counts, canonical encoding, hashes, and
read stability are checked before use. Symlinks and unexpected entries are
rejected. The installed library itself is root-owned, included in the guest
policy measurement, and pinned by complete boundary verification.

The engine's output is content-free metadata. Component identities and
authorization/evidence fields are opaque identifiers or digests; prompts,
source, credentials, execution output, private keys, and user data do not
belong in transaction state.

## Acceptance gates

1. Unit tests cover the complete forward lifecycle, preactivation rollback and
   expiry, expired authorization, irreversible activation, exact idempotency,
   identity mismatch, tampering, untrusted storage, and reuse by distinct
   workflow families.
2. Fault injection interrupts after an event fsync but before the head update;
   exact retry repairs the head without duplicating the event.
3. Gateway, Research, and Target run isolated root-owned live transactions and
   prove commit, lost-response recovery, rollback, and expiry.
4. Guest policy hashes and the complete boundary verifier pin the exact engine
   bytes on all three roles.
5. The exact public-release candidate passes the repository-wide publication
   gate before either remote is advanced.

The reviewed deployment entry point is
`scripts/deploy-privileged-workflow-transaction-engine-ddd.sh`.
