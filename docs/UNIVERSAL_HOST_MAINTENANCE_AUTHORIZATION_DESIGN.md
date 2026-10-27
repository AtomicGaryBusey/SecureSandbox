# Universal Host Maintenance Authorization

## Decision

All ordinary SecureSandbox host-maintenance mutations use the protected,
operator-visible authorization broker. The remaining typed operations are:

- publish the pinned Canonical installer;
- publish the byte-for-byte reviewed autoinstall derivative;
- repair protected-store traversal modes after verifying the canonical image;
- create the exact three-VM SecureSandbox set; and
- reprovision that set while retaining the originals in ignored quarantine.

Read-only verification, installer construction in the user's workspace, and VM
dry-run planning remain unprivileged. No project workflow invokes a generic
root shell or accepts an arbitrary command.

## Installer boundary

The protected installer verifier authenticates the Canonical signature,
archive-key fingerprint, pinned canonical digest, and reviewed derivative
digest. Publication is the only root operation. The broker constructs a fixed
verifier argv from an allowlisted operation and a canonical release directory
beneath the invoking user's real home. The request binds the repository,
release directory, exact expected digest, declared agent/session, purpose,
nonce, expiry, and request digest.

Already-published images are read and rehashed without privilege. Root
ownership, `0444` image mode, non-writable root-owned directory ancestry, and
the store's traversal-only `0711` modes establish the trust boundary; caller
UID zero is neither necessary nor sufficient for a read.

## Parallels boundary

The `vm_maintenance` coordinator, role-bound seed verifier, and all three
verified seed images are immutable host-controller payloads. Mutable seed build
outputs are never attached to a VM. An unprivileged dry run derives a canonical plan that
binds:

- the canonical repository and VM home paths;
- the exact VM names and current stopped/absent state;
- the protected installer path and digest;
- all three verified seed-image digests; and
- the root-owned, non-writable `prlctl` path and digest.

The broker displays those bindings and passes the operation, invoking UID,
repository, expected plan digest, and every displayed component digest to the
coordinator. The coordinator independently requires all of them to equal the
recomputed plan. Execution begins as
root solely so the immutable coordinator can prove it came through the broker.
Before it verifies the final plan or invokes Parallels, it initializes the
operator's supplementary groups, changes GID and UID, clears the environment,
and proves that UID zero cannot be regained. `prlctl` therefore never runs as
root. A direct unprivileged invocation of an apply operation fails with
`root_broker_required`.

The coordinator recomputes the entire plan after the privilege drop and
immediately before mutation. Installer, immutable seed, Parallels binary,
repository, VM identity, or home-path drift changes the plan or rejects
outright. Free space is a fail-closed threshold check: crossing below 30 GiB
rejects; fluctuations above the threshold do not change the plan digest.
Creation verifies effective optical media, network topology, removed devices,
and disabled device-sharing settings before success. Partial creation deletes
only VMs whose complete UUID, canonical home, and bundle device/inode identity
was durably recorded as created by that invocation.

Reprovisioning binds each original VM's UUID, canonical home, and bundle
device/inode in addition to its name and stopped state. It requires at least 30
GiB of recoverable free space and uses an automatically released file lock.
Before mutation it atomically writes and fsyncs a typed transaction journal.
Every unregister, quarantine move, and replacement identity is journaled. An
ordinary exception recovers immediately; process death or host restart causes
the next reprovision plan to become a recovery plan. Recovery removes only
replacement UUIDs whose home and bundle identity still match, restores only
the recorded original bundles, verifies re-registration, and leaves the journal
intact on any unknown name/UUID collision. Rollback never deletes a same-named
VM it did not create.

## Receipts and concurrency

Installer and VM apply requests use the same UUIDv4 nonce, three-minute request
life, per-user foreground-ceremony lock, root-owned exclusive replay receipt,
and content-minimized completion record as other broker operations. VM execution
has a one-hour bound because virtual-disk creation can be slow; dialog and
request expiry remain short. Receipts contain hashes of output, not output or
plan content.

## Migration exception

The first thirteen-payload release cannot be installed by the preceding immutable
eight-payload release manager, and the old stable launcher cannot validate the
new manifest shape. `bootstrap-maintenance-schema` is therefore a one-time
schema migration analogous to the original authorization bootstrap. It shows
the declared agent/session, purpose, aggregate release identity, manager and
broker digests, and installed/replacement launcher digests before one
terminal-bound administrator request. An isolated fixed loader accepts only the
user-owned manager file whose displayed SHA-256 matches, and the manager accepts
only the exact old payload set and exact bound replacement release. It refuses
after migration. This exceptional bootstrap does not use the ordinary broker
receipt because the old broker cannot validate the new schema; the operator's
terminal transcript is the migration evidence. All subsequent maintenance
mutations use ordinary root-owned receipts.

This exception is narrowly about extending the immutable release schema. It
does not authorize installer publication or VM mutation.

## Scope and honesty

SecureSandbox controls its official maintenance workflows, not the trusted Mac
owner. The owner can still use Parallels Desktop or `prlctl` independently.
Agent labels remain operator-declared rather than OS-attested model identities.
Guest-side `sudo` behind the separate forced-command control plane and the two
documented first-install schema bootstraps are not Mac host-maintenance prompts
and are not represented as ordinary broker operations.

## Acceptance

Acceptance requires negative tests for extra parameters, path escape, digest
drift, direct coordinator execution, reversible privilege drop, replay, prompt
concurrency, partial creation, unowned-name deletion, and quarantine rollback.
It also requires post-create containment verification, a full regression suite,
public-material scanning, independent source review, one live attributed
maintenance ceremony, and inspection of the resulting root-owned receipt.
