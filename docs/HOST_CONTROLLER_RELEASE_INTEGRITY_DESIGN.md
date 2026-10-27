# Host Controller Release Integrity

## Decision

The long-lived `labctl claude` path is a versioned host control plane. It must
not execute from the mutable repository after dispatch.

`scripts/labctl` performs only an immediate `exec` for the `claude` command.
The stable entry point is `/usr/local/bin/secure-sandbox-claude`, a root-owned
Python launcher. The launcher validates a release manifest, creates a live-run
marker while holding the deployment coordination lock, and executes exactly
one immutable release at:

```text
/usr/local/libexec/secure-sandbox-host/releases/<release-id>/
```

Each current release contains the Claude run controller, the unprivileged
control-protocol client, its SSH configuration, the pinned `gpgv` executable,
the Ubuntu installer verifier, the read-mostly PKI generation-anchor manager,
the host release manager, and the operator-authorization broker. The controller
release does not contain a 1Password bridge or guest
administrative credentials.
Short-lived production operator workflows invoke the same root-owned active
`control_client` and `ssh_config` payloads directly. Their mutable repository
copies are only release-build and expected-byte inputs; they are never the
executed production client or SSH configuration.
The release ID is a SHA-256 digest over the named payload hashes. Installed
payloads and manifests are root-owned and not group- or world-writable.
The stable launcher is installed once; a byte change is rejected as a launcher
migration rather than silently mixed into an ordinary controller deployment.
An explicit migration requires the exact installed launcher hash, preserves
those old bytes in a content-addressed root-owned backup, and atomically
replaces and verifies the launcher while holding the same coordination lock.

## Security properties

- The stable launcher resolves `current` once, validates every payload hash,
  and passes the resolved controller path to `execve`. It never executes
  through the mutable `current` symlink.
- A running Bash controller is never overwritten or removed. Its EXIT cleanup
  therefore reads the same bytes as its launch path.
- Launch, deployment, and rollback serialize through a per-user coordination
  directory. The launcher publishes its PID and release ID before releasing
  that lock. Deployment and rollback reject every live marker.
- Stale markers are removed only after their PID is no longer alive. A
  malformed marker fails closed.
- Incomplete coordination locks receive a 30-second grace period and are then
  reclaimed by atomically renaming the stale directory before deletion. Lock
  release likewise renames first, so interruption cannot strand the live lock
  name or delete a successor's lock.
- Publication writes and fsyncs a fresh temporary release before one atomic
  rename. Activation replaces `previous` and then `current` with atomic
  symlink renames, explicitly sets the selector symlinks to mode `0755`
  independent of the caller's umask, and fsyncs the containing directory.
- Rollback accepts only an already installed, fully verified release. Releases
  are retained. Publication rejects a 33rd retained release or an oversized or
  untrusted release-root inventory; garbage collection remains an explicit
  future operator action.
- The controller preserves the distinction between registry membership
  failure (remote status 42) and registry availability failure.
- New and resumed sessions take separate Bash 3.2-safe branches. No empty
  array expansion is used for a new session.

The marker and coordination directory protect against accidental concurrent
operator actions, not a malicious owner of the Mac account. The root-owned
installed tree is the integrity boundary. Guest controls, model credentials,
and lease authority remain unchanged.

## Lifecycle

`scripts/deploy-host-controller.py deploy` acquires the coordination lock,
rejects active invocations, validates both scripts with `/bin/bash -n` or the
Python compiler as applicable, and asks the protected authorization broker to
invoke the protected release manager. The prompt and root-owned receipt bind the
declared agent/session, purpose, operation parameters, nonce, expiry, and exact
request digest. See `OPERATOR_AUTHORIZATION_PROVENANCE_DESIGN.md`.
The manager repeats active-marker validation before publication.

An older manager could create `current` with mode `0700` when invoked under the
authorization broker's restrictive umask, making the broker unreachable to the
invoking user. The deploy wrapper recognizes only the exact root-owned release
layout with this selector-mode defect and offers a one-time terminal-bound
recovery. It verifies the mutable source manager by SHA-256 in a minimal
isolated loader, binds the expected source release ID, and installs the fixed
release. No general sudo fallback exists for a missing or otherwise invalid
broker.

`scripts/deploy-host-controller.py rollback [RELEASE_ID]` uses the same gates.
Without an explicit ID it activates the verified `previous` release.
Rollback reports whether the activated generation still matches repository
source; a mismatch intentionally makes boundary verification fail closed until
the repository is realigned.

`scripts/host-controller-release.py verify --json` is read-only and verifies
ownership, modes, symlink confinement, the release ID, and all payload hashes.
Boundary verification compares the active release with the repository's
expected payload bytes.

Migration recognizes only the exact historical three-, four-, six-, and
pre-authorization payload
manifest shapes needed to validate installed predecessors. The original
three-payload shape is additionally bound to its pinned production release
ID. The migrated launcher can validate those predecessor shapes, avoiding an
unusable crash window between launcher migration and current publication.
Historical generations are never advertised as `previous` and cannot become
the normal rollback target. New publication, normal verification, and managed
rollback require the current eight-payload format. Replacement launcher bytes
are bound to both the exact installed SHA-256 supplied by the operator and the
repository replacement SHA-256 calculated by the unprivileged wrapper before
privileged installation.

Installing the first authorization-capable release is an explicit bootstrap
exception because no protected broker exists yet. The bootstrap uses a
foreground notice, is terminal bound, and labels the declared requester, source
digests, and exact installed/replacement launcher hashes before `sudo`. The
manager verifies those bindings, migrates the launcher when necessary, and then
publishes the exact broker release. A retry after interruption recognizes an
already-migrated launcher and completes publication. Bootstrap refuses after
the broker is available. It is not an ongoing fallback.

## Failure semantics

Any malformed manifest, hash mismatch, unsafe symlink, writable installed
file, unexpected owner, active invocation, lock timeout, or failed syntax
check rejects the operation. A failure before activation leaves `current`
unchanged. A failure after release publication but before activation may leave
an unreachable immutable release, but cannot partially activate it.

A crash after `previous` changes but before `current` changes may leave both
links naming the old current release. Implicit rollback then rejects
`rollback_target_already_current`; explicit rollback by retained release ID
remains available.

The stable launcher reports structured, specific error tokens on stderr. It
removes its marker if `execve` fails; once exec succeeds, the controller's EXIT
trap owns marker cleanup and lease finalization.
