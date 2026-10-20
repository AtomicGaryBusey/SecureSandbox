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

Each release contains the Claude run controller, its SSH configuration, the
small 1Password Keychain bridge used by that controller, and the read-mostly
PKI generation-anchor manager.
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
  symlink renames and fsyncs the containing directory.
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
Python compiler as applicable, and invokes the privileged release manager.
The manager repeats active-marker validation before publication.

`scripts/deploy-host-controller.py rollback [RELEASE_ID]` uses the same gates.
Without an explicit ID it activates the verified `previous` release.
Rollback reports whether the activated generation still matches repository
source; a mismatch intentionally makes boundary verification fail closed until
the repository is realigned.

`scripts/host-controller-release.py verify --json` is read-only and verifies
ownership, modes, symlink confinement, the release ID, and all payload hashes.
Boundary verification compares the active release with the repository's
expected payload bytes.

The one-time migration from the original three-payload release accepts only
the pinned production legacy release ID. The migrated launcher can still
launch that one exact release, avoiding an unusable crash window between
launcher migration and four-payload publication. New publication, normal
verification, and managed rollback require the four-payload format; no other
legacy release is accepted. Replacement launcher bytes are bound to the
unprivileged wrapper's expected SHA-256 before privileged installation.

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
