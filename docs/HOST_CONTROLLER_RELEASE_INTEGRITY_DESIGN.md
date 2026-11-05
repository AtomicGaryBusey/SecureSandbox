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
Once `host-release-launcher-pair-fence-v1` is active, the stable launcher is one
half of the authorized Host generation. An ordinary install or rollback commits
the immutable release and one exact retained launcher generation together; it
may change neither half independently. Source and target launcher bytes are
retained under content-addressed root-owned backups before selection. The
low-level `migrate-launcher` implementation remains only for bounded pre-pair
bootstrap migrations and rejects use after a public pair record exists.

## Security properties

- The stable launcher reads the public pair record before resolving `current`.
  PENDING is an unconditional execution fence. STABLE must bind the selected
  release, v2 candidate authority, complete release-tree identity, exact
  launcher hash and installed file identity, and the immutable terminal for the
  last transition. The launcher re-reads the same public record after physical
  verification, then passes the exact verified controller as an in-memory Bash
  program to `execve`; it never executes through the mutable `current` symlink.
- The mode-0444 `host-release-launcher-pair.json` record and its committed
  mode-0444 `install-transitions/<transition-id>.json` terminal are part of the
  launch boundary. A release requiring the feature without those exact
  cross-bindings, or a pre-feature release observed after the pair floor, fails
  closed.
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
  rename. Pair activation first publishes PENDING, then selects the retained
  target launcher, `previous`, `current`, and the target services before exact
  readback. PENDING makes every intermediate physical combination
  non-launchable; STABLE is published only after the terminal is durable.
- Rollback accepts only an already installed release with an exact v2 candidate
  authority, release-tree identity, and retained launcher generation. The
  release and launcher roll back as one pair.
  Publication rejects a 33rd selectable release or an oversized or untrusted
  release-root inventory. Explicit capacity recovery retains the fully
  verified current and rollback releases and moves every other immutable
  generation into a bounded root-owned archive; it never deletes history.
- The controller preserves the distinction between registry membership
  failure (remote status 42) and registry availability failure.
- New and resumed sessions take separate Bash 3.2-safe branches. No empty
  array expansion is used for a new session.

The marker and coordination directory protect against accidental concurrent
operator actions, not a malicious owner of the Mac account. The root-owned
installed tree, candidate authority, launcher generation, public pair record,
and committed terminal together form the Host integrity boundary. Guest
controls, model credentials, and lease authority remain unchanged.

## Lifecycle

`scripts/deploy-host-controller.py deploy` acquires the coordination lock,
rejects active invocations, validates both scripts with `/bin/bash -n` or the
Python compiler as applicable, and asks the protected authorization broker to
invoke the protected release manager. The prompt and root-owned receipt bind the
declared agent/session, purpose, operation parameters, nonce, expiry, and exact
request digest. For an ordinary install they also bind one canonical
`secure-sandbox-host-release-target-plan-v1`: source STABLE digest, exact target
release and payload map, target launcher digest, and candidate-record digest.
The request contains the full candidate record, but the review correctly says
that installed candidate authority and tree identity will be derived only after
authorization. Host install and rollback are Touch-ID-only operations. See
`OPERATOR_AUTHORIZATION_PROVENANCE_DESIGN.md`. The manager repeats active-marker
validation and recomputes the exact plan before publication.

When the 32-release selectable store is full,
`recover-release-capacity` prepares an exact digest-bound archive plan while
unprivileged. Because the monotonic execution-approval floor is root-only, the
wrapper delegates that read during preflight, then explicitly proves that both
retained releases expose the v2 floor capability and that the current broker
reports an active v2 approval identity. The privileged manager recomputes the
plan, revalidates the protected floor, and moves only inactive releases. An
inactive historical target must pass ownership, mode, manifest, payload-hash,
bundle-signature, and release-digest checks, but it may predate the current
activation floor: archival makes it non-selectable, while applying that floor
would make retirement of legacy releases impossible. Live recovery retained
current and rollback, archived 30 inactive generations without deletion, and
then admitted the reviewed successor release.

An older manager could create `current` with mode `0700` when invoked under the
authorization broker's restrictive umask, making the broker unreachable to the
invoking user. The deploy wrapper recognizes only the exact root-owned release
layout with this selector-mode defect and offers a one-time terminal-bound
recovery. It verifies the mutable source manager by SHA-256 in a minimal
isolated loader, binds the expected source release ID, and installs the fixed
release. No general sudo fallback exists for a missing or otherwise invalid
broker.

`scripts/deploy-host-controller.py rollback [RELEASE_ID]` uses the same gates.
Without an explicit ID it targets the verified `previous` release. Its separate
`secure-sandbox-host-release-rollback-plan-v1` binds the source STABLE digest and
the already-installed target release, launcher, candidate-authority digest, and
release-tree-identity digest. The wrapper accepts only an exact repository-bound
result with no warning.

`scripts/host-controller-release.py verify --json` is read-only and verifies
ownership, modes, symlink confinement, the release ID, and all payload hashes.
When the pair feature is active it additionally verifies STABLE and its terminal,
the candidate authority and release-tree identity, the exact stable-launcher
bytes and file identity, and a second unchanged read of the public pair record.
Boundary verification compares the active release and launcher with their
reviewed source and retained-candidate authority.

### Paired install and rollback records

The private mode-0600 `.install-transition.json` journal uses
`secure-sandbox-host-pair-transition-v2`. For an ordinary install or rollback it
binds the operation, exact Touch ID request and pending receipt, authorized
target-plan digest, source STABLE digest, source and target pairs, retained
launcher generations, selectors, services, Team-ID floor, expiry, and any
staged finalization or terminal. The initial bootstrap instead carries null
authorization fields plus a canonical `bootstrap_admission` that binds the
named establishment mode, exact target and immutable predecessor release IDs,
candidate-record digest, and candidate-floor digest. The admission is part of
the transition digest. Its public
`secure-sandbox-host-release-launcher-pair-transition-v1` projection deliberately
contains only the source and target pair generations, operation, transition
identity/digest, prior STABLE digest, and required feature. Any mismatch between
private and public records fails closed.

Every bootstrap execution and replay, including the generic recovery command,
re-reads the candidate floor and requires it to equal the journal admission.
It then cross-binds the installed target candidate authority, release tree and
launcher to the journaled target, verifies the exact below-floor predecessor
inventory, and derives the predecessor only from that admission. The final
pre-selector process census always covers that exact predecessor. No caller can
supply, omit, or infer a different recovery predecessor.

After service fencing, replay admits only source release/source launcher,
source release/target launcher, target release/target launcher, and the inverse
launcher-first prefix required while restoring the source. Unknown mixtures are
not recovery states. Successful target readback stages
`secure-sandbox-host-pair-finalization-v1`; failed target activation may stage
only an exact `source_restored` finalization after the source launcher, release,
selectors, and services are independently verified.

The immutable `secure-sandbox-host-pair-terminal-v1` record has only
`target_committed` or `source_restored` status. It binds the transition and plan,
committed pair, final authorization receipt for a non-bootstrap transition,
finalization, and
`secure-sandbox-host-pair-service-evidence-v1`. That service evidence binds the
operation and transition, committed-pair digest, exact `current` and `previous`
targets, and verified Host service identities. The manager publishes the
terminal before STABLE and removes the private journal only after STABLE
readback. `target_committed` is the only successful requested outcome.

If the authorizing broker or privileged child disappears during service
replacement, transport status is non-authoritative. Exact recovery may report
`host_pair_transition_pending`; the wrapper waits for the public terminal and
its STABLE cross-binding. `activation_pending` is only an intermediate
authorization-receipt status. The older
`secure-sandbox-host-install-transition-v1` journal and
`deployed_verified`/`failed_*` terminal statuses are legacy recovery vocabulary,
not current pair acceptance.

### Pre-pair bootstrap history

Installing the first authorization-capable release is an explicit bootstrap
exception because no protected broker exists yet. The bootstrap uses a
foreground notice, is terminal bound, and labels the declared requester, source
digests, and exact installed/replacement launcher hashes before `sudo`. The
manager verifies those bindings, migrates the launcher when necessary, and then
publishes the exact broker release. A retry after interruption recognizes an
already-migrated launcher and completes publication. Bootstrap refuses after
the broker is available. It is not an ongoing fallback.

Schema advancement after bootstrap is equally narrow. The
`bootstrap-touchid-bundle-v2-schema` transition requires the exact current
release, an installed v1 signed-app bundle manifest, a replacement v2 manifest,
and exact installed and replacement launcher hashes. It runs the reviewed
source manager through the terminal-bound digest-checked loader, publishes the
immutable successor, and restarts the protected authorization daemon only
after the selector commit. A retry can recover only that exact already-published
successor; a v2 predecessor, unrelated source release, or mismatched selector
is rejected.

Adding the authorization-gate icon expands the otherwise exact Touch ID source
manifest by four files. `bootstrap-authorization-icon-schema` is the bounded
transition for that expansion: it binds the exact current release, requires its
installed source manifest to contain precisely the pre-icon source set,
requires the successor to contain precisely that set plus the Icon Composer
JSON and three SVG assets, and binds the prospective release and launcher
hashes before administrator authentication. It publishes through the same
digest-checked loader and supports recovery only for the exact already-written
successor. Routine deployment cannot use this path once the icon source set is
active.

## Failure semantics

Any malformed manifest, hash mismatch, unsafe symlink, writable installed
file, unexpected owner, active invocation, lock timeout, or failed syntax
check rejects the operation. A failure before PENDING leaves the source pair
launchable. Once PENDING is published, every physical prefix is fenced until
exact replay either commits the target or restores the source. A crash may leave
an unreachable immutable release or one of the explicitly admitted launcher/
selector prefixes, but it cannot make a mixed pair launchable.

If target activation fails, recovery first fences services and restores the
exact source launcher, selectors, release, and services. Proven restoration is
published as `source_restored` and returns failure; unproven restoration leaves
PENDING and the private journal intact. Operators must not delete either record,
relink selectors, or start a new plan to escape the fence.

The stable launcher reports structured, specific error tokens on stderr. It
removes its marker if `execve` fails; once exec succeeds, the controller's EXIT
trap owns marker cleanup and lease finalization.
