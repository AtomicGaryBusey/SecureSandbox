# Fresh-VM Containment Restoration and Acceptance

## Purpose

Recreating three VM shells is not the same as restoring SecureSandbox. The
containment claim depends on an ordered graph of identities, packages, private
keys, services, instruments, evidence paths, and launch controls. This design
makes that graph executable and requires a real cold boot before acceptance.

The workflow does not assert that a green test proves a model is harmless. It
asserts only that the documented containment boundaries and evidence paths are
present, source-pinned where claimed, and behaving as measured at acceptance.

## Threat model

The operator and protected host controller are trusted. Guest administrator
accounts are maintenance authorities, not agent authorities. Agent-authored
content, imported sources, package archives, review bundles, and existing guest
state are untrusted until their owning verifier accepts them.

The restoration workflow must fail closed against:

- restoring phases to the wrong VM generation;
- resuming after implementation inputs changed;
- running maintenance while an agent lifecycle is active or unreconciled;
- leaving a temporary Internet adapter or default route behind;
- enabling PKI expiry enforcement before a generation exists;
- treating a historical telemetry record as fresh acceptance evidence;
- publishing a partially restored analysis surface; and
- declaring success before a cold boot reproduces the controls.

## Authority and state

`restore-fresh-vms.py` is the host orchestrator. Its ignored, mode-0600 journal
is atomically replaced and directory-fsynced after each successful phase. The
journal binds the run to:

- the exact UUID and expected bundle path of Gateway, Research, and Target;
- a digest over restoration code and required private/local artifacts; and
- an ordered prefix of completed phases.

A failed phase is never recorded complete. Resume rejects reordered history,
changed VM identities, or changed inputs. The orchestrator recomputes the input
digest before and after every phase and immediately before completion, so a
mid-run source edit cannot produce evidence labelled with an older digest. The
input set includes the privileged-control sudoers policy, SSH policy, and
authorized public key consumed by acceptance. The journal contains hashes and
VM identities, not credentials or vulnerability material.

An explicit `--restart` preserves an incomplete journal with a collision-safe,
no-replace hard link, directory-fsyncs that preserved name, removes the current
name, and directory-fsyncs again. A crash between those operations can leave
two names for the same intact journal, but cannot overwrite or lose the prior
evidence.

Apply holds the host launch-admission coordination lock from the active-marker
check through final cold-boot acceptance. Catchable termination signals are
deferred while a phase child is alive, and the lock is released only after that
child exits. PKI maintenance validates and inherits this exact lock rather than
opening a second coordination window or deadlocking on a nested acquisition.

## Restoration graph

The enforced order is:

1. Give Research and Target one temporary shared adapter at a time. Research
   installs digest-pinned `auditd` and `age` packages; Target installs a
   digest-pinned rootless-Docker package set after verifying the expected Docker
   repository primary-key fingerprint and exact key-file digest. Exact direct
   package versions and archive SHA-256 values are source-bound restoration
   inputs. Downloads occur as `_apt`, then are copied into root-owned,
   non-writable staging before verification and use. Installation is executed
   with downloads disabled, requires a clean dpkg database with no unincorporated
   triggers, and rejects unbound configuration or removal actions as well as any
   installation outside the verified direct set. Transitive requirements must
   already be satisfied by the verified base guest or restoration fails closed.
   Each transaction journals the complete normalized pre-change network-adapter
   inventory. Before any mutation, the host binds all three expected names,
   bundle paths, adapter topologies, and pairwise-distinct UUIDs; every later
   hypervisor read or mutation addresses that UUID and rechecks the returned
   identity. This prevents a same-name registration change between validation
   and use from redirecting maintenance authority. The workflow restores
   the deny policy, removes the guest provisioning netplan, removes the exact
   Parallels adapter, reapplies device-sharing denial, re-reads the VM inventory
   to prove the original adapter set was restored, and proves there is no
   default route.
2. Replace the seed-installed privileged-control files on all three guests with
   the exact source-bound revision, requiring the installer's self-check and an
   exact result for each role; Research is upgraded first and must re-prove an
   idle lifecycle before the other roles change. Then install the Research
   service principal and exact Claude Code, bubblewrap, and socat artifacts.
   Establish or validate bootstrap PKI, then install the
   Gateway broker/telemetry/conversation receivers and the Research relay,
   telemetry, conversation capture, artifact capture, and tool auditor.
3. Deploy PKI lifecycle code without starting its timer on an empty generation,
   rotate a complete generation, verify both guests, start and exercise expiry
   checking, and bind the result to the protected host anchor.
4. Deploy source acquisition, source integrity, corpus intelligence, CodeGraph,
   and direct-dependency orchestration.
5. Deploy disposable execution on Target and Research, then evidence receipts.
   Receipts therefore never install against a missing execution producer.
6. Deploy memory proposals, sealed review bundles, and findings adjudication.
7. Deploy run leases last because their Research installer restarts and binds
   the higher-level services into the lifecycle supervisor.
8. Run the complete boundary verifier while hot.
9. Gracefully stop all guests, remove remaining installer media, reapply device
   sharing denial, boot Gateway then Research then Target, synchronize time, and
   run the complete verifier again.
10. Scan the non-ignored worktree and every object reachable from the intended
    Git ref, including commit and recursively nested annotated-tag messages, for
    private identifiers and forbidden publication material. The restoration
    identity binds the complete scanned worktree, `.gitignore`, the private
    deny-pattern policy, exact `HEAD`, and every local tag ref/object identity;
    any change before completion requires an explicit restart.

Cloud export and production model activation remain explicit operator choices.
Safe mock mode and unavailable cloud shippers are labelled gates, not silently
reported as production success.

## Crash and rollback behavior

Package provisioning has an exit cleanup that attempts to stop the affected
guest, remove only the adapter created by that transaction, reapply the gamepad
sharing denial, and restart the guest. It never kills a VM after a failed
graceful stop. An unreconciled adapter therefore blocks subsequent preflight
instead of being mistaken for an accepted topology.

Individual component installers retain their own backups and rollback rules.
The orchestrator does not pretend that a multi-VM restoration is globally
atomic; it provides deterministic, identity-bound resumption. The PKI operation
parent holds the same launch-admission lock until its child exits and defers
catchable termination signals, so launch admission cannot open underneath a
live deployment or rotation child.

If a PKI phase is interrupted after its UUID is pending or host-anchored but
before the restoration journal advances, recovery must name that exact UUID
with `--recover-pki-generation`. Recovery is accepted only when the UUID is
the protected host anchor's pending or current generation and PKI generation
has not already been journaled complete in the journal being resumed. It
replays the guest transitions and postconditions idempotently; an ordinary
resume cannot silently rotate twice. The recovery flag may accompany an
explicit restart when patched restoration source requires a new identity-bound
journal, including after the superseded journal recorded PKI complete; the
fresh journal then replays only the exact protected pending/current generation.
The orchestrator derives a required recovery UUID from a protected pending
anchor or from an exact host-anchor identity change relative to the snapshot
durably journaled immediately before PKI generation. Legacy journals without
that snapshot conservatively compare whole seconds so a later same-second
commit cannot be missed. In every case, omission or mismatch is a hard failure.
Caller-supplied generation IDs are forbidden outside recovery mode, preventing
retained committed generations from being selected as implicit rollbacks.

Privileged deployments run with their staged `/tmp` in a private,
non-propagating mount namespace. An installer that creates or stops a system
mount through PID 1 must therefore inspect and mutate that mount through PID
1's mount namespace as well. The review-bundle installer and rollback use
`nsenter` for every canonical/view operation and postcondition; checking from
the installer namespace would otherwise produce a false negative after a new
mount and retain a stale read-only view after stopping an existing mount.

Initial PKI bootstrap is also resumable. Existing private keys are validated
and retained; missing CSRs are reconstructed from those keys; client
certificates are re-signed from validated, role-specific CSRs; and installed
identities are reused only when the key, certificate, subject, purpose, chain,
and Gateway CA all agree. Symlinked, corrupt, or contradictory key material is
rejected rather than regenerated. Bootstrap exchange files are derivative and
can be reconstructed after interruption.

The audit configuration update retains the prior root-owned configuration until
the new ENRICHED producer contract has restarted and passed validation. Any
error or caught interruption restores and restarts the prior configuration;
failure to complete that rollback is itself an orchestration failure.

Evidence-receipt and findings installers validate the dedicated
`findings-broker` account and group before service activation. The group may
contain no explicitly listed member other than `findings-broker`; legacy
installs whose account has primary group `agent` are repaired with that sole
supplementary membership. Component rollback restores payload files and each
affected service's prior enabled/active state, including a previously absent
unit. Root-created service accounts, groups, and their validated membership are
intentionally retained across rollback so identity numbers are not recycled.

Target installation disables and masks the system `docker.service`,
`docker.socket`, and `containerd.service`, removes the rootful socket, and then
starts only the lingering `labadmin` user service. Hot and cold acceptance
independently require the system units to remain masked and inactive, the
rootful socket to be absent, and the user daemon to report both rootless and
no-new-privileges security options.
The rootless runtime builder records Docker's canonical full image ID. Cleanup
resolves every labelled candidate to its full ID, preserves the configured ID,
removes only older images, and re-inspects the configured image before the
installer can report success; abbreviated CLI output is never compared as an
authority-bearing identity.

## Fresh evidence

Acceptance creates a `boundary-test` evidence marker without granting agent
admission. It then:

- invokes the active PKI generation's expiry check with a one-time UUID and
  requires that exact generation-bound, content-free event in the Gateway
  spool; and
- performs a blocked agent-identity connection canary to an unused internal
  benchmark-network address and high port chosen with a cryptographic random
  nonce, and requires that exact destination, port, run attribution, and fresh
  timestamp in the Gateway spool. The connection attempt is bounded to 0.5
  seconds and exact evidence correlation may wait up to 10 seconds. Freshness
  cutoffs allow six seconds of cross-machine skew: the independently enforced
  clock bound is five seconds, and the additional second covers whole-second
  timestamp truncation. Exact one-time evidence identity remains mandatory.
  Each evidence wait runs inside one authenticated guest request with a
  75-second end-to-end client deadline, so it consumes one durable control
  receipt rather than one receipt per poll.

Before the privileged checks, acceptance verifies that every guest's bounded
at-most-once request ledger retains substantial headroom. Exhaustion therefore
fails at the front of acceptance rather than stranding the workflow midway.
Long-term, replay-preserving receipt retirement remains a separate control-plane
lifecycle concern; restoration does not silently delete replay evidence.

Research pins auditd to enriched socket-address records and acceptance verifies
that producer/parser contract and the pinned agent UID before injecting the
canary. Historical or concurrent fixed-tuple records therefore do not satisfy
either assertion except with negligible nonce-collision probability.

## Operator workflow

Read-only preflight and plan:

```sh
python3 scripts/restore-fresh-vms.py plan
```

Apply or resume the exact plan:

```sh
python3 scripts/restore-fresh-vms.py apply \
  --requesting-agent Codex --requesting-session SESSION_LABEL
```

After an intentional source or VM-identity change, preserve the incomplete
journal and begin a new identity-bound run explicitly:

```sh
python3 scripts/restore-fresh-vms.py apply --restart \
  --requesting-agent Codex --requesting-session SESSION_LABEL
```

The apply operation intentionally causes guest-initiated `systemctl poweroff`
through the role-bound privileged control plane, controlled VM starts, temporary
maintenance egress on one guest at a time, two macOS administrator prompts for
the PKI anchor, and a final three-VM cold boot. It should be run only from an
attended console with no agent session active.

## Acceptance

Acceptance requires all local tests and syntax checks, a completed restoration
journal, a fully passing hot boundary suite, a fully passing post-cold-boot
boundary suite, publication-safety checks over the intended Git object set, and
an independent adversarial review of the design, implementation, and live
evidence. A gate is not a failure, but its exact limitation must remain visible.
The VM inventory portion compares the exact permitted adapter key, enabled
state, type, interface, and card for every guest: Gateway has one shared uplink
plus `control-net`, Research has only `control-net` and `lab-net`, and Target
has only `lab-net`. A shared-adapter count or missing default route alone is not
accepted as proof of physical topology restoration.
