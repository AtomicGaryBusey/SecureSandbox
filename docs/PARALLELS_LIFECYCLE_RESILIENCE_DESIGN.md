# Parallels lifecycle resilience

## Status

Implemented and deployed. Adversarial fault-injection tests, the reviewed live
stop/start and idempotent-recovery sequence, and complete boundary verification
pass. The first published Parallels 27.1 stopped-service bootstrap reached and
proved its Gateway-only state on the Neo, then rejected because Parallels
vetoed both its Apple-event quit and SIGTERM while Gateway remained running.
An exact-PID termination repair is implemented and source-tested. Physical
acceptance of the later isolated-stop prerequisite exposed that disconnecting
Gateway `net0` also removes the Shared-network transport used by the protected
Gateway SSH proxy. The corrected stop path keeps the disconnect-first rule but
uses Parallels' local graceful ACPI stop for each exact VM, never `--kill`, and
accepts completion only after independent `prlctl` stopped-state readback.
Deployment-specific state, VM identities, and acceptance transcripts remain
private.

## Problem and evidence

SecureSandbox intentionally omits ambient host-to-guest network authority.
The authenticated guest control plane is reached through Gateway's Shared
adapter, so it is not a valid shutdown transport after the required
disconnect-first egress isolation. Graceful stop instead uses Parallels' local
ACPI transition for the exact VM and treats its response as non-authoritative;
only independent VM-state readback can prove completion.
Separately, the Parallels Desktop GUI has crashed while network state changed
during both stack shutdown and startup. In each retained incident, command or
transport status alone disagreed with the VM state that was subsequently read
back from Parallels.

Physical acceptance on macOS 27.2.1 with Parallels Desktop 27.1.0 exposed a
second vendor boundary: when every VM is stopped, quitting the GUI also removes
the per-user Parallels service that backs `prlctl`. Keeping the GUI closed makes
inventory unavailable, while keeping it open correctly blocks ordinary
lifecycle mutation. `prl_bglaunch` is not a headless service bootstrap on this
release; it launches the GUI client. This creates an all-stopped service
deadlock rather than a VM-state ambiguity.

The former `labctl start` suppressed every `prlctl` failure and then continued.
The former `labctl stop` reported expected shutdown disconnects as action
failures even when all guests were independently proven stopped. Neither path
serialized concurrent lifecycle mutations or emitted the same structured
completion evidence.

## Threat and failure model

The controller assumes any mutating command can:

- succeed and return success;
- succeed but lose, truncate, or overproduce its response;
- fail before changing state;
- leave only some VMs changed before the controller or Mac process exits;
- race another lifecycle command;
- encounter a stale disconnected Gateway uplink; or
- coincide with the known GUI crash without stopping the Parallels service.

The mutable repository, command response, SSH exit code, and GUI process are
not evidence of a completed transition. The locally installed `prlctl`,
protected control client, protected SSH configuration, and final independently
parsed VM inventory form the observation path. Complete boundary verification
remains a separate and stronger requirement after startup.

## State machine

`scripts/parallels-lifecycle.py` implements three operations behind
`scripts/labctl`:

- `status` performs read-only VM, uplink, and authenticated guest-control
  observation. It never takes the transition lock or changes state.
- `start` holds a nonblocking per-operator lock, refuses to proceed while the
  Parallels GUI is running, and converges each `running`/`stopped` VM in
  Gateway, Research, Target order. It repairs a disconnected Gateway uplink,
  waits for each role's authenticated control endpoint, synchronizes clocks,
  and completes the full boundary verifier.
- `start --bootstrap-parallels-service` is an explicit, narrowly bounded
  recovery for the all-stopped service deadlock. It requires exactly one stable
  GUI PID and either the exact all-stopped inventory or the exact recovery
  inventory Gateway running/Research stopped/Target stopped. While holding the
  ordinary lifecycle lock, it may start only the Gateway. It verifies that
  exact intermediate state and the unchanged GUI PID, terminates only that
  bound PID, proves
  the GUI absent, and proves the same intermediate inventory is still readable.
  Only then does it transfer the already-held lock and its recorded outcome to
  the ordinary closed-GUI start controller. Adapter mutation, Research and
  Target startup, guest readiness, clock synchronization, and complete boundary
  verification remain ordinary-controller operations with the GUI closed.
- `stop` holds the same lock, refuses a running GUI, disconnects and rereads
  Gateway `net0`, then converges in Target, Research, Gateway order with local
  graceful `prlctl stop` transitions. Already-stopped guests are not contacted.
  A lost, oversized, or failing Parallels response is recorded as
  `lost_response` only when independent `prlctl` readback proves that exact
  guest stopped. The controller never adds `--kill`.

The shell entry point performs a credential-readiness gate before either
mutating operation. The provisioning and control agents use separate fixed
Unix sockets. Each socket must expose exactly one identity whose SHA-256
fingerprint matches its regular, non-symlink public-key file. Missing, stale,
or multi-key agents are rebuilt from the 1Password Agents vault by the existing
`key-load` operation and checked again. An incomplete restore fails before the
lifecycle controller can issue a VM, adapter, clock, or guest-control mutation.
Read-only `status` deliberately bypasses this gate so its no-mutation contract
includes local credential state and vault access.

Unexpected, malformed, or unavailable inventory becomes `unknown` and fails
closed before a new mutation. A residual guest, inaccessible control endpoint,
clock failure, or failed boundary gate produces a rejected final record. A
retry after controller or GUI failure derives work only from fresh state; it
does not replay a remembered command.

Parallels physically returned Apple-event error `User canceled (-128)` and
left the same GUI PID resident after SIGTERM. Exact-PID SIGKILL removed only
the GUI; the service remained available and independently reported the
unchanged Gateway-only inventory. The controller therefore sends TERM first,
repeatedly requires either absence or that same sole PID during a bounded grace
period, and permits KILL only while the exact PID remains unchanged. A new,
missing, or additional PID rejects rather than broadening the signal target.

The service bootstrap rejects multiple or changing GUI PIDs, every other mixed
VM state, failed Gateway readback, failed GUI quit, service loss after quit, and
any changed post-quit inventory. Its Gateway-only recovery state exists solely
to resolve an interrupted prior bootstrap without issuing a duplicate start.
Operators must inspect fresh state before retrying a rejected transition.

## Evidence contract

The final record retains the restart-safety schema used by the operator
runbook:

```json
{
  "schema": "secure-sandbox-host-lifecycle-v1",
  "operation": "start|stop|status|panic",
  "status": "verified|rejected",
  "phase": "preflight|transition|readiness|time_sync|boundary_verification|complete|readback",
  "observed": {
    "gateway": "running|stopped|unknown",
    "research": "running|stopped|unknown",
    "target": "running|stopped|unknown",
    "gateway_net0": "connected|disconnected|unknown"
  },
  "action_outcomes": [],
  "action_failures": []
}
```

Mutating records include a fresh transition UUID. `action_outcomes` identifies
`succeeded`, `lost_response`, `already_satisfied`, or `failed`; it never
overrides `observed`. Shutdown is safe for a Mac restart only when the final
record is `verified` and all three observed VM states are `stopped`, regardless
of individual lost responses. Startup is accepted only when all VMs and their
control endpoints are live, the Gateway uplink is connected, time is trusted,
and the complete boundary verifier passes.

## Resource and authority bounds

- Only one mutation can hold the owner-only, non-followed lifecycle lock.
- Lifecycle mutations fail closed unless both ephemeral SSH agents contain
  exactly their expected identity; reboot recovery never writes private keys
  to disk.
- The lock lives in the macOS-provided private per-user temporary directory;
  that directory must be owner-controlled and not group- or other-writable.
- Every external command runs in a controller-owned process group with a
  deadline, bounded termination grace, and captured output bounded to 64 KiB.
- Protected control-client calls have an explicit inner deadline shorter than
  the controller deadline, so the client terminates its separately-sessioned
  SSH process before the lifecycle transaction can reject and release its
  lock. Direct clock-check SSH calls use bounded keepalives as well.
- The exact three VM names, start/stop orders, control roles, Gateway adapter,
  and permitted state vocabulary are fixed in source.
- Lifecycle code never invokes `prlctl` as root and gains no new guest or host
  authority.
- GUI detection occurs before the transition lock is allowed to issue a
  mutating command. The explicit stopped-service bootstrap instead binds one
  stable GUI PID under that lock and removes the GUI before transferring to the
  ordinary mutation path.
- The bootstrap's GUI probes and termination grace periods are bounded. TERM
  and any KILL fallback target only the previously bound PID after exact
  process-list readback. It runs as the login user, never invokes `prlctl` as
  root, and cannot select a VM, adapter, or executable path at runtime.
- `panic` remains an independent emergency containment path and does not depend
  on guest cooperation.

## Acceptance gates

Automated tests must prove:

1. read-only status emits schema-checked state without mutation;
2. a running GUI prevents every start/stop action;
3. mixed safe states and a stale Gateway uplink converge without restarting an
   already-running VM;
4. successful actions with failed, timed-out, or oversized responses are not
   retried and are accepted only after exact readback;
5. unapplied actions, malformed inventory, unreachable guests, and failed time
   or boundary checks fail closed;
6. an already-satisfied stop is idempotent;
7. concurrent transitions are rejected before mutation;
8. a timed-out command cannot leave a descendant that produces a late effect,
   and every protected control call carries a shorter inner deadline;
9. an untrusted runtime directory is rejected before mutation; and
10. the real stack survives controlled stop, repeated stopped-state recovery,
   controlled start, repeated running-state recovery, and the complete live
   boundary gate with the GUI closed.
11. status never restores credentials, start and stop gate every mutation on
    identity readiness, missing agents are restored and rechecked, and a failed
    restore produces no Parallels action.
12. the explicit stopped-service bootstrap starts only Gateway from exact
    all-stopped state, accepts only the exact Gateway-only recovery state,
    rejects GUI PID change and post-termination service loss, and delegates through the
    same already-held lock only after an exact closed-GUI readback.

The live cycle is disruptive and is never launched implicitly by a unit test or
ordinary publication gate. The operator must first quit Parallels Desktop and
explicitly run the reviewed DDD deployment entry point.
