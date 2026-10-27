# Parallels lifecycle resilience

## Status

Implemented and deployed. Adversarial fault-injection tests, the reviewed live
stop/start and idempotent-recovery sequence, and complete boundary verification
pass. Deployment-specific state, VM identities, and acceptance transcripts
remain private.

## Problem and evidence

SecureSandbox intentionally omits Parallels Tools from all guests. Graceful
shutdown therefore travels through the authenticated guest control plane and
normally closes its own SSH transport before a success response can return.
Separately, the Parallels Desktop GUI has crashed while network state changed
during both stack shutdown and startup. In each retained incident, command or
transport status alone disagreed with the VM state that was subsequently read
back from Parallels.

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
- `stop` holds the same lock, refuses a running GUI, and converges in Target,
  Research, Gateway order. Already-stopped guests are not contacted. A closed
  SSH transport is recorded as `lost_response` only when independent `prlctl`
  readback proves that exact guest stopped.

Unexpected, malformed, or unavailable inventory becomes `unknown` and fails
closed before a new mutation. A residual guest, inaccessible control endpoint,
clock failure, or failed boundary gate produces a rejected final record. A
retry after controller or GUI failure derives work only from fresh state; it
does not replay a remembered command.

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
  mutating command.
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

The live cycle is disruptive and is never launched implicitly by a unit test or
ordinary publication gate. The operator must first quit Parallels Desktop and
explicitly run the reviewed DDD deployment entry point.
