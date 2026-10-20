# Trusted Guest Time Synchronization

## Status

Status: **implemented design**. Deployment state, acceptance evidence, and
recovery-generation details are private.

## Problem

The three Ubuntu guests intentionally have no Parallels Tools and no general
Internet route. After the Mac slept, their clocks lagged the host by about 30
minutes. The clocks continued to advance together, but did not catch up to wall
time after resume.

That drift has security consequences:

- certificate validity can be evaluated against the wrong time;
- guest-authored event timestamps can fall outside alert query windows;
- run and source evidence can appear older than it is;
- time-bounded plans, leases, and approvals can last longer than intended.

Azure alerts use ingestion time for freshness so a stale guest clock cannot
hide a newly ingested event. That is a necessary off-host safeguard, not a
substitute for correcting the guests.

## Trust and authority

The Mac controller is the time authority for this local lab. It already owns
VM lifecycle and the provisioning path, and macOS maintains its clock outside
the untrusted Research workload. No agent-facing identity can invoke the
synchronizer.

The controller:

1. reads the Mac's UTC epoch;
2. authenticates to each exact guest through the pinned SSH configuration;
3. obtains each guest's sudo password directly from the Agents vault;
4. sets UTC with `date` under root;
5. independently measures all three clocks and fails if any differs from the
   Mac by more than five seconds.

Secret values are streamed directly from `op-agents` to `sudo`; they are never
printed, stored in this repository, or placed on a command line.

## Admission rules

- `--check` is read-only and succeeds only when every guest is reachable and
  within five seconds of the host.
- `--apply` refuses while a Claude run marker exists. Moving time during a live
  run could invalidate ordering, approval, expiry, and evidence assumptions.
- `labctl start` synchronizes time after all guests become reachable and before
  the boundary suite runs.
- `labctl claude` performs a read-only clock check before it claims a run ID.
  It never repairs time implicitly at agent launch.
- Client-certificate rotation requires the same read-only clock check and an
  absent run marker before creating or installing any certificate.
- The target list and corresponding vault references are fixed in the script;
  caller-supplied hosts or commands are not accepted.

## Failure behavior

Unreachable guests, malformed epochs, failed sudo, excessive post-set drift,
or an active run all fail closed. The controller does not weaken certificate,
telemetry, or launch checks to accommodate stale time.

The command to recover an idle running lab is:

```sh
./scripts/labctl time-sync --apply
```

## Verification

Acceptance requires:

- shell syntax validation;
- a demonstrated precondition failure from `--check` while clocks are stale;
- successful synchronization of all three guests;
- a postcondition check at or below the five-second maximum;
- the complete containment suite;
- a cold start proving `labctl start` performs synchronization before boundary
  verification.

## Residual risk

This control trusts the Mac clock and host controller. A compromised host can
already manipulate the hypervisor and therefore lies outside the protection a
guest-only clock source could provide. An enterprise deployment should use an
authenticated, isolated time service and independently monitor offset. For
this single-laptop lab, host injection avoids adding Internet egress,
Parallels Tools, or another reachable service to the attack surface.
