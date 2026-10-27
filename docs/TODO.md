# Roadmap

This is the public product roadmap. Deployment-specific tasks, findings,
incident notes, review transcripts, identifiers, and acceptance evidence belong
in ignored local records, not in this file.

## Before a public release

- Keep the clean-history `public-release` branch as the only published branch.
- Run `scripts/run-public-release-checks.sh` against the exact candidate commit.
- After GitHub-hosted capacity returns on 2026-11-01, explicitly dispatch and
  confirm the first remote CI run and signed build-provenance attestation.
- Verify both remotes' default branch, branch protection, and sole-ref policy.
- Make repository visibility public only by an explicit operator decision after
  those controls and the exact remote state are verified.

## Engineering backlog

- Periodically re-run the completed Parallels Lifecycle Resilience DDD's
  fault-injection, controlled stop/start, idempotent recovery, and complete
  boundary gates with the Parallels Desktop GUI closed.
- Build a reusable Privileged Workflow Transaction Engine DDD with an
  append-only, fsync-safe state machine for prepare, authorize, activate,
  verify, commit, rollback, expiry, and lost-response recovery.
- Complete an Authority Loss and Disaster-Recovery DDD covering permanent loss
  of the Mac, its non-exportable Secure Enclave identity, the protected Host
  installation, or any single VM without weakening fail-closed replacement and
  revocation rules.
- Complete a Full-Stack Chaos and Restart Matrix DDD that injects termination at
  every Host, Gateway, Research, and Target transition and rejects mixed
  generations, stale admission, authorization reuse, and false evidence.
- Complete an Operator Ceremony and Diagnostics DDD that consolidates Touch ID
  instructions, distinguishes approve/cancel ceremonies, prevents ambiguous
  retries, and emits one content-free actionable diagnosis for each terminal
  failure.
- Extend the completed Secure Enclave execution-approval evidence with
  separately reviewed destructive-negative tests on a disposable Mac. The
  deployed generation, reboot acceptance, commitment, software-authority
  retirement, live expiry gate, and postdeployment audit are complete.
- Periodically re-run the completed Local Broker Protocol Hardening DDD's
  adversarial framing, deadline, peer-authentication, and saturation gates.
- Periodically re-run the completed Transactional Publisher Crash-Recovery
  DDD's phase-boundary, substitution, idempotency, and rollback gates.
- Preserve and periodically test the implemented exact-candidate CI,
  deterministic source release, and signed build-provenance controls.
- Keep public architecture documents descriptive; store live acceptance and
  operations records only in ignored local storage.

## Change discipline

New capabilities should begin with a threat model, use the narrowest authority
that satisfies the workflow, carry explicit evidence semantics and resource
bounds, and receive independent review before deployment. A passing test suite
does not replace cold-boot and boundary acceptance for changes affecting the
live lab.
