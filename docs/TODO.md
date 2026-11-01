# Roadmap

This is the public product roadmap. Deployment-specific tasks, findings,
incident notes, review transcripts, identifiers, and acceptance evidence belong
in ignored local records, not in this file.

## Public-release controls

- Keep the clean-history `public-release` branch as the only published branch.
- Run `scripts/run-public-release-checks.sh` against the exact candidate commit.
- After GitHub-hosted capacity returns on 2026-11-01, explicitly dispatch and
  confirm the first remote CI run and signed build-provenance attestation.
- Keep GitHub public with `public-release` as its only and default branch. Keep
  `public-release` as the private Hobby Forgejo remote's default branch and
  verify that both live remote tips equal the reviewed commit before and after
  publication.
- Preserve GitHub's no-bypass branch/tag freeze and private vulnerability
  reporting. Reapply and verify those controls after publication with
  `scripts/seal-public-github-release.py --apply`; any future visibility change
  requires an explicit operator decision.

## Engineering backlog

- Complete the Human Identity and Release Authenticity DDD before claiming that
  a GitHub account, repository, workflow attestation, Apple certificate, or
  signing key alone proves that a package was authorized by the project owner. Define
  a privacy-minimized externally identity-proofed Human Identity Covenant bound
  to immutable GitHub account/repository IDs; hardware-separated account,
  commit, human-release, threshold-root, targets, recovery, Apple, and
  post-quantum key roles; canonical release authorization; GitHub/Sigstore and
  in-toto/SLSA provenance; Developer ID/notarization cross-binding; TUF-style
  threshold/expiry/rollback/rotation controls; hybrid classical plus ML-DSA
  signatures; transparency monitoring; and compromise, revocation, succession,
  rename, recovery, and historical re-attestation. This is a research and
  design backlog item, not authorization to create keys, publish identity data,
  change GitHub settings, or alter the production updater trust root.
- Periodically re-run the completed In-App Updates DDD's metadata-only
  scheduling, manual download separation, signed-manifest and artifact bounds,
  Developer ID/notarization admission, Touch ID install, crash recovery,
  monotonic floor, explicit rollback, protected-environment non-authority, and
  no-bypass adversarial matrix. Production end-to-end acceptance remains gated
  on Apple Developer Program enrollment, separate release keys, a notarized
  bootstrap, and an approved GitHub distribution endpoint.
- Periodically re-run the completed Attested Model Profile Configuration DDD's
  catalog validation, native Settings build, exact Touch ID activation,
  transaction recovery, profile/session/lease binding, adapter fixtures,
  encrypted credential staging, inactive-profile isolation, production
  readback, and complete boundary gates.
- Periodically re-run the completed SecureSandbox Control Center DDD's native
  build and bundle validation, cold Stop/Start, emergency containment and
  recovery, accepted-restore readback, export integrity, protected-launch
  safety audit, and complete boundary gates. Production-data-dependent finding,
  memory-proposal, and snapshot actions remain fail-closed until legitimate
  records or policy milestones exist.
- Periodically re-run the completed Azure Evidence and Alerting Plane DDD's
  destructive-change-rejecting what-if, exact resource/role/lock/budget
  verification, synthetic alert-semantics matrix, fresh off-host heartbeat and
  denial gates, shared-installer active-state preservation, and complete
  boundary verification.
- Periodically re-run the completed Parallels Lifecycle Resilience DDD's
  fault-injection, controlled stop/start, idempotent recovery, and complete
  boundary gates with the Parallels Desktop GUI closed.
- Periodically re-run the completed Privileged Workflow Transaction Engine
  DDD's append-only chain, lost-response, exact-identity, expiry, rollback,
  irreversible-activation, and complete boundary gates.
- Complete an Authority Loss and Disaster-Recovery DDD covering permanent loss
  of the Mac, its non-exportable Secure Enclave identity, the protected Host
  installation, or any single VM without weakening fail-closed replacement and
  revocation rules.
- Complete a Full-Stack Chaos and Restart Matrix DDD that injects termination at
  every Host, Gateway, Research, and Target transition and rejects mixed
  generations, stale admission, authorization reuse, and false evidence.
- Complete a Harness Lifecycle and Verified Upgrade DDD for Claude Code and
  future harnesses. Treat each harness release as a versioned, provenance-
  verified artifact; stage compatibility and policy tests before exact Touch ID
  activation; pin active sessions to one harness generation; forbid model-
  initiated installation or switching; and provide atomic rollback, audit, and
  policy-hash readback without exposing credentials or weakening sandbox
  boundaries.
- Preserve the completed Multi-Harness Admission and Plugin-Ecosystem
  Isolation DDD's conditional direction: admit only a small set of immutable
  core-only harness generations through first-party adapters; treat vendor
  marketplaces as acquisition leads, never runtime authority; decompose every
  ecosystem package by capability class; keep in-process extensions, native
  hooks, runtime packages, connectors, and peer-harness calls prohibited; and
  bind any separately admitted skill or outer tool service to the exact
  harness, model-profile, session, and extension-set revisions. Codex and Pi
  are evaluation-order candidates only. No new harness or extension is
  authorized until the neutral framework, conformance matrix, transactional
  Touch ID lifecycle, disposable-Mac acceptance, and separate admission
  decision are complete.
- Preserve the completed First-Party Research Harness Feasibility DDD's hybrid
  decision: SecureSandbox owns authority, admission, model, tool, evidence, and
  lifecycle contracts while each inner harness remains untrusted and
  replaceable. Do not build a general-purpose first-party harness. A separately
  authorized narrow reference prototype is eligible only after a documented
  trigger and must meet the DDD's conformance, security, quality, cost, latency,
  UX, provenance, and maintenance thresholds before a new production decision.
- Periodically re-run the completed Operator Ceremony and Diagnostics DDD's
  approve/cancel separation, expiry distinction, sink enforcement, diagnostic
  authenticity, authoritative receipt binding, and complete boundary gates.
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
