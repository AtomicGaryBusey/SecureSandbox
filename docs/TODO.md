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

- Complete the Attested Model Profile Configuration DDD: stage bounded vendor,
  model, adapter, credential-reference, lease, and inference settings in the
  ignored local catalog and native Settings window; require exact Touch ID
  activation; bind each session and lease permanently to one reviewed profile
  revision; and keep inactive models, credentials, and endpoints unreachable.
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
- Complete a Multi-Harness Admission and Plugin-Ecosystem Isolation DDD before
  introducing ChatGPT Codex, Kimi Code, Grok Build, Google Antigravity, Pi, or
  another harness. Admit only harnesses whose distribution, protocol,
  capabilities, update path, and sandbox behavior can be independently pinned
  and attested. Keep plugins disabled by default; require provenance-verified
  sealed bundles and per-harness allowlists; prohibit runtime marketplace or
  model-initiated installation; normalize tool authority at the outer control
  plane; and prevent harness, plugin, credential, model, or session authority
  from crossing profiles.
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
