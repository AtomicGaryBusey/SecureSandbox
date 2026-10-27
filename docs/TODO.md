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

- Extend the completed Secure Enclave execution-approval evidence with
  separately reviewed destructive-negative tests on a disposable Mac. The
  deployed generation, reboot acceptance, commitment, software-authority
  retirement, live expiry gate, and postdeployment audit are complete.
- Periodically re-run the completed Local Broker Protocol Hardening DDD's
  adversarial framing, deadline, peer-authentication, and saturation gates.
- Expand crash-injection coverage for transactional publishers and rollback.
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
