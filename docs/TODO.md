# Roadmap

This is the public product roadmap. Deployment-specific tasks, findings,
incident notes, review transcripts, identifiers, and acceptance evidence belong
in ignored local records, not in this file.

## Before a public release

- Create a clean-history release from the reviewed tree.
- Run the public-material checker over every reachable object intended for push.
- Run an offline secret scan and the complete automated test suite.
- Review example configuration for placeholders and safe defaults.
- Confirm ignored live configuration and vulnerability reports are absent from
  the release archive.
- Verify repository visibility and branch protections before the first push.

## Engineering backlog

- Add trusted, request-bound approval attestation if operator confirmation for
  disposable execution is to become a cryptographic security invariant. Until
  then, treat the prompt as a human-control surface, not a containment boundary.
- Continue reducing broker attack surface and add adversarial framing/deadline
  tests for every local protocol.
- Expand crash-injection coverage for transactional publishers and rollback.
- Add reproducible build metadata and signed release artifacts.
- Add CI for tests, syntax checks, publication checks, and secret scans on the
  exact candidate commit.
- Keep public architecture documents descriptive; store live acceptance and
  operations records only in ignored local storage.

## Change discipline

New capabilities should begin with a threat model, use the narrowest authority
that satisfies the workflow, carry explicit evidence semantics and resource
bounds, and receive independent review before deployment. A passing test suite
does not replace cold-boot and boundary acceptance for changes affecting the
live lab.
