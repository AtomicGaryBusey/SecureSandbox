# Request-Bound Disposable-Execution Approval

## Status

Implemented for live deployment and acceptance. This design replaces the prior
Claude permission prompt as the authorization boundary for disposable execution.
The Target containment boundary remains unchanged and independently enforced.

## Security objective

No Python fixture job may reach Target unless the operator approves the exact
job with Touch ID during the active Claude Code session. Approval binds:

- the root-issued run UUID and the explicit Claude session UUID;
- the registered source UUID and canonical source-manifest digest;
- the submitted code digest;
- every fixture path, byte length, digest, and the aggregate fixture-manifest digest;
- the timeout; and
- the immutable Target runtime-image digest.

Approval is valid for 90 seconds, for one request only. Cancellation, timeout,
substitution, malformed state, invalid signatures, and replay all fail closed.

## Authority and transport

```text
Claude MCP client
  -> Research execution broker (validates source, code, fixtures, run/session)
  -> root-owned pending request
  -> host controller long-polls through the forced-command SSH control plane
  -> signed macOS authorization UI displays the complete binding
  -> Touch ID only (no password fallback for execution approval)
  -> protected host broker signs the canonical approval
  -> forced-command SSH returns the envelope to Research
  -> Research verifies the pinned host public key and atomically consumes approval
  -> existing fixed Target execution service and rootless container
```

Research never initiates a connection to the Mac. The host remains the only
side that crosses the control boundary. The approval relay accepts only pending
requests whose run and session match the controller's root-issued lifecycle.
Each typed control request waits up to 30 seconds on Research while checking
locally for a pending approval, so an idle four-hour run cannot exhaust the
bounded privileged-control receipt ledger. A transport failure is retried only
twice; a third consecutive failure terminates the run through its ordinary
fail-closed cleanup path instead of silently leaving an unapproved session.
The MCP-to-broker response deadline is 120 seconds, covering the 90-second
approval lifetime plus the maximum bounded Target execution window.

## Session identity

For a new conversation the controller generates a canonical UUIDv4 and launches
Claude Code with `--session-id` using that value. For a resumed conversation it
uses the already registered resume UUID. The same UUID is written by root into
the Research lifecycle record and included in every approval request. Therefore
the displayed and signed session identity is the actual Claude session, not a
free-form label supplied by the agent.

## Host signing authority

The host authorization broker owns an Ed25519 key under
`/usr/local/var/lib/secure-sandbox/execution-approval`, mode 0600. Its public key
is pinned in Research's root-owned `allowed_signers` file during deployment.
The signing subcommand is root-only and is reachable through the signed Touch ID
UI and protected authorization service. The signed envelope also records the
outer Touch ID authorization request UUID, its canonical request digest, and the
immutable host-controller release ID.

The host root account is part of the trusted computing base. The follow-on
Secure Enclave migration is specified in
`SECURE_ENCLAVE_EXECUTION_APPROVAL_DESIGN.md`. It reduces private-key extraction
risk but does not claim hardware remote attestation of a potentially malicious
host OS.

## Atomic consumption and recovery

Research verifies the signature and exact request equality, then creates a
0600 consumed record with `O_EXCL` and fsyncs it before contacting Target. A
crash after consumption can deny a retry but cannot execute twice. A crash
before response delivery leaves no executable approval; the broker times out
and removes its pending state. Root relay claims are removed on delivery and
stale claims are pruned only when their corresponding pending request is gone.

This deliberately chooses at-most-once execution over transparent retry.

## Evidence

Measured-execution receipts are content-free and now include run UUID, session
UUID, approval UUID, and the digest of the signed approval envelope alongside
the existing code, fixture, output, timeout, and runtime-image measurements.
They correlate an observed Target result with the exact operator-approved job
without retaining source, code, fixture, stdout, or stderr content.

## Acceptance gates

1. Unit tests prove strict parameter typing and complete operator display.
2. The native UI proves execution approval has no password fallback.
3. Real Ed25519 signing tests prove exact binding, cancellation, substitution
   rejection, and one-time replay rejection.
4. Run-lease tests prove fresh and resumed Claude sessions use a canonical,
   root-bound session UUID.
5. Research deployment pins the host public key and Target runtime image.
6. Boundary verification checks ownership, modes, service hardening, topology,
   and the unchanged Target containment controls.
7. Live acceptance must approve one harmless exact request, reject a changed or
   cancelled request, pass the complete boundary suite, and pass a cold boot.

## Deployment runbook

Deploy the reviewed host authority, lifecycle binding, Research verifier, and
Target runtime, then run the live boundary suite with one attributed command:

```sh
./scripts/deploy-execution-approval-ddd.sh \
  --requesting-agent Codex \
  --requesting-session request-bound-execution-ddd-live
```

The first protected host release change requires an attributed authorization.
If the execution signing key does not yet exist, the same command presents a
second, explicitly labeled Touch ID-only request to create it. The script never
deletes a VM or legacy archive. Perform the harmless approved/cancelled live
requests before cold-boot acceptance.

The deployment synchronizes all three isolated guest clocks through the typed
control plane before running freshness-sensitive telemetry acceptance. The
boundary verifier independently fails if any guest differs from the Mac by more
than five seconds; this prevents valid content-free evidence from being
misclassified after host sleep and prevents stale evidence from satisfying a
fresh canary.

Before those checks, the workflow losslessly moves older completed control
receipts into a root-only archive while retaining recent and in-progress
receipts in the active ledger. Receipt IDs in both locations remain part of the
replay check, so archival restores bounded acceptance headroom without weakening
at-most-once control requests or deleting audit evidence.

If an older deployment created the root-owned `current` release selector under
a restrictive umask, the broker may be present but unreachable. The same
command detects only that narrowly validated state and offers a one-time,
attributed release-selector recovery. That recovery uses the terminal password
because the signed UI is behind the inaccessible selector; it loads the
reviewed source release manager only after binding its SHA-256 and expected
release ID. The replacement selector is mode `0755`. Subsequent host mutations
return to the signed authorization UI, and execution approval remains Touch
ID-only.

