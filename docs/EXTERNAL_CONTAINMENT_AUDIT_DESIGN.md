# Verified external-containment audit adapter

## Decision

SecureSandbox reports two independent Claude Code postures:

1. **host-direct** — the unmodified result of the generic
   `agent-safety-check` audit for Claude Code launched directly on the Mac; and
2. **SecureSandbox launch path** — Tier 4 only when a fresh, fail-closed check
   of the exact `scripts/labctl claude` path proves the external controls.

The adapter supplements the generic auditor. It never changes, filters, or
upgrades the generic audit result and does not assert that a direct host launch
inherits controls that it does not traverse.

## Trusted path and evidence

The only recognized isolated launch path is the repository's canonical
`scripts/labctl` with the `claude` subcommand. The adapter records its SHA-256
and requires its resolved path to equal the configured absolute path. It
invokes the existing `scripts/verify-boundaries.sh` from the same canonical
repository root. A copied or alternate launcher is not recognized. The report
also records the generic auditor's resolved path and SHA-256.

Tier 4 requires all of the following in the same invocation:

- the generic host audit parses successfully and its findings are retained;
- the complete live boundary suite exits zero, emits its success sentinel,
  and emits no `FAIL` or `GATE` line;
- the boundary suite verifies VM isolation, restricted networking, the
  root-managed Claude launcher and policy, process/run correlation, protected
  provider-credential injection, capture/monitoring readiness, and immutable
  policy artifacts;
- the current Gateway and Research policy hashes are readable through their
  non-secret guest interfaces and are valid SHA-256 values; and
- Azure contains recent Gateway and Research heartbeats bound to those exact
  policy hashes plus a recent Research denial from the reserved
  `boundary-test` correlation marker.

Unavailable commands, invalid JSON, a stale or differently hashed Azure row,
partial results, any boundary gate, or any subprocess timeout yields an
unverified launch path. The adapter never falls back to an earlier report.

## Interface

The host-only operator command is:

```sh
./scripts/labctl safety-audit
```

It emits schema `secure-sandbox-external-containment-audit-v1` as JSON. The
generic auditor path may be selected with `AGENT_SAFETY_TOOL`; otherwise the
adapter discovers the installed skill in the normal Codex/Agents skill roots.
No credential is accepted as an argument or written to the report.

## Bounds and failure behavior

- boundary verification timeout: 180 seconds;
- Azure query timeout: 60 seconds;
- generic audit timeout: 30 seconds;
- maximum accepted off-host evidence age: 15 minutes; and
- captured diagnostic output: 16 KiB per failed subprocess.

The command exits zero only for a verified Tier-4 SecureSandbox path. Its JSON
still reports the host-direct tier and findings when the external path fails.

## Non-claims

The Tier-4 result applies only to a new invocation through the exact reported
launcher and only at the time of the live check. It does not harden host-direct
Claude Code, attest future state, prove model behavior safe, or suppress any
finding from the generic auditor.

