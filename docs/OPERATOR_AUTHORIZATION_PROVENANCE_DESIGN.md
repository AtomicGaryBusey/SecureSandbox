# Operator Authorization Provenance

## Decision

Host-controller publication and rollback are now atomic Host
release/stable-launcher pair operations authorized only through the signed
Touch ID UI. They do not expose administrator-password or missing-UI fallback.
Other allowlisted host maintenance and PKI anchor transitions retain the
operator-visible, two-stage administrator ceremony described below. Before
macOS requests credentials for one of those operations, a foreground window
identifies the declared requesting agent and session, the purpose, protected
resource, exact allowlisted operation, expected identity where applicable,
request SHA-256, one-time nonce, and expiry. The native macOS authorization
prompt repeats the identity, purpose, operation, nonce, and digest. An operator
should approve only when both windows match the agent conversation they intend
to authorize.

The words **declared agent** and **declared session** are deliberate. macOS
authenticates the human administrator, not the model that caused a terminal to
request elevation. SecureSandbox binds the operator's declaration to the
request and audit record; it does not misrepresent that declaration as an
OS-attested model identity.

Installer publication and VM creation/reprovisioning were subsequently migrated
to this ceremony. Their additional plan binding and privilege-drop rules are in
`UNIVERSAL_HOST_MAINTENANCE_AUTHORIZATION_DESIGN.md`.

## Observed risk

Multiple AI sessions can run under the same macOS account. A generic
administrator dialog does not reveal which session initiated it. Approval can
therefore be granted to the wrong concurrent request even when every individual
command is otherwise legitimate. Background AppleScript elevation also made it
possible for a prompt to be hidden behind other windows, leaving the operator
unsure whether a request was pending.

The previous PKI rotation path constructed an administrator command directly in
the mutable shell workflow. The host-controller deployment wrapper invoked
`sudo` directly. Neither path produced a durable receipt that bound the human
approval to an exact request.

## Architecture

`authorization_broker` and `release_manager` are executable payloads in the
immutable, root-owned host-controller release. The unprivileged request phase:

1. requires a declared agent and session plus a bounded purpose and resource;
2. validates a typed operation and its exact parameters;
3. takes a per-user exclusive lock, so only one SecureSandbox authorization
   ceremony can be visible at a time;
4. writes a canonical `0600` request with a UUIDv4 nonce and three-minute life;
5. prints the same details in the invoking terminal and displays them in a
   foreground macOS dialog whose safe default is Cancel; and
6. only after explicit Continue, opens the native administrator prompt with the
   same identifying fields.

The privileged phase receives only the invoking UID, nonce, and request digest.
It derives the request path from the OS account, opens it without following a
symlink, verifies ownership, mode, link count, canonical bytes, digest, time
bounds, identity fields, and operation schema, then verifies its own immutable
release manifest and payload hashes. It never accepts a shell command from the
request. Host-controller publication additionally binds the aggregate identity
of every prospective release payload; source drift after approval is rejected.
The allowlist maps the request to either the protected release manager or
protected PKI anchor with constructed argv.

The resource label is derived from the operation, not trusted from an agent.
Every security-relevant parameter is rendered in the applicable authorization
window. A post-pair install binds
`secure-sandbox-host-release-target-plan-v1`: source STABLE pair digest, exact
target release and payload map, canonical candidate-record digest, and target
launcher digest. Candidate authority and installed-tree identity are derived
and independently checked only after authorization. Rollback binds
`secure-sandbox-host-release-rollback-plan-v1`: the retained target release,
launcher, candidate authority, installed-tree identity, and source STABLE
digest. PKI requests continue to bind their generation, manifest, and current
anchor. Free-form labels are limited to printable ASCII to prevent
bidirectional-text and control-character spoofing. Repository roots may vary
for public clones, but must be real, non-symlinked directories canonically
beneath the invoking user's home; the exact path and plan digest are displayed
and bound.

Before execution, the privileged phase creates a root-owned receipt using
exclusive creation. That is the replay barrier: the same nonce cannot execute
twice even if the user recreates the original request bytes. Completion
atomically replaces the pending receipt with status, timestamps, exit status,
and hashes of stdout and stderr. Output content and operation parameters are not
copied into the receipt.

## Failure semantics

Cancellation, dialog timeout, expiry, malformed identity, extra operation
parameters, digest mismatch, request mutation, unsafe ownership or mode,
untrusted release bytes, replay, or a concurrent request rejects before the
protected operation. Dialog subprocesses run in a separate process group; a
timeout terminates that group so an abandoned prompt does not remain live.
The privileged operation has a shorter independent bound and its entire process
group is terminated on expiry; the receipt records exit status 124.

A crash after receipt creation but before completion ordinarily leaves an
`executing` receipt and fails closed on retry. The one intentional exception is
an already-authorized Host pair transition. Its private mode-0600
`secure-sandbox-host-pair-transition-v2` journal and public mode-0444 PENDING
record fence launch and permit replay only of that exact install or rollback.
Recovery accepts no new target and completes only when a canonical
`secure-sandbox-host-pair-terminal-v1` terminal and STABLE record cross-bind the
same transition, plan, receipt, committed pair, finalization, and service
evidence. `source_restored` records a failed requested operation, never success.

The receipt-free first-pair exception is not generic replay authority. Its v2
journal carries a transition-digest-bound `bootstrap_admission` containing the
named establishment mode, target and immutable predecessor release IDs,
candidate-record digest, and candidate-floor digest. Every recovery entry point
revalidates that exact floor, cross-binds the target authority, verifies the
predecessor inventory, and repeats the final predecessor process census. A
generic recovery command cannot infer a missing admission or accept a
caller-supplied predecessor.

The user-owned serialization lock prevents accidental cross-agent ambiguity; it
is not a defense against a malicious process already running as the Mac owner.
The root-owned release, strict operation allowlist, digest binding, and
root-owned replay receipt are the security boundary against request
substitution.

## Migration

The first release containing the broker cannot authorize its own installation.
`deploy-host-controller.py bootstrap-authorization` is the single explicit
bootstrap path. It prints and displays the declared agent/session, purpose,
aggregate release identity, source digests, and exact installed/replacement
stable-launcher hashes before using terminal-bound `sudo` to publish the first
protected broker. The approved manager bytes are loaded by an isolated
(`python -I`) fixed bootstrap loader that verifies their digest before
compilation. The isolated loader and manager together verify every binding,
perform the narrowly typed pre-pair launcher bootstrap when required, and only
then publish the bound broker release. If a
crash lands between those steps, a rerun binds the already-migrated launcher as
both installed and replacement and safely completes publication. Bootstrap
refuses once the broker is installed. Once
`host-release-launcher-pair-fence-v1` is active, ordinary deploy and rollback
change the release and launcher only as one protected Touch-ID-authorized pair;
standalone launcher migration is rejected.

PKI rotation requires `--requesting-agent` and `--requesting-session`. Both the
begin and commit anchor transitions receive distinct nonces and purposes. A
rotation cannot silently fall back to the old generic AppleScript command.

## Alternatives rejected

A cosmetic wrapper around arbitrary `sudo` or AppleScript commands would improve
labels but leave command substitution, replay, and mutable root execution. It is
not a security boundary.

A signed macOS application with a dedicated XPC privileged helper could provide
stronger code-signing identity and richer window management. It also adds a
signing, notarization, helper-installation, and update authority that this local
lab does not currently operate. The protected release broker provides the
needed request binding without adding that supply chain. A signed application
remains a possible future UX layer over the same request protocol.

## Acceptance

Acceptance requires tests for prompt-field binding, cancellation, concurrent
request exclusion, strict operation schemas, expiration, mutation, replay,
protected-release tampering, content-minimized receipts, process-group
termination on timeout, exact Host target-plan binding, PENDING launch denial,
and crash replay across different launcher generations. Production acceptance
additionally requires first-person install and rollback Touch ID ceremonies and
independent inspection of their receipts, STABLE records, terminals, launcher
identities, tree identities, and service evidence. No test claims that a
declared model identity is independently authenticated.
