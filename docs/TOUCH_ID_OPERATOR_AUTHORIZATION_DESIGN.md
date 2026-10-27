# Touch ID Operator Authorization

## Decision

SecureSandbox may authorize an already allowlisted host mutation with Touch ID,
but biometric success is not root authority.  A code-signed, hardened native
macOS program owns the visible ceremony and LocalAuthentication call.  A
separate root-owned broker owns the Unix socket, validates the connecting
process against the exact UI bytes in the active immutable release, and then
performs the same request, release, operation, expiry, and replay checks used by
the administrator-password path.

The approval window makes the choice explicit: **Approve with Touch ID**,
**Use Administrator Password**, or **Cancel**.  It displays the declared agent,
declared session, purpose, resource, operation, request digest, one-time nonce,
expiry, and the operation-specific parameters.  The password button returns to
the existing macOS administrator-password ceremony; biometric failure never
silently falls back to a password prompt.

Negative acceptance uses a separately bound **cancel-test** ceremony. Its
window is visibly titled as a cancellation test, instructs the operator not to
authenticate, and exposes no approval path. Terminal failures produce the
content-free retry disposition defined in
`OPERATOR_CEREMONY_DIAGNOSTICS_DESIGN.md`.

## Threat model

The design protects against an agent or other unprivileged process substituting
a different request after approval, replaying an approved request, claiming
that a biometric prompt succeeded, or sending an arbitrary root command.  It
also prevents one of several concurrent agent sessions from hiding which
session and purpose caused the prompt.

The Mac owner remains the trust anchor.  This does not defend against a user
who can modify root-owned files, a compromised kernel, compromise of the
signed UI while it is executing, or coercion of the operator.  The agent and
session labels remain operator-declared rather than OS-attested identities.

## Components and authority

`touchid_authorization_ui` is a native Swift/AppKit application bundle. It is
signed with the hardened runtime, contains an eligible embedded macOS
provisioning profile, and is installed as a read-only tree in the immutable
host-controller release. A canonical bundle manifest binds every regular file,
mode, size, and SHA-256 into the release identity. It parses the canonical request itself, recomputes
its SHA-256, renders the security-relevant fields, and uses
`deviceOwnerAuthenticationWithBiometrics`.  It can only submit the nonce and
digest that it displayed.

`authorization_broker serve-touchid` is a root launch daemon.  Its socket is
available to local users, but possession of the socket grants no authority.  On
each connection it obtains the kernel-supplied peer audit token, resolves the
executable from that audit token, and requires it to be the exact root-owned,
code-signed UI executable inside the exact manifest-bound app bundle in the
broker's own verified release.
It then derives the request path from the peer UID and invokes the existing
privileged validation and operation dispatcher.

The privileged broker, not LocalAuthentication, decides whether an operation
may run.  It accepts no command string.  It independently checks canonical
request bytes, UID, nonce, digest, three-minute expiry, typed parameters,
resource mapping, immutable release manifest and payloads, and the root-owned
exclusive receipt before constructing an allowlisted argv.

## Protocol

The UI sends one bounded canonical JSON line containing only the protocol
schema, request ID, and request SHA-256 after successful biometric evaluation.
The broker derives the UID from the peer audit token; a caller cannot nominate
another account.  The broker returns a bounded binary response containing exit
status plus stdout and stderr lengths and bytes.  Initial reads, operation
execution, and the UI process all retain independent deadlines.

The request nonce is UUIDv4 and the request lifetime is 180 seconds.  The
existing root-owned `O_EXCL` receipt remains the replay barrier.  Receipts add
an authorization-method field so Touch ID and administrator-password approvals
are distinguishable without recording biometric data.

## Deployment and update

The Swift/Xcode source manifest and built signed app-bundle manifest are
separate release payloads, so the aggregate host-controller release identity
binds both. The unprivileged deployment wrapper builds and signs the app,
obtains or refreshes its eligible macOS profile, rejects development debugger
entitlements, and hashes its complete tree before calculating the prospective
release identity. The existing administrator-password broker then
publishes that exact release.  As part of publication, the release manager
atomically installs a root-owned LaunchDaemon property list, switches the
immutable `current` link, validates the release, and reloads the daemon.

The existing protected manager predates the four Touch ID payload names and
must not silently accept an expanded release schema.  The initial deployment
therefore uses `bootstrap-touchid-schema`: a one-time, exact-predecessor,
content-bound migration whose reviewed manager bytes and complete prospective
release ID are displayed before terminal-bound administrator authentication.
It refuses any predecessor other than the maintenance release schema.  Later
releases can use Touch ID because the already protected daemon only dispatches
requests through the strict current broker rules.

An authorization broker must not terminate itself while returning the result
of a host-controller update.  If launchd already has the service loaded, the
release manager atomically replaces the plist and current-release selector but
does not boot out the authorizing process.  After sending the bounded response,
that broker compares its resolved release with the new selector, exits, and is
restarted by launchd from the new immutable release.  First installation still
bootstraps the service explicitly.  This response-before-restart handoff is
covered by regression and live update acceptance.

The configured Apple Personal Team issues short-lived local provisioning
profiles. Publication requires more than 48 hours of remaining validity and
fails closed after profile expiry. Rebuilding and publishing the reviewed
release refreshes the profile without rotating the Secure Enclave key. This
renewal must be automated or replaced by a longer-lived eligible team profile
before unattended use.

## Failure semantics

Cancel, UI timeout, biometric lockout or failure, request parse or digest
mismatch, peer identity mismatch, unsigned or non-hardened UI code, protocol
framing errors, expiry, replay, release tampering, and operation failure all
fail closed.  The request file is removed by the requester on every terminal
path.  A crash after receipt creation leaves an executing receipt and remains
at-most-once, as in the password design.

Choosing administrator password is not an error and is the only fallback.  It
starts the existing password prompt with the same nonce and digest.  The
fallback is never automatic because an unexpected password prompt is itself a
confusion risk.

## Acceptance

Automated acceptance covers canonical parsing and display binding, explicit
fallback, cancellation, biometric failure, socket framing limits, kernel peer
identity, exact UI hash and signature checks, request expiry and mutation,
replay, receipt attribution, daemon installation modes, and unchanged password
behavior.  Live acceptance additionally requires inspection of the app's code
signature and hardened-runtime flags, one first-person Touch ID execution, its
root-owned receipt, explicit password fallback, cancellation, a live
response-before-restart release update, and a launchd restart check.
