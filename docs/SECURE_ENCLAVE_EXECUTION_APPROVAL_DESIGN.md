# Secure Enclave Execution-Approval Signing

## Status

Implementation, signed-bundle verification, staged deployment, forward
rotation, an actual Mac reboot, end-to-end approved and cancelled acceptance,
final commitment, software-key retirement, boundary verification, and the
postdeployment completion audit are complete for generation epoch 2. The
retained evidence matrix documents the automated and live proof for each gate;
current-generation expiry and destructive macOS availability/invalidation
variants remain open evidence items. This DDD replaces the extractable host
Ed25519 execution-approval key with a non-exportable Secure Enclave P-256 key.
It changes only the approval-signing authority and verifier. Request binding,
Research replay prevention, evidence semantics, and Target containment remain
independent enforcement layers.

## Security objective

An execution approval must be signed only after the operator authorizes that
exact request with Touch ID. The signing private key must never exist as host
filesystem bytes or as exportable process memory. Research must accept only the
configured Secure Enclave key generation and the exact signature algorithm.

The signed attestation continues to bind:

- the approval UUID, root-issued run UUID, and Claude session UUID;
- the registered source UUID and source-manifest digest;
- the submitted code digest;
- every fixture path, byte length, and digest, plus their aggregate digest;
- the timeout and immutable Target runtime-image digest;
- the outer operator-authorization request UUID and protected host release; and
- the Secure Enclave key generation, public-key digest, and signature algorithm.

Approval remains short-lived and at most once. Cancellation, expiry, signature
or key substitution, replay, incomplete migration, and recovery ambiguity fail
closed before Target execution.

## Threat model

This DDD adds protection against offline copying or later extraction of the
approval private key, including by a process that obtains host root filesystem
access. The Secure Enclave performs the private operation and exposes only a
signature.

The host OS and its root-controlled protected release remain in the trusted
computing base. Secure Enclave storage does not make a fully compromised live
host trustworthy: host root can deny service, replace displayed information,
or attempt to induce the operator to authorize a malicious request. Exact
display, signed-code verification, the system biometric prompt, Research's
independent request equality checks, and the pinned public key reduce those
risks but are not hardware remote attestation of the whole Mac.

The design specifically rejects these weaker substitutes:

- wrapping the existing Ed25519 private-key file with Keychain encryption;
- retaining an automatic software-key fallback;
- treating a standalone Touch ID success as authority for a later root signing
  operation;
- trusting a public key supplied inside the same envelope it verifies; or
- allowing an older host release to reactivate the retired software key.

## Cryptographic profile

Apple Secure Enclave signing supports NIST P-256 rather than Ed25519. The new
profile is therefore:

- key: Secure Enclave P-256 signing private key;
- access control: `WhenPasscodeSetThisDeviceOnly`, `privateKeyUsage`, and
  `biometryCurrentSet`;
- signing API: `SecKeyCreateSignature` with exactly
  `SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256`;
- signature wire format: strict ASN.1 DER `ECDSA-Sig-Value`, canonical base64,
  no whitespace, no trailing bytes, positive minimally encoded `r` and `s`,
  and low-S required (`s <= n/2`). Because Security does not promise low-S,
  the UI strictly parses the returned DER, validates `1 <= r,s < n`, replaces
  `s` with `min(s, n-s)`, and re-encodes canonical DER before base64; root and
  Research independently enforce the same canonical low-S rule;
- signed bytes: the SecureSandbox canonical JSON profile: recursively sorted
  object keys, compact separators, finite JSON values, ASCII-only signed
  identifiers and fixture paths, UTF-8/ASCII bytes, no BOM, and no trailing
  newline. This deliberately constrained profile is implemented identically by
  Python, Swift, and `jq`; it does not claim unrestricted RFC 8785/JCS support;
- public key: the uncompressed ANSI X9.63 point returned by Security is
  deterministically wrapped in the fixed P-256 SubjectPublicKeyInfo DER
  structure; SHA-256 is over those DER bytes, while PEM is display/transport
  encoding only;
- envelope namespace: `secure-sandbox-execution-approval-v2`.

`biometryCurrentSet` deliberately invalidates key use after Touch ID enrollment
changes. That condition enters the explicit rotation/recovery flow; it never
falls back to a password or software key.

## Authority split and protocol

```text
Research execution broker
  -> exact pending approval through the host-initiated forced-command relay
  -> protected host authorization broker writes one canonical request document
  -> signed macOS UI verifies and displays every security-relevant field
  -> operator chooses Approve
  -> UI loads the configured Secure Enclave key generation
  -> Secure Enclave signing operation requires Touch ID for the current set
  -> UI sends the signed v2 envelope over the local authenticated socket
  -> root broker verifies peer code identity, request equality, key generation,
     public-key digest, ECDSA signature, freshness, and one-time request state
  -> host relay delivers the verified envelope to Research
  -> Research independently repeats exact equality, pin, signature, freshness,
     and atomic O_EXCL replay checks before contacting Target
```

For `execution-approval-sign`, the Secure Enclave signing operation itself is
the biometric authorization event. The UI must not first authenticate and then
ask a different process to sign. General privileged operations keep the
existing Touch ID authorization behavior.

The local socket protocol becomes versioned. A v2 execution-sign message
contains only the outer request UUID and digest plus the signed envelope. The
root service binds the connection to the exact protected UI path, Team ID,
bundle identifier, designated requirement, hardened-runtime state, and pinned
entitlements. It additionally validates the envelope against the canonical
root-owned request before emitting it. No caller-provided public key is trusted.

Every execution approval creates a fresh `LAContext`, sets
`touchIDAuthenticationAllowableReuseDuration` to zero, uses that context for
exactly one `SecKeyCreateSignature` call, and invalidates it immediately after
success or failure. A prior biometric success can never authorize a second
signature.

## Key state

The private key is a permanent Secure Enclave key in the Data Protection
Keychain of one configured operator UID under a versioned application tag. It
is never exported. Key creation uses one exact dictionary containing Secure
Enclave token, EC P-256 key type/size, permanent storage, exact application
tag, exact access group, Data Protection Keychain selection, and the access
control flags above. Lookup uses its own exact supported query: private-key
class, application tag, access group, EC key type, Data Protection Keychain,
a bounded `kSecMatchLimitAll` result, and an `LAContext` supplied only for the
sign operation. The UI requires exactly one returned `SecKey`/attribute record;
zero, two, an over-limit result, or any malformed result fails closed. After
lookup, it validates all available key attributes, derives the public key,
reproduces the canonical SPKI DER and digest, and matches every root-owned
generation field before signing. Creation-only attributes are never assumed to
be valid search predicates.

The key's access group is exclusive to the authorization UI and appears in the
UI's signed `keychain-access-groups` entitlement together with the exact
application identifier derived from the locally configured Team ID and bundle identifier
`org.zebeth.SecureSandbox.AuthorizationUI`. The host release pins those
entitlements, the UI designated requirement, the eligible embedded macOS
provisioning profile, and every member of the signed app bundle. The Release
build suppresses Xcode's development-only `get-task-allow` entitlement. No broker, CLI, helper, test
binary, or differently signed build receives the access group. Deployment
fails if macOS cannot enforce this access-group policy for the selected
Data Protection Keychain item; there is no legacy ACL or software fallback.

Before building, copy `Signing.example.xcconfig` to the ignored
`Signing.local.xcconfig` beside it and set the local Apple Developer Team ID.
The build derives the effective team, application identifier, and access group
from the signed product and provisioning profile, then records that policy in
the immutable bundle manifest. A signing-identity change therefore changes the
release identity and requires the explicit approval-key rotation path.

The configured operator UID is root-owned deployment state and immutable
during a key generation. Key creation, lookup, and signing are rejected for a
different login UID or session. Multi-user operation requires a distinct,
explicitly migrated generation per authorized UID and is out of scope for the
first deployment.

The host keeps only root-owned public metadata:

- schema and key-generation UUID;
- algorithm and access-control profile;
- canonical public key and SHA-256 digest;
- creation and activation timestamps; and
- authorized operator UID, application tag, access-group identifier, and the
  immutable Host release ID whose manifest and verifier pin the exact UI
  designated requirement and entitlements;
- lifecycle state: `prepared`, `active`, `revoked`, or `retired`.

Research stores the corresponding root-owned public key, generation UUID,
algorithm, and digest. An envelope is invalid unless every one of these fields
matches its configured active generation.

## Migration and rotation transaction

Migration is an explicit, resumable, quiesced transaction. Admission closes
before it begins, remains closed through both activations and cold-boot proof,
and reopens only after both authorities durably commit. The transaction cannot
start while a run is active or a pending execution approval exists. Each Host
and Research transition is a compare-and-swap from an expected prior phase.
Every record binds the transaction UUID, old and new generation UUIDs and
integer epochs, algorithm, SPKI DER digest, Host and Research release IDs,
configured operator UID, and expected prior phase.

Canonical journal records are root-owned regular files (`root:wheel 0600` on
Host and `root:root 0600` on Research) beneath fixed, non-symlink directories.
Each transition writes a new canonical JSON file with `O_NOFOLLOW|O_EXCL`,
fsyncs the file and containing directory, atomically replaces the phase
selector, fsyncs its directory, and verifies the reread bytes before exposing
the next phase. Each key generation has a random identity UUID and a strictly
increasing unsigned integer epoch. A root-owned monotonic minimum-protocol/epoch
floor is advanced with the same durability discipline. Protected releases and
Research deployments must refuse to start if older than that floor, and no
recovery path may lower it.

1. **Predeploy v2-capable Research code.** While v1 remains active, Research
   installs and hash-verifies the broker, transition manager, and run-admission
   implementation that understand the fenced and v2 states. No floor advances.
2. **Prepare host generation.** The signed UI creates a new Secure Enclave key,
   proves possession by signing the canonical preparation record, and the root
   broker validates and records the pending public generation.
3. **Prepare Research trust.** Research receives the exact pending public key
   and generation through the typed control plane. It verifies the deployment
   artifact but does not yet admit it for execution.
4. **Fence Research.** Under the same exclusive lock used by run admission,
   Research proves there are no lifecycle markers, agent processes, or pending,
   claimed, or delivered approval responses; it then writes and fsyncs the
   fence before stopping and independently proving the broker inactive. Research enters a durable transition state that accepts
   neither v1 nor v2 execution approvals. The stopped broker and closed run
   admission are independently verified before Host activation.
5. **Activate host generation.** The root broker atomically selects the pending
   generation, advances the Host minimum-protocol/epoch floor to v2 and the new
   epoch, and marks v1 revoked. From this boundary it cannot issue v1/software
   signatures.
6. **Activate Research generation.** Research atomically selects the exact same
   generation and v2 algorithm, advances its minimum-protocol/epoch floor, and
   restarts the broker in fenced verification mode. It can validate only v2
   from that generation, but normal execution admission remains closed.
7. **Issue one exact acceptance permit.** The Host first authorizes one exact,
   append-only acceptance-attempt record. Research verifies that Host proof,
   keeps the global migration fence in place, and writes a separate root-owned permit for the generated
   run/session pair. The permit binds the source, code digest, empty or exact
   fixture manifest, timeout, runtime image, generation, and expiry. Run
   admission atomically consumes this permit under its normal lifecycle lock;
   every other run remains denied. The execution broker independently repeats
   every equality check and durably claims the attempt-specific marker before
   it requests approval or contacts Target. Cancellation, expiry, Target
   failure, or an interrupted run leaves immutable attempt history. A retry
   requires a new Host-authorized attempt UUID and run/session pair, the next
   integer attempt number, and the SHA-256 binding of its predecessor. It is
   allowed only while the Host remains uncommitted, Research remains fenced and
   quiescent, the prior permit is consumed or expired, and no exact successful
   receipt exists.
8. **Reboot and prove real execution.** Deployment stops at a root-independent
   checkpoint while v1 remains revoked but its file has not been deleted. The
   protected Host migration record already contains the pre-activation
   `kern.boottime` identity. An actual Mac reboot is required. The resume
   command compares `kern.boottime` as an early check, while the root Host
   correlation operation independently reads the current boot identity,
   requires it differ from the protected preboot value, and seals both digests
   into the protected verifier artifact. Therefore changing the user-owned
   checkpoint cannot satisfy the reboot gate. The resume command then
   re-runs the full boundary suite, and launches the exact pre-authorized
   run/session in the operator's current terminal. A successful real
   `run_python_fixture` must yield one v2 approval consumption record and one
   measured-execution receipt whose generation, request, runtime, and content
   digests all match the acceptance journal.
9. **Correlate, test negatives, and commit.** The Host correlates that Research
   receipt with exactly one Host `execution-approval-sign` receipt and stores a
   root-owned verifier artifact. Commit reopens and hashes that protected
   artifact; a caller-supplied digest is insufficient. A fresh post-reboot
   signature then proves wrong-key and replay rejection, and a distinct fresh
   request must open a new biometric prompt and be cancelled. Cold-boot and
   boundary evidence is persisted in the checkpoint before both journals
   commit. Research removes the exact permit and global fence only after the
   consumed permit is verified.
10. **Retire software authority.** The old Ed25519 key is already cryptographically
   revoked by both monotonic floors. Its filesystem entry is deleted, absence
   and lack of any executable v1 signing path are verified, and only then is a
   final retirement receipt written. The design makes no claim that SSD blocks
   are physically securely erased; safety comes from permanent v1 rejection.

Before Research is fenced, rollback may discard the pending generation and
leave the current authority unchanged. Once Research is fenced, recovery may
only resume the recorded transaction forward or restore pre-fence v1 on both
authorities while the Host v2 floor has not advanced. Once Host advances to
v2, rollback to v1 is impossible: recovery either completes Research v2
activation for the recorded generation or remains safely unavailable. After
commit, rollback means a new forward key-rotation transaction. It never
reactivates a retired generation, the software key, or a v1-only protected
release.

On reboot, both authorities reconcile only records with identical transaction
and generation bindings. Missing, conflicting, noncanonical, partially
durable, or unexpected phases keep admission closed. A locked login Keychain,
absent console user, wrong operator UID, unavailable Secure Enclave, absent
device passcode, unavailable biometrics, enrollment-invalidated key, missing
key, or public/private mismatch is a hard unavailable state. Recovery never
creates or substitutes a key implicitly; a new key requires an explicit,
operator-authorized forward rotation transaction.

Acceptance-attempt recovery distinguishes two expiry cases without ambiguity.
If the immutable Host authorization artifact was fsynced before interruption,
exact redelivery reuses its original authorization timestamp and repairs the
pending selector even after the attempt TTL has elapsed. If no artifact exists,
the Host returns a bounded `not_issued_expired` proof without changing either
the history or selector; only that result permits the orchestration checkpoint
to replace the unissued plan at the same sequence/CAS position. Research also
reconciles the receipt-publication boundary: one exact, fully validated durable
success receipt idempotently promotes a broker-owned `claimed` or `failed`
attempt marker to `succeeded`, so a crash between receipt fsync and marker
finalization neither re-executes code nor strands migration.

The acceptance run's Gateway lease is issued before Host authorization, and
the acceptance expiry is copied from that exact lease.  Research therefore
never receives a lease whose authority outlives the one-time acceptance
permit.  Before lease issuance, the orchestrator fsyncs a draft containing the
fixed attempt, run, and session identities; a lost lease response reuses that
run identity.  If the lease expired after issuance but before the draft was
materialized, only a finalized zero-use summary permits replacement identities
at the same unissued attempt number.  Host authorization is then fsynced into
the checkpoint before the Research compare-and-swap.  On restart, an expired
Host-authorized record is applied idempotently to Research as terminal history
before the next append-only attempt is created; an unissued expired record is
the only case that may be replaced in place.

Rotation uses the same phases with a new Secure Enclave generation. The prior
generation remains usable only for bounded transaction recovery before Host
activation advances the minimum floor; afterward it is unusable even if the
new transaction has not completed. Biometric-enrollment invalidation, missing
keychain state, key substitution, and public/private mismatch all require this
explicit operator-authorized rotation path.

## Research verification and replay safety

Research verifies the canonical attestation with the pinned P-256 public key
and exact algorithm. It parses DER strictly, rejects non-minimal integers,
negative or zero/out-of-range values, high-S signatures, trailing bytes,
noncanonical base64, algorithm confusion, malformed SPKI, and any envelope
whose canonical attestation bytes differ by even one byte. Swift-generated
cross-language vectors fix X9.63-to-SPKI conversion and signature verification
behavior. It rejects v1 envelopes whenever fenced and permanently after its
minimum-protocol floor reaches v2. It then creates the existing root-hidden
0600 consumed marker with `O_CREAT|O_EXCL|O_NOFOLLOW`, performs a bounded
complete write, fsyncs and closes the marker, and fsyncs the consumed-record
directory before Target contact.

The public-key generation becomes part of the consumed record and measured
receipt. Ordinary approvals remain at most once. Migration acceptance uses the
append-only attempt protocol above: a failed attempt can be replaced only by
the next Host-authorized CAS-bound attempt, while any exact durable success is
reconciled and categorically prevents retry. Lost host responses may redeliver
only the same content-bound pending request; they do not mint a second
signature or consumed record.

## Evidence

Measured-execution receipts remain content-free and add:

- signing-key generation UUID;
- signing public-key SHA-256;
- signature algorithm identifier; and
- signed-attestation SHA-256.

The Host also emits a content-free authorization receipt containing request and
approval UUIDs, outcome (`approved`, `cancelled`, `expired`, or `rejected`),
transaction/key generation, SPKI digest, algorithm, and attestation digest.
Migration, rotation, and retirement emit content-free receipts containing the
transaction UUID, old/new generations, phase, both release IDs, public-key
digest, algorithm, prior-record digest, outcome, and timestamp. Research's
measured receipt carries the Host approval UUID and attestation digest so the
two ledgers remain durably correlatable after the transient envelope is gone.
Before a forward rotation correlates its acceptance, a bounded root-only
repair validates the predecessor singleton's generation and release identity
against the archived committed journal, and validates the persisted acceptance
phase receipt's journal digest against that committed journal's prior-record
digest, before moving it to a transaction-addressed immutable history entry. This
preserves predecessor evidence while letting the unchanged, release-pinned
Research verifier create the current generation's singleton; malformed,
substituted, conflicting, or over-capacity history fails closed.
The correlation verifier is itself a protected, canonical artifact. Its digest
is mandatory commit input and commit independently recomputes that digest and
checks its transaction, generation, release, and acceptance-binding fields.

No receipt contains code, fixture bytes, output content, biometric data,
private-key material, or the Secure Enclave keychain representation.

Each committed generation also produces a canonical root-owned `0644`
completion receipt beneath a root-owned, non-listable `0711` directory. Its
transaction-addressed name is the only public lookup surface. The receipt binds
the generation/epoch, algorithm, public-key digest, Host and Research release
identities, previous generation, Research activation digest, cold-boot evidence
digest, acceptance binding, and the root-validated acceptance verifier; its own
digest covers the canonical object. Retirement advances the same receipt from
`committed` to `software_retired`. Before a forward rotation replaces pending
state, the prior private migration record and acceptance verifier are durably
archived and the public completion receipt is revalidated or published. The
final auditor queries both the current and predecessor receipts through the
immutable broker and rejects user-checkpoint evidence that differs from those
root-produced commitments.

## Acceptance gates

1. Swift tests prove canonical v2 attestation/envelope construction, exact
   Security algorithm selection, strict DER/base64 handling, zero biometric
   reuse, one-context/one-signature behavior, and no fallback branch.
2. The production UI creates and looks up the key using the exact documented
   Security.framework dictionaries, requires one result, validates returned
   attributes and public identity, and explicitly rejects any successful
   private-key external representation. Live preparation and signing exercise
   those production paths. The final review must treat differently signed
   helper isolation, ambiguity rejection, and locked/enrollment-changed behavior
   as live negative gates where macOS does not expose a safe unit-test seam.
3. Availability tests prove absent Enclave, passcode, Touch ID, console/login
   session, unlocked configured Keychain, or current enrollment fails without
   password, implicit recreation, or software signing.
4. Host tests prove exact peer path/code identity/designated requirement and
   entitlement pinning, public-key pinning, public/private match before every
   sign, preparation proof validation, CAS migration, minimum-floor enforcement,
   and verified software-key retirement.
5. Research tests prove exact P-256 verification, cross-language Swift vectors,
   X9.63-to-SPKI conversion, malformed/noncanonical DER and base64 rejection,
   forced-high-S normalization/rejection, algorithm/key-generation substitution
   rejection, expiry, cancellation, and atomic replay rejection.
6. Multi-user, locked-Keychain, biometric-enrollment-change, and reboot tests
   prove only the configured UID/generation can sign and all ambiguous states
   keep admission closed.
7. Crash injection covers every file and directory fsync, selector CAS,
   Research fence, Host activation, Research activation, key deletion, receipt
   publication, and lost-response boundary. It proves the consumed marker's
   directory entry survives every crash after the directory-fsync boundary and
   that Target is never contacted before that boundary.
8. The staged harness must stop before commit, survive a real Mac reboot, admit
   only its exact TTL-bound acceptance run, correlate the Host and Research
   receipts, pass wrong-key and replay checks, require a new biometric event for
   a second request, and only then commit and retire the old software key.

The user-owned orchestration checkpoint is not an authority. It is a durable
restart cursor whose exact transition records are persisted and fsynced before
they cross the control boundary. Every resumed mutation is revalidated by the
root Host or Research compare-and-swap state. The deploy, resume, and finalize
harnesses fsync checkpoint files and their containing directory. Resume first
asks Research whether the exact successful acceptance receipt already exists,
so a lost shell or SSH response after execution does not relaunch or replay the
run. Finalize similarly persists the exact committed Research record before
Host commit and reuses it after interruption.

### macOS 27 foreground-launch recovery

The initially activated generation was bound to a signed app bundle whose
executable was spawned directly. macOS 27 could start that process without
granting it a foreground application/window, so authorization timed out even
though the process existed. The corrected UI uses a real `NSApplication`
delegate lifecycle, presents only from `applicationDidFinishLaunching`, owns
and explicitly fronts its modal window, and writes an O_EXCL 0600 canonical
result sidecar binding the request UUID, request digest, and exit status. The
request wrapper registers and opens the exact protected bundle through
LaunchServices and treats missing, malformed, substituted, or late results as
failure.

The already-active predecessor cannot be silently rebound to that corrected
Host release: its Host release identity is part of both Host and Research
trust. Recovery therefore uses the exact predecessor bundle-manifest digest
only for a bounded allowlist of schema-checked *successful* responses needed
to correlate and commit the in-flight generation. Missing output is never
interpreted as cancellation or success. That generation is recorded as a
bridge, its software-key deletion and cancellation gate remain deferred, and
the checkpoint is archived rather than deleted. The corrected Host release is
then installed and a new explicit forward-rotation transaction creates a new
Secure Enclave generation and advances both monotonic epochs. Cancellation,
approved execution, cold boot, and software-key retirement are mandatory on
the corrected rotation generation before the DDD can be complete.

9. Rollback tests prove old Host/Research releases, v1 envelopes, retired
   generations, and attempts to lower either minimum floor are rejected.
10. Static inspection proves no private-key file, export command, legacy
   Keychain fallback, password fallback, or software-signing fallback exists in
   the committed v2 path.
11. Boundary verification proves matching active generations, algorithms,
    public-key digests, minimum floors, and UI entitlement hashes on Host and
    Research while Target containment remains unchanged.
12. Live acceptance includes cancellation, expiry, one approved harmless
    execution with durable Host/Research receipt correlation, a second-sign
    attempt without a new biometric, and deliberate wrong-key and replay
    rejection.
13. Cold boot proves the configured Keychain and key are never accessed before
    the reviewed UI requests one signature, Touch ID is required, and all three
    authorities return to the same committed generation.
14. An independent review traces the implementation rather than relying on the
    acceptance narrative.

## Platform basis

The design uses Apple's documented Secure Enclave P-256 signing support and
Security-framework access-control flags. Secure Enclave availability is a hard
deployment prerequisite. Restricted keychain entitlements also require a
properly provisioned macOS app bundle; macOS rejects a standalone signed Mach-O
before launch. This Mac reports `SecureEnclave.isAvailable == true`.

