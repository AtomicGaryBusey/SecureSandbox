# Protected Release Build Principal and Signing Custody DDD

Status: backlogged architecture and attended feasibility gate; required before
SecureSandbox claims hostile-local-peer-resistant or public-distribution-grade
source derivation

## Decision

SecureSandbox will separate ordinary interactive development from production
release compilation and signing. A Developer ID signature proves which key
authorized bytes; it does not prove that an active process sharing the signing
user's UID could not transiently alter compiler input or output. The normal
login account is therefore a **trusted signing principal** suitable for bounded
operator-local acceptance only. Its receipts must say so explicitly.

A production-grade release instead requires one protected transaction:

1. root imports an exact, receipt-bound source capsule into root custody;
2. a fixed non-login build UID with no pre-existing processes compiles only
   that capsule in private scratch;
3. root waits for and reaps the complete build process tree, proves the build
   UID has no remaining processes, imports every output by descriptor, and
   changes the complete generation to root custody;
4. the signing step modifies only those exact root-custodied bytes;
5. notarization uploads that exact signed carrier, and root staples and
   independently verifies the returned ticket; and
6. publication imports only the same protected generation.

Failure, ambiguous process ancestry, unexpected build-UID activity, changed
identity, missing key custody, unavailable attestation, or any mismatch leaves
the generation non-admitting. There is no bypass or automatic signing,
notarization, installation, or publication.

## Why the ordinary login UID is insufficient

The release source can be copied to a read-only disk image and every resulting
digest can be signed, but macOS permits the mounting user to force-detach that
image. More importantly, SwiftPM necessarily uses writable build state. An
active process with the same UID can transiently change copied compiler input
or a derived executable, allow `codesign` to authorize the altered bytes, and
restore a clean-looking source tree around phase-boundary checks. A receipt
that names clean source cannot close that gap.

This is not a defect in Developer ID. It is a custody boundary: a compromised
signing principal can ask its own key to sign attacker-selected bytes. Source
archive hashes, notarization, Gatekeeper, and a detached receipt remain
necessary, but none substitutes for separating the build/signing principal
from ordinary same-UID workloads.

## Signing-custody branches

### Preferred feasibility branch: existing key, protected root signer

The first attended experiment uses only an Apple Development identity and a
disposable test artifact. It determines whether root can run `/usr/bin/codesign`
inside the operator's GUI security/audit session with `launchctl asuser`, retain
root write custody over the test artifact, and obtain the normal local Keychain
authorization UI without exporting a private key.

Success permits the existing Developer ID private key to remain in the
operator's login Keychain while a narrowly scoped root signer modifies exact
root-owned outputs. The production design must still prove the process UID,
audit session, executable identity, key/certificate fingerprint, input
descriptor identity, output identity, timestamp, and final CDHash.

### Fallback branch: dedicated signer keychain and identity

If the existing-key experiment fails, the protected signer receives an
explicit file-based keychain and preferably a newly issued Developer ID
identity created for that principal. Exporting the existing identity as
PKCS#12 is a migration fallback, not the preferred steady state, because it
expands private-key exposure. Keychain password provisioning, unlock lifetime,
backup, rotation, revocation, and recovery require their own root-owned,
content-free receipts. Secret values never enter repository files, logs, chat,
command lines, or retained public evidence.

A smart-card-backed signing key, including a future YubiKey PIV ceremony, may
strengthen human/key custody. It does not by itself prevent compiler-output
substitution and therefore cannot replace the protected build transaction.

## Exact source capsule

The capsule binds:

- the public-release commit and literal authorized remote identity;
- deterministic Git archive SHA-256 and closed extracted-tree SHA-256;
- the reviewed untracked signing configuration by digest;
- the exact release-driver and dependency-lock bytes;
- a closed path/type/mode/size/hash inventory; and
- the intended Team ID and certificate fingerprint.

Root creates the capsule without executing repository code, publishes it by
no-replace identity-bound operations, fsyncs it, and makes it unreadable for
mutation by the development UID and build UID. The build UID receives read
access only. The source capsule, build transaction, signed generation,
notarization submission, stapled carrier, and publication record form one
cross-digested chain.

## Build-principal lifecycle

The build UID is non-login, fixed, non-admin, network-denied during compilation,
and owns no long-lived service. Before and after each build, the controller
performs a system-wide UID process census. Any unexpected process blocks the
transaction. The controller owns the build process tree, uses bounded resource
limits and deadlines, denies ambient environment and toolchain overrides, and
requires exact descendant absence before importing outputs.

Compilation and notarization are separate phases. Compilation has no provider
or notarization egress. The signing/notarization phase receives only the exact
protected generation and narrowly scoped Apple endpoints. No release step can
fetch source dependencies or reinterpret a mutable checkout.

## Receipt and UI semantics

Every signed carrier receipt and Touch ID review displays one closed custody
classification:

- `trusted-login-principal-v1`: operator-local acceptance only; active
  same-login-UID resistance is not claimed; or
- a future `protected-build-principal-v1`: admitted only after this DDD's live
  acceptance evidence passes.

The signed carrier receipt binds the source archive/tree digests, certificate
fingerprint, notary submission, product identities/CDHashes, custody class, and
release commit. A separate canonical candidate record binds the retained
generation path, device, inode, and whole-tree digest to those receipt facts.
The GUI reviews both without pretending that either replaces the other, and it
must never collapse a trusted-login-principal build into the stronger protected
classification.

## Acceptance gates

Production-grade completion requires all of the following:

1. the Apple Development feasibility probe modifies only the exact root-owned
   test artifact and retains content-free evidence;
2. the selected signing branch proves exact key/certificate custody without
   exposing private material;
3. hostile development-UID processes cannot write, rename, remount, or replace
   source, scratch, unsigned output, or signed output;
4. injected build-UID siblings, descendants, PID reuse, compiler crashes,
   timeout, and controller death all fail closed with exact process absence;
5. source and product substitution at every descriptor/path boundary is
   rejected before signing or publication;
6. the same protected generation is independently verified before signing,
   after signing, after notarization, after stapling, and after publication;
7. reboot and crash replay resume only exact durable state and never repeat a
   signing or publication authorization implicitly; and
8. repository publication, secret checks, independent security review, and
   identical reviewed remote tips pass.

Until those gates pass, SecureSandbox may use the existing login principal for
an explicitly labeled local test installation. That evidence must not be cited
as public-release-grade supply-chain attestation.

## Primary platform references

- Apple, [Code Signing Guide: Procedures](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
- Apple, [TN3147: Migrating to the latest notarization tool](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool)
