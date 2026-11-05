# SecureSandbox In-App Updates DDD

Status: **implemented, production channel intentionally unprovisioned**. The
native update workflow and rejection controls are present. One separately
notarized Developer ID preflight is installed, but production update admission
remains unavailable until an exact current-source bootstrap embeds a separately
protected manifest-signing key and an operator-approved GitHub distribution
endpoint.

Decision owner: lab operator

The proposed multi-authority human identity, threshold release authorization,
TUF, transparency, and hybrid post-quantum evolution is intentionally deferred
to [the Human Identity and Release Authenticity DDD](HUMAN_IDENTITY_AND_RELEASE_AUTHENTICITY_DESIGN.md).

## Decision and scope

SecureSandbox Control Center may check for, review, download, install, and roll
back its own user-local application bundle. It does not update the protected
Host controller, Gateway, Research, Target, harness, plugins, provider
credentials, model profiles, or active sessions. Those components retain their
existing independently reviewed plans, authorization ceremonies, immutable
release stores, admission fences, and readback.

There is deliberately no automatic-update mode. An optional scheduled check
may fetch only bounded signed metadata and notify the operator. It cannot fetch
an artifact, prepare an installation, install on quit, schedule a mutation, or
create an install authorization. Manual download is a separate authority after
the signed release fields are visible. Installation is another separate action
and the external installer performs a fresh Touch ID-only check before any
bundle replacement. No configuration key, command-line option, or UI control
can convert a scheduled or manual check into download or installation.

GitHub is a delivery carrier, not a trust root. An authorized GitHub hostname
can serve bytes only after it is compiled into the signed update policy. TLS,
repository ownership, a GitHub workflow result, or an artifact attestation is
useful evidence but cannot replace the offline manifest signature, artifact
digest, Apple distribution identity, notarization decision, or monotonic
release policy.

## Security invariants

1. Production update policy is part of the signed app. It pins the HTTPS
   manifest URL, channel, Ed25519 key ID and public key, initial artifact
   origin, bounded GitHub redirect hosts, Developer ID Team ID, bundle ID,
   manifest limit, and artifact limit.
2. The manifest envelope contains the exact base64 payload bytes and an
   Ed25519 signature. Verification is over those bytes; reserialization is not
   trusted. Unknown or missing envelope, manifest, artifact, security, or
   compatibility fields reject.
3. The signed manifest binds release sequence, display version, build,
   publication time, minimum macOS, minimum directly updatable sequence,
   release commit, artifact URL, exact byte count and SHA-256, security impact,
   and separate Control Center/protected-environment compatibility statements.
4. Release sequence is the rollback authority. A candidate must exceed both
   the running bundle sequence and the retained accepted floor. Explicit
   rollback may start the retained predecessor but never lowers that floor.
5. Download uses an ephemeral session with no cookies or cache. Metadata has a
   128 KiB ceiling. Artifact transfer has a 256 MiB ceiling. Metadata redirects
   are refused. Artifact redirects are limited to three HTTPS hops and only to
   the policy's signed hostname set. Redirects cannot introduce credentials or
   fragments. The final artifact must independently match the manifest size
   and SHA-256.
6. A candidate bundle must contain the exact bundle identifier, signed update
   sequence, version, and build. Its tree cannot contain symlinks, devices,
   sockets, group/world-writable entries, excessive entries, or non-owner
   files. `codesign --verify --deep --strict`, the pinned Team ID and Developer
   ID authority, hardened runtime, absence of an ad-hoc signature, and
   Gatekeeper acceptance are all mandatory.
7. Verification has no bypass. There is no trust-on-first-use, alternate URL,
   add-certificate dialog, “Install Anyway”, local/ad-hoc fallback, or option
   to disable verification. A missing verifier, malformed sequence floor,
   changed certificate, unknown signing key, broken chain, failed Gatekeeper
   assessment, altered archive, or unavailable trust service bricks update
   admission until the trusted release path is repaired.
8. The external installer reads fixed user-local paths and fixed operations; it
   accepts no app path, URL, signer, policy, shell command, or rollback target
   argument. It re-verifies the envelope, artifact, candidate, current app, and
   fresh request, then performs its own Touch ID-only authorization. Directly
   invoking the helper does not bypass Touch ID or cryptographic admission.
9. The app retains no release private key, GitHub credential, Apple signing
   credential, provider credential, or notarization credential. The update
   signing secret is supplied only through `op-agents run` to the release
   signer. The release build requires a Developer ID identity and an existing
   `notarytool` Keychain profile.
10. Host and guest advancement never rides along with a Control Center update.
    The signed compatibility text can report that a protected change is
    available or required, but the Control Center installer has no authority
    to perform it.

## Architecture and authority flow

The app's `UpdateStore` owns only the current UI workflow. `UpdateAuthority`
maps scheduled and manual checks to `fetchSignedMetadata`, manual download to
`fetchArtifact`, and authenticated installation to
`installVerifiedArtifact`. These capabilities are disjoint rather than flags
on a common all-powerful update function.

1. A manual or due scheduled check loads the signed `UpdatePolicy.json`, makes
   one bounded request to its exact HTTPS URL, and verifies the envelope and
   monotonic manifest. A scheduled result may post a notification saying that
   review is available.
2. Settings displays the exact version, build, sequence, publication time,
   commit, byte count, artifact and envelope digests, classification, security
   summary, and compatibility statements. No artifact exists yet.
3. `Download Reviewed Artifact` makes the bounded artifact request. It verifies
   size and digest before extraction, admits exactly one `SecureSandbox.app`,
   rejects unsafe tree entries, and performs the complete distribution checks.
4. `Install with Touch ID` writes a short-lived request and starts the fixed
   bundled installer. The app then exits. The helper repeats all persistent
   checks, authenticates Touch ID with the exact version, sequence, and digest
   prefix in the reason, and waits for the old process to exit.
5. The helper atomically swaps the candidate and installed bundle on the same
   filesystem, moves the predecessor into one retained rollback slot, records
   each phase, and launches the candidate. The candidate commits a health
   record only when it is running from the fixed installed path with the exact
   journal version, build, and sequence.
6. If the health commitment does not arrive within 30 seconds, the helper stops
   the candidate, atomically restores the predecessor, retains the failed
   candidate for inspection, records automatic rollback, and relaunches the
   predecessor. A successful candidate advances the monotonic floor and keeps
   the accepted predecessor for explicit Touch ID rollback.

State files are owner-only beneath
`~/Library/Application Support/SecureSandbox/Updates`. Candidate, installed,
and retained predecessor apps live on the same user Applications filesystem so
`RENAME_SWAP` supplies the replacement commit point. These user-owned controls
protect against interruption, replay, accidental concurrent actions, and
untrusted release input. They do not claim to withstand a malicious process
that already has unrestricted control of the operator's macOS account. The
signature, pinned identities, and notarization boundary still prevent such a
process from turning arbitrary bytes into a trusted SecureSandbox release.

## Threat model and mitigations

| Priority | Scenario and capability gain | Required controls and result |
| --- | --- | --- |
| Critical | A compromised carrier substitutes a model, harness, helper, or app binary and gains the operator account's authority | Exact offline signature, artifact size/digest, bundle identity, Team ID, nested signatures, hardened runtime, and Gatekeeper must all agree; otherwise reject with no bypass |
| Critical | A release-system attacker steals the online GitHub credential and publishes a poisoned archive | GitHub cannot mint the offline manifest signature or Apple identity; unknown payload or archive rejects |
| High | A compromised Apple signing identity publishes a different app | The attacker still needs the offline manifest key and monotonic signed metadata; key separation prevents either credential alone from admitting a release |
| High | A compromised offline manifest key points to arbitrary signed software | Exact bundle ID, pinned Team ID, Developer ID authority, hardened runtime, notarization, manifest version/build binding, and safe-tree checks reject unrelated software |
| High | A server replays an older valid release | Sequence must exceed the installed/accepted floor; explicit rollback is limited to the locally retained predecessor and does not lower the floor |
| High | A malicious redirect exfiltrates cookies or downloads from another origin | Ephemeral no-cookie session; metadata never redirects; artifact redirects are HTTPS-only, count-bounded, and hostname-allowlisted; digest still binds final bytes |
| High | A malformed archive escapes staging or substitutes a symlink | The signed digest must first pass; extraction occurs in an owner-only unique directory; the output must be exactly one app and every admitted tree entry is owner-controlled, non-symlink, regular, and not group/world-writable |
| Medium | A crash leaves no launchable app or falsely reports success | Same-filesystem atomic swap, durable phase journal, bounded candidate health commitment, automatic predecessor restore, and explicit readback |
| Medium | A scheduled check unexpectedly mutates the installation | The scheduled trigger receives only `fetchSignedMetadata`; tests assert that it has neither artifact nor install capability |
| Medium | An operator or future developer adds a bypass for a broken verifier | The protocol has no bypass field or alternate verifier. Documentation, tests, and UI name unavailability as rejection, not a warning |
| Low | Update checks reveal use of SecureSandbox | Scheduled checking is disabled by default and operator-configurable; requests contain no installation ID, credential, model, session, or protected-environment state |

These are threat hypotheses and required controls, not claims that Apple,
GitHub, the operator account, or release credentials cannot be compromised.
Compromise of both separated signing authorities, or unrestricted control of
the operator account plus replacement of the already trusted installed app,
remains outside the updater's direct boundary.

## Signing, notarization, and release construction

`macos/ControlCenter/script/build_update_release.sh` is the production release
entry point. It refuses without a Developer ID Application identity, hardened
runtime signing, a `notarytool` Keychain profile, an update signing key supplied
in the environment, a bounded key ID, and explicit security and compatibility
summaries. It rejects an unreadable, dirty, detached, or changing source tree,
archives the captured commit into a fresh source directory, and builds only
that archive with a fresh SwiftPM scratch/config/security state, dependency and
manifest caches disabled, and versions restricted to the archived
`Package.resolved`. It validates the resulting distribution bundle, first
requiring exact identifiers and designated requirements, the pinned Apple team,
hardened runtime, and secure timestamps on both signed products without
treating pre-notarization Gatekeeper rejection as failure. It submits with JSON
output, accepts only an exact `Accepted` result with a UUID, retrieves the
independent notary log, and requires `Accepted`, integer status code zero, and
null-or-empty issues. Only then does it staple and validate the ticket and
apply the separate Gatekeeper distribution gate. It stages the app under the
updater's required `SecureSandbox.app` name, round-trips the ZIP through
extraction and the full distribution gate, computes its exact size and SHA-256,
and constructs the manifest from the captured commit. The update private key is
removed from the inherited environment before any child starts. Tracing and
automatic export are disabled, loader and Python injection variables are
cleared, the signer is explicitly built from the archived source while no key
is present, and only that exact signer process receives the key. The shell then
forgets the key. After one final source check, the verified app is
transactionally published to the original `dist` directory for the separate
installation step. The command creates local release output only; it does not
upload or publish to a remote automatically.

The user-local installer retains `--local` for ad-hoc development builds, but
a production replacement must invoke `script/install_local.sh --distribution`.
That mode repeats the complete distribution gate on the source, staging copy,
and final installed app, and also requires an interrupted predecessor to remain
distribution-valid before restoring it. It refuses before mutation while the
Control Center process is running and never kills the app automatically. Local
mode admits only exact ad-hoc signatures at the source, predecessor, staging,
and installed boundaries; it rejects Apple Development, every Developer ID
team, ambiguous signature output, and an invalid existing installation. The
weaker default therefore cannot silently lower an installed distribution
floor.

The standalone bootstrap installer uses repeated exact-process observations,
including immediately before publication, but those observations are not a
cooperative lifetime lock. During this one-time bootstrap the operator must
quit SecureSandbox and keep it closed until installation completes. A future
in-app transition uses the app/helper protocol rather than claiming that this
standalone polling closes every process-launch race.

The signer accepts the raw 32-byte Ed25519 private key only through
`SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64`. Production invocation must use an
ignored environment template with `op-agents run` and execute the release
builder directly, not through a caller-selected shell. Its absolute privileged
Bash shebang ignores `BASH_ENV` startup injection before the script can capture
and remove the inherited key. The key must never appear in
argv, logs, a build/notary child, tracked source, GitHub Actions secrets, or the
app. Publication to
the approved GitHub distribution repository is a separate reviewed operation
that uploads only the stapled archive and signed envelope and then reads both
back by digest. The production policy may name only that exact GitHub endpoint
and the minimum GitHub delivery host set it actually needs.

`Resources/Update/UpdatePolicy.github.example.json` records the intended
GitHub-only shape without containing a usable key or Team ID. Provisioning must
replace every placeholder, validate the real policy, and copy it to the signed
`UpdatePolicy.json` before the notarized bootstrap build. The disabled tracked
policy remains the default and cannot contact a network endpoint.

Apple requires Developer ID distribution software to use a Developer ID
certificate, hardened runtime, secure timestamp, and valid signatures before
notarization. The current Mac now has the required Developer ID Application
identity; an Apple Development identity remains an unacceptable substitute.
[Apple notarization requirements](https://developer.apple.com/documentation/Security/notarizing-macos-software-before-distribution)

## Bootstrap, migration, and compatibility

An existing development/ad-hoc installation cannot authorize its own promotion
into the production trust chain. The installed Developer ID preflight likewise
is not that bootstrap because its production update policy is unprovisioned.
The operator must build, notarize, independently verify, and manually install
the exact current-source bootstrap through the reviewed release path. That
release embeds the production public key, Team ID, and GitHub endpoint. Only a
running Developer ID app with the same pinned identity may use the helper to
install its successor.

Legacy installs have no accepted sequence-floor file. The first production
bootstrap establishes the bundle sequence. The first accepted in-app update
creates the retained floor and rollback slot. A missing floor is valid only
before one has ever been recorded; a present but malformed, unsafe, or
unreadable floor fails closed. Schema or trust-root rotation requires a future
DDD and a release signed by the currently trusted key; silent key replacement
or trust-on-first-use is forbidden.

## Acceptance contract

Implemented acceptance includes:

- native Swift build, update helper build, signer build, and local bundle
  validation;
- valid Ed25519 envelope acceptance plus bad signature, unknown field,
  cross-origin, size, digest, disabled-policy, replay, and rollback rejection;
- explicit proof that scheduled checking has metadata capability only;
- distribution validation rejecting the present ad-hoc build;
- Settings rendering of exact identities, digests, impact and compatibility;
- installed-app readback showing the channel as unprovisioned rather than
  offering a local-signature bypass.

Production acceptance remains gated on the external prerequisites above. It
must include a notarized predecessor and successor, approved GitHub upload and
digest readback, scheduled notification with no artifact creation, manual
download, cancellation before installation, Touch ID cancellation, successful
atomic replacement and health commitment, injected candidate-launch failure
with automatic rollback, explicit Touch ID rollback, malformed floor, unknown
key/certificate, altered manifest/archive/bundle, blocked verifier, and complete
post-update Control Center and protected-boundary checks. Private identifiers,
receipts, and release digests belong in ignored acceptance evidence.
