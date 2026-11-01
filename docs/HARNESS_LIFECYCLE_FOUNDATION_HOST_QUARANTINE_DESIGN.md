# Harness Lifecycle Foundation and Host Quarantine DDD

Status: implemented and source-verified; live release policy and candidate acceptance not configured

This first lifecycle layer preserves the project's foundational
[Anthropic CVP Defense containment guidance](ANTHROPIC_CVP_DEFENSE_CONTAINMENT_FOUNDATION.md).
Its inert Host quarantine and no-execution authority ceiling are prerequisites
to the guidance's disposable validation, credential exclusion, post-change
testing, and technical scope enforcement. Canonical source:
<https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants>.

## Decision

SecureSandbox implements the first harness-lifecycle layer as a Host-only,
non-executing system. It can verify bounded threshold-signed release metadata,
advance an equivocation-detecting metadata floor, explicitly download one exact
artifact into owner-only quarantine, and reverify the artifact and typed
evidence bindings. It cannot extract, execute, qualify, stage, install,
activate, roll back, retire, revoke, or expose a candidate to Research.

The CLI exposes only:

```text
labctl harness status
labctl harness check
labctl harness acquire GENERATION_SHA256
labctl harness verify GENERATION_SHA256
```

`check` is the only action eligible for future scheduling. This DDD installs no
scheduler. `acquire` and `verify` require explicit operator commands. There is
no update, latest, channel-following, automatic-download, or install command.

## Authority ceiling

The implementation returns `authority: none`, `automatic_download: false`, and
`automatic_install: false`. A successful verification receipt says
`artifact_and_evidence_bindings_verified` and
`not_admitted_not_executable`. It is not an admission, compatibility,
conformance, vendor-trust, project-authorization, or runtime receipt.

The live policy file is intentionally absent and ignored. Copying the example
does not create a valid policy because its key is a conspicuous placeholder.
Configuring real roots, metadata, or candidates is a separate reviewed action.
Because this foundation cannot cross into protected or executable state, the
future protected-generation DDD must move policy roots and admission decisions
behind the protected Host controller rather than treating this editable policy
as installation authority.

## Canonical contracts

The shared implementation defines:

- `secure-sandbox-harness-release-policy-v1`;
- `secure-sandbox-harness-release-metadata-envelope-v1`;
- `secure-sandbox-harness-release-metadata-v1`;
- `secure-sandbox-harness-release-manifest-v1`;
- `secure-sandbox-harness-metadata-floor-v1`;
- `secure-sandbox-harness-lifecycle-receipt-v1`; and
- `secure-sandbox-harness-lifecycle-status-v1`.

JSON is bounded, UTF-8/ASCII-canonical, sorted, compact, newline-terminated,
free of duplicate keys, non-finite numbers, and unknown fields. Identifiers,
versions, platforms, media types, URLs, sizes, counts, sequence values,
lifetimes, and digests are closed and bounded.

The generation ID is SHA-256 over the canonical manifest with its
`generation_id` field removed. It therefore binds harness, vendor, adapter,
version, platform, release sequence, artifact URL/size/hash/type/name,
compatibility projection, and evidence inventory. A marketing version is never
an identity.

## Metadata verification and floor

The envelope uses threshold Ed25519 signatures over the canonical `signed`
object. Policy keys are identified by SHA-256 of canonical Ed25519
SubjectPublicKeyInfo DER, so alternate textual PEM encodings cannot count as
distinct threshold keys. Unknown, duplicate, malformed, or invalid signatures
fail closed; the configured threshold must pass. Verification invokes only the
fixed MacPorts OpenSSL 3 path after checking its root-owned selector, exact
resolved path, package-owner, type, mode, and executability; ambient `PATH` is
irrelevant. The later protected-store DDD must carry the verifier inside the
measured Host release before it can support admission authority.

Metadata has bounded publication and expiry times, a maximum 31-day lifetime,
one monotonically increasing sequence, and at most 64 releases. The local floor
binds the sequence, exact envelope SHA-256, and exact policy SHA-256. A lower
sequence is rollback; the same sequence with different bytes is equivocation;
an unreviewed policy replacement is trust-root substitution. None overwrites
the last verified cache or floor.

The metadata client accepts one exact HTTPS URL, system TLS validation, no
redirect, bounded response size, a 60-second whole-transfer deadline, and HTTP
200 only. TLS is transport; the threshold signature is release-metadata
authenticity.

## Manifest and evidence binding

Every manifest binds one exact HTTPS artifact under an allowlisted origin,
positive bounded byte count, SHA-256, media type, and safe filename. It also
binds adapter digest and controller schema.

Evidence records are typed as vendor signature, vendor checksum manifest,
source/build provenance, SBOM, license, vulnerability, malware, or static
review. Every record binds its digest and the exact artifact SHA-256. Policy
names mandatory evidence kinds, and each must be marked required.

This DDD verifies the signed inventory and subject/digest bindings. It does not
claim to semantically validate every vendor-specific GPG, Sigstore, SLSA, SBOM,
or scanner format. Those verifiers and externally observed behavior belong to
the qualification DDD. A digest declaration is evidence inventory, not proof
that its narrative is true.

## Quarantine and acquisition

State defaults to ignored `.private/harness-lifecycle` storage. The live policy
must be an owner-only, mode-0600 regular file; the tracked example is inert and
cannot be used without replacement and an explicit permission change. Root,
metadata, quarantine, generation, and receipt directories are owner-only.
Files are regular, owner-only, single-link objects opened without following
symlinks and checked for change while read.

Acquisition:

1. reopens and revalidates the policy, signed cache, and exact floor;
2. selects one generation SHA-256, never a version or latest pointer;
3. requires the artifact origin, size, and digest from the signed manifest;
4. downloads over exact HTTPS with no redirect, a hard byte bound, and a
   five-minute whole-transfer deadline;
5. streams to an anonymous, non-executable owner-only staging file;
6. requires exact length and SHA-256 before no-overwrite publication;
7. publishes the canonical manifest beside it; and
8. emits a content-free typed receipt.

Carrier bytes are completely length- and digest-verified in an anonymous,
owner-only staging file before a generation directory is created. A length,
deadline, digest, or carrier rejection therefore performs no quarantine
mutation and requires no destructive pathname cleanup. Publication then holds
the quarantine and generation directory descriptors, creates `artifact` and
`manifest.json` without overwrite, and verifies both through those descriptors.
Immediately before the receipt rename that publishes success, it revalidates
the held/live directory identities, exact two-file inventory, and each file's
device, inode, size, modification/change times, type, owner, link count, and
mode. Byte-identical substitution or an added child therefore rejects the
transaction without a success receipt. Receipt capacity is preflighted before
quarantine mutation and is not reinterpreted afterward, so an uncooperative
same-UID capacity fill cannot turn a completed mutation into unreceipted state.
An existing empty directory remains retryable; any mixed state after durable
publication remains fail-closed for inspection rather than being erased.

Existing complete state is reverified and returns `already_acquired` without
network reuse. Unexpected paths, links, modes, owners, counts, partial state,
or changed bytes fail closed. Nothing invokes a shell, interpreter, archive
extractor, package manager, installer, or candidate process.

## Threat stories and controls

| Threat | Control |
| --- | --- |
| Metadata substitution | Threshold signature over canonical bytes |
| Key-label substitution | Key ID is digest of exact public-key PEM |
| Rollback or freeze replay | Sequence/expiry plus local sequence-and-digest floor |
| Same-version replacement | Content-derived generation ID |
| Redirect or origin escape | Exact HTTPS URL, no redirects, origin allowlist |
| Endless or truncated artifact | Signed exact length and hard streaming bound |
| Artifact substitution | Signed SHA-256 is verified in anonymous staging before quarantine creation and on every later verify; rejected carrier bytes cannot change the quarantine inventory |
| Evidence retargeting | Every evidence record binds exact artifact SHA-256 |
| Symlink or mutable-file swap | Descriptor-relative no-follow reads, stable-read identity, exact inventory, and a final identity recheck immediately before receipt publication |
| Candidate execution | No extraction or execution surface; files stay mode 0600 |
| Verification mistaken for admission | Explicit non-admitting status and no protected API |

## Recovery and limitations

Metadata cache and floor use atomic same-directory replacement with file and
directory synchronization. Acquisition validates an anonymous staging file
before quarantine mutation, then uses held directory descriptors,
no-overwrite file creation, file and directory synchronization, and canonical
manifest publication. Exact retry revalidates a complete generation and does
not redownload it.

This checkpoint does not yet provide the component journal required for all
crash points between artifact and manifest publication. An interrupted mixed
generation fails closed for manual inspection; automatic repair is reserved
for the protected transactional-store DDD. The receipt ledger is capped at 256
owner-only regular files and fails closed at capacity; authenticated archival
is reserved for the protected transactional-store DDD. Both limitations are
explicit prerequisites before protected staging.

## Acceptance

Source acceptance requires tests for canonical parsing, duplicate keys,
manifest identity, origin and evidence binding, real Ed25519 verification,
signature tampering, expiry, rollback, equivocation, exact inert acquisition,
length/digest substitution, idempotency, byte-identical substitution,
unexpected-child insertion, slow-EOF deadline enforcement, receipt-capacity
races, artifact tampering, symlinks, wrong key identity, HTTP rejection,
non-admitting receipts, CLI surface limits, and the seven-item roadmap.

Repository publication and secret checks must pass on the exact commit. Live
metadata, vendor keys, artifacts, and candidate qualification remain outside
this DDD.
