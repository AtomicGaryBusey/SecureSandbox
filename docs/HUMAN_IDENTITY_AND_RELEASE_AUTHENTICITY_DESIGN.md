# Human Identity and Release Authenticity DDD

Status: **research and implementation backlog**. This document does not
authorize enrollment with an identity provider, creation or publication of a
personal identity document, key generation, GitHub-account changes, repository
rule changes, Apple certificate issuance, transparency-log submission, or a
change to the production updater trust root.

Decision owner: project owner

## 1. Decision question

Design and evaluate a durable, publicly verifiable chain supporting this
bounded claim:

> The project owner, the bona fide human identified by the selected external
> identity-proofing evidence, controls the GitHub account presently named
> `AtomicGaryBusey`; the owner has declared the identified GitHub repositories
> to be genuine; and a specific published package was authorized by the owner,
> built from the declared source revision through the declared process, and
> admitted by the platform and product-specific release policies.

No one credential proves that whole sentence. The DDD must keep these claims
separate:

1. **human identity** — an external party has identity-proofed a legal person;
2. **account control** — a principal authenticated to a particular GitHub
   account at a particular time;
3. **repository identity** — the account and repository have stable numeric
   identities independent of renameable display names;
4. **human authorization** — an offline operator key approved an exact release
   statement;
5. **source authorship** — commits were made with recognized contributor keys;
6. **build provenance** — an identified workflow built named outputs from an
   exact source revision;
7. **artifact identity** — exact bytes match the approved digests and, where
   applicable, the pinned Apple Developer identity;
8. **distribution admission** — threshold, expiry, rollback, compatibility,
   and product policy permitted those bytes to become an update; and
9. **historical continuity** — rotation, revocation, compromise, rename, death,
   incapacity, and post-quantum migration do not silently rewrite earlier
   claims.

The intended result is not “absolute proof on the Internet.” It is a
multi-authority evidence chain in which no single compromise of GitHub, CI,
Apple, a carrier, a signing device, or one cryptographic family is sufficient
to manufacture an accepted release.

## 2. Current architecture and evidence

| Existing component | Current property | Source evidence | Missing identity property |
| --- | --- | --- | --- |
| Public release branch | Only a reviewed exact commit may be published; pre-push scans reject alternate refs and private material | `docs/PUBLIC_RELEASE_CONTROLS_DESIGN.md:8-33` | The Git commit is not presently bound to a public human-identity covenant |
| Frozen GitHub publication | The repository is frozen between explicit unseal/push/reseal ceremonies and the exact remote tip is read back | `docs/PUBLIC_RELEASE_CONTROLS_DESIGN.md:35-61` | Repository name/account name remain renameable labels unless stable numeric IDs are retained |
| Reproducible source release | Deterministic archives bind size and digest to an exact commit and tree | `docs/PUBLIC_RELEASE_CONTROLS_DESIGN.md:77-89` | Reproducibility does not prove who authorized release |
| GitHub build attestation | The workflow has read-only contents authority plus narrowly scoped OIDC and attestation permissions | `.github/workflows/public-release.yml:24-50` | Workload identity proves a workflow/repository event, not Alex's legal identity or human approval |
| Provenance limitations | Documentation already rejects the claim that attestation proves source correctness or a clean runner | `docs/PUBLIC_RELEASE_CONTROLS_DESIGN.md:108-114` | The missing human authorization and independent artifact identities must be added, not inferred |
| Control Center updater | The signed policy pins manifest key, origins, Team ID, bundle ID, and bounds | `docs/IN_APP_UPDATES_DESIGN.md:40-53` | A single classical manifest root is not yet a threshold or hybrid human-identity root |
| Control Center admission | Unknown keys/certificates, altered bytes, broken trust, rollback, or unavailable verification reject without bypass | `docs/IN_APP_UPDATES_DESIGN.md:54-84` | Future root rotation and identity succession need a separately governed protocol |
| macOS release | Candidate admission requires exact Apple identity, hardened runtime, nested signature validation, and Gatekeeper acceptance | `docs/IN_APP_UPDATES_DESIGN.md:63-79` | Apple identity is platform-scoped corroboration, not a universal proof of GitHub ownership |
| Release-key handling | The updater signing secret is injected through `op-agents run` and forbidden from app, source, argv, logs, and GitHub Actions | `docs/IN_APP_UPDATES_DESIGN.md:155-175` | The existing software-held Ed25519 key does not yet provide hardware-backed threshold or post-quantum authorization |
| Security policy | Publication provenance, replay, approval bypass, and fail-open behavior are high-value boundaries | `SECURITY.md:28-50` | Identity-substitution and false-authority claims should become explicit reportable boundaries when implemented |

This architecture review was performed sequentially because independent agent
delegation was unavailable for this task. It establishes design context, not a
completed security audit or proof that future external services satisfy their
claims.

## 3. Proposed trust chain

```text
externally identity-proofed project owner
              |
              v
versioned Human Identity Covenant
  | legal-name evidence references
  | GitHub account ID + current login
  | repository IDs + current names
  | domain + Apple Team/certificate identities
  | classical, threshold, recovery, and PQ public keys
  | revocation/succession policy
              |
      offline human authorization
              |
              v
canonical Release Authorization Statement
  | covenant digest and generation
  | repository ID, commit, and tree
  | version and monotonic release sequence
  | artifact names, sizes, and digests
  | workflow and policy identities
  | security/compatibility declarations
              |
       +------+-------------------+
       |                          |
       v                          v
GitHub OIDC/Sigstore       reproducible/in-toto
build provenance           supply-chain evidence
       |                          |
       +-------------+------------+
                     v
     platform signatures and notarization
                     |
                     v
    TUF-style threshold update admission
                     |
                     v
       exact installed artifact readback
```

Every verifier must name which edge it established. “Verified” without a claim
type, subject digest, issuer, time, policy generation, and verification result
is insufficient evidence.

## 4. Human Identity Covenant

The DDD should define a canonical, bounded, machine-readable covenant plus a
human-readable projection. At minimum it should contain:

- schema and covenant generation;
- legal name and explicitly labeled external identity-proofing evidence;
- current GitHub login and immutable GitHub account ID;
- each covered repository's current `owner/name` and immutable repository ID;
- controlled domain names and exact proof method, if used;
- Apple Developer Team ID and approved certificate fingerprints, if used;
- human release-root, targets, recovery, witness, and post-quantum public keys;
- allowed algorithms, parameter sets, contexts, and verifier versions;
- effective time, expiry, superseded covenant digest, and next-generation
  constraints;
- compromise, revocation, incapacity, death, and succession procedure;
- explicit limitations on what each external issuer actually attests; and
- canonical byte encoding and SHA-256/SHA-512 digests.

The initial research must compare at least these human-identity anchors:

1. a recognized notarial or qualified trust-service signature over the exact
   covenant digest and public-key fingerprints;
2. an identity-vetted personal S/MIME or document-signing certificate whose
   certificate policy and public validation path are acceptable;
3. Apple individual Developer Program issuance as Apple-specific corroboration
   for macOS software; and
4. direct attestations by named independent witnesses with published key and
   verification practices.

A domain, GitHub profile, self-issued DID, OpenPGP user ID, or self-signed
certificate proves control or continuity only. None may be labeled as legal
identity proof without an external identity-proofing issuer. A verifiable
credential or DID is useful only to the extent its issuer and evidence policy
are trusted; decentralization of the identifier does not manufacture identity.

The covenant should be published identically in the covered repositories, at
the controlled domain, with releases, and through at least one append-only
transparency or timestamp system. Cross-publication provides independent
evidence of control; it does not replace the external identity proof.

## 5. Key roles and separation

| Role | Intended custody | Authority | Must not authorize |
| --- | --- | --- | --- |
| GitHub authentication | Two or more phishing-resistant passkeys/security keys, with one recovery device offsite | Account login and privileged GitHub actions | Git commits, human release approval, Apple signing, updater root rotation |
| Commit signing | Dedicated hardware-backed SSH or OpenPGP signing key | Contributor authorship/committer continuity | Release admission merely because a commit is signed |
| Human release authorization | Offline hardware-backed key requiring presence | Exact Release Authorization Statement | Arbitrary shell commands, CI execution, repository mutation |
| TUF-style root | Threshold of separately stored offline keys, proposed 2-of-3 | Key-role definitions, thresholds, algorithm transition, root rotation | Routine online target publication |
| Targets/release | Hardware-backed or tightly brokered release key with narrower lifetime | Exact approved artifacts and metadata | Root policy changes or rollback-floor reduction |
| Snapshot/timestamp | Short-lived online role with minimal publication authority | Freshness, inventory, and freeze-attack resistance | New artifact authorization |
| GitHub workload identity | Ephemeral OIDC identity for an exact repository/workflow/ref policy | Build and provenance claims | Human identity or offline release approval |
| Apple Developer ID | Keychain/hardware custody compatible with Apple's issuance and notarization workflow | macOS platform artifact identity | GitHub account ownership or non-Apple packages |
| Post-quantum release key | Offline ML-DSA key; separate implementation and custody from classical key | Hybrid authorization over the same canonical statement | Sole production authority until interoperability, implementation maturity, and recovery are accepted |
| Recovery/succession | Offline, geographically separate, documented custody | Explicit recovery or covenant succession under threshold policy | Routine releases |

Using one key for GitHub login, commit signing, human release approval, and
update-root authority is prohibited. Threshold keys held by one human on
separate devices improve compromise resistance but do not become independent
human approvals; the evidence must describe that distinction honestly.

## 6. GitHub account and repository grounding

The design should bind immutable numeric account and repository IDs in every
covenant, release statement, and attestation policy. Display login and
`owner/name` remain useful labels but cannot be the sole identity because names
can change and may later be reassigned.

The account baseline should require:

- vigilant mode and signed commits;
- repository rules requiring recognized signatures where workflow semantics
  remain compatible;
- at least two phishing-resistant passkeys/security keys and offline recovery
  codes;
- an inventory and periodic review of PATs, deploy keys, OAuth applications,
  GitHub Apps, Actions secrets, environments, and recovery channels;
- exact workflow allowlists with actions pinned by commit;
- no long-lived human release or update-root key in GitHub Actions; and
- monitoring for account, key, ruleset, workflow, repository-ID, attestation,
  and transparency-log changes.

GitHub currently verifies GPG, SSH, and S/MIME commit signatures and offers
vigilant mode to mark unsigned work as unverified. SSH is operationally simpler
for most individuals, while OpenPGP remains useful for expiry, revocation, and
cross-certification. Neither becomes legal identity merely because GitHub shows
“Verified.”

## 7. Release authorization and provenance

Every release should have one canonical Release Authorization Statement that
binds:

- covenant generation and digest;
- immutable account and repository IDs plus current labels;
- exact commit, tree, source archive digest, and monotonic release sequence;
- every artifact's media type, filename, byte count, and cryptographic digests;
- applicable package coordinates, Apple bundle ID, Team ID, and certificate
  fingerprint;
- exact build workflow repository ID, workflow path/digest, environment, and
  reusable-workflow identity;
- GitHub/Sigstore and in-toto/SLSA evidence digests;
- security impact, compatibility, migration, downgrade, and rollback policy;
- verifier-policy generation and minimum accepted versions; and
- authorization time, expiry, nonce, and signature set.

The human authorization signature must occur only after the statement is
complete. CI may build candidate artifacts and produce provenance, but it may
not silently complete or alter the human authorization statement. If the final
notarized artifact differs from the pre-notarization candidate, the final bytes
must be rebound and reauthorized or the protocol must use a reviewed two-stage
authorization that binds both transformations and exact final readback.

GitHub Artifact Attestations/Sigstore should prove the identified workload
built the subject digest from the identified repository event. Verification
must constrain the repository ID and exact workflow, not only the renameable
owner/repository label. Sigstore transparency provides detection and historical
evidence; it does not make the workload correct or the human approver genuine.

in-toto/SLSA evidence should describe the allowed build steps and functionary
identities. Reproducibility should compare independently built outputs where
the platform format permits it. Apple Developer ID, hardened runtime,
notarization, and Gatekeeper remain additional mandatory macOS evidence rather
than substitutes for human authorization or build provenance.

## 8. TUF-style update admission

The implementation phase should evaluate replacing or enveloping the current
single-key manifest with The Update Framework semantics:

- threshold offline root metadata;
- separately delegated targets, snapshot, and timestamp roles;
- exact key IDs, thresholds, expiry, and metadata versions;
- consistent snapshots and target size/digest binding;
- freeze, rollback, mix-and-match, fast-forward, and endless-data defenses;
- explicit root rotation requiring the old and new threshold policies during
  planned transition;
- an emergency compromise path that cannot lower the accepted rollback floor;
  and
- offline verification bundles for long-term evidence.

The client must continue to require the existing Apple and SecureSandbox
admission checks. TUF proves authorized distribution state; it does not prove
legal identity, source correctness, build integrity, or harmlessness.

## 9. Post-quantum and cryptographic agility

AI-assisted vulnerability discovery and implementation compromise are present
risks; they should not be described as direct cryptanalytic breaks without
evidence. Cryptographically relevant quantum computers are a migration risk,
not a reason to discard effective current controls.

The DDD should evaluate a hybrid signature policy over the exact same canonical
covenant and release statement:

- an interoperable classical signature required by current GitHub, Apple,
  Sigstore, and package ecosystems; **and**
- an ML-DSA-65 signature using a reviewed FIPS 204 implementation and explicit
  context string.

Both signatures should be required where SecureSandbox owns the verifier. A
post-quantum signature must not be an optional decoration that a downgrade can
strip, nor should it replace classical platform verification before ecosystem
support and implementation maturity exist. SLH-DSA should be evaluated as an
algorithmically distinct backup for low-frequency root or covenant operations,
with its larger signature and performance costs measured rather than assumed.

The format must support algorithm identifiers, parameters, contexts, multiple
signature families, minimum verifier versions, and a non-downgradable
transition policy. Historical evidence should be periodically re-attested under
new algorithms and independent timestamps before old algorithms are retired.
SHA-256 remains acceptable for current artifact identity, but a dual SHA-256
and SHA-512 digest can reduce future migration ambiguity at negligible release
frequency cost; the DDD should decide whether the extra digest is warranted.

## 10. Threat model, boundaries, and assumptions

### Protected assets and objectives

- the truthful public binding between the project owner and the covered account,
  repositories, and keys;
- human release intent and the exact authorized bytes;
- stable account/repository identity through rename or transfer;
- updater roots, rollback floors, expiry, and recovery policy;
- build and platform provenance;
- revocation and succession history; and
- the distinction between identity, control, authorship, build, and artifact
  claims.

### Realistic attacker capabilities

An attacker may compromise one online account, carrier, workflow, package
registry, build runner, release server, signing device, certificate, classical
algorithm, or transparency service. They may publish lookalike names, replay
old valid statements, exploit rename/reassignment, steal tokens, or induce the
operator to approve a misleading ceremony. The base model does not assume the
attacker already controls every offline threshold key, the operator's physical
presence, all independent identity issuers, and every verifier implementation.

### Assumptions and unresolved boundaries

- External identity-proofing strength and public verifiability vary by issuer
  and jurisdiction and must be measured before selection.
- Apple, GitHub, Sigstore, notaries, CAs, DNS, registrars, timestamp services,
  and transparency logs remain external trust dependencies with distinct
  compromise and availability modes.
- A malicious process with unrestricted control of the operator account may
  impersonate UI and steal software-held keys; hardware presence and exact
  review binding reduce but do not eliminate that risk.
- Threshold devices controlled by one person provide key-compromise separation,
  not independent governance.
- Long-term legal non-repudiation is jurisdiction-specific and must not be
  claimed from technical evidence alone.
- Quantum migration cannot retroactively repair evidence that was never
  timestamped, witnessed, archived, or rebound before a classical compromise.

## 11. Attack stories and required outcomes

| Priority | Hypothesis and capability gain | Prerequisites | Required outcome |
| --- | --- | --- | --- |
| Critical | GitHub account takeover publishes an apparently genuine poisoned release | Attacker controls account or online token but not offline threshold/human keys or Apple identity | Human authorization, threshold metadata, artifact/platform identities, and exact workflow policy do not all agree; reject and alert |
| Critical | Offline human release key is stolen | Attacker lacks root threshold, protected account, Apple key, or approved workflow | One key cannot rotate roots or satisfy all required evidence; reject and invoke compromise recovery |
| Critical | CI or reusable workflow is compromised and emits malicious bytes | Attacker lacks human final authorization and/or final platform signing | Provenance alone cannot authorize release; final digest mismatch or missing approval rejects |
| Critical | Apple Developer ID key is stolen or mis-issued | Attacker lacks offline release/TUF threshold and exact GitHub provenance | Apple-valid but unauthorized artifacts reject |
| High | Identity proof, CA, notary, or witness is fraudulent | Issuer is compromised or evidence policy is weak | Other anchors may establish control but not legal identity; covenant status becomes disputed/revoked rather than silently trusted |
| High | GitHub login or repository is renamed and the old name is reassigned | Verifier trusts labels only | Numeric account/repository IDs disagree; reject lookalike and surface rename |
| High | Valid old metadata and artifact are replayed | Old signatures remain valid | Expiry, metadata version, release sequence, and local rollback floor reject |
| High | One cryptographic family is broken, including by future quantum capability | Break is limited to classical or one PQ family | Hybrid policy and independent timestamp/history prevent one-family acceptance; rotate under threshold policy |
| High | Recovery mechanism becomes a bypass | Operator has lost or replaced a normal key | Recovery requires its own threshold, delay, public notice, exact new covenant, and readback; no emergency unsigned path |
| Medium | Transparency or timestamp service equivocates or disappears | One external service is faulty or unavailable | Retained inclusion proofs, witnessed checkpoints, multiple publication channels, and fail-closed fresh release admission preserve evidence |
| Medium | Operator signs visually misleading or incomplete release information | Malicious content or concurrent session influences review | Canonical bounded statement, grouped digests, immutable IDs, safe rendering, explicit claim types, Touch ID/presence, and final readback bind approval |
| Medium | Signature verifies but verifier policy is obsolete or maliciously downgraded | Old client or format remains installed | Minimum verifier/policy versions and root metadata reject stripped PQ or threshold requirements |
| Low | Public covenant exposes unnecessary personal information | Overbroad identity evidence is published | Publish only bounded claims, issuer references, public keys, and digests; keep government identifiers and raw identity documents private |

These are design hypotheses, not validated vulnerabilities in the present
repository.

## 12. Severity calibration

- **Critical:** an attacker without prior offline threshold authority can cause
  arbitrary bytes to be accepted as an Alex-authorized production release, or
  can replace the covenant/root without the required old and new thresholds.
- **High:** an attacker can forge a material identity/account/repository binding,
  defeat rollback or revocation, or satisfy one major evidence layer in a way
  that becomes accepted only when another documented prerequisite is also
  compromised.
- **Medium:** an attacker can create durable misleading evidence, suppress or
  delay compromise detection, spoof review presentation, or force availability
  failure without gaining release authority.
- **Low:** bounded metadata, privacy, diagnosability, or interoperability defects
  that do not create false identity or release admission.

Ordinary account recovery by the already-authorized human, public information
already intentionally contained in the covenant, and refusal to update when a
required external verifier is unavailable are not security findings by
themselves. A fail-closed availability loss is an expected outcome unless it
violates an explicit recovery guarantee.

## 13. Research and delivery phases

### Phase A — evidence and identity research

1. Inventory candidate legal-identity issuers, certificate policies,
   jurisdictions, public validation paths, privacy exposure, revocation, and
   longevity.
2. Record immutable GitHub account and repository IDs and verify how GitHub
   attestations expose them across rename and transfer.
3. Evaluate hardware-backed SSH/OpenPGP signing options, device recovery, and
   GitHub verification behavior without changing the production account.
4. Evaluate TUF implementations and whether the Control Center should adopt a
   library, a narrow verifier, or an externally generated compatibility layer.
5. Evaluate OpenSSL 3.5 ML-DSA and SLH-DSA implementations, available hardware
   custody, deterministic encoding, contexts, signature sizes, verification
   portability, and dependency risk.

### Phase B — schemas and offline prototype

1. Specify canonical covenant and release-statement schemas, test vectors, and
   safe human-readable projections.
2. Prototype classical-plus-ML-DSA signing and strict verification using only
   disposable keys and non-production repositories.
3. Prototype threshold root rotation, delegation, expiry, freeze, rollback,
   mix-and-match, and recovery failure cases.
4. Verify GitHub/Sigstore bundles offline and bind numeric repository IDs and
   exact workflows.
5. Define content-minimized public evidence and private operational receipts.

### Phase C — operator decision

Produce an evidence-backed decision that selects or rejects:

- the human-identity issuer(s);
- covenant publication and witness channels;
- commit-signing mechanism;
- hardware and geographic key custody;
- threshold and TUF implementation;
- classical/PQ algorithms and transition schedule;
- GitHub and Sigstore policy;
- Apple cross-binding;
- recovery and succession governance; and
- compatibility/migration for already published commits and installations.

No production provisioning begins merely because the prototype passes.

### Phase D — separately authorized implementation

Only after the Phase C decision may a follow-on implementation checkpoint seek
explicit operator authorization to create keys, change GitHub settings,
publish a covenant, request external identity proof, alter the updater trust
root, or release a notarized bootstrap. Each external mutation requires exact
preview, approval, application, and independent readback.

## 14. Acceptance contract

The DDD is complete only when it has:

- an explicit claim taxonomy and verifier output that never collapses legal
  identity, account control, authorship, provenance, and artifact admission;
- independently reviewed covenant and release-statement schemas with canonical
  test vectors;
- external identity evidence whose issuer policy, privacy, expiry, revocation,
  and public verification are documented without publishing raw identity data;
- stable GitHub account/repository ID binding and rename/reassignment tests;
- hardware-backed account, commit, human release, root, and recovery roles with
  no prohibited key reuse;
- GitHub vigilant-mode/ruleset, token/app inventory, workflow, Sigstore, SLSA,
  and offline-attestation acceptance;
- reproducible/in-toto evidence bound to exact final artifact digests;
- Developer ID, notarization, Team ID, and bundle binding for macOS releases;
- TUF-style threshold, expiry, rotation, delegation, rollback, freeze,
  mix-and-match, and compromise-recovery tests;
- hybrid classical and ML-DSA verification plus downgrade, stripping,
  unsupported-verifier, and one-family-compromise tests;
- monitored transparency/timestamp evidence and an equivocation/unavailability
  exercise;
- a complete loss, revocation, succession, and historical re-attestation drill;
- updated updater, publication, implementation, roadmap, evidence, and operator
  documentation; and
- focused commits, exact publication checks, and independently verified remote
  publication.

Production acceptance must never manufacture legal identity, external issuer
approval, Apple authority, or independent witnesses for the sake of closing the
DDD. Missing authority remains an explicit gate.

## 15. Alternatives to compare

- **PGP alone:** useful for continuity, expiry, revocation, cross-signing, and
  human review, but self-asserted user IDs do not prove legal identity and GitHub
  verification does not add that proof.
- **GitHub “Verified” alone:** proves a recognized signature/account mapping or
  GitHub-generated signature under GitHub's rules, not a legal human, correct
  source, clean build, or human release intent.
- **Sigstore keyless alone:** excellent workload/account-time binding and public
  transparency, but inherits OIDC identity and does not replace offline human
  approval or legal identity proof.
- **Apple Developer ID alone:** strong macOS platform distribution identity and
  notarization evidence, but does not cover non-Apple packages or independently
  establish GitHub account ownership.
- **DID/blockchain alone:** provides identifiers or timestamp/publication
  mechanisms but no stronger human identity than the credential issuer and
  evidence policy behind it.
- **Post-quantum signature alone:** protects against one future cryptographic
  threat class but does not solve endpoint compromise, account takeover,
  malicious CI, key theft, legal identity, transparency, or recovery.
- **One offline key for everything:** operationally simple but creates one
  compromise and recovery domain and prevents meaningful claim separation.

## 16. Primary references

- [GitHub commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- [GitHub vigilant mode](https://docs.github.com/en/authentication/managing-commit-signature-verification/displaying-verification-statuses-for-all-of-your-commits)
- [GitHub passkeys](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
- [GitHub offline attestation and repository-ID verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
- [Sigstore keyless signing](https://docs.sigstore.dev/cosign/signing/overview/)
- [Sigstore threat model](https://docs.sigstore.dev/about/threat-model/)
- [in-toto supply-chain layouts](https://in-toto.io/docs/getting-started/)
- [The Update Framework compromise-resilience model](https://theupdateframework.io/papers/survivable-key-compromise-ccs2010.pdf)
- [NIST post-quantum standards](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved)
- [OpenSSL 3.5 ML-DSA and SLH-DSA operations](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)
- [Apple notarization requirements](https://developer.apple.com/documentation/Security/notarizing-macos-software-before-distribution)
