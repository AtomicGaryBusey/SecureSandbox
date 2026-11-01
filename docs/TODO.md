# Roadmap

This is the public product roadmap. Deployment-specific tasks, findings,
incident notes, review transcripts, identifiers, and acceptance evidence belong
in ignored local records, not in this file.

## Public-release controls

- Keep the clean-history `public-release` branch as the only published branch.
- Run `scripts/run-public-release-checks.sh` against the exact candidate commit.
- After GitHub-hosted capacity returns on 2026-11-01, explicitly dispatch and
  confirm the first remote CI run and signed build-provenance attestation.
- Keep GitHub public with `public-release` as its only and default branch. Keep
  `public-release` as the private Hobby Forgejo remote's default branch and
  verify that both live remote tips equal the reviewed commit before and after
  publication.
- Preserve GitHub's no-bypass branch/tag freeze and private vulnerability
  reporting. Reapply and verify those controls after publication with
  `scripts/seal-public-github-release.py --apply`; any future visibility change
  requires an explicit operator decision.

## Engineering backlog

- Complete an Anthropic CVP Defense Individual Conformance DDD using
  Anthropic's “Cyber Verification Program Security Requirements” as the
  authoritative baseline:
  <https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements>.
  Implement CVP conformance as an account/program/profile-scoped policy option
  in the settings file and Control Center, not as a universal SecureSandbox or
  Anthropic-provider rule. Model Anthropic access in two branches:
  `cvp-disabled` for ordinary API or subscription accounts and `cvp-enabled`
  for accounts or Granted Workspaces enrolled in CVP. CVP-disabled Anthropic
  profiles do not inherit any CVP requirement. A CVP-enabled profile must also
  select exactly one access level—`defense`, `red-team`, or `specialized`—and
  the selected tier's applicable controls become mandatory and non-disableable
  for that account/workspace binding. Direct API, subscription, Google Vertex,
  Amazon Bedrock, and Microsoft Azure AI Foundry are transports or account
  surfaces, not evidence of CVP enrollment; routing Claude through any one of
  them must not activate CVP policy unless that exact account/workspace is
  declared CVP-enabled. Bind program and tier state to the exact provider
  account/workspace and credential identity, require exact Touch ID to change
  it, prohibit downgrade while a bound session or lease exists, and retain an
  auditable activation/change receipt. It also does not apply to
  Abliteration.AI's Abliterated GLM, OpenAI models, Google models, or any other
  vendor merely because they use the same harness, Gateway, or cloud transport;
  those profiles remain governed by their own provider policies and the
  provider-neutral SecureSandbox containment baseline.
  Produce a requirement-by-requirement matrix for the operator's individual
  Defense grant, separating SecureSandbox-enforced controls, Anthropic/identity-
  provider settings, operator procedures, evidence, true gaps, and requirements
  that do not apply to an individual. Inventory every path by which CVP models
  are reached and do not conflate unrelated providers or non-CVP profiles with
  the Granted Workspace. Verify personal-only access and attribution; Google or
  equivalent identity-provider sign-in; current MFA; the December 15, 2026
  phishing-resistant MFA and no-magic-link cutoff; traffic retention and
  monitoring; and the Incident Reporting, Cooperation, and Ongoing Review
  obligations. Reconcile the interim single-key exception—secret/local-store
  custody, no sharing or source inclusion, and replacement at least every seven
  days—with the current model-profile design. By the cutoff, make static or
  long-lived credentials inadmissible for CVP-enabled Defense bindings and
  design OAuth for Claude Code/Console/claude.ai plus Workload Identity
  Federation for programmatic CVP access where Anthropic offers it. Ordinary
  CVP-disabled Anthropic profiles remain subject to Anthropic's ordinary terms
  and their selected authentication mechanism, not this CVP cutoff; they may
  use WIF voluntarily when their Anthropic account supports it. Use Anthropic's
  WIF documentation as the primary implementation source:
  <https://platform.claude.com/docs/en/manage-claude/workload-identity-federation>.
  Extend the Anthropic profile schema with an explicit authentication mode and
  non-secret organization, workspace, service-account, federation-issuer, and
  federation-rule identities. Bind the service account to the exact workspace;
  admit only an explicitly named rule; constrain issuer, audience, subject,
  claims/CEL condition, OAuth scope, and token lifetime; and keep upstream IdP
  JWTs and minted Anthropic tokens out of Research, receipts, arguments, logs,
  and persistent profile data. Select and threat-model a supported upstream
  identity source—AWS, Google Cloud, Microsoft Entra ID, GitHub Actions,
  Kubernetes, SPIFFE, Okta, or another standards-compliant OIDC issuer—without
  introducing a new static bootstrap secret on the Gateway or Mac. Treat WIF as
  unavailable until the exact individual CVP account/workspace exposes the
  required organization, service-account, issuer, and rule administration.
  Enforce the documented RFC 7523 exchange at `/v1/oauth/token`, bounded token
  refresh, fresh single-use `jti` identity tokens, and fail-closed expiry;
  disabling issuer-wide `check_jti` is not an acceptable production fallback.
  Reject any WIF launch if `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, an
  explicit higher-precedence credential, or another static source would shadow
  federation. Migration must configure and test federation in parallel, prove
  the federated source wins with independent readback, remove every injected
  static key, delete the provider key, and prohibit rollback to it after the
  applicable CVP cutoff. Add hostile issuer/JWKS, claim, audience, subject,
  rule, workspace-membership, scope, lifetime, replay, stale-token-file,
  refresh-failure, precedence-shadowing, revocation, and cross-profile tests.
  Add fail-closed credential-age/admission checks, evidence receipts, a 24-hour
  security-incident and 72-hour suspected-
  breach/misuse reporting procedure where applicable, a 48-hour abuse-
  investigation procedure, a seven-day misuse-inquiry response procedure, and
  an exportable compliance-evidence bundle. The DDD must label every row
  `conforming`, `partial`, `gap`, `operator-external`, or `not-applicable`, cite
  evidence, and prohibit a compliance claim until every applicable row is
  independently verified. Backlogging this work does not authorize account,
  credential, identity-provider, workspace, or live Gateway changes.
- Complete a separate Anthropic CVP Red Team and Specialized Compatibility DDD
  as research for access levels the operator does not currently hold. Compare
  Red Team and Specialized requirements independently, identify their delta
  from individual Defense, and distinguish harness/stack engineering from
  organizational prerequisites that code cannot satisfy. Treat the resulting
  policy profiles as hypothetical selections only beneath the Anthropic
  `cvp-enabled` branch; they must not alter ordinary CVP-disabled Anthropic,
  Abliteration.AI, OpenAI, Google-model, or other vendor profiles.
  Assess short-lived platform-native credentials; phishing-resistant MFA
  across workspace, IdP, cloud, credential-administration, and enclave
  surfaces; organization-domain
  accounts and Specialized SSO; named-admin and 25-user governance; gateway
  admission and transcript restrictions; customer-issued credential lifetimes
  of at most 12 hours with logged KMS/secret-manager roots; 24-hour revocation;
  three-business-day offboarding; off-host enforced and logged egress
  allowlists; managed-device update posture; Specialized application control or
  preventative EDR; background/identity checks; and incident procedures. Map
  existing SecureSandbox controls, then specify the exact harness, Gateway,
  identity, device-management, evidence, and operating-process improvements
  needed for hypothetical compatibility. Determine whether the Defense WIF
  implementation also proves Red Team/Specialized requirements for verified
  workload identity, at-most-12-hour customer-issued credentials, no static
  endpoint credential, access-logged issuer roots, gateway short-lived
  credentials, and 24-hour revocation; record any tier-specific delta rather
  than assuming WIF alone establishes compliance. Use Anthropic's canonical
  requirements as the primary source:
  <https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements>.
  Use Anthropic's WIF documentation for the federation mechanics:
  <https://platform.claude.com/docs/en/manage-claude/workload-identity-federation>.
  This DDD is comparative research only: it must not claim Red Team or
  Specialized eligibility, request access, enroll users, deploy enterprise
  identity/EDR, impose Anthropic policy on non-Anthropic profiles, or relax the
  provider-neutral containment baseline or any explicitly selected provider
  policy.
- Complete an OpenAI Daybreak Blue Account Policy and Conformance DDD for the
  operator's approved individual Blue access. Reuse the provider-account
  program-policy pattern without importing Anthropic CVP semantics. Model every
  OpenAI account, organization, workspace, and API project as either
  `daybreak-disabled` or `daybreak-enabled`; a Daybreak-enabled binding must
  select exactly `blue` or `red`. Ordinary OpenAI API and subscription accounts
  are Daybreak-disabled and inherit no Daybreak requirement. Provider, model,
  transport, Codex harness, ChatGPT sign-in, API key, Bedrock route, or mere
  model availability must never imply enrollment or tier. Bind the program and
  tier to the exact approved account plus organization/workspace/API-project
  and product-surface identity, require Touch ID for changes, prohibit downgrade
  while a bound session or lease exists, and issue auditable receipts without
  storing session credentials or recovery material. Treat API-project and
  ChatGPT/Codex-workspace enablement as separate authorities. Keep Daybreak off
  by default per request; for the Responses API, explicitly bind and emit only
  `access_programs.cyber=standard` or the authorized
  `access_programs.cyber=daybreak_blue` value and
  never infer the highest available tier. Add a versioned model/tier capability
  catalog because Blue approval does not reduce refusals for every model,
  authorize cyber-specialized models, confer Red, or confer model-specific
  approvals. Verify the approved organization/workspace/project, model, access
  path, product surface, and exact response/request evidence before reporting
  Blue active. Preserve standard OpenAI safeguards whenever Blue is off.
  Enforce individual onboarding and continued-eligibility evidence: eligible
  paid plan, Advanced Account Security, identity verification, at least two
  secure sign-in methods including one cross-device method, at least one
  compatible physical FIDO2 hardware key, separately completed Daybreak-key
  setup, privately retained recovery keys, and current access status. A synced
  or software passkey must not satisfy the physical-key requirement. Because
  the published October 1, 2026 deadline for existing individual users has
  passed, treat missing or stale eligibility evidence as an immediate
  fail-closed gate, not future work. Record that Advanced Account Security
  disables password, email/SMS-code, and standard email-recovery paths; never
  weaken it for automation. Map SecureSandbox's outer tool brokers and exact
  Touch ID approvals against OpenAI's recommended Codex auto-review instead of
  claiming equivalence without tests. Preserve sandbox isolation, boundary
  retesting, agent-action monitoring, active human oversight, and technically
  scoped permission profiles. Permit only lawful work on owned or explicitly
  authorized systems; prohibit customer-facing, downstream, third-party,
  resale, proxy-access, or shared-session use; and do not infer Zero Data
  Retention. Use OpenAI's announcement and current onboarding overview as
  primary sources:
  <https://openai.com/index/expanding-daybreak-as-the-cyber-defense-window-narrows/>
  and
  <https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview>.
  Deliver a row-level `conforming`, `partial`, `gap`, `operator-external`, or
  `not-applicable` matrix and independently verified evidence bundle before any
  conformance claim. Backlogging this work authorizes no account, key, project,
  workspace, model, harness, or live Gateway change.
- Complete a separate OpenAI Daybreak Red Compatibility DDD for a tier the
  operator does not hold. Treat Red as a hypothetical selection only beneath
  `daybreak-enabled`; it must not alter Daybreak-disabled OpenAI accounts,
  Daybreak Blue bindings, or any other provider. Research current business or
  enterprise organization eligibility, stronger identity and access controls,
  approved-user/project governance, and the separately published onboarding
  requirements before designing implementation. Model Red approval and each
  additional cyber-model approval as independent grants: Red must not imply
  access to every cyber-specialized model, and a model identifier must not
  imply Red. Require the exact approved organization, non-default API project or
  workspace, supported client/product surface, model, and explicit
  `access_programs.cyber=daybreak_red` request binding; preserve standard
  safeguards when Red is not explicitly enabled. Compare SecureSandbox's
  containment, request-bound approvals, monitoring, scope enforcement, source
  authorization, exploit execution boundary, and evidence with OpenAI's
  advanced-research, exploit-validation, penetration-testing, and red-team
  expectations. Include the announcement and onboarding overview above as
  primary sources, but re-review current OpenAI organization onboarding and
  model-approval documentation when the DDD begins. This is comparative
  research only: it must not claim eligibility, apply for Red, enable a model,
  or broaden authorized targets or users.
- Complete a Google Fairwind Account Policy and Conformance DDD using Google
  DeepMind's current Fairwind Program description as the authoritative public
  baseline: <https://deepmind.google/fairwind-program/>. Model every Google
  provider account, Cloud organization, project, workspace, and principal as
  either `fairwind-disabled` or `fairwind-enabled`. Do not invent subtiers:
  Google currently documents no named access levels beneath Fairwind-enabled.
  Represent model, feature, product-surface, and retention entitlements as a
  separate versioned grant set so program enrollment never implies access to
  Gemini 4 Argon, CodeMender, every cyber capability, or a future Fairwind
  offering. Ordinary Gemini, Gemini API, Google AI Studio, Vertex AI, Gemini
  Enterprise, Antigravity, CodeMender, subscription, and Cloud accounts are
  Fairwind-disabled unless the exact organization/account/project/workspace and
  principal have independently verified program evidence; provider, model,
  transport, harness, endpoint, or product availability must never imply
  enrollment. Bind an enabled policy to those exact identities plus supported
  client/product surface and model grant, require Touch ID for policy changes,
  prohibit downgrade or rebinding while a bound session or lease exists, and
  issue auditable receipts without storing credentials or recovery material.
  Fail closed when entitlement, organization, project, principal, model,
  product-surface, or current-status evidence is absent, stale, conflicting, or
  cannot be independently read back. Map Google's published governance terms
  row by row: approved-partner due diligence; defensive or academic-research
  use; permitted authorized threat simulation, reverse engineering, and malware
  analysis; rejection of malicious malware creation; user-level authentication;
  phishing-resistant MFA; applicable access controls; access limited to
  internal cybersecurity, incident-response, or penetration-testing teams;
  employee access-and-use tracking; and no sharing, redistribution, resale, or
  proxy access. Treat organizational vetting and program approval as
  Google/operator-external controls that SecureSandbox cannot manufacture.
  Link phishing-resistant MFA to the Physical FIDO2 Security Key DDD only when
  the exact Google account policy and retained evidence establish an accepted
  authenticator; do not infer that Fairwind requires a YubiKey specifically or
  that a login factor authorizes a SecureSandbox action. Model data-retention
  claims per exact access surface: the public program page says zero data
  retention is supported when Gemini 4 Argon is accessed directly as a managed
  model on Gemini Enterprise, so Fairwind enrollment alone must never imply
  zero data retention on another route. Produce a versioned capability and
  requirement matrix with `conforming`, `partial`, `gap`, `operator-external`,
  and `not-applicable` rows, plus hostile cross-account, cross-project,
  cross-principal, cross-model, cross-surface, stale-grant, downgrade, and
  retention-claim tests. Re-review the canonical page and any account-specific
  agreement or onboarding material when the DDD begins because the program and
  its public requirements are young and may change. This backlog item does not
  claim the operator is enrolled, apply for access, alter a Google account or
  Cloud project, enable a model, or impose Fairwind controls on
  Fairwind-disabled Google profiles or any other provider.
- Complete a Physical FIDO2 Security Key and Human-Origin Authorization DDD
  with first-class CLI and Control Center support for YubiKey and other
  compatible roaming hardware authenticators. Keep two trust purposes
  separate: a vendor may require a physical key for account enrollment or
  eligibility, while SecureSandbox requires request-bound proof that a local
  human approved an exact protected action. Vendor enrollment evidence must
  never be accepted as an action signature, and a local key touch must not
  claim vendor-account compliance. Preserve Touch ID as the current macOS
  operator factor and explicitly design per-operation policies such as Touch ID,
  physical key, either, or a reviewed two-factor composition; never weaken an
  existing Touch-ID-only ceremony merely by adding a fallback. Define native
  enrollment, naming, inventory, backup-key, removal, rotation, loss, recovery,
  revocation, and replacement ceremonies. Require at least one primary and one
  separately stored recovery key for policies whose loss could brick protected
  administration. Store only privacy-minimized credential public material and
  protected policy bindings—never a PIN, recovery key, vendor session, or
  unnecessary serial number—and never accept PINs or challenges through shell
  arguments, environment variables, logs, or agent-readable files. Bind every
  WebAuthn/CTAP challenge to the canonical operation digest, nonce, expiry,
  requesting conversation, protected resource, and current release/policy
  generation; verify RP/origin, allowed credential, algorithm, user presence,
  user verification where required, authenticator class, signature, and replay
  state before the existing Secure Enclave authority issues a composite receipt.
  Decide explicitly how attestation, AAGUID/metadata, signature counters,
  counterless authenticators, PIN/UV, resident credentials, and cloned-key
  signals are handled rather than trusting USB presence. The native GUI and CLI
  must expose insertion/touch prompts, exact-action review, timeout, cancel,
  wrong-key, locked-PIN, unavailable-key, replay, and ambiguous-result states
  without giving the agent control of the authenticator. Add destructive and
  recovery acceptance on the disposable Mac, including two-key enrollment,
  backup restoration, removal confirmation, reboot, process crash, repeated
  touch, wrong account/tier binding, Touch ID plus key composition, and proof
  that neither factor can authorize a different request. OpenAI Daybreak's
  physical FIDO2 requirement is the immediate driver; Anthropic or another
  provider may select the same capability only through its own explicit account
  policy, never by inference. This DDD does not enroll a real key, alter vendor
  accounts, or change a deployed authorization ceremony until separately
  reviewed implementation and operator acceptance are complete.
- Complete the Human Identity and Release Authenticity DDD before claiming that
  a GitHub account, repository, workflow attestation, Apple certificate, or
  signing key alone proves that a package was authorized by the project owner. Define
  a privacy-minimized externally identity-proofed Human Identity Covenant bound
  to immutable GitHub account/repository IDs; hardware-separated account,
  commit, human-release, threshold-root, targets, recovery, Apple, and
  post-quantum key roles; canonical release authorization; GitHub/Sigstore and
  in-toto/SLSA provenance; Developer ID/notarization cross-binding; TUF-style
  threshold/expiry/rollback/rotation controls; hybrid classical plus ML-DSA
  signatures; transparency monitoring; and compromise, revocation, succession,
  rename, recovery, and historical re-attestation. This is a research and
  design backlog item, not authorization to create keys, publish identity data,
  change GitHub settings, or alter the production updater trust root.
- Periodically re-run the completed In-App Updates DDD's metadata-only
  scheduling, manual download separation, signed-manifest and artifact bounds,
  Developer ID/notarization admission, Touch ID install, crash recovery,
  monotonic floor, explicit rollback, protected-environment non-authority, and
  no-bypass adversarial matrix. Production end-to-end acceptance remains gated
  on Apple Developer Program enrollment, separate release keys, a notarized
  bootstrap, and an approved GitHub distribution endpoint.
- Periodically re-run the completed Attested Model Profile Configuration DDD's
  catalog validation, native Settings build, exact Touch ID activation,
  transaction recovery, profile/session/lease binding, adapter fixtures,
  encrypted credential staging, inactive-profile isolation, production
  readback, and complete boundary gates.
- Periodically re-run the completed SecureSandbox Control Center DDD's native
  build and bundle validation, cold Stop/Start, emergency containment and
  recovery, accepted-restore readback, export integrity, protected-launch
  safety audit, and complete boundary gates. Production-data-dependent finding,
  memory-proposal, and snapshot actions remain fail-closed until legitimate
  records or policy milestones exist.
- Periodically re-run the completed Azure Evidence and Alerting Plane DDD's
  destructive-change-rejecting what-if, exact resource/role/lock/budget
  verification, synthetic alert-semantics matrix, fresh off-host heartbeat and
  denial gates, shared-installer active-state preservation, and complete
  boundary verification.
- Periodically re-run the completed Parallels Lifecycle Resilience DDD's
  fault-injection, controlled stop/start, idempotent recovery, and complete
  boundary gates with the Parallels Desktop GUI closed.
- Periodically re-run the completed Privileged Workflow Transaction Engine
  DDD's append-only chain, lost-response, exact-identity, expiry, rollback,
  irreversible-activation, and complete boundary gates.
- Complete an Authority Loss and Disaster-Recovery DDD covering permanent loss
  of the Mac, its non-exportable Secure Enclave identity, the protected Host
  installation, or any single VM without weakening fail-closed replacement and
  revocation rules.
- Complete a Full-Stack Chaos and Restart Matrix DDD that injects termination at
  every Host, Gateway, Research, and Target transition and rejects mixed
  generations, stale admission, authorization reuse, and false evidence.
- Preserve the completed Harness Lifecycle and Verified Upgrade DDD's immutable
  generation, inert acquisition, quarantine, fail-closed provenance,
  conformance qualification, exact Touch ID activation, session pinning,
  monotonic floor, rollback, retirement, revocation, crash recovery, and
  evidence contracts. Optional scheduling may check bounded signed metadata
  and notify only; it must never download, stage, install, activate, roll back,
  retire, or revoke automatically. Implementation and live admission remain
  separate future authorizations, beginning with neutral manifests and a
  disposable qualification fixture.
- Preserve and extend the completed Harness Lifecycle Foundation and Host
  Quarantine DDD. Its implemented CLI may check bounded signed metadata,
  advance a monotonic metadata floor, explicitly acquire one exact artifact,
  quarantine it as non-executable data, and verify artifact/evidence bindings.
  It grants no staging, installation, activation, runtime, or automatic
  download authority. The remaining four implementation DDDs below are
  independently authorized and fail closed if their prerequisites are absent.
- Preserve and extend the completed Harness Conformance and Disposable
  Qualification DDD's exact plan, complete ordered matrix, independently
  executed synthetic malicious-harness fixture, outer-observer facts,
  non-admitting reports, and first-party Claude core adapter projection. Its
  built-in command may execute only the tracked synthetic fixture; it accepts
  no vendor artifact, executable path, policy override, or admission action.
  Any real harness generation still requires exact provenance verification, a
  separately accepted disposable supervisor with independent process, network,
  filesystem, resource, credential, and journal observation, and a new
  content-bound qualification report. A fixture pass has `authority: none` and
  must never be treated as staging or activation evidence for vendor bytes.
- Preserve and extend the completed Protected Harness Generation Store and
  Transactional Activation DDD. Its source implementation adds immutable
  content-inventoried Research release directories, protected catalogs and
  selectors, monotonic admission and revocation floors, exact five-minute
  Touch ID plans with no password fallback, run-admission fencing, independent
  health/readback, exact predecessor restoration, deterministic recovery,
  retention-only storage, zero-reference retirement, monotonic revocation, and
  complete boundary verification. Its public inspection CLI is read-only. It
  rejects the tracked synthetic fixture and has not configured a release
  policy, admitted vendor bytes, changed the live Research selector, or
  migrated a session. Those production gates remain separate.
- Preserve and extend the completed Harness-Bound Sessions, Leases, and Runtime
  Migration DDD. Session catalog v4, Gateway lease v2, Research lease v2, and
  process seed v2 bind every new or resumed run to one exact independently
  remeasured harness/manifest/executable/inventory/adapter generation. The
  protected release path, not `/usr/local/bin/claude`, is runtime authority.
  Legacy sessions fail closed and require exact fresh attestation plus a
  five-minute Touch ID migration with no password fallback or selector
  inference. The source and transactional deployment path are complete, but no
  live deployment, vendor admission, selector change, or migration occurred.
  The public migration CLI is plan-only; committing a migration remains fenced
  until a protected Host Touch ID consumer is implemented.
- Preserve the completed Control Center Harness Lifecycle GUI DDD. It adds
  typed models, bridge/client/store layers, a Harnesses settings surface,
  floor-bound evidence and compatibility review, confirmed manual
  check/acquire/verify and synthetic-self-test controls, read-only protected
  catalog inspection, and metadata-only notification scheduling. It never
  automatically downloads or installs. Protected mutation controls now defer
  to the independently implemented authorization consumer below.
- Preserve the completed Protected Harness Lifecycle Authorization Consumer
  DDD. Its fixed Research manager owns bounded inert staging, exact plan
  creation, store mutation, contained health probing, active-run readback, and
  deterministic recovery. The immutable Host broker derives request-bound
  Touch ID-only receipts with no password fallback; its manager independently
  rereads the v4 Host session catalog and verifies protected status and boundary
  after every result. Control Center enables only capabilities proved by fresh
  protected state and displays the exact expiring plan before Touch ID. No live
  deployment, vendor admission, or selector change occurred in this source
  checkpoint; those remain acceptance and operator-authorized gates.
- Complete the in-progress Disposable-Mac Harness Lifecycle Acceptance DDD.
  The exact 91-case/198-observation campaign contract, clean-machine enrollment,
  evidence-only verifier, and journal-before-fence crash repair are implemented
  and source-tested. Bootstrap, provenance, the production-bound archive
  driver, qualification, and recovery are source-complete; five of ten declared physical driver
  classes still lack entrypoints.
  Campaign initialization now fails closed against both that fixed source
  inventory and an exact-commit, root-owned, self-digested protected-driver
  manifest. A checkout alone reports zero physically available drivers, and
  there is no incomplete or unprotected-driver bypass. The Host recovery supervisor is also source-complete: it
  deploys exact-commit synthetic fixtures through protected Research control,
  binds current-Mac and Research process/boot identity, shares the VM lifecycle
  lock, and can hard-power only Research while preserving Gateway and Target.
  Its fixed observation bridge independently revalidates and snapshots each
  raw recovery artifact set before crash-resumable, non-overwriting projection
  into the suite-assigned collector observations. The clean-machine bootstrap
  driver is likewise source-complete for the first two cases: it independently
  verifies the installed Host/Research boundary, revalidates enrollment,
  repeats the metadata-only production-material scan, reserves failed attempts,
  and projects only fixed-authority evidence from private canonical snapshots.
  Provenance acceptance has also closed its first production-state gap:
  carrier bytes are completely verified in anonymous staging before quarantine
  creation, while successful publication is descriptor-relative and
  no-overwrite, with exact inventory and file identities rechecked immediately
  before success-receipt publication. Regression coverage proves length and
  digest rejection preserve absent and concurrently introduced state, and that
  byte-identical substitution or unexpected children cannot receive success.
  The sixteen-case provenance fixture core and exact-source evidence projector
  are now source-complete, backed by real production-store behavior including
  delegated signer chain, validity, cascading intermediate policy revocation,
  carrier, freshness,
  rollback, fast-forward, and equivocation paths. Its root-only installer now
  requires a clean exact commit, reads payloads from immutable Git objects,
  serializes publication with a root-owned lock, publishes a canonical
  self-digested manifest without overwrite, post-verifies the release, and the protected invocation emits
  root-owned mode-0444 observations. It remains unavailable until installed and
  run on the disposable Mac; owner-run fixture output is not physical Host
  evidence. The non-extracting archive preflight now runs inside the real
  `HarnessStore.acquire` production boundary after signed carrier length/digest
  verification and before quarantine creation. All twelve fixed attacks use
  signed synthetic carriers, independently inventory the isolated protected
  store before and after rejection, and require an empty quarantine. Archive is
  again physically eligible, and the shared exact-commit Host installer binds
  and post-verifies both provenance and archive inventories. The common
  existing-generation verification path now rereads and digest-checks archive
  bytes before applying the same current preflight, so neither idempotent
  acquisition nor explicit verification can issue a success receipt for an
  unsafe legacy quarantine. The Research recovery deployment now stages and
  protects the archive-preflight dependency imported by the lifecycle module.
  The qualification acceptance projection core now binds each of its ten cases
  to the complete thirty-case synthetic qualification report, pins the sole
  fixture path, rejects observation overrides, and remains explicitly
  non-admitting and physically ineligible. Its root-only Research wrapper now
  runs that unchanged core in an exact-commit installed transient systemd unit
  with a dynamic user, deny-all private network, strict protected filesystem,
  credential-environment removal, bounded process count, complete unit-policy
  readback, empty post-run cgroup, and Research boot binding. The outer wrapper
  alone can mark its Research result physically eligible; constructed inner
  facts still cannot be relabeled. Its fixed Host supervisor now verifies the
  enrolled Mac and exact protected manifest, reserves evidence before remote
  mutation, rescans production material and Keychain state, proves the Host
  fixture stayed inert, deploys only manifest bytes, and records no admission
  or lifecycle mutation. Its projector revalidates the complete four-record
  mixed-authority set before non-overwriting publication. Live protected
  installation and all ten physical cases remain pending the disposable Mac.
  Physical execution remains pending the dedicated disposable Mac: exercise
  fresh bootstrap, Touch ID
  approve/cancel/expiry/replay, signature and chain failures,
  rollback/freeze/equivocation, archive attacks, process and Research-VM power
  loss at every transition, cold-boot readback, legacy-session handling,
  rollback, revocation, containment, reclamation, and independent off-machine
  evidence export. Do not treat source tests as physical evidence or begin the
  First Exact Claude Generation Admission DDD before this campaign passes.
- Complete the First Exact Claude Generation Admission DDD. Select one immutable
  Claude Code release rather than a channel, retain every original vendor
  artifact and attestation, pass the complete provenance and conformance
  matrix, activate with exact Touch ID, prove old-session pinning and explicit
  rollback, and publish an admission decision. This DDD does not admit Codex,
  Pi, plugins, or any second harness.
- Preserve the completed Multi-Harness Admission and Plugin-Ecosystem
  Isolation DDD's conditional direction: admit only a small set of immutable
  core-only harness generations through first-party adapters; treat vendor
  marketplaces as acquisition leads, never runtime authority; decompose every
  ecosystem package by capability class; keep in-process extensions, native
  hooks, runtime packages, connectors, and peer-harness calls prohibited; and
  bind any separately admitted skill or outer tool service to the exact
  harness, model-profile, session, and extension-set revisions. Codex and Pi
  are evaluation-order candidates only. No new harness or extension is
  authorized until the neutral framework, conformance matrix, transactional
  Touch ID lifecycle, disposable-Mac acceptance, and separate admission
  decision are complete.
- Preserve the completed First-Party Research Harness Feasibility DDD's hybrid
  decision: SecureSandbox owns authority, admission, model, tool, evidence, and
  lifecycle contracts while each inner harness remains untrusted and
  replaceable. Do not build a general-purpose first-party harness. A separately
  authorized narrow reference prototype is eligible only after a documented
  trigger and must meet the DDD's conformance, security, quality, cost, latency,
  UX, provenance, and maintenance thresholds before a new production decision.
- Periodically re-run the completed Operator Ceremony and Diagnostics DDD's
  approve/cancel separation, expiry distinction, sink enforcement, diagnostic
  authenticity, authoritative receipt binding, and complete boundary gates.
- Extend the completed Secure Enclave execution-approval evidence with
  separately reviewed destructive-negative tests on a disposable Mac. The
  deployed generation, reboot acceptance, commitment, software-authority
  retirement, live expiry gate, and postdeployment audit are complete.
- Periodically re-run the completed Local Broker Protocol Hardening DDD's
  adversarial framing, deadline, peer-authentication, and saturation gates.
- Periodically re-run the completed Transactional Publisher Crash-Recovery
  DDD's phase-boundary, substitution, idempotency, and rollback gates.
- Preserve and periodically test the implemented exact-candidate CI,
  deterministic source release, and signed build-provenance controls.
- Keep public architecture documents descriptive; store live acceptance and
  operations records only in ignored local storage.

## Change discipline

New capabilities should begin with a threat model, use the narrowest authority
that satisfies the workflow, carry explicit evidence semantics and resource
bounds, and receive independent review before deployment. A passing test suite
does not replace cold-boot and boundary acceptance for changes affecting the
live lab.
