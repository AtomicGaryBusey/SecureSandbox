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
  download authority. The remaining six implementation DDDs below are
  independently authorized and fail closed if their prerequisites are absent.
- Complete the Harness Conformance and Disposable Qualification DDD. Build the
  synthetic malicious-harness fixture, neutral conformance runner, externally
  observed behavior receipts, Claude core adapter, and hostile update, login,
  tool, plugin, MCP, network, credential, process, session, interruption, and
  evidence tests. Qualification remains disposable and grants no production
  execution authority.
- Complete the Protected Harness Generation Store and Transactional Activation
  DDD. Add immutable root-owned Research generations, protected catalogs and
  selectors, monotonic admission floors, exact Touch ID plans, run-admission
  fencing, independent health/readback, predecessor restoration, recovery,
  retention, retirement, revocation, and boundary verification.
- Complete the Harness-Bound Sessions, Leases, and Runtime Migration DDD.
  Advance session, Gateway lease, Research lease, and process schemas; bind
  every new or resumed run to one exact harness/manifest/executable/adapter
  generation; remove `/usr/local/bin/claude` as authority; and provide an
  explicit non-inferential legacy-session migration.
- Complete the Control Center Harness Lifecycle GUI DDD. Add typed models,
  catalog client operations, store, Harnesses settings surface, evidence and
  compatibility review, manual check/acquire/verify/qualify controls, exact
  Touch ID protected actions, confirmation safeguards, and metadata-only
  notification scheduling. Never add automatic download or installation.
- Complete the Disposable-Mac Harness Lifecycle Acceptance DDD. Exercise fresh
  bootstrap, Touch ID approve/cancel/expiry/replay, signature and chain
  failures, rollback/freeze/equivocation, archive attacks, process and power
  loss at every transition, cold-boot readback, legacy-session handling,
  rollback, revocation, containment, reclamation, and independent evidence
  export before production data or credentials are in scope.
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
