# Harness Lifecycle and Verified Upgrade DDD

Status: research and design complete; implementation and live admission not authorized

## 1. Decision

SecureSandbox will replace the current one-shot harness installer with a
fail-closed lifecycle for immutable harness generations. Each generation is
acquired as inert data, verified against an exact release manifest, quarantined,
qualified against the Harness Admission Contract, staged without runtime
authority, and activated only by an exact Touch ID authorization. Existing
sessions remain bound to the generation with which they began.

There is no automatic harness update. SecureSandbox may optionally check for
bounded release metadata and notify the operator, but it never automatically
downloads an artifact, verifies it as a candidate, stages it, installs it,
changes a selector, activates it, rolls it back, retires it, or revokes it.
Those are distinct capabilities, not modes of one updater.

The model, harness, source tree, project configuration, provider response,
extension, and session content have no lifecycle authority. They cannot invoke
or influence checking, acquisition, verification policy, qualification,
activation, rollback, retirement, or revocation.

This DDD defines the implementation contract. It does not admit a new Claude
Code version, Codex, Pi, or any other harness; modify the live Research VM; or
turn the Control Center application updater into a protected-environment
updater.

## 2. Why the current installer is insufficient

The current `scripts/install-claude-code.sh` is a reproducible bootstrap for
Claude Code 2.1.300, not a lifecycle:

- it verifies fixed SHA-256 values for the Claude binary and two packages;
- it installs dependencies and overwrites `/usr/local/bin/claude` directly;
- it verifies only the reported version after installation;
- `research/run_lease_process.py` launches that mutable pathname; and
- the session registry proves membership, but does not bind a session to a
  harness generation.

The supervisor correctly disables harness updates and upgrade, login, logout,
and built-in agents. That is a containment control, not provenance. A matching
hash proves only equality to the locally expected bytes; it does not prove who
released them, how they were built, whether the expectation was substituted,
or whether the generation satisfies SecureSandbox's current contracts.

The existing 2.1.300 installation is therefore a named **legacy bootstrap
generation**. Migration must measure its exact bytes and dependencies and bind
them to a local legacy record. It must not invent vendor signatures, build
provenance, or source history that were not retained. A separately authorized
migration may keep it as a rollback generation only if it passes the then-current
minimum conformance policy.

## 3. External evidence and local authority

Anthropic currently publishes an exact-version manifest with SHA-256 values
and a detached signature for Claude Code releases from 2.1.89 onward. Its Linux
binaries are not individually code-signed, so the signed manifest is the
relevant vendor integrity path. Anthropic also documents that
`DISABLE_AUTOUPDATER` stops only background checks, while `DISABLE_UPDATES`
blocks manual update paths as well. SecureSandbox keeps the stronger setting
and independently removes update authority from the sandbox.

Vendor evidence is necessary but insufficient. A compromised vendor key,
build, account, release service, or dependency could still produce correctly
signed malicious bytes. GitHub or a vendor bucket is a carrier, not the final
trust root. SLSA provenance is useful because it binds an artifact to where,
when, and how it was produced. Sigstore bundles and transparency inclusion are
useful independent evidence when a vendor supplies them. TUF-style threshold,
expiry, rollback, freeze, and consistent-snapshot rules inform the metadata
client. None of these alone expresses the project owner's decision to activate
a generation.

Until the Human Identity and Release Authenticity DDD is implemented, the
project cannot claim a complete public human-to-release chain. Production
activation therefore requires both all vendor evidence mandated by the
harness policy and a locally reviewed, Touch ID-authorized SecureSandbox
release manifest. Missing, expired, inconsistent, unrecognized, or
cryptographically invalid required evidence fails closed with no bypass.

## 4. Trust and threat model

### Trusted for the proposed implementation

- the protected Host controller generation and fixed lifecycle dispatcher;
- root-owned Gateway and Research policy, transaction state, and selectors;
- the signed Touch ID authorization application and non-exportable operator
  key;
- pinned verification implementations and locally installed trust roots; and
- the reviewed admission adapter, conformance suite, and release policy.

### Untrusted

- vendor sites, GitHub, mirrors, DNS, TLS alone, redirects, clocks, and release
  prose;
- archives, manifests, signatures, certificates, transparency responses,
  provenance, SBOMs, package metadata, source, and build output until verified;
- every candidate harness, installer, updater, plugin manager, hook, package
  manager, and post-install script;
- model output, project files, session data, UI cache, and editable settings;
  and
- process exit status or harness-reported version without independent readback.

### Principal threats

- substitution of a release, manifest, key, certificate, source revision,
  dependency, adapter, or conformance report;
- rollback, freeze, mix-and-match, fast-forward, replay, equivocation, and
  indefinite-download attacks;
- archive traversal, symlink, device, sparse-file, decompression, or dependency
  confusion attacks;
- a candidate executing during verification or smuggling an updater, login,
  credential, marketplace, peer-harness, arbitrary-network, or child-process
  path through qualification;
- a selector changing between review and activation, or a session silently
  moving to a new generation;
- partial activation, lost response, crash, disk exhaustion, or mixed Host,
  Gateway, Research, model-profile, adapter, and harness generations;
- malicious remote revocation acting as a kill switch; and
- deletion of a generation or evidence still required by a live or resumable
  session.

## 5. Capability separation

The implementation exposes six fixed capabilities with separate policy and
entry points:

| Capability | Effect | Touch ID |
| --- | --- | --- |
| Check | Fetch bounded signed metadata into an untrusted cache and notify | No |
| Acquire | Download one operator-selected exact artifact and evidence set | No, but explicit action |
| Verify | Quarantine and validate bytes/evidence without executing candidate | No, but explicit action |
| Qualify | Run the candidate only in disposable, denied-by-default fixtures | No, but explicit action |
| Stage | Copy a qualified immutable generation into protected inactive storage | Yes |
| Activate/rollback/revoke/retire | Change protected lifecycle authority | Yes, exact action |

An automatic schedule, if enabled, can invoke only `Check`. It is disabled by
default, has a bounded interval and response size, and may report “new metadata
observed” or a verification error. It cannot resolve “latest” into install
authority, fetch target bytes, create an activation plan, prompt for Touch ID,
or retry a protected operation. There is deliberately no auto-download or
auto-update preference.

The acquisition worker runs outside Research with no provider credential,
session access, protected selector, or activation API. The qualification worker
runs in a disposable candidate VM or equivalent future fixture with synthetic
credentials and no route to production services. Research never contacts a
vendor update service.

## 6. Release manifest

Every candidate has canonical `secure-sandbox-harness-release-manifest-v1`
metadata. Bounds are fixed in policy. The manifest contains:

- harness ID, adapter ID, vendor ID, exact version, monotonically increasing
  release sequence, target platform, and generation ID;
- artifact media type, exact byte count, SHA-256, extraction inventory, modes,
  and entry digests;
- exact executable, interpreter, runtime libraries, resources, and dependency
  closure; no PATH discovery or ambient package resolution is permitted;
- vendor origin, immutable release locator, vendor manifest/signature/certificate
  identities, verified key fingerprints, and stapled evidence digests;
- source revision and source provenance when source is available; build
  predicate, builder identity, parameters, materials, and SLSA/in-toto evidence
  when supplied; a deliberate `unavailable` value otherwise;
- SBOM, licenses, vulnerability/malware/static-review results, exceptions, and
  their policy versions;
- adapter, persona, event, tool, session, model-profile, extension-set, and
  conformance-suite schema/digests;
- compatible SecureSandbox controller, Gateway, Research, and policy ranges;
- qualification report, hostile-fixture corpus, reviewer decision, publication
  and expiry times, and the exact mandatory evidence policy;
- predecessor, rollback eligibility, retention class, and known-revocation
  state; and
- canonical manifest digest and future project authorization envelope.

The generation ID is derived from the canonical manifest and complete installed
inventory, not a version label. Two builds of the same marketing version are
different generations. Unknown keys, duplicate paths, aliases, absolute or
parent paths, links, devices, sockets, executable writable files, unexpected
set-ID/capability bits, unbounded numbers, and noncanonical encodings are
rejected.

The manifest never contains credentials, prompts, responses, session content,
or secret-derived values.

## 7. State machine

The normal state sequence is:

`observed -> acquired -> quarantined -> provenance-verified -> qualified -> staged -> active -> retired`

`rejected` and `revoked` are terminal security states. `archived` is a storage
state for retained inactive bytes and evidence, not an admissibility state.
Transitions never skip forward and cannot be inferred from a familiar version
or filename. Reverification under a changed policy produces a new qualification
record; it does not rewrite history.

Only one generation per admitted harness ID is active for new sessions. More
than one generation may remain installed because active/resumable sessions are
pinned, a predecessor is retained for rollback, and evidence retention may be
longer than executable retention.

## 8. Acquisition and quarantine

The metadata client accepts only fixed HTTPS origins and policy-pinned root
identities. Redirects, mirrors, and delegated roles must be explicitly bounded.
It verifies canonical signed metadata, threshold, role, version, expiry,
consistent-snapshot name, target size/hash, and the monotonic local metadata
floor before announcing a candidate. Invalid metadata raises a red warning and
does not overwrite the last known-good cache.

An explicit acquisition selects an exact target digest and byte count. It uses
bounded time, byte, redirect, filename, and content-type limits; streams into a
new inert Host quarantine object; verifies the digest before publication; and
never pipes network bytes into a shell, installer, package manager, interpreter,
or decompressor. A resumed download must prove it is the same immutable object.

Quarantine extraction occurs as an unprivileged identity in a disposable
filesystem with no network, device, credential, session, repository, or
protected-state access. The extractor preflights the complete archive inventory
and expansion bounds, then independently reads back every output. Install
scripts and lifecycle hooks are data for inspection and are never run.

## 9. Provenance verification

Verification is policy-driven per harness and platform. It requires, at
minimum:

1. exact artifact size and digest from locally trusted release metadata;
2. vendor manifest signature or package-repository signature, with the exact
   pinned identity and algorithm policy;
3. certificate validity, usage, chain, timestamp, and revocation evidence where
   that signature format uses certificates;
4. complete extraction/dependency inventory and dependency provenance;
5. source/build provenance and transparency proof when the vendor offers them;
6. SBOM, license, vulnerability, malware, secret, and static-behavior review
   required by policy; and
7. agreement among all overlapping identities, versions, sizes, hashes, source
   revisions, platforms, and dependencies.

The absence of optional evidence lowers the displayed assurance tier. The
absence or failure of mandatory evidence rejects the candidate. No GUI, CLI,
environment variable, support mode, debug flag, or root command may bypass a
cryptographic or policy failure. Changing what is mandatory is itself a
reviewed SecureSandbox policy release, never a per-candidate override.

Verification stores the original evidence and a canonical decision receipt.
Online transparency and revocation responses are stapled so later audit does
not silently depend on mutable network state. Wall-clock claims require the
trusted-time design; ambiguous time fails closed for activation.

## 10. Qualification and admission

Only a provenance-verified candidate may enter qualification. It runs against
the neutral harness conformance matrix from the completed Multi-Harness DDD in
a disposable environment. The suite covers:

- fixed adapter protocol, event ordering, interruption, cancellation,
  compaction, new/resume/close semantics, and stable session identity;
- canonical tool projection and denial of hidden tools, native shells, direct
  MCP, arbitrary child processes, dynamic code, packages, hooks, marketplaces,
  extensions, subagents, login, model switching, and self-update;
- clean environment and data-root isolation, provider/network denial, secret
  absence, resource ceilings, and process-tree containment;
- hostile project files, prompts, tool results, session state, malformed
  responses, configuration precedence, and filesystem fixtures;
- exact model-profile, persona, policy, adapter, tool, and event bindings;
- authoritative evidence produced outside the candidate; and
- quality, latency, cost, reliability, and operator-UX regression thresholds.

The candidate cannot write its own passing report. The outer fixture records
inputs, policy, binary measurements, system calls/network attempts, outputs,
and pass/fail evidence. Any unexplained feature discovery, network attempt,
credential access, executable write, policy bypass, or schema drift rejects the
generation. A candidate may crash without being a security failure, but cannot
be admitted until required reliability gates pass.

## 11. Protected storage and execution

Qualified generations are staged into a root-owned Research store such as:

`/usr/local/libexec/secure-sandbox-harnesses/releases/<generation-id>/`

The eventual implementation fixes the actual path. Each release directory is
immutable after publication and contains the complete executable closure,
manifest, verification receipt, qualification receipt, and adapter projection.
It is owned by root, non-writable to the agent, free of links to mutable vendor
or user paths, and remeasured before use.

Root-owned canonical catalog records replace `/usr/local/bin/claude` as
authority. A selector is only an index. The run controller opens the catalog
without following links, validates ownership/mode/schema/hash, resolves the
exact generation and real executable, opens or measures that file, and passes
the fixed descriptor/path into the supervisor. PATH lookup, shell aliases,
vendor launchers, mutable `current` links, and executable self-replacement are
not trusted.

The active profile record, harness generation, adapter, persona, tools,
extension set, and SecureSandbox policy generation form one launch tuple.
Mismatch keeps run admission closed.

## 12. Activation ceremony and transaction

Staging is not activation. Control Center displays the exact candidate and
evidence projection, compatibility result, current and predecessor generations,
session impact, rollback eligibility, and plan digest. It then creates a
bounded five-minute activation plan. The protected Touch ID prompt binds the
plan ID and SHA-256; password fallback is forbidden.

Activation refuses if a run is active, admission is already fenced, recovery
is pending, evidence expired, policy changed, the candidate or plan changed,
storage is inconsistent, or independent Host/Research readback disagrees.
The privileged transaction then:

1. records the exact component identities in the append-only transaction
   engine and fences new run admission;
2. reopens and revalidates the plan, candidate, catalog, active selector,
   monotonic floors, policy, and qualification evidence;
3. publishes the immutable generation and proposed catalog record with fsync;
4. atomically selects the candidate for **future sessions only**;
5. independently reads back and rehashes the installed inventory and selector;
6. runs a bounded synthetic launch through the production adapter with no
   production model or credential;
7. only after the selector and health result agree, records the generic
   transaction engine's irreversible `activated`, `verified`, and `committed`
   events and reopens admission; or
8. if post-activation health fails, restores the exact prior selector within
   the same already-authorized transaction, reads it back, records failure, and
   keeps the failed generation rejected.

Automatic restoration in step 8 occurs in the component journal while the
generic transaction is still `authorized`; its `activated` event is never
written for a failed candidate. This respects the transaction engine's rule
that activation is irreversible. The restoration is crash safety inside one
authorization, not automatic updating or a new rollback decision. A lost
response is retried only with the same action ID and exact identities. Recovery
never chooses a newer, older, or “closest” generation.

## 13. Session generation pinning

The session catalog and every run lease gain immutable `harness_id`,
`harness_generation_id`, `harness_manifest_sha256`, and `adapter_sha256`
bindings. A new session receives the then-active generation. A resumed session
must use its exact recorded generation; it never inherits the current selector.

Research verifies that the lease, session catalog, protected harness catalog,
executable measurement, and active model-profile tuple agree before spawning.
The process receipt repeats the generation and executable digest. Authoritative
evidence and exports retain that binding.

Legacy sessions without a trustworthy generation binding cannot be guessed or
silently migrated. A separate reviewed migration may bind them to a measured
legacy generation, create a new session, or leave them non-resumable.

An inactive pinned generation remains non-callable by other sessions. It may be
loaded only for a resume whose trusted catalog record names it. A revoked
generation is never resumable.

## 14. Rollback, retirement, revocation, and retention

An explicit rollback is a new exact Touch ID transaction. It may select only a
retained, fully verified, currently policy-compatible, non-revoked predecessor.
The monotonic metadata and admission floors do not move backward; the receipt
records that an older admitted generation was deliberately selected. This
prevents a replayed repository from turning rollback into downgrade authority.

Retirement removes a generation from selection for new sessions after a
confirmation that names affected resumable sessions. It does not erase bytes
or evidence. Destructive executable reclamation requires a separate Touch ID
action, exact inventory, zero active or resumable references, a retained
predecessor, and durable evidence archive. Current, predecessor, session-bound,
and investigation-held generations cannot be reclaimed.

Revocation is monotonic and fail closed. A signed remote notice may produce a
red notification, but cannot remotely kill a process or mutate local authority.
The operator may explicitly revoke through Touch ID, or a separately installed
SecureSandbox policy generation may carry a reviewed emergency denylist. A
revoked generation cannot start or resume and cannot be a rollback target.
Containment of an already-running revoked generation is a distinct emergency
action with its own authoritative receipt.

There is no bypass for a broken signature, unrecognized certificate, revoked
identity, expired mandatory evidence, inconsistent chain, policy mismatch, or
tampered artifact. Updating can remain bricked until a valid policy or release
is produced; availability never outranks integrity.

## 15. Crash recovery

Every mutation uses the privileged workflow transaction engine and a
component-specific journal for subphases. Publication uses new names, fsync,
no-overwrite boundaries, atomic selector replacement, and independent
readback. Recovery reconstructs truth from durable records rather than GUI
state or a command response.

Fault injection must cover termination before and after every artifact write,
directory sync, catalog publication, selector change, health probe, transaction
event, admission fence, and response. Recovery has only three valid outcomes:
the old generation remains authoritative, the exact authorized new generation
commits, or admission stays closed awaiting operator-visible recovery. Mixed or
ambiguous state never launches a harness.

Disk exhaustion, clock loss, missing predecessor, corrupt evidence, extra
files, changed ownership/mode, symlink substitution, transaction fork, and
stale authorization all fail closed. Repeated exact recovery is idempotent.

## 16. Control Center UX

The future Harnesses settings surface shows:

- active, retained, pinned, staged, rejected, retired, and revoked generations;
- vendor version, generation digest, evidence tier, policy, qualification,
  compatibility, expiry, predecessor, and affected sessions;
- `Check for Releases`, `Download Selected Candidate`, `Verify`, `Qualify`,
  `Stage with Touch ID`, `Activate with Touch ID`, `Rollback with Touch ID`,
  `Retire`, and `Revoke` as distinct actions; and
- an optional `Check automatically` notification preference, disabled by
  default.

There is no `Update`, `Update All`, `Automatically download`, or `Automatically
install` control. A metadata notification never becomes a modal authorization
prompt on its own. Security failures are red, persistent, content-free, and
non-bypassable. Destructive retirement/reclamation and revocation use explicit
confirmation dialogs in addition to Touch ID.

## 17. Audit and attestability

Each check, acquisition, verification, qualification, staging, activation,
rollback, retirement, revocation, containment, reclamation, and recovery action
emits a typed, bounded receipt. Receipts bind action ID, actor class, time
source, old/new generations, manifest/evidence/policy/adapter/conformance
digests, authorization provenance, transaction state, result, and independent
readback. They never contain prompts, responses, credentials, session content,
or unbounded vendor text.

An evidence export includes original signed metadata and signatures, stapled
certificate/transparency/revocation material, artifact and inventory digests,
provenance/SBOM/scan references, conformance results, activation transaction,
session bindings, monotonic floors, and current catalog readback. The export
distinguishes vendor-authenticated, project-reviewed, operator-authorized, and
runtime-observed facts; it does not collapse them into “trusted.”

## 18. Severity model

| Severity | Example |
| --- | --- |
| Critical | Unreviewed bytes gain Research execution; candidate gets lifecycle/provider/Host authority; model triggers activation; signature failure can be bypassed |
| High | Session runs another generation; revoked generation launches; mixed-generation activation commits; authoritative evidence accepts candidate self-report |
| Medium | Valid candidate cannot activate; bounded qualification misses a non-authority behavior regression; notification freezes or repeats |
| Low | Cosmetic metadata, progress, or sorting defect while authority and receipts remain correct |

Denial of update is an expected safe outcome under uncertainty. It does not
become High merely because a newer harness is unavailable.

## 19. Implementation sequence

Implementation requires separate authorization and proceeds in checkpoints:

1. neutral manifest, metadata verifier, quarantine store, receipts, and hostile
   parser tests with no live mutation;
2. disposable qualification fixture and Claude adapter conformance suite;
3. immutable Research release store, catalog, transaction/recovery manager, and
   complete boundary verifier;
4. session catalog/run lease/supervisor generation binding and legacy migration;
5. protected lifecycle planner, Touch ID operations, and Control Center UI;
6. destructive-negative and crash matrix on the disposable Mac; then
7. separately reviewed admission of one exact Claude generation.

The existing direct installer remains bootstrap-only during implementation. It
must not be generalized, connected to a release channel, or treated as the
production lifecycle.

## 20. Disposable-Mac acceptance

Before production admission, the disposable Mac must prove with synthetic
credentials and sessions:

1. clean acquisition from each supported carrier and rejection of redirects,
   oversized data, archive attacks, substitution, bad/unknown/revoked/expired
   signatures, broken certificate chains, stale/future metadata, rollback,
   freeze, fast-forward, equivocation, and inconsistent provenance;
2. zero candidate execution before qualification and zero production authority
   during qualification;
3. all forbidden updater, login, model, tool, extension, child-process,
   credential, and network paths remain unavailable;
4. Touch ID approve, cancel, expiry, replay, changed-plan, and wrong-generation
   behavior;
5. exact future-session activation and exact old-session generation pinning;
6. explicit rollback, retirement, reclamation, revocation, emergency
   containment, and legacy-session handling;
7. power/process loss at every transition followed by deterministic recovery;
8. cold boot and independent Host/Research/catalog/executable/policy readback;
   and
9. a complete evidence export that can be verified without trusting the
   candidate harness.

Production data, provider credentials, and research sessions remain out of
scope until this matrix passes.

## 21. Relationship to adjacent DDDs

### Multi-Harness Admission and Plugin-Ecosystem Isolation

This DDD completes its lifecycle design dependency. The immutable generation,
adapter, extension-set, session, and model-profile bindings defined there are
the admission inputs here. It does not admit Codex, Pi, or an ecosystem.

### First-Party Research Harness Feasibility

The hybrid decision remains unchanged: SecureSandbox owns lifecycle authority
and contracts while the inner loop is replaceable and untrusted. A future
first-party reference harness follows this same lifecycle.

### Model Profile Configuration

Model profiles remain the sole provider/model/settings authority. Harness
activation cannot change a model profile, and profile activation cannot change
a harness generation. A run requires both exact bindings to agree.

### In-app Updates

The Control Center app updater is user-local and cannot update protected
harnesses. The two systems share fail-closed principles but have separate
roots, manifests, storage, authorization operations, monotonic floors, and
receipts.

### Human Identity and Release Authenticity

That backlogged DDD must provide the future public human-to-project release
authorization chain. This lifecycle already reserves a project authorization
envelope and treats vendor/GitHub/Sigstore/SLSA evidence as evidence rather
than final human authority.

## 22. Primary research references

- Anthropic, “Agent containment best practices for CVP participants,” the CVP
  Defense baseline for isolation, external credential brokering, validation,
  monitoring, target scoping, human supervision, and high-consequence target
  exclusion; see the project's
  [normative summary and mapping](ANTHROPIC_CVP_DEFENSE_CONTAINMENT_FOUNDATION.md):
  <https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants>
- Anthropic, “Advanced setup,” exact versions, update controls, signed release
  manifests, checksums, and platform signatures:
  <https://code.claude.com/docs/en/setup>
- SLSA v1.2, “Provenance”:
  <https://slsa.dev/spec/v1.2/provenance>
- Sigstore, “Verifying Signatures”:
  <https://docs.sigstore.dev/cosign/verifying/verify/>
- The Update Framework Specification 1.0.37:
  <https://theupdateframework.github.io/specification/latest/>

These sources describe evidence mechanisms and threat patterns. SecureSandbox's
manual activation, no-bypass policy, and separation of carrier, vendor,
project, and operator authority are local design decisions.

## 23. Acceptance contract for this DDD

This research/design DDD is complete when:

- the current bootstrap installer and runtime seams are mapped to source;
- automatic behavior is limited to optional metadata-only checking and all
  download/install/activation remains manual;
- manifest, acquisition, quarantine, provenance, qualification, protected
  storage, and immutable-generation contracts are explicit;
- Touch ID activation, monotonic floors, session pinning, rollback, retirement,
  revocation, retention, recovery, audit, and severity are explicit;
- cryptographic and policy failures have no bypass;
- model-initiated or harness-initiated lifecycle changes are impossible by
  contract;
- implementation and disposable-Mac gates are measurable; and
- the roadmap no longer presents the design question as unanswered.

This document satisfies that research/design contract. It intentionally does
not satisfy implementation, live migration, candidate qualification, or
production admission.
