# Native Vendor Harness + Model Stack Mode acceptance evidence

Status: source DDD completion record. Executable checkpoint `d5393bf`, the
final immutable security scan, focused and aggregate suites, and deterministic
public-release checks are green. The original immutable changed-boundary scan of
`c8a67ee..459b10a` confirmed five findings: **one high, three medium, and one
low**. A later immutable scan of `c8a67ee..133d1a5` confirmed a further **one
high and one medium** containment finding. All seven are source-remediated;
the final immutable remediation scan is recorded below. Final publication
requires the same documentation-only descendant on both configured remotes;
signed protected installation, admitted live harnesses, real Linux/systemd
behavior, provider logins and entitlement requests, physical/disposable tests,
and production activation remain independent gates until their corresponding
rows pass.

This matrix is the evidence authority for the
[Native Vendor Harness + Model Stack Mode DDD](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_DESIGN.md).
It deliberately records the two initial vendor stacks independently. A passing
Claude row cannot waive a Codex requirement, and a provider response cannot
waive an outer containment requirement.

## Assurance labels

Every entitlement and acceptance fact uses one of these labels:

- `provider-enforced`: demonstrated by a successful request under the exact
  provider account, workspace, model, and access-program selection;
- `operator-external`: declared by the operator in a fresh Touch ID ceremony
  and bound to the exact opaque account/workspace digests and requirements
  snapshot, but not independently exposed by the provider protocol;
- `attested-harness-enforced`: enforced by the admitted, measured vendor
  harness generation;
- `outer-control-enforced`: enforced and independently read back by
  SecureSandbox outside the vendor harness; or
- `unverified`: not yet demonstrated and therefore not admission authority.

Anthropic Mythos access is provider-enforced model evidence. The exact CVP
Defense enrollment/tier is an operator-external assertion unless Anthropic
later exposes an independent, documented attestation. OpenAI Daybreak Blue is
provider-enforced only for a completed turn that explicitly carries
`cyberAccessProgram: daybreakBlue`; model-catalog presence is never enough.

## Source and hostile-test matrix

`Implemented in source` is not a production acceptance label. It records only
that the reviewed boundary and focused tests exist in this branch. The final
candidate has passed the repository-wide test gate and independent
changed-boundary security review recorded below. The exact current Host pair
and notarized Control Center are installed with protected/read-back evidence;
the record now includes the final exact Host install and canonical publication
gate. Publication is complete only when both configured live remote tips equal
this exact reviewed commit; the handoff verifies that condition independently.
Guest deployment and live native-stack acceptance remain separate red gates.

| Boundary | Source evidence | Protected/live state |
|---|---|---|
| Closed stack pairing | Implemented in `shared/native_vendor_stack.py` with cross-vendor, cross-harness, alternate auth/custody, unknown-model/settings, and fallback rejection in `shared/test_native_vendor_stack.py` | `unverified`: no live stack activated |
| Harness generation | Runtime binding and every session consumer require the exact Harness Lifecycle generation, manifest/executable/inventory/adapter identity | `unverified`: no Claude or Codex generation admitted for this mode |
| Catalog publication | Host and Research use a durable fenced transaction, exact catalog-digest readback, and release-last recovery. Gateway does not publish the catalog; it participates separately in protected runtime deployment. | `unverified`: protected Host/Research publication not run |
| Protected runtime deployment | Deterministic Gateway/Research packages, exact predecessor typing, a Host cross-plane journal, shared installer/probe barriers, a durable Research lifecycle fence, release-last commit, exact compensation, and independent closed-state readback form the source contract. Transport success is non-authoritative. The final coordinator and driver paths are included in the green source suites below. | `unverified`: protected Host/Gateway/Research installation and execution have not run |
| Host coordination anti-rollback floor | Source cross-binds a private mode-0600 authoritative floor to a mode-0444 launcher enforcement projection; orders Host shared lock → controller lock → release verification → active marker; and performs its one-time pre-pair bootstrap under the Host exclusive lock. The sole pre-floor exception requires the complete exact `d8653cb` payload inventory and seven pinned payload digests. It suspends the exact historical broker, proves its PID/generation/stopped state and empty direct-child census, boots it out, performs two UID-scoped scans rejecting an old-release process or orphan, and retains both historical locks through selector/floor/install publication. Both scans recognize relative stable-launcher argv spellings by the basename of the explicit absolute launcher alias, closing the interpreter observation gap without broadening release containment. Crash-replay, exact-near-match, active-child, orphan-process, relative-launcher, and second-snapshot cases are included in the green source suites below. It is not the ordinary update protocol. | `host-verified`: protected readback retains the Developer ID, coordination, and candidate-admission enforcement projections for Team `389K3H8Y32`; the exact current Host pair is a descendant of those floors. Protected three-plane deployment remains `unverified`. |
| Host release/launcher atomic pair | Once `host-release-launcher-pair-fence-v1` is active, source admits only one exact release/launcher pair transition. A mode-0444 public PENDING record fences every launch before physical mutation; for ordinary install or rollback a private mode-0600 v2 journal binds the Touch ID plan and exact source and target generations; and a public terminal binds the completed receipt when non-bootstrap, committed pair, selectors, verified service identities, finalization, and service-evidence digests before STABLE replaces PENDING. Ordinary authority must remain within `created_at <= now < expires_at` before PENDING, after source-prefix authentication, and immediately before the first launcher mutation; the broker also evaluates recovered PENDING admission at child completion. Authenticated durable prefixes and finalization/terminal evidence converge exactly after expiry, while the receipt-free bootstrap remains floor-bound. Capacity recovery treats any private install journal as a schema-agnostic veto in both planning and locked execution. The initial candidate-schema bootstrap has null authorization fields and a transition-digest-bound `bootstrap_admission` naming its exact mode, target, retained predecessor, candidate-record digest, and floor digest. Every initial execution and replay revalidates the floor, target authority and predecessor inventory and repeats the exact predecessor process census; generic recovery cannot infer or substitute that authority. Install plans bind the source stable digest, target release/payloads, target launcher and candidate-record digest; rollback plans bind the retained installed authority and tree identity. Hostile tests cover every durable crash checkpoint, pre-target expiry boundaries, fence-to-launcher expiry, durable-prefix convergence, source restoration, public/private conflicts, plan-receipt substitution, terminal tampering, tree/ACL races, lock contention, typed-bootstrap tampering, stale/newly loaded/relative predecessor processes, and archive/journal exclusion. | `host-verified` for ordinary install and exact lost-response readback: the retained Touch ID request committed release `f8c176b4...65eb4342` from source commit `b6ad74b`; independent readback agrees across STABLE, immutable terminal `e8cf7e75...45406`, receipt, launcher `b3ad2f22...96f1fc`, tree `078239e8...10cd`, selectors, candidate authority, and service evidence. The wrapper's missing result was classified ambiguous; the separately invoked exact recovery correctly rejected after authoritative state already showed the target committed. An earlier failed target activation remains retained as an immutable `source_restored` terminal. Protected rollback execution remains `unverified`. |
| Host candidate admission | Source carries the exact deterministic `source.tar` in one retained generation and a private canonical Host-release preimage under retained evidence. The signed v3 receipt binds archive/tree/configuration/preimage digests and the `trusted-login-principal-v1` custody class. Installation takes generation-native bytes from the exact generation and every other payload from the exact private preimage; it never reruns mutable derivation code. The reviewed candidate binds generation and preimage path/device/inode/size/digest plus provenance, certificate and notarization facts into the operator plan. For this Mac's candidate-schema transition, a separate public-first/private-second floor admits only the complete pinned predecessor encoded by `NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID` and its exact payload map. A separately typed first-authorization bootstrap binds its independently validated predecessor and establishment mode into the same fail-closed floor format. Either mode permanently rejects supported rollback to pre-candidate admission. Public `artifacts/host` bytes are non-authoritative and the preimage is never published there. | `host-verified`: the exact `b6ad74b` retained generation and private preimage produced candidate authority `1b05a11c...1be5`; the protected floor, authority, installed release, and ordinary candidate-bound Touch ID transition agree. Public-distribution-grade derivation remains separately gated. |
| Release build principal | Receipt/UI semantics distinguish the present `trusted-login-principal-v1` ceremony from a future protected build principal; source-copy equivalence is checked, but the ordinary login UID is not claimed as a hostile same-UID boundary. | `operator-local-verified`: the exact Host candidate and Control Center were signed/notarized under the bounded login-principal ceremony. This is not a hostile same-UID boundary; public-distribution-grade source derivation remains gated on the Protected Release Build Principal DDD. |
| Session identity | `shared/native_stack_session.py` and the Host session manager bind session/source/persona/tool/extension, stack, account/workspace, program, model, generation, network policy, and lease profile | `unverified`: no signed Touch ID session receipt or installed run |
| Resume isolation | Canonical runtime/session tests reject cross-mode/vendor/account/workspace/program/tier/model/generation and expired-authority reuse | `unverified`: live resume denial not run |
| Controller lifetime and resource containment | Every vendor child arms `PR_SET_PDEATHSIG(SIGKILL)` and checks its exact parent both before and after credential drop. A descriptor-minimal pidfd watcher alone occupies an exact owner scope; each vendor scope has `BindsTo`/`After`/`PartOf` edges to that owner and the supervisor, uses group-wide SIGKILL, and proves exact 256-task, 4-GiB, zero-swap, 300%-over-100-ms kernel cgroup-v2 ceilings through descriptor-relative no-follow reads. Lifecycle and installer quiescence cover run, bounded-Claude, and owner units; custody cleanup retries only while the exact watcher remains live. | `unverified`: real Research Linux controller-death, fork/`setsid` descendant, post-UID-drop parent-death, transient-unit rendering, dependency teardown, and kernel-enforcement tests have not run |
| Claude credential custody | The native adapter, bounded status derivation, replay store, opaque terminal authority, dedicated home, Claude 2.1.248 floor, restricted/managed-settings-only launch, empty built-in tool set, blanket/MCP denial, no-tools qualification, exact owner watcher, dependency-bound SIGKILL scope, and kernel resource ceilings are covered by Research/Host focused tests | `unverified`: exact unmodified Claude process/filesystem/network observation, controller-death behavior, and hostile child probes not run |
| OpenAI credential custody | Signed-helper contract, Keychain coordinator, session-capped one-shot projection permit, fixed C launcher, owner-bound process scope, kernel ceilings, app-server firewall, run journal, and global token-reflection guard have Swift/Python/C tests. The v2 ledger publishes only complete PID/start/provider/stack/policy-bound rows atomically before token release; pre-commit failure leaves no durable pending row. The launcher emits a fresh content-free PID/start/environment receipt and waits on a private fd-7 gate bound to that exact receipt before vendor execution. The same process generation must then pass a fresh hostile qualification; an older receipt cannot qualify a later session. Distinct one-shot identity-import and closure-reconciliation codecs bind the exact helper row and Host evidence. Host activation rejects any unexpected legacy v1 ledger before selecting the candidate release. | `unverified`: signed installed helper, live token rotation, controller-death behavior, `/proc`/ptrace/process-memory/descriptor/core hostile probes not run |
| Phase egress | Closed login/inference/status/logout policies, exact timed nft sets, UID/mark rules, structural ruleset verification, durable deny recovery, independent Gateway/Research watchdogs, and conntrack purge have focused tests. Codex receives only the fixed HTTP/HTTPS proxy variables required for the reviewed Research proxy; direct routing plus `NO_PROXY`, `ALL_PROXY`, lowercase proxy aliases, and inherited ambient network configuration are absent. | `unverified`: live nft/conntrack, proxy-only routing, and expiry readback not run |
| Model/program lock | Claude policy names only Mythos 5.1. Codex fixes one of Sol, Luna, or 6.1 Sol and every turn must carry Daybreak Blue; catalog-only availability is rejected | `unverified`: bounded provider request not run |
| Operator UI isolation | Source separates opaque no-capture Claude terminal from the typed schema-pinned Codex surface; raw app-server JSON and credentials are outside the UI contract. Touch ID authority requires an explicit button click: Return is never an authorization shortcut. The broker holds the exact request-directory and request-file inodes across biometric review and commit. Swift-parent and Python-supervisor liveness, bounded process-group teardown, and one-shot request invalidation revoke authority on cancellation or owner loss. Projection identity import and final reconciliation use separate direct-broker canonical plans, separate Touch ID reviews, exact result validation, and accurate read-only versus custody-clearing labels. | `signed-install-verified`: Control Center `0.2.1` build `3`, sequence `3`, exact commit `477045d`, is installed, launched, Developer-ID-signed, hardened, stapled, and Gatekeeper-accepted. The earlier ad-hoc responsive-layout inspection remains the visual evidence; installed close/recovery-path acceptance remains `unverified`. |
| Tool isolation | Source denies ambient plugins, hooks, MCP, skills, agents, connectors, project settings, self-update, peer harnesses, credential inheritance, and direct provider egress. Each Codex session runs the hostile qualification against its own fresh PID/start generation, exact environment, descriptor set, cgroup, scratch inode, owner scope, and independently enforced resource ceilings before READY. | `unverified`: exact-generation conformance and hostile live tool/controller-death probes not run |
| Crash/reboot | Installer, promotion, run journal, qualification-scratch journal, terminal handle, projection, watchdog, owner-scope lifecycle, and deny-recovery tests cover injected interruption and ambiguous state. Qualification reserves the exact scratch path before creation, binds its device/inode before use, removes that exact empty inode before a terminal pass, and reconciles unfinished attempts fail closed. Swift tests cover pre-commit failure with no durable row, atomic identity commit before release, post-commit expiry/cancellation ambiguity, exact identity import, replay rejection, PID-generation-bound reconciliation, and parent-loss cancellation. The exact transient cgroup remains frozen across the final quiet drain and typed READY write; only a successful READY path may thaw it. Owner release is retried only while exact watcher custody remains live, then independently proves stable absence. | `unverified`: physical cold-boot, live systemd owner-loss, and disposable fault campaigns not run |
| Destructive ceremonies | Source implements confirmed, one-attempt, idempotent logout/disconnect/stop/recovery with exact process, projection, lease, egress, and absence readback | `unverified`: protected live ceremony not run |

## Current source-verification record

These results are command/suite records, not a summed test count; some focused
paths intentionally overlap broader suites.

- The current security-hardening checkpoint passed 239 of 239 Host release
  tests with two intentional skips in 199.530 seconds, 20 of 20 isolated
  hostile pair tests in 126.653 seconds, and 160 of 160
  operator-authorization tests in 1.729 seconds. Focused selections separately
  covered relative-launcher and second-snapshot census, schema-agnostic archive
  exclusion, every pristine expiry boundary, the fence-to-launcher race,
  half-open expiry, durable-prefix and typed-bootstrap convergence, and
  completion-time broker admission. Affected Python compilation and diff
  validation passed, and a fresh independent repair review found no surviving
  bypass. The earlier 68 deploy-wrapper and 12 external-containment-audit
  results remain unchanged and are not presented as a rerun.
- The earlier native-mode checkpoint's clean hermetic Host release suite passed
  167 tests with two intentional skips for superseded bootstrap cases, and its
  affected Host script suites passed 358 of 358 tests. Those historical counts
  are not presented as coverage of the later pair transition.
- The macOS Control Center Swift suites passed 118 of 118 tests.
- The affected guest suites collected 234 tests: 233 passed and one pre-existing
  macOS skip remained because Linux `SO_PEERCRED` is unavailable on the
  development host.
- The Gateway lease suite passed 21 of 21 tests.
- The Research lease/watchdog suite passed 56 of 56 tests.
- The final owner-scope/resource-remediation focused selection passed 99 tests
  with one intentional macOS `SO_PEERCRED` skip.
- At executable checkpoint `d5393bf`, canonical discovery passed 1,331 script
  tests with two intentional skips, 553 Research tests with one intentional
  macOS skip, 274 Shared tests, 113 Gateway tests, and five Target tests.
- Changed Python source compiled successfully, and `git diff --check` passed.
- The original immutable scan of `c8a67ee..459b10a` confirmed five findings:
  one high, three medium, and one low. The source remediation mapping is
  `51f4205`, `2f9493b`, `9eb755c`, and `05229db`.
- Immutable scan `75f30fe9` of
  `c8a67ee..133d1a5` reviewed 234 of 234 items and confirmed two further
  findings: one high controller-lifetime escape and one medium absence of
  per-session resource ceilings. Checkpoint `d5393bf` remediates both.
- Final immutable scan `e0e3cb96` of
  `c8a67ee..d5393bf` closed 235 of 235 review items with zero candidates and
  zero findings. The report is retained in local Codex scan state under the
  exact executable SHA-256. Exact scan token usage was unavailable because the
  scan thread accounting record was unavailable; no value is inferred.
- Immutable scan `d7fec83c` of exact range `2a035bc..eeeb55c`
  completed full coverage and confirmed one medium relative-launcher argv
  census bypass and one low expired pair-authority replay. This checkpoint
  remediates both; the archive/journal veto is adjacent operational hardening.
- Final changed-boundary scan of exact range `4937d57..c7029a4` reviewed all
  34 changed-file receipts across five threat surfaces with complete coverage,
  zero candidates, and zero findings. The exact executable checkpoint also
  passed 1,579 Scripts tests with two intentional skips, 113 Gateway tests,
  553 Research tests with one intentional macOS skip, five Target tests, and
  274 Shared tests: 2,524 passes and three expected skips in total. This proves
  the reviewed source boundary only; it does not prove notarization,
  installation, runtime behavior, provider access, or publication.
- The final expiry-fence repair at executable checkpoint `b6ad74b` passed the
  complete Host suite (261 passes and two intentional skips), the 20-case
  hostile pair suite, and all 161 operator-authorization tests. Immutable scan
  `9bab7f0c` covered all three changed threat surfaces with zero findings or
  open questions. The canonical publication gate then passed 1,587 Scripts
  tests with two intentional skips, 113 Gateway tests, 553 Research tests with
  one intentional macOS skip, five Target tests, 274 Shared tests, source
  reproducibility, compilation, and public worktree/history material scans for
  exact commit `b6ad74b`.

The security-hardening results above establish executable source checkpoint
`c7029a4`; the later `b6ad74b` repair and final documentation descendant carry
their own evidence. Exact remote-tip verification remains required before
publication authority exists.
No source-remediated finding becomes installed or live-verified merely because
its focused regression test passed.

Formal scan accounting is immutable and finding-specific:

| Original `c8a67ee..459b10a` finding | Severity | Remediation checkpoint | Current state |
|---|---|---|---|
| A fresh Codex app-server could reuse an older process-isolation qualification receipt | High | `05229db` | `source-verified` by final clean immutable scan; live gate unchanged |
| The outer Control Center deadline could leave the Touch ID broker or authorized mutation running | Medium | `2f9493b` | `source-verified` by final clean immutable scan; live gate unchanged |
| Privileged-stream cancellation could strand nested SSH or cross a buffered readiness boundary | Medium | `9eb755c` | `source-verified` by final clean immutable scan; live gate unchanged |
| Codex projection timeout/cancellation could orphan the signed credential client | Medium | `9eb755c` | `source-verified` by final clean immutable scan; live gate unchanged |
| Native-stack inspect lacked the shared descriptor gate, close-on-exec discipline, and root-peer verification | Low | `51f4205` | `source-verified` by final clean immutable scan; live gate unchanged |

The later scan's findings are tracked separately so its high severity is not
collapsed into the original five-finding count:

| Later `c8a67ee..133d1a5` finding | Severity | Remediation checkpoint | Current state |
|---|---|---|---|
| A credential-bearing vendor descendant could outlive the admitting controller | High | `d5393bf` | `source-verified` by final clean immutable scan; live Linux gate unchanged |
| Native vendor sessions omitted per-session kernel resource ceilings | Medium | `d5393bf` | `source-verified` by final clean immutable scan; live kernel gate unchanged |

The latest exact-range scan is retained separately from both earlier scan
families:

| `2a035bc..eeeb55c` finding | Severity | Remediation checkpoint | Current state |
|---|---|---|---|
| Relative stable-launcher argv could evade the post-bootout predecessor census | Medium | this security-hardening checkpoint | `host-verified` by focused Darwin-shape regressions, full affected suites, independent repair review, and exact `b6ad74b` protected install |
| Expired ordinary pair journals could replay stale Touch ID authority | Low | this security-hardening checkpoint | `host-verified` at PREPARED, PENDING/source, pre-launcher, completion-time, durable-prefix, and bootstrap boundaries, followed by exact `b6ad74b` protected install |

Return-key nonauthorization, held request-inode custody, exact proxy-only
egress, scratch journaling, and whole-cgroup freeze are adjacent hardening and
regression closure; they do not alter the original five-finding count.

## 2026-11-05 protected preflight

This is a bounded operational checkpoint, not production acceptance:

- the Host completed the one-time Developer ID and coordination-floor migration
  to the exact installed release retained in protected local evidence under
  Team `389K3H8Y32`; the predecessor remains retained and fenced, and
  unprivileged readback proves the public enforcement projection while only
  checking the private mode-0600 floors' protected metadata;
- the separately installed Control Center `0.2.0` build `2` is signed by that
  Developer ID team, has hardened runtime, is notarized, passes Gatekeeper, and
  has a valid staple. This is not evidence for the exact four-product Host
  carrier gate;
- the exact interrupted PKI rotation recovered through the same durable
  generation and committed. Its generation, Host manifest, and anchor
  identities remain in protected local evidence; expiry, cross-generation,
  and source-pinning checks pass; and
- the installed GUI reached the native-mode surface but its first direct broker
  query failed closed as `native_json_framing_invalid`. Diagnosis found invalid
  mixed dynamic/static Security.framework flags before query classification.
  Source now authenticates the audit-token-bound live process separately from
  supplemental all-architecture bundle validation and decodes only the exact
  content-free rejection frame. The responsive-layout checkpoint also replaces
  the overflowing fixed-width mode selector. A separate ad-hoc current-source
  bundle was visually inspected: both compact segments remain within bounds,
  the full selected-mode title and explanation remain visible, and the complete
  accessibility labels are exposed. This is local UI evidence only; neither
  source repair is present in the signed installed app, and the broker repair
  has no protected readback yet; and
- checkpoint `6519676` was rebuilt from its exact Git archive in a fresh
  owner-only SwiftPM scratch as Control Center `0.2.1` build `3`, update
  sequence `3`. The ad-hoc bundle passed the local bundle gate, retained the
  exact signed `SSReleaseCommit`, carried the disabled updater policy, and the
  product-scoped build produced no `SecureSandboxUpdateSigner` executable.
  This proves the offline source/product routing only; it is not Developer ID,
  notarization, Gatekeeper-distribution, installation, or protected readback
  evidence.

The boundary remains red for current-source/install drift and known stale guest
control, lease, watchdog/supervisor, and Claude-policy artifacts. No protected
native catalog, harness generation, provider login, model turn, activation, or
session authority exists.

## 2026-11-06 exact Host and Control Center acceptance

The next checkpoint closed the bounded Host and signed-GUI drift from the
preflight without claiming guest or provider acceptance:

- exact Git commit `b6ad74b` produced the final retained
  Developer-ID/notarized Host candidate. The retained Touch ID receipt and
  independently read-back terminal committed release `f8c176b4...65eb4342`;
- the public STABLE record, immutable terminal, current/previous selectors,
  service evidence, candidate authority `1b05a11c...1be5`, launcher digest
  `b3ad2f22...96f1fc`, and release-tree identity `078239e8...10cd`
  agree. No install-transition fence remains. The ordinary wrapper lost its
  result after commit; exact recovery rejected because the target plan was
  already current, and both source and installed release verifiers returned
  `status: verified`. A prior target-activation failure independently converged
  to a durable `source_restored` terminal;
- the separately pinned GUI checkpoint `477045d` produced Control Center
  `0.2.1` build `3`, sequence `3`. The retained Apple notarization submission
  was accepted. The installed
  `$HOME/Applications/SecureSandbox.app`
  passed strict signature validation, staple validation, and Gatekeeper as
  `Notarized Developer ID`; both app and helper carry Team `389K3H8Y32` and
  hardened runtime. Their retained CDHashes independently match the notary
  receipt; and
- the installed app launched from that exact path. This establishes signed
  installation and process launch, not an installed visual/close/recovery-path
  pass and not native provider authority.

The Host and GUI gates above are therefore bounded passes. Protected
Gateway/Research deployment, catalog promotion, harness generation admission,
provider login, entitlement/model qualification, hostile credential probes,
session activation, and the disposable-hardware campaign remain `unverified`.

## Gate ledger

The following gates are deliberately independent. A later handoff may change a
row only by naming the retained evidence for that exact gate.

| Gate | State in this record | What is still required |
|---|---|---|
| Final source candidate | `source-complete; exact publication conditioned` | Executable checkpoint `b6ad74b` includes the final expiry-fence repair; the complete affected suites, immutable zero-finding scan, and canonical publication/secret gate passed. The final documentation descendant receives the same gate. Publication is complete only after independent readback proves both configured remote tips equal that exact commit. |
| Developer ID credential components | `host-verified` | The retained exact v3 carrier, detached signature, receipt, private preimage, four product identities, Team `389K3H8Y32`, notarization, staple, Gatekeeper, and installed readback passed for the exact Host candidate. This is bounded `trusted-login-principal-v1` evidence, not the future protected-build-principal claim. |
| Notarized Developer ID Host products | `host-verified` | The exact retained `b6ad74b` candidate was admitted through an ordinary Touch ID transition. STABLE, immutable terminal, current/previous selectors, candidate authority, launcher/tree identity, launchd service files, and both independent release verifiers agree on release `f8c176b4...65eb4342`; the transition journal is absent. An earlier failed activation converged to `source_restored`. Protected rollback execution remains unverified. |
| Notarized Control Center | `signed-install-verified` | Exact commit `477045d`, version `0.2.1`, build/sequence `3`, retained Apple submission, app/helper Team and CDHashes, hardened runtime, staple, Gatekeeper, installed bundle identity, and process launch passed. Installed visual/close/recovery-path acceptance remains unverified. |
| Protected release build principal | `backlogged` | Complete the [Protected Release Build Principal and Signing Custody DDD](PROTECTED_RELEASE_BUILD_PRINCIPAL_SIGNING_CUSTODY_DESIGN.md): root-owned source capsule, process-empty non-login build UID, root output custody, attended signing-key feasibility or dedicated signer identity, hostile substitution tests, crash replay, and exact publication. |
| Protected Host/Gateway/Research deployment | `unverified` | Transactionally install the exact reviewed payloads and independently match release, file, service, policy, firewall, watchdog, and closed-state digests |
| Claude harness and account | `unverified` | First pass the complete 91-case/198-observation [Disposable-Mac Harness Lifecycle Acceptance](DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_DESIGN.md) campaign and export gate. Only then admit one exact unmodified Claude Code generation, perform the operator's own subscription login, bind opaque account/workspace, declare CVP Defense, and pass Mythos plus hostile custody acceptance. |
| Codex harness and account | `unverified` | Admit one exact supported Codex generation, perform SIWC and rotating-token acceptance, prove Daybreak Blue on every turn, and pass hostile access-token isolation |
| Physical/disposable campaign | `unverified` | Run crash, reboot, process-inspection, cross-session, cross-harness, expiry, logout, revocation, and recovery cases on authorized hardware |
| Production activation | `unverified` | Complete a fresh exact-stack Touch ID activation and a separate bounded session-start/stop ceremony after every preceding applicable gate passes |

## Claude Code + Anthropic acceptance

The stack is not accepted until all rows pass against one exact admitted Claude
Code generation.

This stack's CVP Defense value is a program-scoped operator declaration and
policy binding. It does not complete the separate requirement-by-requirement
Anthropic CVP Defense conformance DDD and must not be presented as Anthropic
certification.

1. Touch ID authorizes only the exact login plan. The operator interacts with
   Claude Code's own terminal login flow over the opaque no-capture channel.
2. A bounded native status observation emits only purpose-separated opaque
   account/workspace digests. Raw email, organization, subscription label,
   paths, browser material, and credential content are absent from every Host,
   Gateway, GUI, log, and receipt surface.
3. The operator stages and promotes those opaque bindings, then separately
   attests CVP Defense enrollment for that exact binding. The GUI labels this
   `operator-external`.
4. A no-tools, no-persistence, budget-bounded Mythos 5.1 turn succeeds. This is
   `provider-enforced` model evidence; it is not by itself proof of the exact
   CVP tier.
5. The exact admitted binary reports Claude Code 2.1.248 or later. Both the
   qualification and session launch use `--restricted`, load only managed and
   explicit settings, pass `--tools ""`, deny the all-tool and `mcp__*` sets,
   refuse permission bypass, and cannot create a cloud session. Flag omission,
   duplication, reordering ambiguity, unsupported-version fallback, or an
   ambient settings source rejects before vendor execution.
6. Activation and a later session start are separate Touch ID ceremonies.
   Window close, EOF, logout, cancellation, timeout, and crash all close the
   exact process tree and native egress before success can be recorded.
7. Hostile attempts to inspect the credential store, parent environment,
   process memory, file descriptors, logs, configuration paths, or alternate
   provider destinations fail without revealing a credential-derived value.
8. On real Research Linux, kill the exact controller after the harness forks
   and calls `setsid`, including during the credential-drop window. The
   post-drop parent-death arm or exact owner-scope dependency must kill the
   complete vendor cgroup, and two independent reads must prove the owner,
   vendor cgroup, and process generation absent.

## Codex + OpenAI acceptance

The stack is not accepted until all rows pass against one exact admitted Codex
generation at or above the documented Daybreak floor.

1. Touch ID authorizes dynamic SIWC registration/login for the exact stable
   SecureSandbox agent identity, account, and workspace. State, nonce, PKCE,
   callback, token rotation, and expiry tests pass.
2. The signed Host credential helper retains the rotating refresh token and
   projects one access token only after a distinct exact-session authorization.
3. Codex app-server initializes with honest stable client identity and the
   experimental API capability. A model-list result is treated only as a
   catalog hint.
4. Every turn explicitly includes `cyberAccessProgram: daybreakBlue`; omission,
   `standard`, Red, unknown, or catalog-only availability rejects. A completed
   bounded turn is the provider-enforced program/model proof.
5. The human-facing Control Center surface drives the app-server protocol; raw
   JSON-RPC is never presented as a terminal session and credentials never
   enter that UI process.
6. A hostile shell/tool process cannot recover the access token from inherited
   environment, `/proc`, process memory, descriptors, diagnostics, core dumps,
   transcript state, or peer sessions. This row is mandatory even when the
   ordinary child environment is empty.
7. Refresh expiry, rotation, account/workspace change, logout, cancellation,
   process crash, and Host restart all terminate/reap the exact process
   generation and independently prove projection and egress closure.
8. A crash before the helper's complete ledger-row publication releases no
   credential bytes and leaves no durable zero-PID reservation. A crash after
   publication requires **Import Identity** first when the Host journal lacks
   the helper reply, followed by a fresh **Reconcile Closed Projection** plan.
   The first action is read-only; only the second may clear the exact row after
   guest absence, egress closure, and consumer PID/start absence or reuse are
   independently proved.
9. Every session obtains a fresh launcher receipt bound to the exact app-server
   PID and start time, token digest, environment proof, projection permit,
   runtime authority, and session. The private fd-7 gate releases only that
   process generation while both the session lease and the session-capped
   projection permit remain current. A prior qualification receipt is not
   reusable admission authority.
10. The app-server environment contains exactly the reviewed session paths,
    locale, fixed PATH, access token, and fixed uppercase `HTTP_PROXY` and
    `HTTPS_PROXY`. Direct provider routing, inherited ambient variables,
    `NO_PROXY`, `ALL_PROXY`, and lowercase proxy aliases are absent. The live
    hostile qualification proves the exact environment, descriptors, process
    generation, namespace, and cgroup for this session before READY.
11. Qualification journals the exact scratch reservation before creation,
    binds its device/inode after creation, removes only that empty inode before
    recording a pass, and reconciles interruption without trusting a pathname
    replacement. The exact transient cgroup is frozen and stably inventoried
    through the final quiet drain and typed READY write. It thaws only after
    READY succeeds; any failure remains frozen for outer teardown.
12. Before `SIGCONT`, live Research readback must show the exact owner watcher
    PID/start generation, both supervisor/owner dependency edges, transient
    fragment path, group-wide SIGKILL policy, and the exact four cgroup-v2
    kernel limit files. Controller death after app-server fork/`setsid` must
    kill all descendants and leave no resumable credential-bearing process.

## Protected deployment and live evidence

For each final candidate, retain only canonical content-free evidence:

- reviewed source commit and Host/Research/Gateway release digests;
- exact installed file/policy digests and service identities;
- canonical Host target or rollback plan and digest, Touch ID request and final
  receipt digests when non-bootstrap, and the exact installed stable-launcher
  readback;
- canonical public STABLE pair bytes/digest and committed
  `install-transitions/<transition-id>.json` bytes/digest, including the
  committed-pair, finalization, service-evidence, candidate-authority, and
  release-tree-identity digests plus exact selector and service identities;
- harness generation, manifest, executable, inventory, and adapter digests;
- protected catalog/promotion and stack-revision digests;
- Touch ID plan/authorization/receipt digests;
- opaque account/workspace bindings and their assurance labels;
- provider qualification evidence digest, never response content;
- fresh PID/start launcher receipt, session-capped permit, fd-7 gate,
  per-session qualification, exact proxy-environment, scratch-journal, and
  cgroup-freeze evidence digests;
- exact owner-unit name, watcher PID/start generation, owner cgroup, vendor
  cgroup, dependency/property readback, transient fragment path, and canonical
  `memory.max`, `memory.swap.max`, `pids.max`, and `cpu.max` values;
- session/runtime/lease/process/egress/final-summary digests; and
- cold-boot, crash, hostile-probe, logout, and absence-readback results.

The final acceptance report must name any external or hardware gate that could
not run. Such a row remains `unverified`; it cannot be converted into a pass by
source tests, operator intent, or success from the other vendor stack.
