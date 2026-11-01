# First-Party Research Harness Feasibility DDD

Status: **research complete; hybrid decision accepted; implementation not
authorized**. This DDD does not authorize development, deployment, admission,
or activation of a new harness; installation of an SDK, package, plugin, or
marketplace; a change to the current Claude Code generation; or a relaxation of
any SecureSandbox boundary.

Decision owner: lab operator

Research date: 2026-10-31

## 1. Decision

SecureSandbox should **not forsake all existing harnesses and should not build a
full first-party replacement now**.

The selected direction is a **hybrid architecture**:

1. Keep every security-relevant authority in the first-party outer control
   plane.
2. Treat each inner agent harness as an untrusted, replaceable execution engine.
3. Define a harness-neutral admission and evidence contract before admitting a
   second harness.
4. Continue using the pinned, restricted Claude Code generation until another
   harness independently passes that contract.
5. Preserve a deliberately narrow first-party reference harness as a
   contingency option, not a committed product. It may be prototyped only under
   a separate explicit authorization and may become production-capable only if
   it clears the quantitative gates in this DDD.

This decision avoids two false choices. SecureSandbox need not accept opaque
harness behavior as authority, and it need not assume permanent ownership of a
fast-moving general-purpose coding-agent product to control its future.

## 2. Decision question

Would replacing Claude Code and all future third-party harnesses with a
purpose-built SecureSandbox harness materially reduce supply-chain and
authority risk enough to justify owning the agent loop, provider protocol,
tool runtime, context management, session durability, terminal experience,
compatibility matrix, and long-term maintenance burden?

The answer is **not yet**. A narrow first-party harness is technically feasible
and could improve attestability, but the present architecture already removes
most consequential authority from Claude Code. The remaining harness behavior
is important to research quality and evidence interpretation, yet mature
harnesses currently provide substantially more tested context, session,
streaming, recovery, approval, and terminal behavior than this project should
reimplement without measured need.

## 3. Scope and non-goals

This DDD evaluates:

- supply-chain and authority reduction;
- model and provider portability;
- tool and protocol coverage;
- session, context, and compaction durability;
- terminal interaction and interruption semantics;
- plugin-capability replacement;
- observability and evidence quality;
- implementation, conformance, and maintenance cost; and
- migration, rollback, and exit risk.

It does not:

- select or admit Codex, Pi, Kimi Code, Grok Build, Antigravity, or another
  harness;
- design the complete multi-harness plugin policy;
- authorize copying code from another project;
- approve a new dependency, license, provider endpoint, or credential;
- change the current model-profile or session bindings;
- claim that open source alone establishes trust; or
- claim that a first-party component is safe merely because this project wrote
  it.

Harness upgrades are governed at the research/design level by the completed
Harness Lifecycle and Verified Upgrade DDD. Admission of additional harnesses
and their ecosystems is governed by the completed Multi-Harness Admission and
Plugin-Ecosystem Isolation DDD. Neither document authorizes implementation or
candidate admission.

## 4. Method

The research used four inputs:

1. source-backed mapping of the current SecureSandbox launch, policy, model,
   tool, session, and evidence paths;
2. current primary documentation and source repositories for Claude Code,
   Codex, Pi, and MCP;
3. threat modeling of the authority that a compromised or defective harness
   could gain; and
4. a weighted decision matrix with explicit reconsideration and build gates.

The threat-model workflow called for a fresh independent architecture review
when delegation is available. Independent delegation was unavailable under the
active execution constraints, so a separate sequential architecture pass was
performed instead. No runtime mutation, new package installation, provider
call, or harness experiment was needed for this research decision.

## 5. Current architecture: what the harness does and does not own

SecureSandbox currently calls the inner harness "Claude Code," but the
security architecture already places it below several independently enforced
boundaries.

| Responsibility | Current owner | Evidence | Consequence for this decision |
|---|---|---|---|
| Host release selection and integrity | Root-owned Host launcher | `scripts/secure-sandbox-claude-launcher.py:120-176`, `scripts/secure-sandbox-claude-launcher.py:205-229` | The harness cannot select or replace its Host controller generation. |
| Run/session/source argument admission | Host controller and Research launcher | `scripts/claude-run-controller.sh:66-95`, `research/research-claude.proposed:9-34` | Caller-controlled harness flags are already reduced to bounded IDs and lease profile. |
| Clock and PKI agreement | Host controller | `scripts/claude-run-controller.sh:344-353`, `scripts/claude-run-controller.sh:620-629` | The harness cannot make stale or mixed-generation guests admissible. |
| Model/profile selection | Gateway status, lease, and session binding | `scripts/claude-run-controller.sh:377-410`, `scripts/claude-run-controller.sh:481-488` | The model cannot switch provider, model, or profile inside a session. |
| Paid model-call authority | Gateway lease and broker | `docs/RUN_LEASE_DESIGN.md:121-123`, `docs/RUN_LEASE_DESIGN.md:158-174` | Harness requests are metered and may be denied independently. |
| Provider credential and routing | Research relay plus Gateway broker | `research/claude_relay.py:17-28`, `research/claude_relay.py:178-251` | The harness receives no reusable provider credential or arbitrary destination. |
| Provider normalization | Closed Gateway adapters | `gateway/model_adapters.py:2-6`, `gateway/model_adapters.py:170-223` | A first-party harness is not required for current multi-model routing. |
| Process identity and resources | Root-owned Research supervisor | `research/run_lease_process.py:56-84`, `research/run_lease_process.py:203-220`, `research/run_lease_process.py:223-270` | Harness code runs as the unprivileged agent in a bounded cgroup. |
| General command execution | Managed policy and restricted launch | `research/managed-settings.proposed.json:29-90`, `research/run_lease_process.py:68-84` | Bash and bypass modes are not authority available to the resident researcher. |
| Managed tools | Root-installed local MCP servers | `research/managed-mcp.json:1-54`, `research/source_integrity_mcp.py:102-158` | Tool implementations and sensitive mutations remain outside the harness. |
| Disposable execution approval | Separate broker and exact Touch ID ceremony | `research/execution_mcp.py:11-25`, `research/execution_mcp.py:52-76` | A harness tool request is not execution authority. |
| Run closure and evidence commitment | Research watchdog, capture, and Host reconciliation | `docs/RUN_LEASE_DESIGN.md:124-154`, `scripts/claude-run-controller.sh:417-479` | A successful harness exit cannot mint a false completed run by itself. |
| Institutional memory | Root-owned policy deployment | `docs/AGENT_SELF_DEFINITION_DESIGN.md:31-42`, `docs/AGENT_SELF_DEFINITION_DESIGN.md:68-91` | Harness-native memory is disabled and cannot promote itself into authority. |

The harness still owns material behavior:

- construction of model messages and tool definitions;
- scheduling, concurrency, cancellation, and retry of tool calls;
- interactive rendering and collection of operator input;
- session journal format and local resume semantics;
- context-window management and compaction;
- interpretation of provider stream events;
- built-in file-reading and search behavior; and
- the truthfulness of its visible progress and final narrative.

Those responsibilities affect research quality, privacy, and evidence
interpretation. They do not currently include credentials, arbitrary egress,
root privilege, provider selection, executable installation, or independent
Target execution authority.

## 6. Existing controls and remaining coupling

### 6.1 Strong existing separation

The active policy disables native auto-memory, unmanaged hooks, sideloading,
connectors, marketplace discovery, general shell execution, unrestricted
networking, and credential-bearing environment variables
(`research/managed-settings.proposed.json:3-16`,
`research/managed-settings.proposed.json:93-139`). The fixed Research launcher
requires restricted/manual mode and an exact persona path
(`research/research-claude.proposed:36-50`).

The resident persona states that repository and tool output are untrusted, that
Internet and shell tools are absent, and that findings remain hypotheses under
independent adjudication (`research/glm-persona.example.md:14-28`).

### 6.2 Harness-specific coupling that remains

- Session discovery parses Claude-owned JSONL fields and paths
  (`research/session_registry.py:20-28`,
  `research/session_registry.py:97-151`).
- Conversation capture walks Claude's project journal tree and therefore
  depends on vendor format and location (`README.md:285-304`).
- The tool-intent auditor is explicitly detection-only and vendor-format-
  dependent; missing events do not prove safety (`docs/DESIGN.md:397-404`).
- The loopback API currently exposes the Anthropic Messages shape
  (`research/claude_relay.py:23-28`), although the Gateway translates it to
  multiple provider protocols.
- The supervisor currently insists on the exact Claude executable and option
  vector (`research/run_lease_process.py:56-84`).

These are adapter seams, not reasons to move outer authority into a new
harness.

## 7. External evidence

### 7.1 Claude Code and its SDK

Anthropic documents the Agent SDK as the same tools, agent loop, and context
management that power Claude Code. The SDK still runs or bundles the Claude Code
binary rather than replacing that supply-chain boundary. Its documented
surface includes built-in tools, permissions, sessions, hooks, MCP, skills,
plugins, checkpointing, usage accounting, and observability. See the official
[Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview) and
[agent-loop description](https://code.claude.com/docs/en/agent-sdk/agent-loop).

The documented loop includes streaming message types, parallel read-only tool
calls, bounded turns and budget, permission modes, automatic compaction,
session resume/fork, and external session storage. Reimplementing "prompt,
model, tool, repeat" would reproduce only the easiest portion of that behavior.

The SDK is governed by Anthropic commercial terms, and its first-party packages
bundle a native Claude Code binary. It is therefore useful for integration but
does not satisfy a goal of independently inspectable harness implementation.

### 7.2 Open Codex harness

OpenAI publishes Codex CLI and its core/app-server implementation under
[Apache-2.0](https://github.com/openai/codex/blob/main/LICENSE). Its documented
core separates business logic from UIs, and its current source includes
sandboxing, approvals, MCP runtime state, thread/turn events, and app-server
protocols. See the official [Codex repository](https://github.com/openai/codex),
[codex-core description](https://github.com/openai/codex/blob/main/codex-rs/core/README.md),
and [app-server protocol](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md).

OpenAI's own platform guidance says the harness materially affects results and
recommends starting from an existing open harness before deciding what an
application should own. That is relevant evidence, not an authority decision
for SecureSandbox. See
[Codex as a platform](https://developers.openai.com/blog/codex-as-a-platform).

### 7.3 Pi

The current Pi project describes itself as a minimal extensible agent harness
with a unified LLM API, agent loop, terminal UI, sessions, compaction,
extensions, skills, and packages. Its source is available under
[MIT](https://github.com/earendil-works/pi/blob/main/LICENSE). See the current
[Pi repository](https://github.com/earendil-works/pi).

Pi demonstrates that a smaller multi-model harness is practical. It also
illustrates why SecureSandbox cannot equate extensibility with admissibility:
runtime extensions and package installation are additional code-execution and
supply-chain surfaces. The completed multi-harness DDD therefore treats Pi as
a core-only evaluation candidate and keeps its package ecosystem disabled;
selected capabilities require separate typed admission outside the harness.

### 7.4 MCP

MCP now supplies a standardized JSON-RPC boundary for tool discovery and calls,
including capability negotiation, cancellation, progress, resources, prompts,
tools, and elicitation. See the authoritative
[MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28).
SecureSandbox already implements bounded stdio MCP servers; for example, source
integrity supports initialize, ping, tools/list, and tools/call with bounded
line framing (`research/source_integrity_mcp.py:94-178`).

MCP materially lowers the cost of a small first-party loop. It does not define
session storage, context compaction, model streaming, terminal behavior,
provider translation, approval meaning, or evidence semantics.

## 8. Candidate architectures

### A. Continue with one closed external harness

Keep the current Claude-only design and adapt to vendor changes.

Advantages:

- strongest immediate feature and model-specific behavior;
- lowest implementation cost; and
- proven compatibility with the deployed environment.

Disadvantages:

- opaque inner implementation;
- vendor journal and CLI coupling;
- concentrated supply-chain and discontinuation risk; and
- no independent harness exit path.

### B. Admit reviewed open-source harnesses

Prefer a pinned, source-built Codex, Pi, or future equivalent only after the
completed multi-harness DDD's neutral framework and conformance gates exist.

Advantages:

- inspectable implementation and licenses that permit adaptation;
- mature loop, session, terminal, and tool behavior; and
- less greenfield maintenance than a new harness.

Disadvantages:

- large and fast-moving dependency surface;
- upstream architecture may expose features SecureSandbox forbids; and
- a fork can become a permanent, difficult-to-merge product.

### C. Build a full first-party general harness

Own the model loop, provider clients, editing and shell tools, plugins,
subagents, IDE integrations, session tree, TUI, and extension ecosystem.

This is rejected. Most of those capabilities conflict with the narrow research
mission or duplicate controls already outside the harness. It would maximize
code ownership while also maximizing new attack surface and maintenance.

### D. Hybrid outer contract with replaceable inner harnesses

Own the admission, model, tool, evidence, and lifecycle contracts. Permit a
pinned external harness only through an adapter. Optionally implement a narrow
first-party reference harness that exercises the same contract and has no
marketplace, plugin runtime, shell, arbitrary file write, provider credential,
or in-session model switch.

This is the selected architecture.

## 9. Weighted evaluation

Scores range from 1 (poor) to 5 (strong). A weighted total is out of 500. The
weights reflect SecureSandbox's high-risk research mission rather than a normal
developer-assistant product.

| Criterion | Weight | Closed external | Reviewed open-source | Full first-party | Hybrid contract |
|---|---:|---:|---:|---:|---:|
| Supply-chain and authority reduction | 20 | 2 | 4 | 5 | 5 |
| Independent enforceability | 15 | 3 | 4 | 5 | 5 |
| Required functional coverage | 15 | 5 | 5 | 2 | 4 |
| Audit and evidence quality | 10 | 2 | 4 | 5 | 5 |
| Research quality/context behavior | 10 | 5 | 4 | 2 | 4 |
| Terminal/operator experience | 8 | 5 | 4 | 2 | 4 |
| Maintenance sustainability | 10 | 4 | 2 | 1 | 3 |
| Model portability | 5 | 3 | 4 | 5 | 5 |
| Migration and exit control | 7 | 2 | 4 | 4 | 5 |
| **Weighted total** | **100** | **339 (67.8%)** | **395 (79.0%)** | **354 (70.8%)** | **447 (89.4%)** |

The matrix is a decision aid, not mathematical proof. The hybrid option wins
because it combines first-party authority with mature replaceable execution
engines. A full first-party harness scores well on control but poorly on
unproven context quality, UX, and maintenance.

## 10. Harness Admission Contract v1

The future multi-harness design should instantiate the following contract. This
section defines requirements; it does not implement them.

### 10.1 Immutable identity

Every admitted generation must bind:

- harness ID and semantic/display version;
- exact executable and resource digests;
- source revision when source is available;
- build provenance, SBOM, license inventory, and vulnerability-review result;
- adapter version and digest;
- supported model-wire protocol;
- supported MCP protocol versions;
- canonical session/event schema version; and
- compatible SecureSandbox Host, Research, and policy generations.

No `latest`, moving tag, PATH discovery, self-update, runtime download, or
model-selected executable is admissible.

### 10.2 Launch authority

The outer controller alone supplies run ID, session ID, registered source,
active model-profile identity, lease identity, persona digest, and tool-catalog
digest. The inner harness receives no authority to alter those values.

One session is bound to one harness generation, adapter generation, model
profile, and persona generation. Resume fails closed on any mismatch. Migration
requires a separate reviewed, one-way transformation that preserves the
original journal.

### 10.3 Model boundary

The harness may reach only the Research loopback relay. It receives no provider
credential, provider URL, routing table, model selector, or marketplace token.
The Gateway continues to inject the activated provider/model settings and to
settle the run lease.

### 10.4 Tool boundary

The admitted tool catalog is a root-owned canonical manifest. Every server,
tool name, schema, annotation, approval class, and expected evidence class is
hashed before launch.

- Unknown or changed tools fail admission.
- Dynamic marketplace discovery is forbidden.
- Plugin and hook execution is disabled by default.
- Tool-name collisions and schema changes fail closed.
- Read-only concurrency is allowed only when the manifest declares it and the
  harness proves deterministic call/result correlation.
- A model request is never approval. Sensitive tools continue through their
  independent broker and operator ceremony.

### 10.5 Session and context boundary

The neutral event journal must represent:

- operator input and steering;
- model text, reasoning visibility class, and tool requests;
- exact tool results and error class;
- model usage and lease counters;
- interruption, cancellation, timeout, and transport failure;
- compaction input range, summary, policy digest, and boundary event;
- resume/fork ancestry; and
- terminal completion reason.

Records use bounded canonical encoding and an ordered hash chain. The harness
may write an untrusted working copy, but the capture path independently closes
and commits it. A compaction summary is evidence about omitted context, not
proof that every prior instruction survived.

### 10.6 Terminal boundary

The terminal renderer must:

- preserve operator/model/tool attribution;
- display pending, running, denied, failed, and completed tool states;
- support cancellation without leaving an untracked child;
- support steering and queued follow-up with explicit delivery semantics;
- reject OSC 52, active links, arbitrary title/control sequences, and binary
  output outside an admitted bounded representation; and
- never convert rendered model content into a trusted approval prompt.

### 10.7 Shutdown and recovery

Harness exit is not run completion. The existing Research close, capture
receipt, Gateway finalization, and Research commit remain authoritative.
Ambiguous harness termination produces a recoverable failed/unknown inner state
inside the outer lifecycle, never a synthetic successful answer.

## 11. Narrow first-party reference harness

If separately authorized, a feasibility prototype should be intentionally
smaller than Claude Code, Codex, or Pi.

Required prototype functions:

1. bounded Anthropic Messages-compatible model loop through the existing relay;
2. text and tool-use streaming with strict event validation;
3. stdio MCP initialize, fixed-version negotiation, tools/list, tools/call,
   cancellation, deadlines, and bounded stderr;
4. sequential mutation and optional declared read-only concurrency;
5. operator text input, cancellation, steering, and follow-up queue;
6. canonical neutral journal with run/session/profile/harness binding;
7. deterministic resume and explicit compaction boundaries;
8. usage, stop-reason, transport-failure, and tool-failure accounting; and
9. a minimal safe terminal renderer.

Explicitly absent:

- shell and generic process execution;
- arbitrary file writes or editing;
- provider credentials or direct provider networking;
- plugins, hooks, packages, marketplaces, or self-update;
- subagents or peer-agent communication;
- web, browser, computer-use, or remote MCP;
- in-session model or harness switching;
- native durable memory; and
- automatic privilege or policy escalation.

The prototype should use standard-library facilities where practical. Any
third-party dependency becomes a reviewed, pinned part of the harness release
and weakens the claim that first-party ownership removed supply-chain risk.

## 12. Prototype trigger and acceptance thresholds

### 12.1 Trigger to authorize a prototype

A prototype should be considered only if at least one trigger is documented:

- no reviewed external harness can satisfy every mandatory admission invariant
  without an unpatchable bypass surface;
- two consecutive candidate releases of the active harness break session,
  tool, or evidence compatibility;
- an independently validated High or Critical harness defect cannot be removed
  or contained by the outer plane within the supported pinned generation;
- licensing, distribution, or discontinued support prevents independent pinning
  and recovery; or
- measured harness adapters repeatedly require more security-sensitive code
  than the narrow reference design would own.

Interest, novelty, dislike of a vendor, or the mere existence of source code is
not a sufficient trigger.

### 12.2 Mandatory prototype gates

All of the following must pass before a prototype can be proposed for
production admission:

- 100% pass on the Harness Admission Contract conformance suite;
- zero unresolved Critical or High security findings;
- deterministic replay for every canonical tool-loop fixture;
- 100% exact resume/profile/harness binding across crash and restart fixtures;
- 100% fail-closed behavior for malformed, truncated, reordered, duplicated,
  oversized, and unknown provider/MCP events;
- no credential, arbitrary-network, dynamic-code, plugin, package, or updater
  path;
- complete SBOM, deterministic build, signed provenance, and immutable release;
- lower bound of the 95% confidence interval no more than five percentage
  points below the admitted external baseline on a blinded corpus of at least
  30 representative research tasks;
- median token cost no greater than 110% and median wall-clock latency no
  greater than 125% of that baseline, unless the operator accepts a documented
  security-for-performance trade;
- operator usability acceptance for cancellation, steering, long output,
  compaction notice, resume, tool review, and terminal closure; and
- a measured maintenance exercise showing that two simulated provider/MCP
  protocol changes can each be reviewed, implemented, tested, and released in
  no more than two focused engineering days.

### 12.3 Production build decision

Passing the gates does not automatically authorize deployment. It permits a new
DDD decision comparing the measured reference harness against the then-current
external alternatives. Touch ID activation, rollback, generation pinning, and
live disposable-Mac acceptance would remain separate steps.

## 13. Threat model

### Protected assets

- provider credentials and approved model/profile routing;
- source confidentiality and integrity;
- Host and guest control-plane authority;
- session identity, continuity, and operator intent;
- exact tool catalog and independent approval semantics;
- conversation and finding evidence;
- run budgets and attributable usage; and
- the truthfulness of terminal and completion state.

### Actors and realistic starting capabilities

- The resident model controls model output and requested tool arguments, but
  does not begin with root, provider credentials, arbitrary egress, or update
  authority.
- Imported source can contain adversarial text and data, but is not trusted
  instruction or executable authority.
- A malicious or compromised harness release begins with the unprivileged
  agent process's admitted files, loopback model endpoint, declared tools, and
  terminal. It does not begin with Host administrator authority.
- A compromised MCP server has only the OS identity, sockets, and data granted
  to that server; the harness must not merge those authorities.
- The operator can authorize protected actions, but approval confusion and
  stale prompts remain in scope.

### Security objectives

1. Harness compromise must not create provider, network, credential, root,
   update, model-switch, or Target-execution authority.
2. Tool visibility must equal the canonical admitted catalog.
3. Session continuation must preserve exact harness, model, persona, source,
   and policy bindings.
4. Untrusted content must not become plugins, hooks, memory, configuration, or
   approval.
5. Evidence must distinguish harness-authored claims from independently
   observed lifecycle, broker, and execution facts.
6. Unknown protocol state must fail closed without silently dropping evidence.

## 14. Prioritized attacker stories

These are design hypotheses, not validated vulnerabilities.

| Priority | Scenario and capability sought | Existing control | Hybrid mitigation |
|---|---|---|---|
| Critical | A compromised harness routes prompts or tool output to an attacker endpoint | Research egress and relay destination are independently fixed | Keep all networking outside the harness; conformance proves no alternate socket or provider path |
| Critical | Harness output fabricates an approval and executes a sensitive action | Execution broker and Touch ID sign an exact request independently | Renderer cannot mint approval; tool result remains bound to broker receipt |
| High | Harness advertises or invokes a hidden shell/plugin tool | Restricted managed policy; root-installed MCPs | Canonical hashed tool catalog; unknown tool or schema aborts admission |
| High | Resume reuses a session under a different model, source, policy, or harness generation | Current session/profile catalog binds model identity | Extend binding to harness and adapter generations; migration is separate and one-way |
| High | Malformed or novel provider stream causes tool/result confusion | Gateway adapters reject unknown shapes | Reference harness validates ordering, IDs, sizes, stop reasons, and completion before dispatch |
| High | Harness journal omission causes false evidence completeness | Current capture receipt proves offsets, not semantic vendor completeness | Neutral canonical event schema plus independent close receipt; retain explicit non-claim for semantic completeness |
| Medium | Compaction drops an early safety instruction or source fact | Root persona is reinjected; native memory disabled | Bind compaction policy and event; authority never depends on remembered prose |
| Medium | A tool server changes its schema after admission | Current managed server files are root-installed and boundary-hashed | Snapshot exact tool catalog at launch and reject runtime list changes |
| Medium | Terminal escape or link tricks the operator into an unsafe host action | Control Center terminal blocks OSC 52/link activation | Apply the same bounded renderer contract to every harness surface |
| Medium | External harness update changes behavior without review | Current update commands and self-update are disabled | Harness Lifecycle DDD supplies sealed staging, conformance, Touch ID activation, and rollback |
| Low | Harness provides a misleading final narrative | Findings remain untrusted candidates and require adjudication | Preserve tool receipts and lifecycle facts separately from narrative output |

## 15. Severity calibration

- **Critical:** a harness defect yields Host/root control, reusable provider
  credentials, unrestricted egress, arbitrary Target execution without exact
  approval, or release/update authority. A misleading answer alone is not
  Critical.
- **High:** cross-session or cross-profile authority, hidden admitted tools,
  evidence forgery accepted as authoritative, or repeatable escape from the
  fixed relay/tool boundaries. A crash that the outer lifecycle records and
  contains is not High.
- **Medium:** bounded session corruption, compaction loss, terminal deception,
  or availability failure that does not cross a stronger authority boundary.
- **Low:** cosmetic rendering defects, inaccurate progress, or local
  self-effects whose authoritative evidence remains correct.

Severity depends on actual privilege gain and surviving outer controls. The
same malicious harness behavior may be Critical in an ordinary workstation and
Medium inside SecureSandbox if the independent network, credential, execution,
and lifecycle boundaries hold.

## 16. Relationship to adjacent DDDs

### Harness Lifecycle and Verified Upgrade

The completed research/design DDD defines how an admitted generation is
acquired, quarantined, provenance-verified, scanned, staged,
conformance-tested, activated with Touch ID, pinned to sessions, rolled back,
retired, and revoked. It applies equally to Claude Code, an open-source
harness, and a future first-party reference implementation; implementation and
candidate admission remain separate authorizations.

### Multi-Harness Admission and Plugin-Ecosystem Isolation

The completed DDD turns the Harness Admission Contract into a concrete
core-only adapter and typed extension-isolation design. It ranks Codex and Pi
as evaluation-order candidates without admitting either. Vendor marketplaces,
in-process extensions, hooks, and peer-harness calls remain prohibited.

### Model Profile Configuration

Remains the sole provider/model/settings authority. Harness identity is an
additional session binding, never a substitute for model-profile identity.

### Human Identity and Release Authenticity

Must eventually attest who authorized a first-party or vendored harness
release. Source availability and deterministic builds do not by themselves
prove human authorization.

## 17. Reconsideration conditions

Reopen this DDD when:

- the current harness becomes unavailable or unmaintainable;
- a separately authorized multi-harness implementation produces an adapter
  whose authority cannot be normalized;
- the harness-neutral conformance contract is implemented and produces new
  measurements;
- provider protocols make the current Anthropic-shaped internal contract
  materially lossy;
- an external harness offers a stable, auditable embedded core with lower
  maintenance than the options evaluated here; or
- a separately authorized reference prototype completes its acceptance matrix.

Absent one of those conditions, the decision remains: **own the authority and
contract; rent or review the replaceable loop; do not build a general-purpose
harness.**

## 18. Acceptance contract for this research DDD

The DDD is complete when:

- the current harness boundary is mapped to source;
- at least one closed and two inspectable external approaches are compared;
- supply chain, authority, tools, sessions, UX, evidence, maintenance,
  portability, and exit risk are evaluated;
- the selected build/hybrid/do-not-build decision is explicit;
- prototype triggers and quantitative build thresholds are explicit;
- threat stories and severity calibration are recorded;
- adjacent DDD responsibilities remain separate; and
- the roadmap no longer presents the feasibility decision as unanswered.

This document satisfies that research contract. It deliberately does not
satisfy any implementation or deployment acceptance contract.
