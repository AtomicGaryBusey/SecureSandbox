# Multi-Harness Admission and Plugin-Ecosystem Isolation DDD

Status: **research and design complete; conditional multi-harness direction
accepted; implementation and admission not authorized**. This DDD does not
install, stage, admit, activate, update, or run another harness or plugin. It
does not enable a marketplace, package manager, hook, connector, subagent,
remote MCP server, or runtime extension path.

Decision owner: lab operator

Research date: 2026-10-31

## 1. Decision

SecureSandbox should support a **small, deliberately selected set of
replaceable research harnesses**, but it should not inherit any harness's
plugin ecosystem as a trusted execution environment.

The selected architecture is:

1. The first-party outer control plane admits immutable harness generations
   through one harness-neutral contract.
2. Every harness begins in **core-only mode** with vendor marketplaces,
   project/user discovery, plugins, hooks, skills, subagents, connectors,
   direct MCP configuration, self-update, login, and model switching disabled.
3. An ecosystem component is admitted separately as a typed SecureSandbox
   extension bundle. Admission is per exact harness generation, model-profile
   revision, extension-set revision, and capability manifest.
4. Prompt-only skills may be imported as inert, reviewed content. Executable
   tools run outside the harness behind the existing outer tool boundary.
   In-process extension code, vendor hooks, mods, runtime package loading, and
   marketplace clients are prohibited in protected Research.
5. A session is permanently bound to one harness generation, adapter
   generation, model-profile revision, persona revision, and extension-set
   revision. The model cannot switch or invoke another installed harness.
6. Activation or rollback of a harness or extension set is a separately
   reviewed, transactional Touch ID action. Saving a catalog or downloading a
   candidate never changes live authority.

This preserves the research advantage of multiple agent loops and selected
ecosystem capabilities without turning vendor compatibility into ambient
authority.

## 2. Answer to “should we even support other harnesses?”

**Yes, conditionally.** Supporting more than one harness is worthwhile when it
adds a materially different research capability, provides an exit from a
single-vendor failure, or permits comparison of agent-loop behavior under the
same model, source, tool, and evidence controls.

The number of installed products is not itself a benefit. A harness earns
admission only when its distribution, configuration precedence, provider
protocol, tool behavior, session format, shutdown semantics, and extension
surfaces can be pinned and independently constrained. SecureSandbox should
prefer two well-understood alternatives over broad compatibility with every
agent product.

Plugin compatibility can be valuable, but only as a source of reviewed
capabilities. It does not justify exposing a marketplace, accepting runtime
downloads, sharing vendor credentials, or executing a plugin in the harness
process.

## 3. Scope and non-goals

This DDD defines:

- the lifecycle states and evidence required to admit a harness;
- a harness-neutral adapter and conformance boundary;
- typed treatment of skills, tools, hooks, subagents, connectors, and native
  executable extensions;
- provenance, packaging, capability, credential, process, network, storage,
  session, and audit isolation;
- activation, rollback, retirement, revocation, and recovery semantics;
- candidate evaluation order and rejection criteria; and
- the implementation and live-acceptance gates for a future authorized build.

It does not:

- approve Codex, Pi, Kimi Code, Grok Build, Antigravity, or any other harness;
- approve an extension from any vendor or community ecosystem;
- authorize cloning, downloading, compiling, or executing candidate code;
- replace the existing Claude Code generation;
- implement the Harness Lifecycle and Verified Upgrade DDD;
- grant a plugin direct provider, Internet, host, credential, or Target access;
- make cross-harness session migration safe by declaration; or
- claim that open source, a vendor signature, or marketplace publication is
  sufficient provenance.

## 4. Method and evidence limits

The decision uses:

1. a source-backed pass over the current Host, Research, Gateway, tool,
   session, and model-profile boundaries;
2. the completed First-Party Research Harness Feasibility DDD;
3. current official documentation and source repositories for Claude Code,
   Codex, Pi, Kimi Code, Grok Build, Google Antigravity, and MCP; and
4. threat modeling of compromised harnesses, ecosystem packages, ambient
   project configuration, and cross-profile authority confusion.

The threat-model workflow calls for an independent architecture review when
delegation is available. Delegation was unavailable under the active execution
constraints, so a second sequential architecture pass was performed. The
result is a design decision and threat map, not a vulnerability finding or a
runtime conformance result.

Product documentation changes quickly. Candidate observations below describe
the cited 2026-10-31 surfaces and are inputs to staging, not permanent trust.
Every actual admission must repeat the review against the exact candidate
generation.

## 5. Current enforceable boundary

The incumbent harness is already below several independently enforced
controls.

| Boundary | Current owner and evidence | Multi-harness consequence |
|---|---|---|
| Host controller release | Root-owned launcher verifies a selected release and every payload before execution (`scripts/secure-sandbox-claude-launcher.py:120-176`, `scripts/secure-sandbox-claude-launcher.py:205-229`) | A future harness launcher must be another reviewed payload, not PATH discovery. |
| Fixed executable and options | Research supervisor admits only `/usr/local/bin/claude` and an exact option prefix (`research/run_lease_process.py:56-84`) | Replace the Claude-specific comparison with a root-owned adapter manifest; never accept caller-supplied flags. |
| Clean child environment | Supervisor constructs a small environment and disables updates, login, and built-in agents (`research/run_lease_process.py:164-190`) | Every adapter requires an explicit environment allowlist and an isolated data root. |
| Managed customization | Claude policy disables unmanaged MCP, hooks, side loading, command plugin sources, skill shell execution, connectors, memory, and marketplaces (`research/managed-settings.proposed.json:3-16`) | Equivalent vendor settings are defense in depth; the outer supervisor must also make forbidden resources absent. |
| Tool catalog | Root-installed MCP server paths are fixed in one managed catalog (`research/managed-mcp.json:1-54`) | Harnesses receive a projected catalog; vendor or project catalogs are never merged. |
| Model routing | Research speaks only to loopback and Gateway chooses the activated adapter/model (`research/claude_relay.py:17-28`, `gateway/model_adapters.py:170-223`) | A harness never receives provider credentials or a free-form provider endpoint. |
| Model-profile binding | Run leases bind adapter, model, vendor, profile ID, and profile digest (`research/run_lease_process.py:39-46`) | Harness and extension-set identities become additional immutable lease/session fields. |
| Source admission | Supervisor resolves a registered source to a verified fixed worktree (`research/run_lease_process.py:87-94`) | Repository plugin/config files remain source data, not executable configuration. |
| Session resume | Root-owned registry gates resume before launch (`research/research-claude.proposed:15-23`, `research/run_lease_process.py:144-161`) | A neutral registry must bind the exact harness/adapter/profile/persona/extension tuple. |
| Resource boundary | Root supervisor launches the unprivileged process in a bounded systemd scope (`research/run_lease_process.py:203-270`) | Each harness and each executable extension service needs separate process and resource attribution. |
| Completion and evidence | Outer lifecycle, conversation capture, Gateway settlement, and Host reconciliation—not harness exit—close a run (`docs/RUN_LEASE_DESIGN.md:124-174`) | A new adapter must translate events without becoming the authority for completion. |

The current code is Claude-specific at the launch vector, session registry,
journal discovery, transcript capture, tool-intent auditing, and internal
Anthropic Messages wire shape. Those are adapter seams to replace or project;
they are not permission to move authority into a vendor abstraction.

## 6. External ecosystem observations

### 6.1 Claude Code

Claude Code plugins may bundle skills, agents, hooks, JavaScript mods, and MCP
servers, and marketplaces provide installation and update catalogs. Its
settings have user, project, local-project, and managed scopes, with some lists
merging across scopes. These features are useful in an ordinary workstation
and hazardous as ambient input in Research. See the official
[plugin overview](https://code.claude.com/docs/en/plugins),
[marketplace documentation](https://code.claude.com/docs/en/plugin-marketplaces),
[settings precedence](https://code.claude.com/docs/en/settings),
[MCP documentation](https://code.claude.com/docs/en/mcp), and
[hook reference](https://code.claude.com/docs/en/hooks).

The incumbent remains admissible only under its current restricted, managed,
plugin-free projection. Native plugin support is not inherited.

### 6.2 OpenAI Codex

Codex is source-available under Apache-2.0 and exposes a separable core and app
server. Current configuration supports managed requirements, disabling plugin
availability, exact MCP identity rules, per-server/tool allowlists, required
servers, timeouts, output limits, and approval modes. Its current plugin format
can bundle skills, MCP configuration, and lifecycle hooks. See the official
[Codex repository](https://github.com/openai/codex),
[configuration reference](https://developers.openai.com/codex/config-reference),
[MCP documentation](https://developers.openai.com/codex/mcp), and
[plugin documentation](https://developers.openai.com/plugins/build/plugins).

These surfaces make Codex a strong first **core-only adapter candidate**, not
an admitted harness. Native plugins, apps, browser/computer use, memories,
multi-agent behavior, cloud automation, login, and in-app update must remain
absent or independently disabled at more than one layer.

### 6.3 Pi

Pi is an inspectable minimal harness with explicit flags to disable extension,
skill, prompt-template, theme, context-file, built-in-tool, and tool discovery.
Its package ecosystem can load TypeScript extensions, skills, prompts, themes,
npm packages, and Git repositories. Pi's own documentation warns that packages
run with full system access and that extensions execute arbitrary code. See the
official [Pi coding-agent documentation](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/README.md)
and [security model](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/security.md).

Pi is a strong second **core-only adapter candidate** because its small,
inspectable loop is useful for validating the neutral contract. All Pi package,
extension, skill, model-provider, and self-update paths remain disabled. A Pi
extension cannot be admitted in process.

### 6.4 Kimi Code

Kimi Code currently supports skills, plugins, hooks, subagents, local and
remote MCP, project/user configuration, model switching, browser access,
remote control, and marketplace or GitHub installation. Skills can be found in
shared user directories and invoked automatically by the model. See the
official [Kimi Code repository](https://github.com/MoonshotAI/kimi-code),
[documentation](https://www.kimi.com/code/docs/en/kimi-code), and
[skills documentation](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/skills.html).

Kimi remains a **later core-only candidate**. Admission requires proof that
all ambient discovery, remote control, browser, marketplace, hooks, subagents,
direct model selection, and user/project configuration are absent under the
outer launcher—not merely hidden in UI.

### 6.5 Grok Build

Grok Build publishes a Rust source tree and documents skills, plugins, hooks,
MCP, sandboxing, headless operation, and ACP. Its ecosystem breadth is useful
for comparison but expands the conformance surface. See the official
[Grok Build repository](https://github.com/xai-org/grok-build),
[announcement](https://x.ai/news/grok-build-cli), and
[CLI reference](https://docs.x.ai/build/cli/reference).

Grok Build remains a **later core-only candidate** after exact source-to-binary
provenance, distribution pinning, noninteractive launch, provider redirection,
and complete extension disablement are demonstrated for one generation.

### 6.6 Google Antigravity

Antigravity exposes plugins containing skills, MCP servers, subagents, rules,
and lifecycle hooks, and its product includes browser, editor, remote-agent,
and cloud-integrated surfaces. See the official
[agent overview](https://www.antigravity.google/docs/agent/),
[plugin documentation](https://antigravity.google/docs/build-plugins/), and
[Build with Google bundles](https://www.antigravity.google/docs/build-with-google/).

Antigravity is **research-only and not currently eligible for protected
Research staging** until a stable headless artifact, deterministic local
protocol, exact update and credential boundaries, and complete disablement of
cloud/browser/editor/plugin authority can be independently demonstrated. The
existence of an MCP API or vendor plugin schema does not satisfy those gates.

### 6.7 MCP and portable package formats

MCP standardizes capability negotiation, tools, resources, prompts,
elicitation, tasks, cancellation, and related message flow. It does not attest
the server binary, authorize its process, constrain its destination, protect a
credential, classify side effects, make a tool idempotent, or establish the
meaning of an approval. See the authoritative
[MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28).

Likewise, a plugin or skill format that parses in several harnesses establishes
syntax portability, not semantic or authority equivalence. SecureSandbox may
use portable formats as quarantine inputs, but the admitted output is always a
new typed manifest bound to one exact policy context.

### 6.8 Evaluation order is not trust

The initial authorized implementation, if any, should build the neutral
adapter/conformance framework and test it against fixtures before touching a
new binary. A separately authorized candidate experiment should evaluate:

1. Codex core-only, because its source, app-server seam, and managed
   configuration provide a broad test of the contract; then
2. Pi core-only, because its small inspectable loop and explicit disable flags
   provide an intentionally different implementation.

Kimi Code and Grok Build follow only if those two experiments expose no
unresolved contract defect. Antigravity remains outside protected staging
until the eligibility gap above closes. No candidate displaces Claude Code by
passing a documentation review.

## 7. Admission state machine

Every harness generation and extension bundle has an independent state:

`observed -> acquired -> quarantined -> reviewed -> fixture-qualified ->
staged -> activated -> retired`

From any preactivation state it may become `rejected`. From `staged` or
`activated` it may become `revoked`. There is no transition from `rejected` or
`revoked` back to an admissible state; changed bytes are a new generation.

- **Observed:** metadata or documentation only. No bytes are trusted.
- **Acquired:** exact bytes and source, when available, are recorded outside
  Research.
- **Quarantined:** unpacked without execution; archive and path rules pass.
- **Reviewed:** provenance, source/build relationship, license, SBOM,
  capabilities, configuration precedence, network, credentials, updates, and
  known vulnerabilities are assessed.
- **Fixture-qualified:** the immutable candidate passes protocol,
  configuration, negative, and evidence fixtures in a disposable environment
  with synthetic data and credentials.
- **Staged:** a root-owned sealed bundle is present but cannot be selected by a
  model or session.
- **Activated:** a Touch ID-approved immutable catalog generation permits new
  sessions to select it. Existing sessions do not change.
- **Retired:** no new sessions; already-bound sessions may finish or resume
  only under an explicit retention policy.
- **Revoked:** no new launch or resume. An active process is contained and
  closed as failed/unknown according to incident policy.

Downloading, building, reviewing, or staging never implies activation.
Activation adds an exact generation to the operator-selectable set; it does not
let the harness or model choose a session's harness. For a new session, only an
operator-facing Control Center or fixed Host command may select one already
activated harness and one compatible already activated extension set. The Host
binds that choice before lease issuance and records it. Changing the selectable
set or any admitted bytes requires a new Touch ID activation.

## 8. Harness Admission Manifest v1

The root-owned canonical harness catalog uses schema
`secure-sandbox-harness-catalog-v1` and contains at most eight harness IDs.
Each immutable generation binds:

- stable harness ID, vendor ID, display version, and exact generation digest;
- executable, resource, runtime, and dependency digests;
- source revision, license inventory, SBOM digest, vulnerability-review
  digest, and reproducible-build result when available;
- vendor signature/notarization and project provenance results without
  treating either as sufficient alone;
- adapter ID, adapter version, adapter digest, and fixed launch-vector digest;
- supported model-wire, lifecycle, terminal, tool, session, and event-schema
  versions;
- clean home/config/cache roots and the complete allowed environment keys;
- expected child-process tree, OS identities, resource limits, filesystem
  mounts, sockets, and network destinations;
- native feature-disable claims and independent outer enforcement;
- compatible Host, Gateway, Research, model-profile, persona, tool-catalog,
  and extension-set schema versions;
- neutral event coverage and explicit semantic-loss declarations; and
- activation, retirement, revocation, and rollback identities.

Unknown fields, duplicate IDs, aliases, symlinks, special files, hard-link
escapes, mutable interpreters, dynamic libraries outside the bundle, PATH
lookup, moving tags, unsigned catalog mutation, or missing evidence fail
closed.

## 9. Adapter boundary

Each harness has a small first-party adapter. An adapter is reviewed code and
data, not a vendor plugin.

The adapter may only:

- validate a fixed command vector and environment projection;
- create the harness-specific read-only configuration from a canonical
  admitted manifest;
- translate neutral start, prompt, steering, cancel, tool, usage, compaction,
  session, and completion events;
- project the canonical tool catalog into the harness protocol;
- locate and parse the harness working journal under strict bounds; and
- report semantic loss or unsupported events as explicit failures.

It may not:

- select a provider, model, credential, source, persona, tool, plugin, or
  extension set;
- download or execute code;
- interpret source-tree configuration as policy;
- turn a vendor approval into SecureSandbox authorization;
- silently discard an unknown event or emulate unsupported security behavior;
- migrate sessions across harnesses; or
- declare a run complete.

Adapters use a common conformance suite but remain separate implementations.
A shared bug must not automatically authorize every harness.

## 10. Plugin-Ecosystem Isolation Contract v1

### 10.1 No marketplaces in Research

Marketplace URLs, indexes, search, authentication, update polling, install
commands, package managers, Git fetches, `npx`/`uvx` launchers, and arbitrary
plugin directories are absent from protected Research. The model and harness
cannot list what is available outside the activated extension set.

Candidate acquisition is an operator-initiated Host staging workflow against
an explicitly configured source. It produces an inert review bundle. A
marketplace signature or vendor allowlist is evidence about origin, not
execution authority.

### 10.2 Decompose every package

A vendor package is unpacked into independently reviewed components:

| Component class | Protected-Research treatment |
|---|---|
| Prompt-only skill, rule, or template | May be imported as inert UTF-8 content after canonicalization, review, size limits, and exact digest binding. Model auto-invocation is disabled unless the admitted manifest explicitly permits it. |
| Reference or static asset | Read-only data with type, size, path, and digest bounds; no active content interpretation. |
| Script shipped with a skill | Data only. It is not executable merely because the skill references it. Any desired behavior becomes a separately reviewed tool. |
| MCP or other executable tool | Runs as an outer-plane managed service with its own identity and capability manifest; never as a harness child chosen from plugin configuration. |
| Remote MCP, connector, app, or data source | Not directly reachable. A separately designed Gateway broker must own destination, credential, scopes, request policy, budgets, and receipts. |
| Hook or lifecycle callback | Native executable hooks are prohibited. Needed deterministic behavior is reimplemented as a first-party outer lifecycle rule. |
| In-process extension, mod, native library, or dynamic module | Prohibited in the harness process. It may be reconsidered only as an out-of-process service with a narrow protocol. |
| Subagent definition | Inert until the separate subagent contract is enabled; it cannot choose a model, harness, credential, or broader tool set. |
| LSP/editor integration | Separate read-only or explicitly mutable tool service; no editor process, user home, or credential inheritance. |
| Theme or renderer customization | Static, bounded data only; terminal-control sequences and executable rendering code are rejected. |

One rejected component rejects the package as a package. Safe components may
be imported only as a new SecureSandbox-authored extension bundle with their
own provenance and review record; the remainder is not silently dropped.

### 10.3 Extension Admission Manifest v1

The schema `secure-sandbox-extension-set-v1` binds at most 32 extension
components and includes:

- extension-set ID, revision digest, origin package identities, and component
  digests;
- allowed harness ID and exact harness-generation range, normally one
  generation;
- allowed model-profile IDs and exact profile digests;
- component class, invocation policy, and whether invocation is operator-only
  or model-requestable;
- canonical names and collision-free tool/skill namespaces;
- data read/write classes, tool schemas, side-effect class, approval class,
  idempotency, deadlines, output bounds, and evidence class;
- process identity, filesystem roots, network policy, credential handles,
  resource limits, and shutdown behavior for executable services;
- transitive dependencies, licenses, SBOM, provenance, and review digest;
- neutral journal events required for invocation and result; and
- retirement/revocation policy.

There is no wildcard harness, model profile, provider, destination, executable,
tool, environment variable, filesystem root, or credential scope. Reusing the
same content with another harness is a new compatibility review and manifest
revision even when a portable format parses successfully.

### 10.4 Process and filesystem isolation

The harness process receives:

- an empty, per-generation home/config/cache root;
- read-only harness and adapter bundles;
- only the selected verified source tree and bounded session working area;
- the loopback model relay and neutral tool proxy sockets;
- no package-manager caches, compiler search paths, user dotfiles, login
  state, host mounts, provider credentials, or other harness homes; and
- a process-tree and cgroup policy that rejects unregistered descendants.

Every executable extension service is launched by the outer supervisor under
a distinct service identity and resource scope. It receives only declared
mounts and broker sockets. The harness cannot supply its executable path,
arguments, environment, working directory, or credentials. Prefer a narrow
local protocol through an outer authorization proxy; raw stdio child launch by
the harness is not an isolation boundary.

Project `.claude`, `.codex`, `.pi`, `.kimi-code`, `.agents`, `.gemini`, Grok,
Antigravity, MCP, plugin, hook, skill, and equivalent configuration paths are
source data. They are not copied into a configuration root and are never
executed or auto-discovered.

### 10.5 Network and credentials

The harness retains only the Research loopback model relay. An executable
extension has no network by default. Networked capabilities require a separate
fixed Gateway broker that enforces:

- an exact destination and protocol;
- a non-exportable credential or short-lived scoped delegation;
- extension-set, component, harness, profile, session, run, and lease binding;
- request method/schema/size/rate/cost policy;
- response type/size/content handling;
- independent receipts and denial records; and
- expiry and revocation.

No bearer token, OAuth refresh token, API key, cookie jar, SSH agent, cloud
profile, browser profile, or provider credential enters a harness or plugin
environment. OAuth login inside a harness or plugin UI is forbidden.

### 10.6 Tools and authority normalization

The outer tool catalog is authoritative. At session start it is canonicalized
and hashed with every server identity, tool name, schema, annotations,
side-effect class, approval class, deadline, output bound, and evidence class.

- Harness-native tools are either disabled or mapped to an admitted neutral
  capability. A built-in shell is not admitted because it has a familiar name.
- Unknown tools, renamed collisions, schema drift, dynamic tool-list changes,
  or changed annotations abort launch or close the run as failed/unknown.
- Vendor approval modes are UX signals only. Sensitive operations continue
  through independently enforced SecureSandbox brokers and exact operator
  ceremonies.
- Tool results are bound to the exact request and component identity.
- Read-only concurrency is allowed only when declared and correlation remains
  deterministic. Mutation is serialized unless the component contract proves
  a stronger safe rule.

### 10.7 Skills and prompt content

Skills are untrusted instructions, not enforcement. Admission records the
canonical text and referenced static files, rejects executable or remote
includes, caps aggregate prompt size, and distinguishes:

- always-present operator policy;
- model-visible skill metadata;
- full skill content loaded by explicit operator request; and
- full skill content eligible for model request.

Model invocation is disabled by default. A skill cannot grant a tool, relax a
denial, alter the persona, rewrite evidence semantics, install another skill,
load scripts, or persist memory. Skill output and cited instructions retain
their untrusted-content label in the neutral journal.

### 10.8 Hooks and in-process code

Vendor hooks, JavaScript mods, Python imports, native modules, dynamic
libraries, preload variables, shell callbacks, and package initialization
scripts are not permitted in the harness process. Configuration that appears
to disable them is not enough if discovery paths or interpreters remain
available.

When a hook supplies useful behavior, SecureSandbox may implement the behavior
as a first-party declarative outer rule with fixed inputs, bounded output, no
ambient environment, and explicit failure semantics. The rule is then part of
the Host/Research policy release, not the plugin.

### 10.9 Subagents and harness-to-harness calls

Subagents remain disabled until an implementation separately proves the
`secure-sandbox-subagent-v1` contract. If later enabled, a child:

- uses the same harness generation, model-profile revision, persona policy,
  source, and extension-set revision as its parent;
- has a strict subset of the parent's tools and remaining run budget;
- receives a first-party child ID and explicit task digest;
- cannot start another harness, choose another model, load another extension
  set, or obtain separate credentials;
- emits separately attributable neutral events and results; and
- is killed and reconciled with the parent run.

A harness, plugin, MCP server, skill, or model may never expose “call Claude,”
“call Codex,” “delegate to Pi,” or an equivalent peer-harness tool in protected
Research. Comparing harnesses means separate sessions over controlled fixtures,
not one resident agent invoking another.

### 10.10 Session and storage isolation

The neutral session record permanently binds:

- session and run IDs;
- harness, adapter, model-profile, persona, tool-catalog, and extension-set
  identities and digests;
- registered source identity;
- parent/child identities when subagents are eventually enabled;
- vendor session ID as non-authoritative metadata; and
- journal schema and capture-chain identity.

Resume rejects any mismatch before lease issuance. Harness-native session
stores are per generation and inaccessible to other harnesses. No harness may
enumerate another harness's sessions, caches, configuration, extension sets,
or transcripts.

Cross-harness migration is not resume. A future migration may create a new
session containing a bounded, operator-reviewed, content-only import with a
digest and ancestry record. It preserves the original transcript and carries
no tool approval, hidden state, credential, plugin state, or authority.

## 11. Activation, rollback, retirement, and revocation

Harness and extension-set activation uses the privileged transaction engine:

1. require no active run and no unresolved lifecycle transaction;
2. construct a short-lived review plan containing old/new catalog digests,
   exact generation identities, capabilities, compatibility, evidence, and
   rollback target;
3. display a privacy-minimized exact projection in the signed authorization
   application;
4. require fresh Touch ID bound to the plan digest;
5. fence run admission;
6. stage and validate Host, Gateway, and Research projections;
7. atomically advance the active catalog generation;
8. independently read back every boundary;
9. commit the receipt and reopen admission; and
10. recover by completing the exact transaction or restoring the previously
    admitted generation—never by synthesizing a mixed state.

Activation affects only future sessions. A session already bound to an older
generation remains there. Rollback selects only a retained, previously
admitted generation and never lowers a revocation floor.

Ordinary retirement blocks new sessions but may retain exact bytes for bounded
resume. Security revocation blocks new and resumed sessions immediately. If a
revoked component is active, emergency containment closes the run as
failed/unknown, settles the lease conservatively, and retains evidence. There
is no “run anyway,” “trust once,” or operator bypass.

## 12. Auditing and attestability

The append-only audit vocabulary includes:

- candidate observed/acquired/quarantined/rejected;
- provenance, source-build, signature, SBOM, license, vulnerability, and
  conformance results;
- harness/adapter/extension staging and removal;
- activation plan, authorization request/result, transaction phases,
  rollback, recovery, retirement, and revocation;
- launch admission/denial and exact effective configuration digest;
- tool-catalog and extension-set readback;
- skill load, tool request/result, service start/stop, denied dynamic
  discovery, and protocol drift;
- session create/resume/migration denial and binding mismatch;
- model/credential/network/harness-switch denial; and
- run close, child reconciliation, capture, lease settlement, and evidence
  commitment.

Every record identifies the relevant harness, adapter, profile, persona, tool,
extension, session, run, lease, source, transaction, policy, and release
digests. Records never include credentials, private source content, model
reasoning, full prompts, or plugin secret values.

Evidence distinguishes:

- vendor or harness claims;
- adapter-observed events;
- outer process/network/tool observations;
- broker-authoritative receipts; and
- operator authorization receipts.

A harness transcript cannot attest to its own confinement.

## 13. Threat model

### Protected assets

- Host, Gateway, Research, and Target authority;
- provider and extension-service credentials;
- activated model, harness, adapter, persona, tool, and extension identities;
- source confidentiality and integrity;
- session continuity and operator intent;
- exact tool and approval semantics;
- conversation, finding, and lifecycle evidence;
- run budgets and attributable usage; and
- update, activation, rollback, and revocation authority.

### Actors and realistic starting capabilities

- The resident model controls generated text, tool arguments, skill requests,
  and attempts to switch or install capabilities. It does not begin with root,
  credentials, Internet, update, or activation authority.
- Imported source can contain adversarial vendor configuration, plugin
  manifests, skills, hooks, scripts, lockfiles, and social-engineering text. It
  is data, not policy.
- A malicious harness generation starts with its admitted process identity,
  mounts, loopback relay, tool proxy, terminal, and session working area.
- A malicious ecosystem package may control every byte in its archive and all
  transitive dependencies, but it does not begin as executable.
- An admitted extension service begins with only its declared service identity,
  mounts, broker handles, and protocol.
- A compromised marketplace, vendor release account, package registry, or
  source repository can substitute candidate bytes but does not possess the
  operator's Touch ID or protected activation key.
- The operator can authorize exact protected changes; stale, misleading, or
  over-broad ceremonies remain in scope.

### Security objectives

1. No model, source, harness, or plugin can install, activate, update, switch,
   invoke, or credential another harness or extension.
2. A compromised harness or extension cannot gain provider, Internet, root,
   Host, update, release, or unapproved Target-execution authority.
3. Plugin ecosystem compatibility never merges credentials, homes, sessions,
   tools, policies, or evidence across harnesses or profiles.
4. Tool visibility and callable authority equal the root-owned canonical
   manifest, not vendor discovery.
5. Session continuation preserves exact generation and policy bindings.
6. Unknown configuration precedence, event semantics, child processes,
   protocol changes, or artifact identity fail closed.
7. Evidence labels the component that observed or asserted each fact.

## 14. Prioritized attacker stories

These are design hypotheses, not validated vulnerabilities.

| Priority | Scenario and capability gain | Prerequisites | Existing control | Required mitigation |
|---|---|---|---|---|
| Critical | Marketplace or package substitution becomes arbitrary Research execution | Runtime install/update or in-process plugin loading exists | Current Claude marketplaces and hooks are disabled | No marketplace client; inert Host quarantine; component decomposition; executable code only as separately admitted outer service |
| Critical | Plugin steals provider or OAuth credentials | Credential enters harness/plugin environment or readable store | Current model provider credential remains in Gateway | Broker-only credentials bound to component/profile/session; no login or secret environment in Research |
| Critical | Harness/plugin opens an attacker endpoint and exfiltrates source | Alternate network path survives | Research model path is fixed loopback | Default-deny network, process-tree enforcement, fixed brokers, negative socket tests |
| Critical | Plugin fabricates approval and executes on Target | Vendor approval is accepted as authority | SecureSandbox execution broker and Touch ID are independent | Vendor approvals remain non-authoritative; exact broker receipt required |
| High | Repository configuration auto-loads a malicious hook, skill, MCP server, or package | Ambient project discovery remains enabled | Current managed Claude settings restrict these surfaces | Empty configuration roots; project config treated as source data; explicit negative fixtures for every known discovery path |
| High | One harness invokes another installed harness to escape its policy or model binding | Peer binary or wrapper is reachable as a tool/child | Current supervisor admits one exact binary | Separate sealed roots; no peer executable visibility; registered descendant tree; explicit harness-to-harness denial |
| High | A portable plugin crosses into another harness/profile with broader semantics | Format compatibility is mistaken for policy compatibility | Model profiles already bind session identity | Per-harness and per-profile extension manifest; new review/digest for every projection |
| High | Resume opens a session under a different harness, plugin set, model, or persona | Registry omits a binding or adapter silently migrates | Current resume is root-registry gated | Exact tuple binding before lease; cross-harness import creates a new session only |
| High | Native built-in tool or dynamic MCP update bypasses canonical catalog | Harness exposes tools outside projection | Current managed MCP paths are root fixed | Disable built-ins or map them explicitly; hash list/schema; abort on drift |
| High | Hook or in-process extension tampers with prompts, results, evidence, or renderer | Native extension execution is enabled | Current hooks are disabled | Prohibit in-process code; reimplement needed behavior as first-party outer rule |
| High | Compromised extension service inherits harness source plus unrelated credentials | Shared uid/home/environment/mounts | Current MCP children are root-installed but harness-specific | Distinct service identity, mounts, resource scope, broker handles, and audit trail |
| Medium | Skill prompt changes agent behavior or induces tool misuse | Skill is model-visible and invocable | Tools remain independently controlled | Inert reviewed content, model invocation off by default, bounded visibility, no authority in instructions |
| Medium | Harness event translation omits compaction, cancellation, or tool correlation | Vendor protocol differs | Current capture is vendor-format-dependent | Neutral schema conformance, explicit semantic-loss declaration, fail on unknown/reordered events |
| Medium | Terminal/plugin renderer deceives operator with active links or fake approval | Untrusted terminal control survives | Control Center already constrains terminal behavior | Common renderer contract; strip active controls; trusted ceremony stays separate |
| Medium | Retired or revoked generation resumes from a stale local cache | Mutable cache remains callable | Session registry gates current resume | Immutable retained bundle, retirement policy, monotonic revocation floor, no bypass |
| Low | Different harnesses produce incomparable narratives | Same source/task is not normalized | Findings remain hypotheses | Controlled comparison corpus and shared evidence labels; do not treat prose as authoritative |

## 15. Severity calibration

- **Critical:** a harness or ecosystem component obtains root/Host authority,
  reusable credentials, unrestricted egress, release/update authority, or
  unapproved Target execution. Merely producing unsafe advice is not Critical.
- **High:** cross-harness/profile/session authority, executable ambient project
  configuration, hidden tools, evidence accepted under the wrong component
  identity, or a repeatable escape from fixed process/network/tool boundaries.
- **Medium:** bounded skill injection, terminal deception, session corruption,
  semantic-loss failure, or denial of service that outer controls contain and
  record without a stronger authority gain.
- **Low:** cosmetic namespace, rendering, or comparison defects whose
  authoritative bindings and evidence remain correct.

Source availability, exploit cleverness, or vendor prominence does not set
severity. Actual added capability and surviving independent controls do.

## 16. Conformance and implementation gates

No candidate may advance to protected staging until an authorized
implementation provides all of the following.

### 16.1 Harness-neutral framework

- canonical harness and extension-set parsers with deny-unknown schemas;
- immutable bundle verification and root-owned sealed storage;
- fixed adapter launch and clean-root construction;
- neutral lifecycle/event journal and independent capture;
- exact session/lease binding extensions;
- canonical tool projection and drift detection;
- process-tree, mount, environment, network, and resource readback;
- transactional Touch ID activation/rollback/revocation; and
- Control Center review, status, activation, retirement, revocation, and
  evidence UI that does not expose secrets.

### 16.2 Mandatory candidate matrix

Each exact harness generation must demonstrate:

- 100% pass on the Harness Admission Contract and this isolation contract;
- zero unresolved Critical or High findings;
- exact source/binary/resource/SBOM/provenance identity;
- deterministic fixed launch with no PATH, user, project, or environment
  configuration influence;
- zero runtime download, marketplace, package, login, update, or self-modifying
  paths;
- no peer-harness invocation or model/profile switching;
- no provider credential or non-loopback model destination;
- complete rejection of every known ambient plugin, hook, skill, MCP, context,
  and configuration discovery path;
- exact tool-list/schema stability before and after every fixture;
- deterministic correlation for streaming, parallel reads, mutation,
  cancellation, timeout, interruption, compaction, resume, and shutdown;
- fail-closed handling of malformed, truncated, duplicated, reordered,
  oversized, and unknown model/tool/session events;
- complete process, socket, file, environment, and child-tree observations
  matching the manifest; and
- cold-start, crash, lost-response, rollback, revocation, and reboot recovery.

### 16.3 Mandatory extension matrix

Every component must demonstrate:

- exact provenance and dependency closure;
- canonical unpacking with traversal, link, collision, special-file, Unicode,
  case-folding, archive-bomb, and alternate-stream rejection;
- class-specific policy with no undeclared executable content;
- exact per-harness and per-profile binding;
- zero credential material in files, environment, arguments, journals, errors,
  or terminal output;
- declared process/mount/network/resource behavior under hostile inputs;
- schema, timeout, cancellation, idempotency, output, and evidence compliance;
- no tool/skill namespace collision or dynamic catalog mutation;
- install/update commands unavailable to both model and harness; and
- retirement/revocation that blocks new and resumed use without deleting
  retained evidence.

Passing these gates qualifies a candidate for a separate live-admission
decision. It does not activate it.

## 17. Live acceptance on the disposable Mac

After an implementation and candidate are separately authorized, live
acceptance must use synthetic credentials and source first, then prove:

1. clean installation from a sealed reviewed bundle;
2. exact Touch ID activation and cancellation;
3. cold boot with independent Host/Gateway/Research readback;
4. a new session bound to the exact harness/adapter/profile/persona/tool/
   extension tuple;
5. denial of model, harness, extension, credential, marketplace, peer-harness,
   and project-config switching attempts;
6. deterministic tool, interruption, compaction, resume, close, capture, and
   lease behavior;
7. crash at every activation and run-lifecycle phase;
8. ordinary retirement, explicit rollback, and emergency revocation; and
9. a complete evidence export whose authoritative facts do not depend on the
   candidate's narrative.

Production data, provider credentials, and active research sessions remain out
of scope until synthetic acceptance is complete.

## 18. Relationship to adjacent DDDs

### First-Party Research Harness Feasibility

This DDD implements its architectural conclusion at the design level: the
outer plane owns authority and contracts; inner harnesses remain replaceable.
It does not reopen the decision to build a general-purpose first-party harness.

### Harness Lifecycle and Verified Upgrade

That open DDD must implement acquisition, provenance verification, build,
staging, compatibility testing, generation retention, atomic upgrade,
rollback, and revocation for the manifests defined here. No harness auto-update
is permitted.

### Model Profile Configuration

Model profiles remain the sole vendor/model/settings/credential authority. A
harness or extension identity is an additional binding, not a route to select
or override a profile. Touch ID activation is exact and transactional.

### Human Identity and Release Authenticity

That backlogged design must supply the future human authorization and release
provenance chain. Vendor signatures, Git commits, SBOMs, and reproducible
builds are evidence but do not alone prove operator authorization.

### Control Center and in-app updates

Control Center may review and invoke fixed harness/extension lifecycle actions,
but its own updater cannot update protected harnesses or plugins. The app never
downloads and activates a harness automatically.

## 19. Reconsideration conditions

Reopen this decision if:

- a candidate cannot disable ambient or executable extension surfaces without
  modifying its trusted core;
- the neutral adapter becomes more security-sensitive than a narrow
  first-party reference harness;
- cross-harness comparisons prove that a second harness adds no material
  research value;
- a stable portable plugin standard gains verifiable capability and provenance
  semantics that reduce, rather than merely rename, these boundaries;
- provider or harness protocols make neutral event capture materially lossy;
- a new separately enforced credential/tool broker safely enables a currently
  prohibited extension class; or
- an admitted harness or extension suffers a High/Critical defect that changes
  the containment assumptions.

Absent one of those conditions, the decision remains: **admit a few harness
cores; import selected capabilities; never import a marketplace or ambient
plugin authority.**

## 20. Acceptance contract for this DDD

This research/design DDD is complete when:

- current enforcement and Claude-specific seams are mapped to source;
- candidate harnesses and extension surfaces are compared using current
  primary evidence;
- the “support other harnesses?” decision is explicit;
- admission states, manifests, adapter responsibilities, and fail-closed
  transitions are defined;
- skills, tools, hooks, extensions, subagents, connectors, credentials,
  sessions, and marketplaces have distinct isolation rules;
- cross-harness and cross-profile authority are prohibited;
- activation, rollback, retirement, revocation, evidence, threat stories, and
  severity are explicit;
- future implementation and disposable-Mac gates are measurable; and
- the roadmap no longer presents the design question as unanswered.

This document satisfies that research/design contract. It intentionally does
not satisfy implementation, candidate qualification, live acceptance, or
production admission.
