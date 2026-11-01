# Harness Conformance and Disposable Qualification DDD

Status: implemented and source-verified for the synthetic fixture; no vendor
generation qualified or admitted

## 1. Decision

SecureSandbox now has a harness-neutral conformance evaluator, an independently
executed synthetic malicious-harness fixture, a first-party Claude core adapter
projection, and content-bound qualification reports. This checkpoint proves the
contract and its hostile failure semantics without running quarantined vendor
bytes, changing Research, creating a protected harness store, or granting
runtime authority.

Qualification remains a pre-admission statement. The only successful status is
`fixture_qualified` with `authority: none` and
`note: fixture_qualified_not_admitted`. No result from this DDD can stage,
install, activate, select, resume, retire, revoke, or delete a harness. A later
protected-generation DDD must verify and consume an exact report through its
own policy and Touch ID transaction; it may not reinterpret this fixture result
as a vendor-candidate result.

The public command is deliberately narrow:

```text
python3 scripts/harness-qualification.py self-test
```

It launches only the tracked synthetic fixture by a fixed vector. It accepts no
executable path, artifact path, generation ID, adapter, policy, environment,
command vector, or bypass argument. `labctl harness` remains limited to its
non-executing foundation actions. There is no live policy or scheduler.

## 2. Relationship to the lifecycle foundation

The completed Host Quarantine DDD verifies signed metadata, exact inert bytes,
and declared evidence bindings. It deliberately does not execute a candidate
or claim that evidence narratives are true. This DDD supplies the next layer's
neutral behavior contract and report format, but does not weaken that
no-execution ceiling for quarantined artifacts.

Only a future disposable supervisor may receive one exact provenance-verified
generation. That supervisor must independently bind the quarantine manifest,
artifact, evidence decision, adapter, suite, fixture corpus, policy, runner,
and disposable-environment identity. The source-verified supervisor in this
checkpoint is synthetic-only and refuses arbitrary vendor bytes.

## 3. Canonical contracts

`shared/harness_qualification.py` defines:

- `secure-sandbox-harness-qualification-plan-v1`;
- `secure-sandbox-harness-qualification-observation-v1`;
- `secure-sandbox-harness-qualification-report-v1`;
- `secure-sandbox-harness-admission-contract-v1`; and
- the fixed observer identity
  `secure-sandbox-disposable-supervisor-v1`.

The exact plan binds:

- a UUIDv4 qualification identity and at-most-24-hour lifetime;
- generation, artifact, and manifest SHA-256 identities;
- adapter ID and exact adapter SHA-256;
- suite, fixture corpus, policy, and runner SHA-256 identities; and
- the complete ordered mandatory case list.

Cases cannot be omitted, duplicated, substituted, or reordered. Unknown plan,
observation, or fact fields fail closed. JSON is ASCII-canonical, sorted,
compact, bounded, and free of non-finite values. Lists, identifiers, output
counts, and evidence records have fixed bounds.

## 4. Observation authority

The runner calls an outer `ObservationBackend` once for each exact case. It
does not accept a report file, status, event stream, or pass/fail assertion
from the candidate. Every returned observation must bind the exact plan digest,
case, sequence, and fixed observer identity. The runner derives pass/fail from
the facts and hashes every complete observation into the final report.

The synthetic malicious harness intentionally emits `claimed_status: passed`
for every case. The parent supervisor ignores that field except to prove that a
candidate-authored claim has no authority. The parent owns process exit,
stdout/stderr byte counts, policy-denial facts, neutral events, tool-catalog
readback, and absence of unexpected connections, descendants, file changes,
secret markers, semantic loss, unknown events, and timeout.

A forged observer identity, changed plan digest, wrong sequence, unknown fact,
malformed fixture protocol, changed fixture digest, output overflow, timeout,
or backend failure aborts qualification. Partial reports never qualify.

## 5. Synthetic disposable fixture

`fixtures/harness-qualification/malicious_harness.py` is executed once per case
in a new temporary working directory using a fixed Python isolated-mode vector,
empty stdin, a four-key synthetic environment, bounded output, and a five-second
deadline. The parent pins the fixture's exact SHA-256 before execution.

The fixture requests every forbidden class, including hidden tools, native
shell, direct MCP, child processes, dynamic code, package installation, hooks,
marketplaces, extensions, subagents, login, model switching, self-update,
peer-harness calls, provider networking, ambient project configuration,
malformed events, and hostile session state. The parent records each request
and returns `policy_denial` without performing the requested effect.

This is a deterministic contract fixture, not a general sandbox. It is trusted
repository test code and has no provider credentials, source corpus, Research
mount, harness artifact, or protected state. A real vendor generation requires
the later disposable-Mac acceptance backend with independent VM, network,
process, filesystem, resource, and audit enforcement.

## 6. Mandatory matrix

The implemented suite contains thirty ordered cases:

| Class | Cases |
| --- | --- |
| Protocol | start, prompt, steering |
| Lifecycle | cancel, interrupt, compaction |
| Sessions | new/resume/close and hostile session state |
| Tools | catalog stability, hidden-tool and native-shell denial |
| Extensibility | direct MCP, dynamic code, packages, hooks, marketplaces, extensions, subagents, and peer-harness denial |
| Provider authority | login, model switching, self-update, and non-loopback provider-network denial |
| Isolation | clean environment, secret absence, filesystem immutability, and no unexpected child or connection |
| Hostile inputs | project configuration and malformed event denial |
| Evidence | outer-observer receipt authority |

Every case also applies common rejection gates for timeout, semantic loss,
unknown events, secret markers, successful network connections, unexpected
descendants, filesystem changes, and known credential environment keys.
Denial cases must be both exercised and independently blocked. A denial that
was never attempted is not evidence. Tool-catalog identity must be identical
before and after its fixture.

## 7. Claude core adapter v1

`shared/claude_core_adapter.py` is first-party reviewed code, not a Claude
plugin. Its initial projection mirrors the existing protected launch seam while
remaining non-executing:

- exact `/usr/local/bin/claude` executable;
- fixed persona, `--no-chrome`, `--restricted`, and manual-permission arguments;
- only `--session-id UUID` or `--resume UUID` after the fixed prefix;
- required update, upgrade, login, logout, nonessential-traffic, subprocess-
  environment, MCP-allowlist, and built-in-agent disable controls;
- rejection of credentials and dynamic-loader environment variables;
- explicit ambient `.claude`, `.mcp.json`, `CLAUDE.md`, `.agents`, `.codex`,
  `.gemini`, `.grok`, and `.kimi-code` discovery paths;
- exact tool-catalog, managed-settings, and managed-MCP digests; and
- explicit empty semantic-loss declaration.

The adapter cannot choose a provider, model, credential, source, persona,
tool, extension, or peer harness. It cannot execute a process. Its deliberately
small stream translation recognizes only known bounded session, assistant,
user, result, and compaction events tied to the expected session. Unknown
vendor events and session mismatch fail closed instead of being discarded.

This projection is a source contract, not a claim that an untested future
Claude release conforms. Every exact Claude generation must pass a separately
authorized qualification with version-specific fixtures before staging.

## 8. Agent-safety cross-check

The repository-visible Claude configuration was audited with the local
`agent-safety-check` skill using the `offensive` workload. The tool reported a
Tier 2 project-visible posture against a Tier 4 requirement and no automatic
project-config remediation. Its manual Tier 4 guidance requires a per-agent VM,
proxy-held credentials, turn/time limits, transcript retention, and egress
logging. No configuration was changed by the skill.

That result reinforces the architecture: native Claude settings are defense in
depth and useful conformance inputs, not the attestation boundary. A later live
backend must observe VM, network, process, filesystem, credential, resource,
and journal behavior outside the candidate.

## 9. Threat stories and controls

| Threat | Control |
| --- | --- |
| Candidate writes its own passing report | Candidate output is never accepted as an observation; runner derives status from the outer backend |
| Operator tests a subset | Plan requires the complete ordered case list |
| Observation replay or retargeting | Every record binds plan digest, case, sequence, observer, generation, adapter, suite, fixture, policy, and runner through the report |
| Hidden network or child effect | Any successful connection or unexpected descendant rejects the case |
| Credential enters the fixture | Known credential environment keys or secret markers reject qualification |
| Tool catalog changes during a run | Exact before/after digest equality is mandatory |
| Vendor schema silently changes | Unknown event or semantic loss rejects qualification |
| Denial is claimed but untested | Denial cases require a recorded attempted action and policy denial |
| Fixture or runner changes after review | Exact source digests are plan and report inputs |
| Fixture pass becomes installation authority | Report says `authority: none`; no staging or activation consumer exists |

## 10. Failure and recovery semantics

Qualification is read-only with respect to lifecycle state. Each synthetic
case has a fresh temporary directory. A crash, timeout, malformed response, or
failed assertion leaves no resumable qualification authority. Retry creates a
new UUID, plan digest, observation set, and report. It never patches or
continues a partial report.

Reports contain identities, counts, stable failure labels, and observation
digests, not prompts, source, credentials, model reasoning, or terminal output.
The `report_sha256` is the digest of the report before that self-identifying
field is added. Persistent, append-only storage and protected report admission
belong to the next protected-generation DDD.

## 11. Acceptance

Source acceptance requires:

1. a complete fixture produces thirty passing outer observations and an
   explicitly non-admitting report;
2. missing, reordered, expired, or malformed plans fail closed;
3. forged observer, plan, case, and sequence bindings fail closed;
4. network, child, file, secret, credential-environment, timeout, semantic-
   loss, unknown-event, event-order, denial, and tool-drift faults reject;
5. the Claude launch and environment projection rejects alternate binaries,
   added flags, credentials, loaders, missing disable controls, unknown events,
   and cross-session events;
6. the lifecycle foundation retains its no-candidate-execution and narrow
   `labctl harness` surface; and
7. repository publication, deterministic release, and secret checks pass on
   the exact commit.

No live Host, Gateway, Research, Target, provider account, model profile,
credential, session, or VM is changed by this DDD.

## 12. Next dependency

The next implementation DDD is the Protected Harness Generation Store and
Transactional Activation DDD. It may define protected storage and a consumer
for exact qualification evidence, but it must not stage this synthetic fixture
or infer that any vendor generation passed. Live vendor qualification remains
gated on a provenance-verified exact artifact and an independently accepted
disposable supervisor environment.
