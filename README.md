# SecureSandbox

Design workspace for a high-risk, agent-driven security research lab on an
Apple Silicon MacBook Air.

- [Proposed architecture and threat model](docs/DESIGN.md)
- [Implementation overview and acceptance contract](docs/IMPLEMENTATION.md)
- [Azure alert-semantics separation](docs/ALERT_SEMANTICS_DESIGN.md)
- [Agent artifact evidence pipeline](docs/ARTIFACT_EVIDENCE_PIPELINE.md)
- [Brokered source acquisition](docs/SOURCE_ACQUISITION_DESIGN.md)
- [Agent-visible source integrity verification](docs/SOURCE_INTEGRITY_DESIGN.md)
- [Verified corpus intelligence](docs/CORPUS_INTELLIGENCE_DESIGN.md)
- [Legacy VM data migration and GLM continuity](docs/LEGACY_VM_DATA_MIGRATION_DESIGN.md)
- [Corpus Intelligence v2: inventory, comparison, and fixed indicators](docs/CORPUS_INTELLIGENCE_V2_DESIGN.md)
- [Large-corpus fixed-profile scan scaling](docs/CORPUS_SCAN_SCALING_DESIGN.md)
- [Default-configuration static reachability](docs/STATIC_REACHABILITY_DESIGN.md)
- [Operator-mediated dependency orchestration](docs/DEPENDENCY_ORCHESTRATION_DESIGN.md)
- [Bounded run leases](docs/RUN_LEASE_DESIGN.md)
- [Transactional PKI lifecycle v2](docs/PKI_LIFECYCLE_V2_DESIGN.md)
- [Agent self-definition and institutional memory](docs/AGENT_SELF_DEFINITION_DESIGN.md)
- [Candidate findings and independent adjudication](docs/FINDINGS_ADJUDICATION_DESIGN.md)
- [Trusted evidence receipts](docs/TRUSTED_EVIDENCE_RECEIPTS_DESIGN.md)
- [Sealed review-bundle verification](docs/REVIEW_BUNDLE_VERIFICATION_DESIGN.md)
- [Verified external-containment audit adapter](docs/EXTERNAL_CONTAINMENT_AUDIT_DESIGN.md)
- [Trusted guest time synchronization](docs/TIME_SYNCHRONIZATION_DESIGN.md)
- [Fresh-VM containment restoration and acceptance](docs/FRESH_VM_CONTAINMENT_RESTORATION_DESIGN.md)
- [Operator-visible privileged authorization provenance](docs/OPERATOR_AUTHORIZATION_PROVENANCE_DESIGN.md)
- [Touch ID operator authorization](docs/TOUCH_ID_OPERATOR_AUTHORIZATION_DESIGN.md)
- [Universal host maintenance authorization](docs/UNIVERSAL_HOST_MAINTENANCE_AUTHORIZATION_DESIGN.md)
- [Disposable Python fixture execution](docs/DISPOSABLE_EXECUTION_DESIGN.md)
- [Parallels snapshot retention](docs/SNAPSHOT_RETENTION.md)

Host-side entry point: `scripts/labctl`.

The long-lived `labctl claude` path immediately enters a root-owned, versioned
host-controller release. Deploy a reviewed controller only while no invocation
is active, naming the requesting agent conversation so its declared label is
visible and distinguishable in the macOS authorization ceremony:

```sh
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent Codex --requesting-session SESSION_LABEL
```

Roll back with the same identity flags and the `rollback` command.
See [HOST_CONTROLLER_RELEASE_INTEGRITY_DESIGN.md](docs/HOST_CONTROLLER_RELEASE_INTEGRITY_DESIGN.md).
The one-time migrations from a release without the protected authorization
broker and from the password-only broker schema use `bootstrap-authorization`
and `bootstrap-touchid-schema`, respectively. Normal mutations then present a
signed native window with explicit Touch ID, administrator-password, and cancel
choices. See [OPERATOR_AUTHORIZATION_PROVENANCE_DESIGN.md](docs/OPERATOR_AUTHORIZATION_PROVENANCE_DESIGN.md)
and [TOUCH_ID_OPERATOR_AUTHORIZATION_DESIGN.md](docs/TOUCH_ID_OPERATOR_AUTHORIZATION_DESIGN.md).

Disposable Python execution has a stronger operation-specific ceremony: the
native window requires Touch ID, offers no password fallback, and signs the
exact run, Claude session, registered source, code, fixtures, timeout, and
pinned Target runtime identity. Research consumes that short-lived approval
once before it can contact the independently contained Target. See
[REQUEST_BOUND_EXECUTION_APPROVAL_DESIGN.md](docs/REQUEST_BOUND_EXECUTION_APPROVAL_DESIGN.md).

Installer publication and VM lifecycle maintenance use the same attributed
ceremony. Read-only installer validation and dry-run VM planning remain
prompt-free; Parallels execution is irreversibly deprivileged to the invoking
Mac user before `prlctl` runs. See
[UNIVERSAL_HOST_MAINTENANCE_AUTHORIZATION_DESIGN.md](docs/UNIVERSAL_HOST_MAINTENANCE_AUTHORIZATION_DESIGN.md).

Historical GLM/Claude continuity from a quarantined VM generation uses a
separate content-bound preservation operation. Its dry run is prompt-free and
its apply operation never boots a legacy guest or deletes a quarantined VM:

```sh
python3 scripts/vm-operation.py preserve-legacy \
  --generation GENERATION
```

See the [legacy migration runbook](docs/LEGACY_VM_DATA_MIGRATION_DESIGN.md#operator-runbook)
before using `--apply`.

PKI v2 deployment and full-generation rotation are serialized against agent
launches through the same host coordination lock:

```sh
python3 scripts/pki-operation.py deploy
python3 scripts/pki-operation.py rotate \
  --requesting-agent Codex --requesting-session SESSION_LABEL
```

The rotation creates fresh CA, Gateway server, and three Research client keys,
uses dual trust while changing generations, resumes a root-anchored pending
transaction after interruption, and commits only after both guests verify the
same manifest. Private keys remain on their owning VM. See
[PKI_LIFECYCLE_V2_DESIGN.md](docs/PKI_LIFECYCLE_V2_DESIGN.md).

The implementation requires new agent launches to fail closed unless the host,
Gateway, and Research all report the same generation UUID and manifest hash.
Deployment state and acceptance evidence are intentionally not asserted here.

Report the ordinary host-direct Claude Code posture and independently verify
the exact isolated launch path with fresh local and off-host evidence:

```sh
./scripts/labctl safety-audit
```

The generic safety-audit result is retained unchanged. Tier 4 applies only to
new runs through the exact reported `labctl claude` path while every live
boundary and policy-bound Azure evidence check passes.

Guest time is a launch boundary. Check it with `./scripts/labctl time-sync` or,
while no Claude run is active, synchronize all three guests from the Mac with
`./scripts/labctl time-sync --apply`. Startup applies the same control before
boundary verification, and Claude launch fails closed when any guest differs
by more than five seconds. See [TIME_SYNCHRONIZATION_DESIGN.md](docs/TIME_SYNCHRONIZATION_DESIGN.md).

Import an exact public GitHub source snapshot without giving the agent, Bash,
or Research general Internet access:

```sh
./scripts/labctl source plan OWNER/REPOSITORY REF
./scripts/labctl source apply PLAN_UUID
./scripts/labctl sources
```

Planning resolves the mutable ref to a full commit SHA. Applying consumes the
15-minute plan once, fetches only through the Gateway's UID-scoped GitHub
allowlist, validates and normalizes the archive in a networkless Research unit,
and publishes only after encrypted provenance is confirmed in locked Azure
storage. The result is a root-owned read-only baseline and a separate
agent-writable, non-executable working copy with no `.git` directory.

Claude Code has one root-managed local MCP capability for independently
recomputing those imported hashes without Bash or network access:

```text
verify_source(source_id="SOURCE_UUID", scope="both")
```

Fresh imports are tied to a root-owned per-entry import manifest. Older imports
are reported explicitly as legacy/unanchored rather than given false assurance.

Assemble the exact scoped direct runtime dependencies of a verified imported
npm source without granting npm, registry egress, or lifecycle execution:

```sh
./scripts/labctl dependencies plan SOURCE_UUID
./scripts/labctl dependencies status PLAN_UUID
./scripts/labctl dependencies apply PLAN_UUID
./scripts/labctl dependencies list
```

Missing packages must first pass through the existing operator-reviewed
`source npm-plan` and `source apply` workflow. Published bundles are sealed and
explicitly non-transitive; they are analysis layouts, not runnable installs.

For a large imported source, build its query-only index while no agent run is
active:

```sh
./scripts/labctl corpus index SOURCE_UUID
```

Claude then receives six root-managed capabilities: exhaustive literal search,
exhaustive fixed-profile scanning, bounded relevance exploration,
manifest-backed tree inventory, exact comparison of two registered source
manifests, and—for code-bearing sources with a sealed CodeGraph index—bounded
`analyze_reachability`. The last traces a fixed-profile static path between
exact symbols in exact registered files. Its result is always non-exhaustive
static evidence, labels the default entrypoint as caller-selected, and
explicitly does not claim measured execution, runtime branch feasibility, or
exploitability. Every excerpt is labelled untrusted; the agent cannot select an
arbitrary filesystem root, define regular expressions, rebuild the index,
execute source content, or add network access.

Successful exhaustive search/scan results include an immutable evidence receipt
minted by a dedicated `corpus-broker` identity. Disposable execution results
likewise include a receipt minted by `execution-broker`. The agent cannot read
or write the receipt registry, and receipt-backed finding evidence must reproduce
the instrument's returned `evidence_receipt` object exactly.

For empirical validation of a static finding, Claude also has one separately
prompted high-risk capability:

```text
run_python_fixture(
  source_id="SOURCE_UUID",
  code="...small experiment...",
  fixture_paths=["optional/registered/file.py"],
  timeout_seconds=5
)
```

The managed MCP call is configured to prompt for operator confirmation. That
prompt is a human-control surface, not a cryptographic authorization consumed by
the broker; containment does not depend on it. Execution runs in a fresh
rootless Target container with no network, a read-only root filesystem, fixed
non-root identity, and hard time/output/CPU/memory/PID bounds. It is not Bash,
cannot select an image or mount, and can receive only re-hashed files from an
immutable registered source. JavaScript remains unavailable in v1.

GLM may also propose durable institutional memory without being able to modify
its own future instructions:

```text
propose_memory(
  category="working_principle",
  title="...",
  proposal="...",
  rationale="...",
  evidence_refs=["..."]
)
```

Proposals enter a bounded broker-owned spool as explicitly untrusted review
inputs. They are never auto-loaded or mechanically promoted. List pending
metadata with `./scripts/labctl memory proposals`; accepted ideas must be
restated by the operator and architect in the root-owned persona and redeployed. Native
Claude auto-memory is disabled, and the exact launcher uses restricted mode so
general command-running tools are absent from GLM's tool surface.

Operator-published white-box handoffs live in a root-owned canonical store with
a read-only `review-bundles/` view in GLM's workspace. GLM verifies one without Bash, arbitrary paths, or
disposable execution by calling:

```text
verify_review_bundle(bundle_id="NAME-review")
```

The result proves that the readable bytes match the sealed handoff manifest; it
does not prove that those bytes are deployed or correct.

GLM can also preserve a bounded security hypothesis with the managed findings
tools. Submissions and amendments are immutable, source-bound candidates; they
cannot validate their own claims or severity. The operator and architect adjudicate
through the separate root-owned, hash-chained operator path:

```sh
./scripts/labctl findings
./scripts/labctl finding show FINDING_UUID
./scripts/labctl finding apply REQUEST.json
```

Sensitive vulnerability reports never belong in source control. The host
`vulnerability-reports/` directory is quarantined by `.gitignore`; only its
tracked policy README may enter either private remote.

`scripts/labctl claude` creates a unique UUIDv4 run ID, claims a root-owned
marker in Research, prints the ID for the operator, and clears only that same
marker when the SSH session ends. A concurrent launch or boundary verification
fails closed instead of overwriting an active run's attribution. Relay and
Gateway events share one request ID end to end.

Every `labctl claude` run also fails closed unless the encrypted conversation
and artifact capture services are healthy. To inspect a completed run, use:

```sh
./scripts/labctl transcript RUN_ID
```

Resume an existing Claude conversation with:

```sh
./scripts/labctl claude --resume CLAUDE_SESSION_UUID
```

The resume UUID is narrowly validated and is the only caller-supplied CLI
option the hardened launcher accepts. It must also appear in the root-owned
registry built from Claude journals created inside the Research workspace. List
eligible sessions with `./scripts/labctl sessions`; it prints the UUID followed
by its earliest journal timestamp in UTC, ordered from earliest to latest. Each
invocation receives a new SecureSandbox run ID for evidence correlation, while
the Claude session UUID remains stable across resumed invocations.

Session validation distinguishes a definitive registry miss from an unreachable
Research VM or failed registry refresh. Both fail closed, but only the former is
reported as an unregistered UUID; availability failures do not make claims
about registry contents.

Inspect or enforce the bounded five-milestone Parallels recovery policy with:

```sh
./scripts/labctl snapshots
./scripts/labctl snapshots --apply
```

Enforcement requires all three lab VMs to be stopped and at least 50 GiB of
host free space. It never operates on unrelated Parallels VMs.

This downloads age-encrypted chunks from the 30-day locked Azure archive,
verifies ciphertext hashes and sequence linkage, obtains the decryption identity
from the Agents vault without writing it to disk, and emits the original Claude
Code JSONL records. Those records include prompts, model-returned visible
thinking, responses, tool calls/results, and approvals that Claude Code wrote to
its journal. They cannot include private provider-side reasoning that the API
never returned to Claude Code.

Agent-authored `.md`, `.txt`, and `.json` reports written directly under
`/home/agent/research-workspace/reports` are independently snapshotted after a
two-second stability window. Each revision is hashed, age-encrypted, transported
through the existing pinned mTLS evidence path, and retained in the locked Azure
archive. List or safely render immutable snapshots with:

```sh
./scripts/labctl artifacts
./scripts/labctl artifact ARTIFACT_UUID
```

The renderer validates both ciphertext and plaintext hashes and neutralizes
terminal control sequences before displaying agent-authored content.

Current readiness and explicit activation gates: [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).
Automated boundary reports are retained only in the ignored local `runs/`
directory.

Before publishing, install the repository hooks with
`git config core.hooksPath .githooks`. The pre-commit hook scans the exact Git
index, and the pre-push hook permits only `public-release` to
`public-release` after scanning every object reachable from the outgoing commit.
Run the complete offline exact-candidate gate with
`./scripts/run-public-release-checks.sh HEAD`. GitHub repeats that gate for each
accepted commit, builds the source bundle twice to prove reproducibility, and
issues signed build-provenance attestations for the resulting archive,
provenance document, and checksums. See
[PUBLIC_RELEASE_CONTROLS_DESIGN.md](docs/PUBLIC_RELEASE_CONTROLS_DESIGN.md).
Installation-local DDD identifiers belong in the ignored
`.private/secure-enclave-ddd.json`, created from
`config/secure-enclave-ddd.example.json`; generated signed authorization apps,
profiles, and bundle manifests are also excluded and rejected if force-added.

Large imported repositories can be searched exhaustively and navigated through
bounded document structure without granting a general shell. The design and
CodeGraph-admission criteria are in
[CORPUS_INTELLIGENCE_DESIGN.md](docs/CORPUS_INTELLIGENCE_DESIGN.md).

No host CLI or agent configuration is managed by this project.

The approved posture is a robust baseline, not a permanent freeze. Proposed
functionality changes should be discussed against observed workflow needs,
threat-modeled, implemented as narrowly as practical, and reverified before
becoming the new baseline.
