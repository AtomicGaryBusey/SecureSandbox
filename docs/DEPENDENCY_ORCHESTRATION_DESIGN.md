# Operator-mediated dependency orchestration

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Decision

Add a narrow dependency-orchestration layer over the existing verified npm
source-import pipeline. Version 1 assembles the exact direct runtime
dependencies declared by one registered scoped npm package into a sealed,
read-only bundle. It does not give the agent a package manager, registry
access, arbitrary filesystem selection, or code execution.

The operator workflow is:

```text
./scripts/labctl dependencies plan SOURCE_UUID
./scripts/labctl source npm-plan @SCOPE/MISSING_PACKAGE EXACT_VERSION
./scripts/labctl source apply SOURCE_PLAN_UUID
./scripts/labctl dependencies status DEPENDENCY_PLAN_UUID
./scripts/labctl dependencies apply DEPENDENCY_PLAN_UUID
./scripts/labctl dependencies list
```

The middle two commands are repeated only for dependencies reported missing.
They retain the existing explicit, reviewed acquisition boundary. Dependency
planning never initiates a download, and dependency apply never uses the
network.

## 2. Version-1 contract

The root package must be a verified imported npm source. Its `package.json`
must agree with the root-controlled registry record. The orchestrator accepts
at most 64 entries from `dependencies`, each with:

- a scoped package name in canonical `@scope/name` form; and
- one exact semantic version, including an optional prerelease suffix.

Ranges, tags, aliases, workspace references, URLs, git references, local paths,
unscoped names, and malformed manifests fail closed. `devDependencies`,
`optionalDependencies`, and `peerDependencies` are not included. Version 1 is
not transitively complete.

Every dependency must already exist as exactly one verified npm source with
the same package identity. Missing sources are reported by plan/status and
must be acquired through the existing operator-mediated npm workflow.
Multiple matching registrations are rejected as ambiguous.

## 3. Plan and apply semantics

A plan is root-owned, expires after one hour, and binds:

- the root source UUID;
- the root package name and exact version;
- the root source tree-manifest hash;
- the sorted direct dependency name/version tuple; and
- the dependency-set SHA-256 derived from those fields.

Apply re-verifies the root source, rereads its trusted manifest, recomputes the
dependency set, and verifies every resolved dependency before publishing. A
changed root tree, changed dependency declaration, missing source, ambiguous
source, expired plan, completed plan, or active agent run is rejected.

Only one apply operation can hold the nonblocking root-controlled lock.
Publication uses same-filesystem atomic renames. The bundle index and plan
state are committed together with compensating rollback: if the plan-state
write fails after the index update, the old index is restored and the bundle
is removed. Atomic JSON writes use unique temporary files, complete-write
checks, file and directory `fsync`, and exact modes.

## 4. Published bundle

A successful apply publishes:

```text
/home/agent/research-workspace/dependency-bundles/BUNDLE_UUID/
  manifest.json
  root-package -> ../../baselines/ROOT_SOURCE_UUID
  node_modules/@scope/name -> ../../../baselines/DEPENDENCY_SOURCE_UUID
```

The directory, manifest, index, and links are created by root and are not
writable by `agent`. Link targets are verified immutable baselines beneath the
workspace; neither agent-owned working trees nor caller-provided paths are
used. The manifest records every source UUID, tree-manifest hash, npm integrity
value, the dependency-set hash, and the following evidence qualifiers:

```text
scope: direct_runtime_dependencies
lifecycle_execution: disabled
transitive_completeness: false
```

The `node_modules` layout is an analysis convenience, not proof that the
package is installable or runnable. No dependency resolver, npm client,
postinstall hook, build step, native addon, or package code runs.

## 5. Trust boundary

```text
operator on Mac
  -> labctl dependency plan/status/apply
  -> forced-command securectl channel
  -> typed, role-bound argv dispatch on Research
  -> root orchestrator, no network
  -> verified root-controlled source registry and immutable baselines
  -> sealed agent-readable dependency bundle
```

The Research VM keeps its existing default-drop egress policy and runtime DNS
remains disabled. The dispatcher permits only UUID-validated `plan`, `status`,
and `apply` operations to the dedicated control identity; `list` remains an
unprivileged read of the sealed public index. Neither `labadmin` nor the agent
has a sudo rule for the orchestrator. The agent can read completed bundles and
their index, but cannot create plans, invoke apply, rewrite the index, replace
links, or modify their baseline targets.

Deployment and rollback both refuse to cross the active-run boundary. The
installer creates a root-only rollback generation before changing the binary,
telemetry normalizer, or sudo policy. Data bundles are retained on rollback as
read-only evidence rather than destructively removed.

## 6. Telemetry and evidence semantics

The orchestrator emits plan-created, bundle-completed, and bundle-rejected
events. Off-host normalization retains only the plan/bundle identifier,
dependency-set hash, dependency and missing counts, and an allowlisted error
token. Package names, versions, source paths, manifest content, and dependency
lists are not exported in these lifecycle events. The normalizer is tested to
discard unexpected payload fields.

The bundle manifest is the local artifact-level provenance record. It supports
the claim that exact verified direct dependencies were assembled without
execution. It does not support claims of transitive closure, runtime loading,
compatibility, safe package behavior, or measured execution.

## 7. Acceptance criteria

Deployment is accepted only after all of the following pass:

- Research, Gateway, Python, Bash, and JSON validation;
- a live plan/status/apply cycle for an imported package whose exact direct
  dependencies are already registered;
- rejection of an unsupported dependency manifest and traversal/malformed IDs;
- proof that the agent cannot invoke the orchestrator or mutate bundles;
- exact installed-artifact hashes and the complete containment suite; and
- current Azure heartbeat, denial, and content-free dependency lifecycle
  evidence.

## 8. Acceptance and repair evidence

Live dependency identities, bundle hashes, review reports, rollback generations, and crash-recovery probes are retained in ignored local records. Acceptance must cover atomic recovery across every commit window and cumulative bounds for plans, records, and bundles.
