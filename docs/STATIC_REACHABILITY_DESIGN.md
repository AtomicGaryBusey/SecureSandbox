# Default-Configuration Static Reachability

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Decision

Add `analyze_reachability` as a sixth managed Corpus Intelligence tool. It
traces a bounded path from one exact, caller-selected default entrypoint to one
exact target in a sealed CodeGraph index. It does not expose CodeGraph's native
MCP, an arbitrary project path, graph construction, filesystem traversal, or
agent-defined graph logic.

The result is deliberately classified as `static_graph_reachability`, with
`measured_execution: false` and `exhaustive: false`. The caller must establish
from separately reviewed source evidence that the selected entrypoint
represents repository defaults. A returned path does not prove that a runtime
branch is feasible or that a behavior is exploitable. No returned path means
only that the bounded graph profile found none.

## 2. Request contract

The tool accepts:

- one registered source UUID with a sealed CodeGraph index;
- an entrypoint symbol plus its exact repository-relative file;
- a target symbol plus its exact repository-relative file; and
- a maximum depth from 1 through 12, default 8.

Both selectors must resolve to exactly one callable graph node in the named
file. Missing and ambiguous symbols fail closed. Absolute paths, traversal,
empty path segments, extra request fields, oversized values, unknown source
UUIDs, and unsealed graphs are rejected.

## 3. Fixed analysis profile

The root-managed runner performs breadth-first traversal with these fixed edge
classes:

- direct `calls` edges;
- CodeGraph `references` edges only when marked as function-as-value callback
  registration;
- `instantiates`; and
- `navigates`.

Generic references, containment, imports, type edges, and caller-selected edge
types are excluded. The traversal visits at most 5,000 nodes and at most 12
hops. Results report the effective edge profile, node count, depth bound, and
whether the node budget truncated the search. Every path step contains only
the graph symbol identity, registered relative path, source lines, and the
edge that reached it.

## 4. Trust boundary

```text
agent: analyze_reachability(source UUID, exact selectors, depth)
  -> managed Corpus Intelligence MCP validation and content-free audit
  -> bounded CodeGraph adapter
  -> peer-authenticated Unix socket
  -> networkless codegraph-query service
  -> root-owned sealed graph, opened read-only/immutable
  -> fixed breadth-first flow profile and bounded structured result
```

The query service revalidates the graph's source UUID, repository revision,
tree-manifest hash, corpus-index hash, CodeGraph build identity, bundle hash,
and graph digest before each analysis. The agent cannot provide a filesystem
root, node ID, edge set, query program, or executable predicate.

## 5. Evidence semantics

`static_path_found` means the sealed graph records an admitted path between the
two exact selectors. `no_static_path_within_bound` is not an absence proof:
dynamic dispatch, unresolved calls, extraction gaps, excluded edge classes,
or the configured depth/node bounds may hide a runtime path.

Default-configuration evidence is intentionally split:

1. exact source review supports the caller's choice of default entrypoint;
2. this tool supplies source-bound static path evidence; and
3. disposable execution, when applicable, supplies separately labeled
   measured evidence.

The tool never combines those into an automatic vulnerability or
exploitability finding.

## 6. Telemetry and recovery

The off-host corpus event contains the tool name, source UUID, SHA-256 of the
selectors/depth tuple, graph-bound analysis ID, fixed edge profile, nodes examined, path
length, and reachable/not-reachable count. Symbol names, repository paths, and
path steps are not exported in telemetry. Conversation capture retains the
operator-visible result through the existing encrypted evidence path.

Deployment uses the existing CodeGraph and Corpus Intelligence rollback
bundles and refuses an active Claude run. The accepted deployment backups are:

- the prior CodeGraph adapter generation; and
- the prior corpus-intelligence generation.

## 7. Acceptance and independent review

Live source identifiers, graph hashes, release generations, review findings, and checkpoint evidence are retained in ignored local records. Acceptance must include selector ambiguity, security-boundary regression, resource-bound enforcement, precise structured errors, and truthful evidence labels.
