# Bounded CodeGraph adapter

Status: **implemented design**. Deployment state and acceptance evidence are private.
## Decision

Use the locally maintained CodeGraph fork as an optional semantic backend for
the existing `explore_corpus` capability. Do not expose CodeGraph's native CLI,
MCP server, project-path parameter, indexer, watcher, daemon, installer, web UI,
or synchronization functions to the research agent.

The exact bundle is CodeGraph 1.6.2 at commit
the release-manifest-pinned revision plus the sealed-read-only patch
set `725bfe2733d1`, packaged with Node 24.16.0 for Linux ARM64. Its deployment
artifact is pinned by SHA-256
the digest recorded in that manifest.

## Boundary

```text
operator: labctl codegraph index SOURCE_UUID
  -> root verifies source anchor and immutable baseline
  -> networkless codegraph-indexer UID receives a verified copy
  -> only .codegraph is writable during indexing
  -> graph, source copy, and metadata are sealed root:root read-only in /var/lib
  -> workspace receives only a read-only availability/binding marker

agent: explore_corpus(SOURCE_UUID, query, limit)
  -> bounded Python adapter
  -> peer-authenticated Unix socket
  -> networkless codegraph-query service
  -> CodeGraph opened read-only with sync/watch/update/telemetry disabled
  -> bounded untrusted-source response
```

The socket request has exactly three fields: a registered source UUID, a
non-empty query of at most 256 characters, and a limit from 1 to 10. The agent
cannot choose a filesystem path. The query service rebinds the graph metadata
to the root-owned source registry, commit or package revision, tree-manifest
hash, CodeGraph build, bundle hash, and corpus-index content hash before use.

The existing SQLite FTS corpus remains authoritative for exhaustive literal
search and fixed threat scans. CodeGraph improves structural and relationship
exploration; it does not replace integrity verification or exhaustive scanning.

The later static-reachability DDD also uses this same sealed query boundary for
`analyze_reachability`. It resolves exact symbol/file selectors and applies a
fixed, bounded call-flow profile; it does not expose native CodeGraph traversal
arguments. See `STATIC_REACHABILITY_DESIGN.md` for its deliberately
non-exhaustive evidence semantics and acceptance record.

## Isolation and failure behavior

- Index and query processes have `PrivateNetwork=yes`.
- Dedicated `codegraph-indexer` and `codegraph-query` UIDs receive no shell.
- The bundle is not readable or executable by the `agent` account.
- Index construction is bounded to 25,000 manifest files and 512 MiB of source.
- Query output is bounded to 40,000 characters and a 25-second deadline.
- A graph error fails closed instead of silently presenting FTS output as a
  semantic-graph result.
- The query socket is mode `0660`, owned by the query service and grouped to
  the agent's primary GID. The broker also checks peer UID. The protected
  run scope clears supplementary groups, so a supplementary client-group-only
  socket makes indexed graphs unreachable during real agent runs.
- A source without a graph continues to use the existing bounded FTS explorer.
- Installation refuses an active agent run and records a root-only backup ID.

## Acceptance criteria

1. The installed bundle hash and build identity match the pinned values.
2. The query service is active and networkless; the socket admits the agent
   after the protected launcher clears supplementary groups, while peer UID
   authorization still rejects other callers.
3. A graph built for a verified source records matching source, tree, corpus,
   bundle, and index hashes.
4. `explore_corpus` returns `semantic_backend` equal to
   `codegraph-1.6.2-source-uuid-adapter` for that source.
5. Arbitrary paths, unknown UUIDs, malformed requests, oversized queries, and
   direct agent execution of the bundle are rejected.
6. Existing `search_corpus` and `scan_corpus` remain unchanged and exhaustive.

## Acceptance evidence

Deployment-specific evidence, release identities, corpus inventory, and rollback generations are retained in ignored local acceptance records.
