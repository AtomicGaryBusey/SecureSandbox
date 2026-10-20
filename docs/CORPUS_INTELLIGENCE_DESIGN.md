# Verified Corpus Intelligence Design

Status: **implemented design**. Deployment state and acceptance evidence are private.

## 1. Purpose

Large imported sources can exceed an agent's practical ability to enumerate and
sample with individual file tools. Granting a general shell to solve that
logistics problem would also grant unrelated process execution and would erase
an important capability boundary. This design instead exposes the operations
the research workflow actually needs:

- `search_corpus`: exhaustive literal search with exact counts, stable result
  ordering, pagination, and a result-set digest;
- `scan_corpus`: exhaustive operator-owned indicator profiles whose regular
  expressions cannot be supplied or changed by the model; and
- `explore_corpus`: relevance-oriented navigation over titles, Markdown
  headings, links, text, and bounded excerpts.

All three accept a registered source UUID rather than a filesystem root. They
operate only on a root-built index of the cryptographically verified immutable
baseline. They do not execute repository content, access the network, rebuild
an index, accept shell fragments, or select arbitrary host paths.

## 2. Threat model

The source corpus is hostile data. It may contain prompt injection, extremely
large or malformed text, secrets, misleading links, pathological repetition,
or instructions designed to induce tool use. The model is also untrusted: it
may attempt path traversal, resource exhaustion, arbitrary regular expressions,
index replacement, scope widening, or use returned prose as authority.

The trusted computing base is limited to the root-owned importer registry and
manifest, integrity verifier, corpus index builder, MCP adapter, managed Claude
policy, Python/SQLite runtime, and the existing VM/network/telemetry boundary.
The model, writable worktree, repository prose, and all MCP arguments are
untrusted.

## 3. Security invariants

1. Every operation requires a UUIDv4 present exactly once in the root-owned
   source registry.
2. Index construction first requires an `import_validated`, byte-exact baseline
   verification against the import manifest.
3. The index records and is checked against source UUID, repository, pinned
   commit, manifest-tree hash, engine version, scan-profile version, and a
   deterministic index-content digest.
4. Index files and their directory are root-owned and not writable by the
   agent. Query-time SQLite access is read-only and immutable.
5. Repository-relative prefixes pass the existing 240-byte safe-path parser.
   No absolute path, `..`, empty component, control character, or backslash is
   accepted.
6. Agent-defined search is literal only. Regular expressions exist solely in
   versioned operator-owned profiles.
7. Indexing is limited to 100,000 source-manifest entries, 8 MiB per text
   document, 1 GiB indexed text, UTF-8 content without NUL bytes, 512 headings,
   and 256 links per document. Skips are recorded in index metadata.
8. Query text is limited to 256 characters; extensions, result count, context,
   pagination offset, execution time, output snippets, and FTS result count are
   independently bounded.
9. Exhaustive tools scan every eligible indexed document or fail; a timeout is
   a rejection, never a partial result labelled exhaustive.
10. Every excerpt is labelled `untrusted_source_content`, and the MCP response
    begins with an explicit data-not-instructions warning.
11. Off-host telemetry contains only source/scan identity, query hash, fixed
    profile name, counts, status, and policy/run correlation. Query strings,
    paths, matches, headings, links, and excerpts stay in encrypted conversation
    evidence.
12. The model can query but cannot create, update, delete, or synchronize an
    index. Index construction is an operator-only `labctl corpus index` action
    and is refused during an active agent run.

## 4. Index and query lifecycle

`labctl corpus index SOURCE_UUID` invokes the root-owned builder on Research.
The builder verifies the baseline, reads only manifest-listed regular files
through `O_NOFOLLOW`, recomputes each indexed file hash, extracts bounded
document structure, creates an FTS5 database in a destination-local temporary
file, fsyncs it, changes it to `root:root` mode `0444`, and atomically publishes
it as `corpus-indexes/SOURCE_UUID.sqlite3`.

The agent-facing MCP opens that exact UUID-derived file with `O_NOFOLLOW`,
checks ownership, link count, permissions, size, and all provenance metadata,
then attaches SQLite through the already-open descriptor in immutable read-only
mode. It never follows a model-provided database or project path.

Literal search scans the complete selected index in repository-path order. It
returns exact occurrence and matching-file counts, files/bytes examined, a
digest over every match coordinate, and a bounded page. The deterministic scan
ID binds the source manifest and normalized query controls; later pages rerun
the same immutable search with an offset rather than trusting model-held state.

Profile scans use fixed indicators for prompt-injection language, external
fetch instructions, likely credential material, and agent-directed language.
These are triage indicators, not vulnerability findings. Semantic exploration
uses SQLite FTS5 ranking plus bounded headings and links and explicitly does not
make completeness claims.

## 5. CodeGraph relationship

The Mac has a private CodeGraph 1.6.2 fork at commit `8877995`. It is not copied
into Research in version 1 because its current language map does not include
Markdown, its FTS index covers symbols rather than complete file content, and
its normal MCP accepts arbitrary `projectPath`. Deploying it unchanged would
add a large runtime while failing the immediate documentation-corpus use case.

The `explore_corpus` contract is deliberately backend-neutral. A future
CodeGraph adapter may replace or augment the bounded Markdown FTS/link backend
after the fork gains a Markdown/`llms.txt` extractor and can be compiled into a
pinned artifact. Admission requires:

- source UUID instead of `projectPath` at the exposed boundary;
- root-built indexes stored outside the immutable baseline;
- query-only runtime with update checks, telemetry, watchers, synchronization,
  UI server, and network disabled;
- provenance binding to the source manifest, CodeGraph commit/build hash,
  extractor configuration, and index digest;
- resource and output limits at least as strict as this implementation; and
- the same cold-boot, rollback, malicious-input, and evidence tests.

Until those gates pass, CodeGraph remains a candidate semantic backend, not a
security boundary or a completeness oracle.

## 6. Managed Claude surface

The root-owned managed MCP configuration exposes one new server with exactly
three tools. Managed permissions allow only:

```text
mcp__corpus_intelligence__search_corpus
mcp__corpus_intelligence__scan_corpus
mcp__corpus_intelligence__explore_corpus
```

No wildcard MCP permission is used. Project MCP configuration, side-loaded
servers, hooks, plugins, shell execution, bypass mode, arbitrary network access,
and agent-selected domains remain prohibited.

## 7. Telemetry and alerting

The existing Research exporter normalizes `corpus_query_completed` and
`corpus_query_rejected` journal records. Completed queries are informational.
Rejected queries retain the denial signal and can be investigated with run and
source correlation, but normal content hits are never treated as containment
violations. Raw query text and source content are deliberately excluded from
Log Analytics.

## 8. Acceptance gates

- unit tests cover pagination, exact counts, fixed profiles, semantic results,
  path/extension/limit rejection, MCP surface restriction, and telemetry
  redaction;
- all existing Research tests remain green;
- managed JSON, Python compilation, and shell syntax validation pass;
- a representative large-corpus index is bound to its registered source and
  every indexed document is verified against the source manifest;
- literal and profile searches finish exhaustively with exact counts and
  bounded output;
- semantic exploration returns relevant Markdown structure without an
  arbitrary project/path option;
- traversal, unknown extension, oversized page, agent index build, mutable
  index, unknown UUID, and extra MCP argument tests fail closed;
- metadata-only events reach the existing off-host telemetry path;
- the complete boundary suite passes hot, after a cold boot, and after a
  coordinated stopped checkpoint.

## 9. Rollback

Deployment creates a timestamped root-only policy backup. Rollback restores the
previous managed settings, managed MCP configuration, telemetry exporter, and
prior/absent corpus binaries, then refreshes the Research policy hash. It
refuses to run during an active Claude session. Derived root-owned index files
are intentionally retained but become unreachable after the MCP and permission
rollback; they can be rebuilt from the immutable baseline and contain no data
not already present there.

## 10. Deployment evidence

Live source identities, index hashes, performance measurements, cloud evidence, and checkpoint identifiers are retained in ignored local acceptance records.
