# Corpus Intelligence v2: inventory, comparison, and fixed indicators

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Decision

Extend the existing root-managed, networkless corpus-intelligence MCP server
with two manifest-backed tools and three fixed scan profiles:

- `list_source_tree` lists validated registered paths and integrity metadata;
- `diff_sources` compares two immutable registered source manifests;
- `personnel_identifiers`, `internal_hostnames`, and
  `infrastructure_assets` add operator-owned indicator families to
  `scan_corpus`.

The change does not grant Bash, arbitrary filesystem access, source-index
construction, custom regular expressions, code execution, or network access.
All operations remain scoped by registered source UUID.

## 2. Research need

The first evaluation exposed three bounded logistics gaps:

1. An agent without shell access could search a corpus but could not cheaply
   enumerate its registered tree.
2. Comparing a fork, dependency snapshot, or later import required manual
   inspection even though both source manifests were already trusted control
   data.
3. Repeated searches for personnel identifiers, private hostnames, and cloud
   infrastructure identifiers were performed manually instead of through
   versioned, exhaustive profiles.

These are data-navigation operations. They do not justify widening the
Research VM's execution or egress authority.

## 3. Threat model

The model, all source content, filenames, symlink targets, writable worktrees,
and MCP arguments are untrusted. The attacker may attempt path traversal,
oversized output, expensive comparisons, result ambiguity, terminal-control
injection, arbitrary regex execution, or use one source identifier to reach a
different filesystem tree.

The trusted computing base remains the root-owned registry and integrity
manifests, source-integrity parser, corpus service and MCP adapter, Python and
SQLite runtimes, managed Claude policy, and existing VM/network/telemetry
boundaries.

## 4. Security invariants

1. Both tools accept only canonical UUIDv4 source identities already present
   exactly once in the root-owned registry.
2. Filesystem paths are derived exclusively from registry fields; the agent
   cannot supply an absolute path, database path, manifest path, or project
   root.
3. Manifest schema, ownership, permissions, size, source identity, and
   canonical tree hash are revalidated on every operation.
4. `list_source_tree` returns only normalized paths, types, sizes, and hashes.
   Symlink targets are never returned; only their SHA-256 digests are exposed.
5. `diff_sources` compares manifest records and emits no source bodies or
   content excerpts. It reports added, removed, and modified paths with bounded
   integrity metadata.
6. Path prefixes pass the existing repository-relative canonical validator.
   Pagination is limited to 50 results and offsets to 1,000,000.
7. Result ordering and result-set digests are deterministic. Counts and
   digests cover the complete selected set even when the visible page is
   bounded.
8. Scan profiles contain only versioned operator-owned regexes. The model
   cannot supply patterns, flags, code, or replacement text.
9. Profile matches are indicators, not findings. Returned snippets remain
   explicitly labelled untrusted source content.
10. Off-host telemetry contains only tool name, source identity, fixed profile,
    query/source-pair hash, counts, status, and run correlation. Paths,
    filenames, identifiers, snippets, and source bytes stay in encrypted
    conversation evidence.

## 5. Tool contracts

### `list_source_tree`

Inputs:

- `source_id` (required registered UUID);
- optional repository-relative `path_prefix`;
- `recursive` boolean, default false;
- optional unique subset of `directory`, `file`, and `symlink`;
- bounded `offset` and `limit`.

Non-recursive root listing behaves like a safe `ls`: it returns only immediate
registered children. Recursive listing is still bounded at the response layer,
while exact totals and the result digest cover every selected entry.

### `diff_sources`

Inputs:

- distinct registered `source_id_a` and `source_id_b`;
- optional repository-relative `path_prefix`;
- bounded `offset` and `limit`.

The comparison may span two imports of one repository or a fork/upstream pair.
It reports whether the registry repository names match but does not require
them to match. Version 1 intentionally omits rename inference and textual
patches: identical hashes across added/removed paths remain available for
agent reasoning without adding a content-rendering surface.

### New scan profiles

- `personnel_identifiers`: email addresses and explicitly labelled contact,
  owner, maintainer, reviewer, username, login, principal, or assignee fields;
- `internal_hostnames`: RFC1918 addresses, loopback names/addresses, common
  internal DNS suffixes, and the enterprise development domains observed in
  the evaluated corpora;
- `infrastructure_assets`: AWS ARNs, Azure resource IDs, context-bound GCP
  project IDs, context-bound OAuth client IDs, and cloud bucket URIs.

False positives are expected and do not weaken the boundary. Profile names,
labels, regex text, and regex flags are included in `PROFILE_VERSION` so a
change is observable and reproducible.

## 6. Index compatibility

The new tree and diff tools use integrity manifests rather than SQLite corpus
indexes. No index rebuild is necessary.

Scan profiles execute over existing indexed text, but profile definitions are
not embedded into that text index. Version 2 therefore accepts the explicitly
supported corpus engine versions 1.0.0 and 1.1.0 while independently validating
the stored profile hash format. Every scan response binds itself to the current
profile version. New indexes record engine 1.1.0 and the current profile hash.

## 7. Managed surface and deployment

The root-owned managed permission list adds exactly:

```text
mcp__corpus_intelligence__list_source_tree
mcp__corpus_intelligence__diff_sources
```

The existing deployment workflow refuses an active Claude session, validates
JSON and Python syntax, backs up every replaced policy/runtime file, installs
root-owned artifacts, updates the Research policy hash, restarts telemetry,
and records a one-command rollback identifier.

## 8. Acceptance gates

- focused tests cover all new profiles, non-recursive and recursive tree
  behavior, symlink-target redaction, exact diff counts, pagination, rejection
  of invalid arguments, and the exact five-tool MCP surface;
- all existing Research unit tests pass;
- managed JSON and Python compilation pass;
- production calls prove tree listing and same-repository diff behavior over
  registered immutable sources;
- telemetry proves only fixed metadata leaves Research;
- the complete containment suite passes after deployment;
- a coordinated stopped-state snapshot is taken only after hot acceptance.

## 9. Rollback

Use the backup identifier printed by `deploy-corpus-intelligence.sh` with the
installed rollback script. Rollback restores the previous managed settings,
managed MCP configuration, corpus runtime, MCP adapter, and telemetry exporter,
then refreshes the Research policy hash. Existing immutable sources and indexes
are retained but the removed tools become unreachable.

## 10. Deployment evidence

Live deployment generations and acceptance results are retained in ignored local records.
