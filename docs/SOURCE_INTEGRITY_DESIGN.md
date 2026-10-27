# Agent-visible source integrity verification

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## Decision

Provide Claude Code one narrowly scoped, read-only MCP tool:

```text
verify_source(source_id, scope = baseline | worktree | both)
```

The tool accepts only a UUID already present in the root-owned source registry.
It cannot accept a path, URL, command, environment variable, size override, or
network destination. It returns hashes, counts, status, and a bounded list of
changed relative paths; it never returns file contents.

This closes the source-acquisition verification loop without enabling Bash,
`sha256sum`, Git, general filesystem traversal, or network access.

## Trust model

- The importer records a canonical per-entry manifest at acquisition time.
- The registry, manifest directory, baseline directory, MCP configuration, and
  verifier are root-owned and non-writable by `agent`; their containing
  directories are also root-owned, preventing anchor replacement by rename.
- The verifier recomputes the manifest hash and requires it to match both the
  manifest and registry `tree_manifest_sha256` values.
- It safely walks and hashes the immutable baseline and, when requested,
  compares the agent-writable worktree with the same expected entries.
- Files are opened with `O_NOFOLLOW`; types, sizes, hashes, symlink targets,
  bounds, path safety, and filesystem-change races are checked.
- The tool runs locally as a stdio MCP process with no credentials and no
  network function. The outer VM, nftables, no-route design, and managed policy
  remain independent controls.

The MCP server is defined exclusively by root-owned
`/etc/claude-code/managed-mcp.json`. User and project MCP servers cannot be
loaded. The managed policy pre-approves exactly
`mcp__source_integrity__verify_source`; no wildcard MCP permission is used.
`CLAUDE_CODE_MCP_ALLOWLIST_ENV=1` gives stdio servers a minimal environment.
The launcher preserves Claude Code's built-in `/compact`, `/clear`, and `/quit`
commands by omitting the overly broad `--disable-slash-commands` switch.
Restricted mode and managed customization controls continue to block custom
commands and skills. The launcher intentionally uses neither `--bare` nor
`--safe-mode`, because both suppress the managed MCP server. It also does not
use `--mcp-config`,
because `disableSideloadFlags` correctly rejects that explicit sideload path.
Claude loads the exclusive root-owned enterprise MCP configuration implicitly;
the managed policy independently disables every other customization surface.

## Results and telemetry

- `match`: the import-time anchor is valid and every checked tree matches.
- `changed_or_unverified`: a checked tree differs or cannot be fully verified.
- `legacy_unanchored_match`: a pre-deployment import has no import-time
  per-entry manifest. Its current worktree can be compared with its current
  root-owned baseline, but the baseline cannot be independently tied back to
  the recorded import hash.
- `rejected`: the UUID, registry, manifest, bounds, or trusted-control-file
  checks failed.

Worktree changes are expected during research and are metadata-observable but
do not trigger a security alert. An immutable-baseline mismatch emits a
critical deny event. Rejections also emit deny telemetry. Off-host telemetry
contains source UUID, scope, status, anchor state, and change counts only—no
filenames or source content. Full local tool inputs/results remain available in
the encrypted conversation evidence.

The verifier refuses more than 100,000 entries, files over 64 MiB, more than
1 GiB total regular-file content, paths over 240 bytes or 32 components,
unsafe names, oversized/untrusted control files, and filesystem-change races.
At most 200 changed paths are returned. These limits are policy, not
model-controlled arguments.

## Acceptance evidence

Live source identifiers, revisions, manifest hashes, tool transcripts, cloud evidence, and checkpoint identifiers are retained in ignored local records. Acceptance covers anchored and legacy sources, baseline and worktree verification, mutation detection, bounded failures, and agent-side use of the managed verifier.

## Rollback

The installer emits a private rollback generation identifier. From the
Mac, after ending any Claude session:

```sh
./scripts/rollback-source-integrity.sh ROLLBACK_GENERATION
```

The installer also retains later deployment backups and records the most recent
one for a no-argument rollback. Rollback refuses while a run marker or Claude
process is active and restores the prior managed policy, launcher, MCP files,
importer, wrapper, and telemetry exporter.
