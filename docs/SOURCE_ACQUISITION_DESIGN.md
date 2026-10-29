# Brokered source acquisition for high-risk research agents

Status: **implemented design for GitHub and exact-version npm paths**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Decision

Do not grant Claude Code, the `agent` account, Bash, or the Research VM general
GitHub access. Do not use `dangerouslyDisableSandbox` for repository
acquisition.

Add an **operator-authorized source acquisition pipeline**. A dedicated,
unprivileged process on Gateway will fetch an exact public GitHub commit as a
source archive. A root-owned importer on Research will validate and extract the
archive without executing it. The existing Research egress policy will not
change.

The initial interface will be deliberately two-step:

```text
./scripts/labctl source plan OWNER/REPOSITORY REF
./scripts/labctl source apply PLAN_UUID
./scripts/labctl sources
```

The same approval boundary supports public scoped and unscoped npm distributions:

```text
./scripts/labctl source npm-plan PACKAGE EXACT_VERSION
./scripts/labctl source apply PLAN_UUID
```

Only exact semantic versions are accepted. Tags and ranges such as `latest`,
`next`, `^4.13.0`, and `4.x` are rejected. The Gateway resolves metadata only
from `registry.npmjs.org`, binds the one-time plan to the package name, version,
tarball path, SHA-1 revision, and registry-published SHA-512 SRI value, then
verifies both digests before export. Redirects, alternate registries, arbitrary
tarball URLs, npm authentication, dependency installation, and lifecycle
scripts are not supported.
The exact `rc@1.2.8` distribution is an unscoped example: it is imported as
`npm/rc` with the registry's integrity value and archive digest verified before
publication. Import does not execute the package or its dependencies.

For the example SDK, the official getting-started guide identifies npm as
the distribution channel. The reproducible analysis set is four separately
registered immutable sources at one exact version: `@example/sdk`,
`@example/sdk-core`, `@example/sdk-api`, and `@example/sdk-cli`.
Separate registrations retain package-level provenance while allowing bounded
corpus and semantic indexes for each package. Nothing runs `npm install`.

`plan` resolves a branch, tag, or full commit reference to a full immutable
commit SHA and records a short-lived, root-owned plan. `apply` fetches only that
resolved SHA and imports it. A plan expires after 15 minutes and can be applied
only once. The two commands intentionally separate inspection from mutation.

The model may recommend an `OWNER/REPOSITORY` and ref in conversation, but it
cannot create, approve, or execute a plan. There is no watched request directory
and no automatic fetch path in version 1.

## 2. Why the three apparent alternatives are rejected

| Alternative | Decision | Reason |
|---|---|---|
| Give Bash or `git` to the agent | Reject | It combines arbitrary execution, workspace mutation, and egress in one ambient capability. Command restrictions are not a meaningful boundary once a general shell is available. |
| Clone on macOS and copy the checkout in | Refine | Operator mediation is correct, but the Mac should not parse or check out attacker-controlled repositories. The fetch and archive parsing belong inside the existing VM boundary. |
| Use `dangerouslyDisableSandbox` | Reject | It is a broad bypass for a narrow data-ingestion need and directly conflicts with the managed policy. The prior observed retry using this flag shows why the outer controls must not rely on model judgment. |

This is a specialized **data import** operation, not Tier 2 network access for
the agent. Claude remains at its current effective capability tier.

## 3. Security properties

The pipeline must provide all of the following:

- explicit human initiation from the Mac for every acquisition;
- an exact public GitHub repository and commit, with no arbitrary URL input;
- no GitHub credential in version 1;
- no new Research route, resolver, listener, or outbound firewall exception;
- no `git clone`, checkout hooks, submodule recursion, Git LFS fetch, package
  installation, build, test, or execution;
- no parsing or extraction of repository content on macOS;
- bounded download size, expanded size, entry count, per-file size, path
  length, time, memory, and disk use;
- safe archive extraction with path and link validation;
- a root-owned, read-only baseline and a separate agent-owned working copy;
- an immutable, encrypted provenance record in the existing Azure WORM archive;
- metadata-only lifecycle telemetry and alerting; and
- fail-closed behavior on validation, storage, evidence, or policy failure.

The system does not assert that imported source is safe. Imported content is
hostile input and may contain prompt injection, exploits, misleading
instructions, terminal control bytes, decompression bombs, malicious filenames,
or code intended to attack tools that inspect it. The purpose of this pipeline
is to move that input into the already-contained Research VM without giving the
model a network or privilege capability.

## 4. Trust and data flow

```text
Operator on Mac
   |
   | SSH: create root-owned, expiring plan
   v
Gateway source controller
   |
   | fixed one-shot unit, source-fetcher UID only
   | HTTPS only to api.github.com, codeload.github.com, registry.npmjs.org
   v
Bounded archive + root-owned manifest in Gateway spool
   |
   | SSH stream through the Mac; bytes are not saved or extracted on macOS
   v
Research source importer (root, no network, stdin only)
   |
   +--> /home/agent/research-workspace/baselines/SOURCE_ID/  (root, read-only)
   +--> /home/agent/research-workspace/repos/REPO_ID/        (agent, writable)
   +--> /home/agent/research-workspace/repos/INDEX.json      (root, read-only)
   +--> /home/agent/research-workspace/source-manifests/ID.json (root, read-only)
   +--> encrypted provenance manifest -> existing evidence outbox -> Azure WORM
```

The Mac is the trusted control plane and terminates the SSH connection to both
VMs. Gateway does not receive a reusable SSH credential for Research. The
streaming pipeline uses kernel/SSH buffers on macOS but does not create a local
archive or invoke an archive parser there.

### 4.1 Agent-visible directory contract

The agent-facing landing zone is predictable:

```text
/home/agent/research-workspace/repos/
  INDEX.json
  OWNER--REPOSITORY--COMMIT12--SOURCE_UUID/
```

`repos/` itself remains root-owned and non-writable by `agent`; each completed
repository directory beneath it is agent-owned and writable. This lets the
agent modify a work tree without renaming it, replacing `INDEX.json`, or
forging/removing another acquisition entry.

`INDEX.json` is a small canonical JSON document atomically regenerated by the
importer. For each completed import it provides the source UUID, canonical
repository, full commit SHA, import time, relative baseline/work-tree paths,
tree-manifest hash, and warnings. It is both the completion signal and the
agent-readable equivalent of `REPO_INFO`: the agent can check it with the Read
tool, and the operator should also announce a completed import in-session. No
polling or watcher capability is required.

The host-side `labctl sources` view does not traverse the agent's protected
home through the administrative SSH identity. It uses a typed, argument-free
`source-list` control operation that validates the root registry and public
index as protected regular files, requires their canonical content to match,
and returns only that bounded metadata. This preserves the `0750` agent-home
boundary while keeping operator discovery functional.

The index is created only after validation, durable local installation, and
confirmation that the encrypted provenance manifest reached the locked Azure
archive. A pending or failed import never appears in the index. The index is a
trusted local convenience view, but the root-owned registry and WORM manifest
remain authoritative.

The read-only baseline is also under the workspace so Claude can compare its
working edits to the original bytes without crossing the workspace boundary:

```text
/home/agent/research-workspace/baselines/SOURCE_UUID/
```

The approved launcher sets its working directory to
`/home/agent/research-workspace`, and the managed Claude policy sets
`blockReadsOutsideWorkingDirectories: true`. Both `repos/` and `baselines/`
therefore fall inside the intended read boundary. Deployment acceptance must
still prove this behavior with the live installed policy: Read succeeds in the
new repository and baseline, Edit succeeds only in the work tree, and both Read
outside the workspace and Edit of the baseline/index fail.

## 5. Plan semantics

Accepted repository syntax is one canonical ASCII form:

```text
OWNER/REPOSITORY
```

Owner and repository components must match a conservative GitHub-name grammar;
`.git`, schemes, ports, credentials, query strings, fragments, encoded
separators, whitespace, control characters, and Unicode are rejected. `REF` is
length-bounded printable ASCII. Neither value is interpolated into a shell
command.

The Gateway planner calls the GitHub REST API without authentication, validates
the response schema, and records:

- a random plan UUID;
- the canonical repository slug;
- the requested ref;
- the resolved full commit SHA;
- repository visibility and archive endpoint class;
- creation and expiry timestamps;
- policy version; and
- the approved endpoint-address set.

Only a root-owned plan file can reach the fetcher. `apply` accepts only a UUID,
not a URL, repository, ref, hostname, path, or size override. Once the plan is
claimed, failures do not make it reusable; the operator creates a new plan.

GitHub documents that public repository archives can be requested without
authentication. The implemented fetcher resolves the ref through the exact
`api.github.com` commit API, then constructs the documented, fixed-shape
`codeload.github.com` archive path for that exact SHA. Redirects are disabled;
every other origin, scheme, port, and path shape is rejected. Both HTTPS
connections use pinned global IPv4 addresses while retaining TLS SNI and
hostname verification.

References:

- [GitHub REST repository archive endpoint](https://docs.github.com/en/rest/repos/contents)
- [GitHub REST commit endpoint](https://docs.github.com/en/rest/git/commits)
- [GitHub REST API rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [GitHub source archive behavior](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)

## 6. Gateway enforcement

### 6.1 Components

- `source_controller.py`: root-only plan creation, state transitions, export,
  expiry, and cleanup. It never makes network connections.
- `source_fetcher.py`: network client running as a dedicated `source-fetcher`
  system user. It can read one claimed plan and write only its bounded spool.
- `source-fetch@PLAN_UUID.service`: fixed hardened one-shot systemd unit. The
  unit takes only a validated UUID and starts no shell.
- `/var/lib/secure-sandbox/source-acquisition/`: root-controlled plans,
  manifests, archives, and state with separate write permissions for the
  fetcher spool.

### 6.2 Network policy

Gateway remains non-forwarding and default-drop. Add a dedicated nftables set
and rule that allows only the `source-fetcher` UID to connect to pre-resolved
global IPv4 addresses for `api.github.com`, `codeload.github.com`, and
`registry.npmjs.org` on TCP/443.
No other UID receives this access.

Runtime DNS remains disabled. Endpoint addresses are resolved during an
explicit operator maintenance action, rejected unless global IPv4, written to
root-owned configuration, and incorporated into the rendered firewall and
policy hash. TLS hostname verification remains mandatory, so an IP allowlist is
not treated as proof of origin. Address rotation fails closed until the operator
refreshes and verifies the endpoint set.

The client uses the system trust store, TLS 1.2 or newer, SNI for the exact
approved hostname, hostname verification, fixed request headers, no proxy
environment variables, no cookies, no authentication, no retries to new
origins, and short connect/read/overall deadlines.

### 6.3 Initial resource limits

Proposed version-1 ceilings, held in root-owned policy rather than request
arguments:

- 256 MiB compressed archive;
- 1 GiB total expanded regular-file bytes;
- 100,000 archive entries;
- 64 MiB per regular file;
- 240 UTF-8 bytes per relative path;
- 32 path components;
- five minutes total fetch time; and
- two completed archives or 512 MiB of spool, whichever is reached first.

These are starting limits, not permanent limits. A real repository that exceeds
one should produce evidence for a reviewed policy revision; the agent cannot
raise a limit per call.

## 7. Research importer

`source_importer.py` is a root-owned, networkless program reachable only through
the role-bound `securectl` dispatcher. Its `stage` operation accepts a bounded,
SHA-256-bound framed stream on stdin and no repository-controlled command-line
arguments; `publish` accepts one validated UUID. Neither `labadmin` nor `agent`
has a passwordless sudo route to the importer.

The importer independently verifies the manifest, archive SHA-256, compressed
size, expanded limits, and every member before committing any files. It extracts
to a root-only temporary directory on the same filesystem and atomically
renames only after complete validation and evidence generation.

It rejects:

- absolute paths, `..`, empty components, NULs, controls, invalid UTF-8,
  Unicode formatting/bidirectional controls, and overlong paths;
- duplicate paths, case-fold collisions, and Unicode-normalization collisions;
- block/character devices, FIFOs, sockets, hard links, symbolic links, sparse
  members, unknown member types, setuid/setgid bits, and extended attributes;
- more than one archive root directory; and
- any archive or manifest mismatch.

Symbolic links are rejected even when their lexical target appears internal.
This deliberately sacrifices compatibility with repositories that contain
links: pathname-only validation cannot safely prove that a chain of archive
members will remain beneath the extraction root. Supporting links later
requires descriptor-relative extraction with kernel-enforced beneath-root
resolution, not a broader lexical allowlist.

Regular files are created non-executable. The manifest records GitHub's mode
metadata, but import does not grant execution merely because a repository marks
a file executable. Baseline directories/files are root-owned `0555`/`0444`.
The separate `repos/` work tree is agent-owned `0755`/`0644`. Neither contains
`.git` metadata. An atomic root-owned registry maps a source UUID to repository
hash, commit SHA, archive hash, tree-manifest hash, paths, timestamps, warnings,
and policy version. `repos/INDEX.json` is derived from that registry; the agent
does not supply any of its values.

New imports also publish a canonical root-owned per-entry integrity manifest.
The separately documented `verify_source` MCP tool validates that manifest
against the registry hash, recomputes the immutable baseline, and optionally
compares the writable worktree. See `SOURCE_INTEGRITY_DESIGN.md`. Imports made
before this extension remain usable but are reported as legacy/unanchored.

## 8. Git features intentionally absent

Version 1 is a commit-pinned source snapshot, not a full clone:

- commit history is absent;
- branches and tags cannot move the imported baseline;
- submodules are not recursively fetched;
- Git LFS is not separately contacted;
- release assets are not fetched;
- dependencies and package registries are not contacted; and
- pull requests from forks are not resolved specially.

If `.gitmodules`, `.lfsconfig`, or LFS pointer patterns are present, the
importer records a warning. It must not follow them. GitHub notes that archive
LFS behavior depends on repository settings and external LFS servers are not
included; the byte and expansion ceilings remain authoritative regardless.

History-aware research should become a separate, explicitly designed
capability (for example, an offline bundle plus a read-only history-query
broker), not a reason to add unrestricted `git` and egress.

## 9. Evidence and telemetry

Before making the work tree visible, Research creates a canonical provenance
manifest containing:

- source UUID and acquisition UUID;
- canonical repository slug and SHA-256 hash of that slug;
- requested ref and resolved commit SHA;
- archive ciphertext-independent SHA-256 and byte count;
- canonical extracted-tree manifest SHA-256, file count, and byte count;
- validation warnings and policy version; and
- Gateway fetch and Research import timestamps.

The manifest is age-encrypted with the existing public recipient and shipped
through the existing pinned mTLS, create-only Azure Blob, 30-day locked-WORM
path under a new `source-...age` namespace. The repository content itself is
not copied to Azure. Log Analytics receives lifecycle metadata only: source and
plan UUIDs, repository-slug hash, commit SHA, counts, sizes, policy version,
decision, and error class. It receives no source bytes, filenames, commit
message, branch/tag text, or repository URL.

Required events include `source_plan_created`, `source_fetch_started`,
`source_fetch_completed`, `source_fetch_failed`, `source_import_completed`,
`source_import_rejected`, `source_manifest_forwarded`, and
`source_manifest_blob_uploaded`. Denials, validation failures, evidence
failures, spool exhaustion, and policy drift alert. Expected rejection of a
malformed hostile archive is warning/deny telemetry; pipeline or evidence
failure is critical/deny and prevents publication of the work tree.

Host output is generated only from validated plan/registry fields and escapes
all terminal controls. `labctl` never prints a repository README, filename,
commit message, HTTP error body, response header, or other attacker-controlled
free text.

## 10. Operator experience

Example:

```text
$ ./scripts/labctl source plan example/sdk main
Plan:       3c...d2
Repository: example/sdk
Requested:  main
Commit:     PINNED_FULL_REVISION
Expires:    RFC3339_EXPIRY

$ ./scripts/labctl source apply 3c...d2
Source:     a1...9f
Baseline:   baselines/a1...9f
Repository: repos/example--sdk--0123456789ab--a1...9f
Index:      repos/INDEX.json
Evidence:   archived and verified
```

`source apply` refuses while another acquisition is active. It also refuses if
Gateway or Research policy hashes differ, telemetry/evidence services are not
healthy, available disk is below a configured reserve, the plan expired, or a
Claude run is active **unless live import is explicitly validated during
deployment**. The initial deployment should require no active Claude session;
later evidence may justify safe live imports.

The model can immediately read the new work tree after a successful import. It
still cannot refresh, fetch another ref, contact GitHub, or execute imported
files without a separate capability decision.

## 11. Deployment and acceptance gates

Acceptance covers plan validation, exact immutable resolution, one-time consumption, endpoint-specific egress, archive bounds, networkless import, provenance confirmation, atomic publication, crash recovery, rollback, and full boundary verification. Live repository names, revisions, source identifiers, cloud evidence, checkpoints, and test logs are retained in ignored local records.

## 12. Deferred extensions

Additional ecosystems require separate endpoint, manifest, integrity, extraction, and lifecycle-execution threat models.
