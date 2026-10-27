# Sealed review-bundle verification

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Problem

White-box DDD reviews are delivered as local bundles beneath the Research
workspace. GLM has intentionally been denied Bash and general command execution,
and the source verifier accepts only registered external sources. Asking GLM to
"verify `SHA256SUMS`" therefore encouraged an expensive and semantically wrong
fallback: copying each file into disposable execution merely to compute hashes.

Disposable execution is not a generic hashing service. Registering internal
review bundles as acquired third-party source would also blur two distinct trust
domains. The handoff needs its own narrow integrity primitive.

## 2. Decision

Publish future bundles in a fixed root-owned canonical directory and expose the
same inode tree through a read-only bind mount inside the workspace:

```text
/var/lib/secure-sandbox/review-bundles/BUNDLE_ID/
  == read-only view ==>
/home/agent/research-workspace/review-bundles/BUNDLE_ID/
```

Each bundle is immutable, root-owned, and contains a root-generated
`SHA256SUMS` plus a hash-bound `.bundle-id`. Extend the existing root-managed
`source_integrity` MCP with:

```text
verify_review_bundle(bundle_id="trusted-evidence-receipts-review")
```

The argument is an identifier ending in `-review`, never a path. The verifier
returns the manifest hash, file count, total bytes, and expected file inventory.
It returns no file content and provides no arbitrary hashing, execution, or
network capability.

## 3. Authority and publication

Only the root operator publisher may create a bundle. Publication is refused
while a run marker or Claude process exists. Input must be a private,
single-owner, non-writable staging tree directly below `/tmp`; symlinks,
hardlinks, devices, sockets, oversized inputs, reserved control filenames, and
ownership changes are rejected.

The publisher copies into a private root-owned temporary tree, hashes while
copying, fsyncs files and directories, makes the tree read-only, and uses Linux
`renameat2(RENAME_NOREPLACE)` for atomic publication. Existing identifiers are
never replaced. A bounded pre-publication scan removes only strictly named,
root-owned crash temporaries and fails closed on every unexpected entry. The
canonical parent and published bundle remain root-owned and non-writable.

The workspace view is a root-managed `ro,nosuid,nodev,noexec` bind mount of the
canonical tree. The verifier reads the canonical root, while GLM reads the same
inodes through the mount. The agent-owned workspace parent therefore cannot
swap a different tree beneath a previously verified identifier.

## 4. Verification contract

Verification fails closed unless all of the following hold:

- the identifier matches the fixed grammar and resolves only under the review
  root;
- the review root, bundle, and nested directories are root-owned and not
  group/world writable;
- every entry is a regular file or directory; symlinks and special files are
  rejected;
- every file is root-owned, non-writable, single-linked, size-bounded, and
  unchanged while read;
- `SHA256SUMS` is strict UTF-8, sorted, duplicate-free, path-safe, and bounded;
- `.bundle-id` is included in the manifest and binds the directory name;
- the actual file and directory inventory exactly equals the manifest-derived
  inventory; and
- every file digest matches; and
- the boundary suite confirms the canonical root and workspace view have the
  same device/inode identity and that the mounted view is read-only.

The initial limits are 128 manifest entries, 4 MiB per file, 32 MiB total, 64
KiB for the manifest, 240 UTF-8 bytes per relative path, and sixteen path
components.
Publication is capped at 64 retained bundles and 64 crash temporaries; reaching
either root-directory bound fails closed rather than allowing an unbounded scan
or silently deleting a completed review bundle.

## 5. Evidence semantics

A successful result establishes that the bytes GLM can read match the sealed
operator-published review bundle. It does not establish that the reviewed code
is deployed, correct, safe, complete, or equivalent to production. The review
must continue to distinguish source inspection from live verification.

This result is review-handoff evidence, not a Trusted Evidence Receipt and not
finding evidence. It must not be accepted by the findings broker as a substitute
for exhaustive-search or measured-execution receipts.

## 6. Telemetry and disclosure

Telemetry contains only the bundle identifier, manifest SHA-256, fixed status,
and file count. Filenames and file contents remain local. Bundle identifiers
must be non-sensitive. Actual vulnerability reports remain confined to the
ignored `vulnerability-reports/` path and must never be included in a review
bundle destined for either source-code remote.

## 7. Acceptance gates

Before deployment, require unit tests for successful publication and
verification; identifier/path rejection; missing, added, modified, relabelled,
symlinked, hardlinked, writable, oversized, and malformed content; no-overwrite
publication; MCP argument narrowing; and content-free telemetry.

Acceptance requires deployment of the root-managed files, a sealed canary or
real review bundle, first-person verification through a fresh restricted GLM
session, confirmation that direct agent mutation fails, the complete
Research/Gateway/host suites and boundary checks, and inclusion in the next
cold-boot acceptance cycle.

The privileged deployment dispatcher deliberately gives installers a private,
non-propagating mount namespace for staged `/tmp` content. The installer and
rollback must therefore perform every canonical/view directory operation and
mount postcondition in PID 1's mount namespace. Acceptance covers both a fresh
mount and an idempotent redeployment over an already-active read-only mount.

## 8. Acceptance and repair evidence

Live bundle identifiers, manifests, policy hashes, review reports, deployment generations, and checkpoint data are retained in ignored local records. Acceptance includes immutable canonical storage, a root-managed read-only mount, exact manifest verification, agent mutation denial, rollback coverage, and fresh-session verification.
