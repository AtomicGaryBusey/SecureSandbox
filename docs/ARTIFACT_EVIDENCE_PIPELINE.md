# Agent Artifact Evidence Pipeline

**Status:** Implemented design. Deployment state and acceptance evidence are private.
**Applies to:** Agent-authored reports in the SecureSandbox Research VM

## Purpose

Claude Code's dedicated Edit/Write tools can persist files even when Bash is denied. That is a useful tiered capability, but it means shell restrictions do not protect workspace integrity. An agent that can create a report can also revise or delete it later.

This pipeline preserves each stable report revision as independently verifiable, encrypted, off-host evidence without granting the agent shell, network, Azure, archive, or decryption access.

## Trust boundaries

```text
Agent / Edit tool
  writes mutable UTF-8 reports
        |
        v
/home/agent/research-workspace/reports
  agent-owned and intentionally mutable
        |
        v
root artifact-collector (networkless)
  validates, snapshots, hashes, age-encrypts
        |
        v
encrypted Research outbox
  inaccessible to agent; bounded to 256 MiB
        |
        v
conversation-shipper UID -> pinned mTLS -> Gateway TCP/9553
        |
        v
bounded Gateway ciphertext spool
        |
        v
add-only Entra identity -> locked Azure WORM container
```

The mutable workspace is not evidence. The first successfully archived snapshot is the evidence boundary. Each later content change creates another immutable version; it never replaces an earlier snapshot.

## Source contract

The collector accepts only direct children of the reports directory whose names:

- begin with an ASCII letter or digit;
- contain only ASCII letters, digits, period, underscore, or hyphen;
- end in `.md`, `.txt`, or `.json`; and
- are at most 132 characters including the extension.

Each accepted source must be:

- a regular file owned by the `agent` UID;
- a single-link file, preventing hard-link aliasing;
- between 1 byte and 4 MiB;
- valid UTF-8;
- unchanged for at least two seconds; and
- unchanged while its descriptor is read.

The collector opens the reports directory and file with no-follow semantics. Symlinks, directories, devices, FIFOs, sockets, hard links, binary data, unsafe names, oversized files, and changing files are rejected. Rejections generate metadata-only warning events and do not kill the session, preventing an agent-controlled malformed report from becoming a reliable denial-of-service primitive.

Nested directories are intentionally unsupported in the first release. This makes path handling and review unambiguous.

## Evidence format

The encrypted plaintext consists of one canonical JSON header, a newline, and the exact source bytes. The header schema is `secure-sandbox-artifact-v1` and contains:

- random UUIDv4 artifact ID;
- capture timestamp in UTC;
- sanitized source filename and media type;
- current SecureSandbox run ID, or `preflight` when no run is active;
- monotonically increasing version for that filename;
- source byte count and SHA-256; and
- schema identifier.

The resulting age ciphertext is named:

```text
artifact-ARTIFACT_UUID-VERSION-CIPHERTEXT_SHA256.age
```

The filename makes transport corruption detectable without decrypting content. After decryption, the operator tool validates the schema, UUID, filename, byte count, UTF-8 encoding, and source SHA-256 before rendering anything.

Artifact blobs use a distinct `artifact-` namespace in the existing `conversations` container. Conversation retrieval matches only run-ID-prefixed objects, so artifact blobs cannot be mistaken for Claude journal chunks.

## Identity and access

- The agent can modify only the source report directory.
- The collector runs as root solely to cross the agent-owned file boundary and signal Claude on trusted-pipeline failure.
- The collector has a private network namespace and sees the report directory read-only.
- The agent cannot read collector state, the encrypted outbox, transport keys, Azure credentials, or the age decryption identity.
- The Research transport identity can send only to the pinned Gateway archive receiver.
- The Gateway Azure identity can create new blobs but cannot list, read, overwrite, or delete them.
- The human operator has blob-reader access, not archive write or delete access.
- The Azure container has a locked 30-day time-based immutability policy.
- The age private identity remains only in the 1Password Agents vault.

## Fail-closed behavior

A trusted collector failure, encryption failure, state failure, or encrypted-outbox capacity failure:

1. removes the ready marker;
2. writes a persistent fatal marker;
3. emits a critical metadata event;
4. terminates an active Claude process; and
5. blocks subsequent `labctl claude` launches.

A separate systemd `OnFailure` unit applies the same fatal marker and termination behavior if the collector is externally killed or crashes before its own handler completes.

The shared transport and Gateway spool remain bounded. Temporary network or Azure outages retain ciphertext locally and do not expose plaintext.

## Observability

Only lifecycle metadata enters Log Analytics:

- `artifact_captured`
- `artifact_rejected`
- `artifact_capture_failed`
- `artifact_forwarded`
- `artifact_forward_failed`
- `artifact_received`
- `artifact_blob_uploaded`
- `artifact_blob_upload_failed`

Metadata can include run ID, artifact UUID or ciphertext digest, byte count, fixed classification, and status. Report content and filenames do not enter Log Analytics. Capture, forwarding, and upload failures are alertable security events.

## Operator workflow

List retained artifact snapshots chronologically:

```sh
./scripts/labctl artifacts
```

The listing shows timestamp, artifact UUID, version, source filename, correlated run ID, and source SHA-256.

Verify, decrypt, and safely render one snapshot:

```sh
./scripts/labctl artifact ARTIFACT_UUID
```

The renderer converts terminal control bytes, including ESC/OSC sequences, to visible escaped text. It never renders Markdown, follows links, loads remote images, or executes content.

## Security properties

The design provides:

- durable recovery of every observed stable report revision;
- detection of ciphertext and plaintext corruption;
- off-host retention after a compromised agent deletes or rewrites its workspace;
- confidentiality from Research, Gateway, Azure operators without the age identity, and Log Analytics;
- separation between file-write capability and shell/network capability; and
- fail-closed operation when the trusted capture boundary fails.

## Limitations

- A malicious agent can modify or delete a file before the collector's two-second stability window expires. Conversation/tool evidence remains the complementary record of attempted writes.
- A rapidly rewritten file may never become stable enough to snapshot.
- The collector proves what it observed, not authorship or factual correctness.
- The run ID is a correlation attribute, not part of the artifact identity.
- The first release accepts only top-level UTF-8 text reports up to 4 MiB.
- Azure immutability is time-bounded to the configured retention policy.
- The existing Azure container name remains `conversations` for compatibility even though it now contains two disjoint encrypted evidence namespaces.

These limits preserve a small, inspectable trusted computing base. Expanding formats, recursion, size, or retention requires a new threat-model and acceptance cycle.

## Rollback

The deploy is reversible without deleting archived evidence:

1. Stop and disable `artifact-collector.service`.
2. Remove the artifact collector and emergency unit from Research.
3. Restore the prior receiver/shipper/exporter binaries and policy hashes from the coordinated VM snapshot or deployment backup.
4. Remove the artifact preflight requirement from `labctl` only after the collector is intentionally retired.

Already uploaded blobs remain immutable until their retention period expires. Rollback cannot and should not remove evidence already captured.
