# Disposable Fixture Execution

## Status

Version 1 is implemented. Deployment state and acceptance evidence are private.
It deliberately supports only bounded Python fixture experiments. JavaScript, package installation, source
builds, browsers, Internet access, and arbitrary shell commands remain out of
scope until a measured research need justifies a separate review.

## Purpose

Static review can identify a plausible path but cannot reliably measure
default-config reachability or distinguish a theoretical sink from an
exploitable behavior. This capability lets the research agent run a small,
non-destructive Python experiment against explicitly selected files from one
registered immutable source.

It is not a general terminal and it does not execute a repository checkout.

## Boundary

```text
Claude Code
  -> managed MCP tool (configured operator-confirmation prompt)
  -> root-managed Research execution broker
  -> isolated lab subnet, fixed Target address/port
  -> authenticated Target execution service
  -> one new rootless Docker container
  -> no network, read-only rootfs, bounded read-only fixture mount
```

The Claude permission prompt is an important human-control surface, but it is
not treated as the containment boundary. An agent that somehow calls the local
broker directly still receives only the same fixed runtime, resource limits,
registered-source fixture validation, and networkless disposable container.

## Request contract

The sole v1 tool is `run_python_fixture`:

- `source_id`: one registered source UUID with a verified import manifest;
- `code`: UTF-8 Python, at most 24 KiB;
- `fixture_paths`: zero to 16 repository-relative regular files, at most 1 MiB
  total, each re-hashed against the immutable import manifest;
- `timeout_seconds`: integer from 1 through 10, default 5.

The request cannot name an arbitrary host path, image, executable, command,
environment variable, mount, network, user, Docker option, or output file.
Fixtures come from the immutable baseline, never the writable worktree.

## Target runtime

The Python image is built offline from the already installed Target guest
interpreter and standard library. The image contains no shell, package manager,
network client, credentials, Docker socket, or source repository. Its immutable
image ID is recorded in the service configuration and checked before each job.

Every request creates a new container with:

- rootless Docker;
- `--network none`;
- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- the default Docker seccomp profile;
- non-root UID/GID 65532;
- one CPU, 256 MiB memory/no swap, 64 PIDs;
- a 16 MiB `noexec,nosuid,nodev` tmpfs at `/tmp`;
- a read-only mount containing only `main.py` and selected fixtures;
- an external wall-clock timeout and forced removal by a controller-generated
  container name.

The Target has no default route, IPv6, forwarding, or allowed outbound
connection. Container network isolation is therefore an inner layer, not the
only layer.

The controller service must remain in the rootless Docker daemon's mount
namespace: on this Ubuntu build, systemd mount-namespace options such as
`ProtectSystem`, `ProtectHome`, or `PrivateTmp` make the rootless socket reject
the otherwise same-UID client. The service retains `NoNewPrivileges`, address-
family restriction, and execute-memory denial, while the per-job container and
outer Target VM provide the stronger runtime boundary. This measured platform
constraint is explicit rather than silently disabling Docker rootlessness.

## Authentication and network policy

The Target service accepts requests only from Research on TCP/8080 and requires
a random bearer capability generated at deployment. The capability is stored
only in root-controlled Research broker configuration and the Target service's
private configuration. It is never placed in the agent environment or tool
result.

Research firewall policy removes direct agent access to Target TCP/8080 and
grants it only to the dedicated `execution-broker` UID. The agent can still
reach the broker on loopback, but cannot widen its destination or protocol.

## Output and evidence

Target returns bounded base64 fields, never terminal text. Research decodes at
most 64 KiB per stream and JSON-escapes control characters before presenting
them as explicitly untrusted execution output. The result contains exit state,
timeout state, truncation flags, SHA-256 digests, duration, runtime image ID,
source ID, code digest, and fixture-manifest digest.

Metadata-only journal events cover accepted, completed, rejected, timed-out,
and internal-error states. No source, code, stdout, or stderr content is sent to
Azure. Conversation capture separately preserves what Claude and the operator
saw.

## Abuse resistance

- one execution at a time;
- conservative per-process request throttling;
- fixed maximum body sizes at every hop;
- a three-second absolute deadline for complete local HTTP request framing,
  including headers and body, so stalled or slow-drip clients cannot starve the
  serialized broker;
- a finite client-socket write deadline so a caller that stops reading cannot
  starve later requests while the broker emits a bounded result;
- fail closed on manifest drift, image mismatch, Target authentication failure,
  malformed output, cleanup failure, or unavailable telemetry prerequisites;
- no persistent container, writable volume, or job directory after completion;
- no secrets or provider credentials on Target.

This limits blast radius but does not make hostile native-runtime behavior
risk-free. Python can invoke kernel interfaces through its standard library and
`ctypes`; Docker, the Target kernel, and the outer Parallels VM therefore remain
meaningful independent boundaries. Kernel/container escape research must use a
separate disposable Target generation, never this convenience runner.

## Acceptance gates

1. unit tests for schema, path, manifest, output, and resource-limit handling;
2. transport tests proving stalled bodies, slow-drip bodies, incomplete
   headers, and non-reading clients cannot monopolize the serialized broker;
3. fixed image-ID and no-shell inspection;
4. happy-path marker calculation against a registered source fixture;
5. proof that network access, arbitrary paths, excessive output, timeout, fork
   pressure, writable rootfs, and direct agent-to-Target access are denied;
6. telemetry presence without content leakage;
7. complete boundary suite;
8. cold boot and coordinated checkpoint before representing the feature as a
   durable baseline.

Live gate results, review reports, and checkpoint identifiers are retained in
ignored local acceptance records.

## Deferred work

- JavaScript requires a separately acquired, digest-pinned runtime image.
- Default-config reachability over CodeGraph is a static-analysis feature, not
  part of this execution service.
- Cross-source diff is already delivered by Corpus Intelligence v2.
- Dependency orchestration and structured findings remain separate DDD cycles.
