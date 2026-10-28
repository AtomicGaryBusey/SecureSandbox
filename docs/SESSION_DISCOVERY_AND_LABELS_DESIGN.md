# Session Discovery and Labels

## Problem

The original `labctl sessions` command emitted only a Claude session UUID and
its earliest journal timestamp. That was sufficient to enforce resume
membership, but not sufficient for an operator choosing among many durable
research conversations. Guessing a UUID risks resuming the wrong context and
turns ordinary continuity into an archive-forensics exercise.

Session discovery must become useful without weakening the existing content
boundary. In particular, user prompts and generated titles must not be copied
into the root-owned, world-readable Research registry or ordinary control-plane
audit output.

## Trust boundaries

Research journals are agent-owned evidence, not an authorization authority.
The root session registry continues to admit a UUID only after finding a
bounded journal record with all of the following:

- a canonical session UUID;
- the exact Research workspace path;
- the CLI entrypoint; and
- a regular journal file owned by the unprivileged agent.

The registry publishes only content-free observations:

1. earliest admitted creation timestamp;
2. latest parseable record timestamp;
3. count of human-shaped user message records;
4. count of explicit compaction markers; and
5. count of Claude journal `mode` records, reported as launch markers.

These counters help identify a conversation but do not attest that every
record is truthful. Resume admission remains membership-only and does not
depend on any counter.

## Privacy-preserving labels

Labels are explicit operator annotations. SecureSandbox never derives them
from prompt or response text. They are stored on the Mac at:

```text
~/Library/Application Support/SecureSandbox/session-labels.json
```

The catalog and its dedicated parent directory are owned by the invoking Mac
user with modes `0600` and `0700`. Symlinks, linked files, wrong ownership,
wrong mode, malformed UUIDs, control characters, and oversized labels fail
closed. Writes use a same-directory temporary file, `fsync`, atomic rename,
and directory `fsync`.

The label catalog is not part of the repository, guest filesystem, encrypted
conversation archive, or publication process.

## Operator interface

```bash
./scripts/labctl sessions
./scripts/labctl session label SESSION_UUID "Bug finding and DDD review"
./scripts/labctl session unlabel SESSION_UUID
```

The listing columns are session UUID, creation time, last activity, user turns,
compactions, launch markers, and the private label. During a rolling deployment
the host renderer accepts the prior two-column registry and displays unknown
metadata. This preserves operator access while the active Research run drains.

The hardened launcher and root supervisor retain their existing compatibility:
they accept a resume only when a registry line begins with the exact UUID and a
tab. Appending metadata cannot broaden that membership test.

## Bounds and failure behavior

- At most 10,000 journal files and 1,000,000 records are inspected.
- Individual journal files remain limited to 64 MiB and lines to 1 MiB.
- Host registry rendering is limited to 8 MiB.
- Counters must be nonnegative decimal integers no greater than 1,000,000.
- Invalid guest rows or an untrusted label catalog abort the entire listing.
- Tool-result-only user records are not counted as human turns.
- Labels are never accepted as evidence, identity, or authorization input.

## Deployment and acceptance

`deploy-session-discovery-ddd.sh` requires idle Research admission, installs
only the reviewed registry implementation through the typed privileged control
plane, refreshes the registry, compares its live SHA-256 to the repository
source, and renders the live catalog.

Acceptance requires:

1. unit tests for bounded discovery, counter semantics, legacy rendering,
   label privacy, atomic persistence, and untrusted-file rejection;
2. exact live registry hash equality;
3. enriched live metadata for historical sessions;
4. preservation of resume membership checks;
5. a full boundary verification after deployment; and
6. publication and secret checks before both remote pushes.
