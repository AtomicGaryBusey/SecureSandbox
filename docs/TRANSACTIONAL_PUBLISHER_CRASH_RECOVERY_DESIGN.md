# Transactional Publisher Crash-Recovery Hardening

## Status

Implemented design. Live deployment state and acceptance evidence are private.

## Decision

Every durable publisher must leave either its predecessor or one complete,
self-consistent successor after process loss, power loss, restart, or a lost
response. Atomic rename is necessary but is not sufficient when one logical
publication spans multiple names or directories. Such publishers require a
durable transaction record, exact recovery identities, or an append-only
no-overwrite primitive whose restart behavior is independently verified.

Recovery never guesses from a familiar pathname. It validates type, owner,
mode, link count, immutable content binding, and—where an object may need to be
removed or advanced—its recorded device and inode. Unexpected replacement or
mixed state fails closed and remains available for operator diagnosis.

## Inventory and recovery contract

| Publisher | Durable boundary | Recovery contract |
|---|---|---|
| Source acquisition | baseline, agent worktree, integrity manifest, root registry, agent index | two-phase root journal; exact inode/device/owner roll-forward across every rename; substituted state rejected |
| Dependency orchestration | sealed bundle, bundle index, completed plan | precommitted bundle transaction; restart completes the exact index and plan without duplicate entries |
| CodeGraph indexing | sealed graph tree and agent-visible marker | per-source single writer; trusted abandoned builds removed; a sealed exact tree recreates only its matching marker |
| Review bundles | immutable bundle directory | `renameat2(RENAME_NOREPLACE)`, fsynced tree and parent, strict abandoned-temporary cleanup |
| Evidence and finding receipts | append-only receipt | fsynced temporary plus atomic no-overwrite hard link; trusted orphan cleanup and duplicate-content reuse |
| Conversation, artifact, and source evidence | encrypted outbox object and remote spool | fsynced no-overwrite publication, content-addressed remote idempotency, durable local consumption or quarantine |
| Gateway telemetry | bounded rotating append log | cross-process lock, fsynced record bytes, and fsynced directory after creation or rotation |
| Run lifecycle and execution approval | phase journals and one-shot records | canonical atomic records, monotonic phases, exact replay/receipt correlation, and restart reconciliation |
| Host releases, PKI, and VM maintenance | multi-system selector changes | precommitted transaction/checkpoint, exact successor identity, explicit recovery mode, and fail-closed ambiguity |
| Guest policy deployment | role-specific backups and install markers | backup before mutation, durable pending marker, idempotent recovery, and host-side cross-guest rollback journal |

## Source publication transaction

The source importer writes a `preparing` record before constructing any
publication temporary. A crash in this phase may remove only the exact expected
unpublished names with their expected owners. Once all three artifacts and both
registry successors are durable, the record advances to `prepared` and binds
each artifact's device, inode, owner, and type.

Recovery rolls those exact objects forward in a fixed order, accepts each
registry only in its exact predecessor or successor state, removes staging, and
then deletes the journal. The journal remains until staging cleanup is durable,
so the last crash window is also idempotent. A changed inode, foreign owner,
unexpected type, unrecognized registry, or impossible coexistence of temporary
and final names stops recovery without deleting either object.

## CodeGraph split-publication recovery

Index construction is serialized by a per-source lock. Restart removes only
root-owned build directories matching the exact source-specific temporary
grammar. If the sealed index exists without its marker, recovery validates the
source identity, toolchain identity, metadata encoding, and graph digest before
publishing the marker. A marker without its index, or any marker mismatch,
fails closed.

## Durability requirements

- Payload bytes are fully written and fsynced before publication.
- Every rename, link, unlink, rotation, or quarantine affecting durable state
  is followed by an fsync of each changed parent directory.
- Multi-object journals are themselves atomically replaced and directory
  fsynced before the first successor becomes visible.
- Recovery is idempotent at every durable phase boundary and never consumes a
  one-shot authority twice.
- Fault-injection tests model every publication boundary, including completion
  after the payload is visible but before its journal is removed.
- Recovery and live verification emit only fixed status and identity metadata;
  source, transcript, model, and credential content is never logged.

## Acceptance gates

1. Deterministic tests interrupt each source-publication rename and prove exact
   convergence without mixed registries.
2. Substituted finals, altered markers, symlinks, foreign state, and ambiguous
   temporary/final coexistence fail closed without deletion.
3. Dependency, evidence, conversation, review-bundle, PKI, lifecycle, host
   release, and VM-maintenance recovery suites remain green.
4. Gateway telemetry rotation, mTLS configuration replacement, and Research
   encrypted-outbox consumption fsync their changed directories.
5. The deployed Gateway and Research implementations pass a content-free live
   recovery verifier using isolated temporary state.
6. The complete boundary verifier and exact public-release gate pass for the
   same commit.

The reviewed deployment entry point is
`scripts/deploy-transactional-publisher-crash-recovery-ddd.sh`. Deployment
identifiers, exact live paths, timings, and transcripts remain in ignored local
evidence only.
