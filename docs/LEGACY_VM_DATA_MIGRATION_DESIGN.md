# Legacy VM Data Migration and Continuity

## Purpose

Fresh-VM restoration rebuilds SecureSandbox controls; it does not migrate the
historical contents of the replaced guests. The quarantined VM generation is
therefore retained until this workflow has preserved, verified, and selectively
imported the data needed to continue the existing GLM/Claude Code work.

The migration has two distinct products:

1. a complete, immutable preservation archive of every in-scope legacy data
   surface; and
2. a narrow continuity import containing only agent workspace data and Claude
   journals that can safely coexist with the rebuilt Research guest.

Preservation is not publication. These archives can contain vulnerability
reports, source material, prompts, credentials accidentally written by an
agent, and other confidential data. They remain below `.private/`, mode 0700,
and are forbidden from Git.

## Non-negotiable deletion gate

No quarantined VM may be deleted until all of the following are true:

- the original bundle remains stopped and byte-for-byte untouched;
- extraction ran from a copy-on-write working clone, never the original;
- Research, Gateway, and Target preservation archives have independently
  verified manifests and archive digests;
- every regular file in scope is represented by path, size, mode, ownership,
  modification time, and SHA-256; symlinks are recorded without traversal;
- unsupported file types and unreadable paths are explicit manifest records,
  not silently omitted;
- the Research continuity import has a disposition for every preserved path;
- every legacy Claude session UUID is visible to the rebuilt root-owned
  session registry and a selected session resumes successfully;
- reports and other agent-created materials match their preserved hashes;
- Gateway conversation/artifact queues and archives have either been imported
  into a non-authoritative legacy namespace or proved present in the locked
  external archive;
- the preservation set exists in at least two independently readable places;
  and
- the operator explicitly approves retirement after reviewing the final
  deletion-gate report.

Passing the ordinary containment verifier is not evidence that historical data
was migrated.

## Threat model

Legacy guests contain adversary-influenced files and pre-remediation system
state. Their files, metadata, archives, indexes, reports, and journals are
untrusted input. A compromised legacy guest must not be able to:

- modify its quarantined source bundle during extraction;
- obtain network access while being inspected;
- overwrite current conversations or reports;
- restore obsolete executables, services, policy, PKI, credentials, lease
  state, or authorization state into the rebuilt guests;
- escape an archive through absolute paths, `..`, symlinks, hard links,
  devices, FIFOs, or sockets;
- hide data through races or unsupported file types;
- cause an incomplete export to be labelled complete; or
- make deletion eligibility depend only on file counts or archive existence.

## Source handling

The quarantined bundles under `.private/vm-quarantine/GENERATION/` are evidence
and rollback assets. They are never registered, booted, renamed, compacted,
mounted read-write, or edited directly.

For each role, the host creates an APFS copy-on-write clone of the legacy hard
disk in a transaction-specific ignored directory. It records the source
bundle's canonical path, device/inode identity, UUID, configuration hash, disk
descriptor hashes, and allocated-byte count before cloning. The legacy VM and
its operating system are never booted: a compromised legacy root must not be
allowed to mediate the export.

The cloned disk is attached temporarily as a non-boot data disk to the rebuilt
Research guest through the reviewed host-maintenance coordinator. This is a
cold attachment: Parallels 27 can accept a running SATA configuration update
while recording `PRL_ERR_VM_APPLY_CONFIG_NEEDS_REBOOT`, in which case the guest
never sees the disk. The coordinator therefore stops rebuilt Research, attaches
the clone as the sole secondary disk, and re-proves that the fixed boot order is
only `hdd0` and that `hdd0` still resolves to the expected fresh system disk
before starting the transport guest. A successful host configuration update is
not treated as evidence of guest-visible attachment.

The current guest verifies the expected disk topology, first switches the
non-root parent block device read-only with `blockdev --setro`, verifies both
disk and partition report `RO=1`, and only then mounts its Linux filesystem
with `ro,noload,nodev,nosuid,noexec`. Any writable block device or unexpected
mount topology is rejected. A bounded, identifier-free topology diagnostic
distinguishes missing disks from direct, LVM, or encrypted layouts without
exposing operator-chosen device or volume names. The exporter runs from current
root-owned code, not code stored on the legacy disk. Attachment, boot, mount,
unmount, shutdown, and detach are one journaled transaction; an incomplete
detach blocks subsequent acceptance.

Research preservation has one additional continuity copy. Before its verified
archive is streamed back to the host, the rebuilt guest atomically publishes a
root-owned, mode-0600 copy below
`/var/lib/secure-sandbox/legacy-migration/`. The continuity importer consumes
that protected copy directly, so a large confidential archive never needs to
pass through an agent-writable staging directory or a relaxed control-plane
payload limit. Gateway and Target archives are streamed to host-private
storage and are not activated in any guest.

Unexpected source identity changes, a running source VM, registration of the
source bundle, insufficient free space, a writable legacy mount, or inability
to prove the temporary disk was detached rejects the operation.

Capacity checks use an upper bound rather than the expected gzip ratio. The
bound includes all regular bytes plus per-path and fixed archive overhead; it
is doubled for Research because the verified archive temporarily exists both
inside the rebuilt Research disk and in host-private storage. Research also
reports its own destination free space before export. Both sides retain a
two-GiB reserve, so low disk stops the operation before it begins writing the
archive.

## Preservation surfaces

The first inventory is deliberately broad so future discoveries do not reveal
that an unanticipated agent artifact was discarded.

Research:

- `/home/agent` in full, including Claude journals, workspace files, reports,
  memory history, and tool-created content;
- `/var/lib/secure-sandbox` in full, including encrypted conversation and
  artifact outboxes, review bundles, findings, receipts, registries, and
  indexes; and
- `/var/log/secure-sandbox` when present.

Gateway:

- `/var/lib/secure-sandbox` in full, including conversation spool/archive
  state, telemetry state, leases, source acquisition state, and PKI history;
  and
- `/var/log/secure-sandbox` when present.

Target:

- `/var/lib/secure-sandbox`, `/var/log/secure-sandbox`, and `/home/labadmin`
  when present. Target is expected to hold less continuity data, but it is not
  assumed empty.

`/etc`, `/run`, `/proc`, `/sys`, `/dev`, and service private keys are not
restored. Configuration needed for forensic explanation is captured only by
an explicit metadata collector and is never activated on the rebuilt guests.

## Archive format

`legacy-guest-export.py` runs as root inside an isolated working clone. It
walks only the fixed roots for the declared role, never follows symlinks, and
does not cross into unexpected mount points. It emits a gzip-compressed POSIX
tar stream whose payload paths are namespaced by role and source path. A
canonical JSON manifest is the final member.

Regular files are opened with `O_NOFOLLOW`. Device/inode/type/size/mtime are
checked before and after streaming, and the manifest digest describes the
exact streamed bytes. Directories and symlinks are represented explicitly.
Sockets, devices, and FIFOs are recorded as omitted special files. Any read
failure or mutation rejects the archive. Bounds apply to path count, path
length, individual file size, and cumulative bytes.

The host verifier treats the tar as hostile. It permits one canonical
manifest, rejects duplicate names and unsafe paths, hashes every payload member
without extraction, and requires an exact one-to-one match with the manifest.
It then writes a separate host receipt binding the archive hash, manifest hash,
legacy VM identity, role, counts, and byte totals.

## Continuity import

Import is not a filesystem restore. A root-owned importer in rebuilt Research
accepts only a host-verified preservation receipt and applies these classes:

- Claude journals below `/home/agent/.claude/projects`;
- agent-authored workspace files below
  `/home/agent/research-workspace`, excluding managed roots; and
- report files below `/home/agent/research-workspace/reports`.

Managed roots such as `repos`, `baselines`, `source-manifests`,
`corpus-indexes`, `codegraph-indexes`, `dependency-bundles`, and
`review-bundles` are archive-only unless their current owning verifier provides
a dedicated import operation. Root state under `/var/lib/secure-sandbox` is
also archive-only by default. Old PKI, leases, active markers, service state,
executables, configuration, and credentials are never imported.

Agent-control files are archive-only at every workspace depth. This includes
`CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json`, and
content below `.claude`, `.git`, or `.cursor`. Historical instructions,
hooks, MCP definitions, repository metadata, and native agent memory are
preserved for review but can never silently become active in the rebuilt
environment.

An absent destination may be created with constrained ownership and mode.
Imported files are always non-executable mode 0600 and newly created
directories are mode 0700; legacy permission bits are evidence, not activated
state. Existing directories are not chmod/chowned from legacy metadata. An
existing identical file is accepted without rewriting. An existing different
file is never overwritten: the plan records the conflict and blocks the import
while the legacy bytes remain available in the immutable preservation archive
for explicit operator adjudication. Journal filename UUIDs must be canonical,
and journal records must parse as bounded JSON lines before becoming
resumable.

After import, the root-owned session registry is rebuilt from one successful
discovery snapshot. The imported and current UUID sets, per-session hashes,
report hashes, conflict dispositions, and archive-only dispositions form the
continuity evidence. The compact receipt names every imported session UUID and
binds the complete disposition list and report-evidence set by SHA-256. It also
binds a canonical scope inventory for Claude conversations, captured
conversations, workspace material, reports, scripts, review material, native
memory, memory proposals, findings, evidence receipts, and related broker
state. Each scope entry carries its record count, regular-byte count, and a
digest of the exact manifest records; the overall scope digest is carried into
the operator's later GLM-continuity receipt. This provides positive evidence
that authority-bearing memory/finding state was preserved without silently
reactivating it. Each
imported journal must itself contain a matching CLI session record for
`/home/agent/research-workspace`; merely having a UUID-shaped filename and
parseable JSON is insufficient.

## Implemented safety primitives

The migration implementation currently includes:

- a read-only plan that binds the quarantine generation, legacy VM UUIDs,
  configuration and disk-descriptor hashes, every disk-chain file's bytes and
  metadata, current Research VM identity, tool hashes, and Parallels CLI. Free
  space is displayed but deliberately excluded from the stable plan digest;
  it is re-measured and enforced immediately before every archive stream;
  Research guest capacity conservatively covers both its retained verified
  archive and an archive-sized continuity import, plus the fixed reserve;
- strict disk-descriptor validation that rejects entities, path traversal,
  absolute extent references, and any mismatch between referenced and present
  `.hds` files before Parallels is allowed to parse a cloned disk;
- a guest preserver that requires an idle agent lifecycle, selects exactly one
  unmounted non-root ext4 partition, verifies the read-only mount options, and
  cannot return success unless unmount succeeds;
- a bounded exporter and a hostile-archive verifier that hold one
  `O_NOFOLLOW` file identity across hashing and parsing;
- a continuity planner that imports only canonical session journals and
  unmanaged workspace files;
- a streaming importer that walks destinations by directory descriptor,
  validates bounded JSON lines, publishes with an atomic no-replace hard-link,
  accepts identical files, and rejects conflicts; and
- a deletion-gate evaluator that cannot delete and remains `preserve` until
  preservation, import, live resume, redundancy, and explicit retirement
  receipts all bind the same archive hashes.
- a crash-recoverable host orchestrator that journals before cloning, creates
  an APFS working clone, cold-attaches only that exact clone as `hdd1` to
  stopped rebuilt Research, revalidates the fixed `hdd0` boot identity before
  startup, streams and verifies each role archive, imports Research continuity,
  and proves shutdown, detach, and exact-inode clone cleanup; and
- an attributed authorization operation whose operator display binds the
  legacy generation, all source and transport VM identities, full source disk
  hashes, Parallels CLI, protected transport configuration, and every mutable
  migration tool. The display names the planner and executor hashes and a
  canonical digest of the complete tool set rather than leaving those bindings
  hidden behind the request digest. No live mutation is
  permitted until that plan is explicitly approved.

Each preservation receipt binds the verified archive and manifest hashes to
the creating authorized plan, quarantine generation, legacy VM UUID,
configuration and disk-descriptor hashes, full disk-chain content hash, and
the rebuilt Research VM used for inspection. A later independently authorized
resume may reuse that immutable archive only after re-verifying every stable
archive, source, and transport binding; the creating plan hash remains intact
as provenance while the resume is separately bound to its current plan and
tool hashes. Once all roles verify, the resume writes a preservation-set
receipt binding all three archive hashes, their distinct creating-plan hashes,
the source disk-chain hashes, and the current authorized resume plan. A valid
archive from a prior attempt is never reused as evidence for a newly attached
clone.

## Operator runbook

These commands are intentionally split into distinct ceremonies. The first
deploys the reviewed coordinator into the protected host release. The second
is a prompt-free, read-only plan. The third starts and stops only the rebuilt
Gateway and Research VMs, creates disposable APFS clones of legacy disks, and
requires its own attributed authorization.

While no agent run is active, deploy the reviewed host release:

```sh
cd /path/to/SecureSandbox
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent Codex \
  --requesting-session legacy-continuity-migration-ddd \
  --purpose "Deploy the reviewed legacy continuity preservation coordinator"
```

Review a fresh plan without an authorization prompt:

```sh
python3 scripts/vm-operation.py preserve-legacy \
  --generation 20261021T040946Z
```

Apply exactly that freshly recomputed plan:

```sh
python3 scripts/vm-operation.py preserve-legacy \
  --generation 20261021T040946Z \
  --apply \
  --requesting-agent Codex \
  --requesting-session legacy-continuity-migration-ddd-live \
  --purpose "Preserve legacy VM data and import verified GLM continuity state"
```

If the host, Parallels, or terminal exits mid-run, do not improvise cleanup.
Run the prompt-free plan again. It reports `operation: recover` when a bound
transaction exists. Re-run the same `--apply` form and approve the recovery
ceremony; recovery detaches only the recorded clone, removes only its recorded
inode and temporary archive, and leaves all quarantined originals untouched.
If a crash happened after an archive rename but before its receipt, recovery
discards that unreceipted derivative and regenerates it from the preserved
source; it never retroactively asserts source provenance for unexplained
bytes.
Then plan and apply once more to resume preservation.

At any point, confirm the fail-closed retirement posture:

```sh
python3 scripts/legacy-migration-status.py \
  --generation 20261021T040946Z | python3 -m json.tool
```

After the import succeeds, list the imported sessions and resume one of the
legacy UUIDs in the normal GLM/Claude Code interface:

```sh
./scripts/labctl sessions
./scripts/labctl claude --resume LEGACY-SESSION-UUID --lease-profile extended
```

Only after GLM has
first-person access to the expected conversation context and reports, record
that observation interactively:

```sh
python3 scripts/record-legacy-continuity-acceptance.py \
  --generation 20261021T040946Z \
  --session-id LEGACY-SESSION-UUID \
  --confirm-session-resumed \
  --confirm-reports-verified \
  --confirm-context-verified
```

Copy all three verified archives to separately administered storage whose loss
is independent of the Mac's internal disk. The second-copy directory must
contain exactly the expected `gateway.tar.gz`, `research.tar.gz`, and
`target.tar.gz` paths (unrelated files are ignored). Then create the redundancy
receipt with a separate interactive attestation:

```sh
python3 scripts/verify-legacy-redundancy.py \
  --generation 20261021T040946Z \
  --copy-root /path/on/independent/storage/20261021T040946Z/archives \
  --confirm-separate-failure-domain
```

This verifier does not create the copy. It requires a distinct mounted
filesystem, hashes both copies byte-for-byte, and records that the operator
attested a separate failure domain. The status evaluator re-hashes the second
copy every time it evaluates deletion eligibility. An unmounted, missing, or
changed second copy therefore closes the gate again; a stale receipt alone is
not sufficient.

Only after the status command reports that the sole remaining failed gate is
`operator_retirement_approved`, the operator may record a separate retirement
decision:

```sh
python3 scripts/record-legacy-retirement-approval.py \
  --generation 20261021T040946Z \
  --confirm-glm-continuity \
  --confirm-independent-backup \
  --confirm-retirement-understood
```

The command independently re-evaluates every technical gate, re-hashes the
three primary archives, requires a TTY and exact typed phrase, and writes a
mode-0600 approval receipt. It does not delete, unregister, move, or modify any
VM. There is deliberately no automatic deletion step.

The expected status remains `preserve` after the byte migration. It cannot
become `eligible` until fresh-VM restoration is complete, GLM has resumed a
legacy session and verified its context, a second independent archive copy is
verified, and the operator supplies a separate explicit retirement approval.
No command in this runbook deletes a quarantined VM.

## Acceptance

Acceptance has three levels:

1. **Preserved**: all three archives and manifests verify independently.
2. **Imported**: every Research record has an explicit imported, identical,
   conflict, archive-only, or rejected disposition; rejected records block
   deletion.
3. **Continuous**: the expected legacy session UUIDs appear in `labctl
   sessions`, the operator resumes the chosen GLM session, and GLM confirms
   first-person access to its reports and expected working context.

Only `continuous`, two-copy preservation, and explicit operator approval make
the legacy VM generation eligible for deletion. Eligibility is a report, not
an automatic delete operation.

