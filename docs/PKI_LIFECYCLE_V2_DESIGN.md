# Transactional PKI Lifecycle v2

Status: implementation contract

## Purpose

SecureSandbox's original certificate rotation renewed the three Research leaf
certificates under the existing Gateway CA. It did not rotate private keys, the
Gateway server identity, or the CA, and a host or guest failure between its
sequential mutations could leave the two VMs with incompatible trust state.

PKI Lifecycle v2 treats the complete mTLS identity set as one generation and
changes generations through a durable, resumable transaction. The safety goal
is stronger than successful rotation: after every committed phase, including a
crash boundary, the Research-to-Gateway control paths remain authenticated and
usable by at least one complete generation.

## Trust and threat model

The protected identities are:

| Role | Private-key home | Required certificate properties |
| --- | --- | --- |
| Gateway CA | Gateway | Ed25519, critical `CA:TRUE,pathlen:0`, keyCertSign/cRLSign |
| Gateway server | Gateway | Ed25519, serverAuth, IP `172.30.10.1`, DNS `secure-sandbox-gateway` |
| Broker client | Research | Ed25519, clientAuth, fixed broker subject |
| Telemetry client | Research | Ed25519, clientAuth, fixed telemetry subject |
| Conversation client | Research | Ed25519, clientAuth, fixed conversation subject |

Private keys never leave their owning VM. Research exports only CSRs. Gateway
exports only public certificates and CA bundles. The host coordinates the
transaction and holds the expected-generation anchor, but never receives a
private key.

The design protects against interrupted deployment, partial transfer, stale or
replayed transaction files, symlink substitution, malformed certificates,
wrong certificate roles, mismatched public/private keys, unbounded state, and
rollback of both VMs to a mutually consistent but obsolete snapshot. It does
not claim protection after compromise of Gateway root, Research root, or the
host administrator account.

## Generation identity and manifests

Each rotation has a lowercase UUIDv4 `generation_id`. Gateway creates a
canonical JSON manifest after all five certificates exist. It contains:

- schema version and generation ID;
- UTC creation, not-before, and not-after epochs;
- DER SHA-256 fingerprints for the CA, server, and three clients;
- SHA-256 SubjectPublicKeyInfo hashes for the same five identities;
- unique certificate serial numbers;
- a SHA-256 hash of the canonical manifest body.

The manifest contains no private material and no workload content. Both guests
store the same byte-identical manifest at
`/etc/secure-sandbox/pki-generation.json`, owned by root and mode 0644. A
generation is active only when installed identities match every fingerprint,
public-key hash, role, name/SAN, issuer, and validity bound in that manifest.

The host stores the generation ID and manifest SHA-256 in the root-controlled
host-controller state tree. Boundary verification requires equality across the
host anchor, Gateway manifest, and Research manifest. This makes a coordinated
VM snapshot rollback visible unless the host anchor is deliberately rolled
back by an administrator as well. Every Claude launch verifies both guests'
active generations against this anchor before it issues a run lease, so the
check is an enforced launch boundary rather than an operator-only diagnostic.

## Durable state

Each guest uses `/var/lib/secure-sandbox/pki-lifecycle`, root:root mode 0700:

- `transactions/<generation>.json`: canonical phase journal, mode 0600;
- `generations/<generation>/`: immutable staged or retired generation data;
- `.lock`: a flock target serializing prepare, apply, recover, and inspect.

State enumeration is bounded to 16 transactions and 8 retained generations.
Unexpected files, links, owners, modes, overlong JSON, duplicate generations,
or non-monotonic phase transitions fail closed. Files are created through a
same-directory temporary file, `fsync`, `rename`, and parent-directory `fsync`.
The journal advances only after the corresponding filesystem and service
postcondition is verified.

The host coordinator keeps a content-free transaction record in the existing
root-controlled host-controller state tree. Re-running rotation with the same
generation resumes; starting another generation while one is pending is
rejected.

## Transaction phases

The only forward phase order is:

1. `prepared`: Gateway has a new CA and server identity; Research has three new
   private keys and CSRs; Gateway has signed and validated all CSRs; both sides
   have the canonical manifest and complete staged public material. Live files
   are unchanged.
2. `research_dual_trust`: Research trusts the old and new CA while continuing
   to present old client identities. Services restart and all three paths are
   probed.
3. `gateway_dual_trust`: Gateway presents the new server identity and trusts
   both CAs and both sets of exact client fingerprints. Research still presents
   old clients but accepts the new server. All three paths are probed.
4. `research_new_clients`: Research atomically installs the three new private
   key/certificate pairs and still trusts both CAs. All three paths are probed.
5. `gateway_new_only`: Gateway removes the old CA and old client fingerprints,
   retaining only the new server, CA, and client fingerprints, publishes its
   active manifest, and probes all paths from Research.
6. `committed`: Research removes the old CA and publishes the same active
   manifest; both guest journals record commit, policy hashes are recomputed,
   expiry evidence is emitted, and the host anchor is atomically advanced.

The coordinator may stop after any phase and safely resume. A phase command is
idempotent: it verifies the already-applied postcondition before returning.
It never infers progress solely from a journal entry.

The order deliberately changes server trust before client presentation. There
is no state in which Research rejects the presented Gateway server or Gateway
rejects every client identity.

## Recovery and retention

Recovery is forward-only: the operator reruns rotation with the pending
generation ID. Each already-recorded phase revalidates its live identity,
trust bundle, allowlists, service state, and path probes before returning;
each unrecorded phase safely repeats its atomic writes before advancing the
journal. There is deliberately no implicit rollback or abandon command once
live mutation has begun.

At preparation time, a guest at its eight-generation cap may prune only
inactive generations whose local journal is `committed`. It retains the active
generation and at least one older committed generation. Pending or partially
applied generations are never pruning candidates. Both guest journals reach
`committed`, so this rule is symmetric.

## Validation and bounds

Before any live mutation, validation proves:

- trusted clock check passes and no Claude run marker/process is active;
- UUID, journal, and manifest schemas are exact and bounded;
- every input is a root-owned regular file with the required mode and no link;
- all keys are Ed25519 and each certificate matches its private key or CSR;
- CA, serverAuth, clientAuth, SAN, subject, issuer, and chain roles are exact;
- certificate serials and fingerprints are unique;
- validity is not-yet-valid by at most five minutes and expires within the
  configured maximum (CA 45 days, leaves 21 days);
- every new certificate has at least seven days remaining at commit;
- generated bundles contain exactly the expected one or two CA certificates;
- configuration allowlists contain exactly the expected old/new fingerprints;
- staging and transaction counts remain within their caps.

OpenSSL commands use absolute paths, fixed arguments, private umask 077, and
random same-directory temporary paths. No shell evaluates certificate fields.

## Expiry evidence

A root-owned daily systemd timer on each guest runs a read-only checker. It
validates the installed generation and emits one structured journal event under
`SYSLOG_IDENTIFIER=secure-sandbox-pki`:

```json
{"event":"pki_expiry_status","generation_id":"...","minimum_not_after":0,"remaining_seconds":0,"status":"ok|warning|critical"}
```

Rotation emits `pki_generation_activated` with the generation ID and minimum
expiry. The telemetry exporters accept only those two event names, a UUIDv4,
integer time fields, and the fixed status vocabulary. They export no subjects,
certificate bytes, paths, package names, source, prompts, or other content.
Warning begins at seven days and critical at 48 hours. Boundary verification
requires a recent event for the active generation.

## Deployment and acceptance

Deployment is idle-only and uses reversible, per-guest policy backups. It
installs the lifecycle managers, expiry timer/service, telemetry normalization,
policy-hash membership, and host coordinator before beginning a generation.
Guest install rollback restores binaries and units; transaction recovery owns
certificate state once phase 3 begins.

Acceptance requires:

- local unit, schema, role, idempotence, and crash-window tests;
- installation and source-hash verification on both guests;
- a real full-generation rotation with a forced stop and resume at every phase
  in a non-production fixture, plus one uninterrupted production rotation;
- all three mTLS paths healthy after every production phase;
- generation/manifests equal to the root-owned host anchor;
- expiry evidence observed in the bounded Gateway telemetry spool;
- the complete boundary suite and a cold boot of all three VMs;
- an immutable review bundle and independent GLM source/evidence review before
  the final Parallels checkpoint.

The evidence claim is limited: these checks prove controlled key provenance,
certificate role and generation consistency, crash-safe transition, expiry
visibility, and observed path health. They do not prove absence of compromise,
cryptographic safety beyond the selected primitives, or future availability.
