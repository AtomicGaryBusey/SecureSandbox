# Trusted evidence receipts

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Decision

Replace agent-authored assertions that exhaustive corpus search or measured
execution occurred with receipts minted by the dedicated process that performed
the operation. Findings may cite these evidence classes only when the findings
broker can resolve an immutable receipt and exactly match its public projection.

```text
GLM -> thin MCP adapter -> dedicated instrument broker -> immutable receipt
                                      |
                                      +-> bounded result + receipt projection

GLM -> findings MCP -> findings broker -> trusted receipt verification
```

## 2. Authority boundary

The `agent` UID cannot publish, read, replace, or delete receipts. Exhaustive
corpus operations execute as `corpus-broker`; disposable execution continues to
execute as `execution-broker`. Each producer can write only its own receipt
subdirectory. `findings-broker` has read-only registry access and cannot mint
receipts. Root controls identities, directories, binaries, and service units.

The MCP adapters are untrusted presentation clients. Directly importing or
running a root-owned analysis module as `agent` may compute a result, but it
cannot create a receipt and therefore cannot satisfy receipt-backed finding
evidence.

## 3. Receipt contract

Every successful attested operation creates a bounded
`secure-sandbox-evidence-receipt-v3` record containing:

- a server-generated UUID;
- producer and instrument identity;
- evidence class and active run UUID;
- production timestamp;
- a canonical request hash;
- the class-specific content-free evidence projection; and
- a canonical record hash.

Publication uses a private producer-owned temporary file, file `fsync`, atomic
no-overwrite hard-link publication, directory `fsync`, temporary-file removal,
and a second directory `fsync`. Strictly named trusted crash remnants may be
cleaned; unexpected entries fail closed. Receipts are never edited.

The exhaustive-search projection binds source UUID, instrument, run UUID,
canonical request hash, corpus-wide result-set hash, and `exhaustive: true`.
The measured-execution projection binds source UUID, execution request UUID,
run UUID, code hash, stdout and stderr hashes, fixture-manifest hash, Target-
reported runtime image digest, exit code, timeout state, output-limit state,
both stream-truncation flags, requested timeout, and Target-reported duration.
Version-1 hot-acceptance and version-2 outcome-bound receipts remain readable,
but all new execution receipts use the timing-bound version-3 projection.

## 4. Finding semantics

Receipt-backed evidence supplied to the findings broker must exactly equal the
receipt's public projection, including receipt UUID and receipt record hash.
Unknown, malformed, inaccessible, wrong-owner, writable, mismatched-class, or
mismatched-field receipts are rejected. Submission remains only a candidate;
receipt verification proves that the named instrument produced the bound result,
not that the result establishes exploitability, severity, reachability, or a
valid security finding. Root adjudication and independent re-execution remain
separate requirements.

## 5. Bounds and non-claims

The registry is locally bounded and content-free. It stores hashes and fixed
identifiers, never queries, source excerpts, code, fixtures, stdout, stderr, or
claims. Receipts attest only to the exact instrument operation and immutable
inputs represented by their hashes. They do not make relevance exploration or
static graph reachability exhaustive, and they do not convert scan indicators
into findings.

Identical projections within a run reuse the existing immutable receipt. Each
producer may mint at most 256 distinct receipts per run and retain at most 4096
active receipts. This prevents one agent run from exhausting the complete
registry. Cross-run citation is intentional: a receipt is durable institutional
evidence bound to its original run, not a capability scoped to the submitting
run. The Target validates its configured image locally; the Research receipt
records the digest reported by that Target and does not independently inspect
the Target image store.

The loopback execution endpoint remains reachable to the local agent UID. The
Claude permission prompt is a user-interface approval boundary, not
cryptographic authentication between same-UID processes. The execution broker
still enforces registered fixtures, fixed Target, fixed image, and all runtime
bounds on every request. Treat direct same-UID invocation as an accepted local
limitation and revisit it only with an independently authenticated approval
channel.

## 6.1 Capacity and repair runbook

At 3072 receipts in either producer directory, schedule maintenance before
another long research run. End the agent run and stop the three brokers. Make a
root-owned mode-0700 copy of the complete registry, generate and retain its
SHA-256 inventory, and enumerate receipt IDs referenced by active candidates,
amendments, adjudication history, and disposed finding archives. Never remove a
referenced receipt. Move only unreferenced receipts into a root-only archival
directory on the same trusted filesystem, fsync both directories, restart the
brokers, run the full boundary suite, and verify one retained receipt through
the findings path. Restoring an archived receipt requires the same quiesced,
root-only procedure and must fail on a filename collision. Unexpected or corrupt
finals are not cleanup candidates: preserve the directory, stop publication,
and investigate before repair.

## 6. Acceptance gates

Acceptance requires unit coverage for producer isolation, atomic no-overwrite
publication, crash cleanup, receipt tamper and projection mismatch, missing and
foreign receipts, corpus and execution result binding, MCP thin-client behavior,
resource bounds, and content-free telemetry. Live probes must demonstrate that
the agent cannot access registry state, both instruments mint usable receipts,
fabricated evidence is rejected, and a receipt-backed synthetic candidate can
be independently rejected and archived. The full boundary suite, Tier 4 audit,
independent white-box review, cold boot, and coordinated checkpoint remain
closing gates.

## 7. Acceptance and repair evidence

Live receipt, run, finding, bundle, policy, deployment, and checkpoint identifiers are retained in ignored local records. Acceptance covers issuer separation, replay semantics, request and result binding, capacity exhaustion, malformed state, exact evidence projection, review-bundle verification, and cold-boot recovery.
