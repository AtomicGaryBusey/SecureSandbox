# Candidate findings and independent adjudication

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Decision

Give the resident researcher a narrow way to preserve security hypotheses
without granting it authority to validate, disclose, ticket, prioritize, or
remediate them. Candidate submission and operator adjudication are separate
planes:

```text
GLM -> managed findings MCP -> broker-owned immutable candidate records
Operator/architect -> labctl finding -> root-only append-only adjudication journal
```

This extends the proven memory-proposal pattern into the finding domain while
retaining evidence semantics as an enforced data model rather than a writing
convention.

## 2. Candidate contract

Each candidate contains one bounded claim, one to eight affected source
locations, one to sixteen typed evidence references, reproduction conditions,
limitations, the strongest counterargument, a proposed severity, and its
rationale. The broker supplies the UUID, active run, current policy generation,
timestamp, immutable status, authority label, and content hash.

Affected locations must resolve through the root-published source registry and
are bound to its tree-manifest hash and exact Git commit. Registry entries with
another source-anchor form do not poison the registry, but they cannot be used
as affected code until their anchor type is supported.

Evidence classes are deliberately non-interchangeable:

- `static_source_review`
- `exhaustive_corpus_search`
- `static_graph_reachability`
- `measured_execution`
- `report_reference`
- `operator_reported`

Graph evidence is cross-checked against the sealed graph manifest. Report
references must be regular files below `reports/`, are size-bounded, opened
without following symlinks, and hash-bound at submission. Execution-language
claims without measured execution are accepted only as candidates and labelled
with an evidence mismatch rather than silently upgraded.

The original version verified only the structure and declared hashes of
exhaustive-search and measured-execution references. The successor design in
`TRUSTED_EVIDENCE_RECEIPTS_DESIGN.md` requires exact resolution against an
immutable receipt minted by the dedicated instrument identity. Once that DDD
passes deployment and acceptance, these references attest that the named
instrument produced the bound result. They still do not validate the security
claim or severity; adjudication must independently inspect or re-execute it.

The findings interface cites those receipts by the evidence class, source UUID,
and receipt UUID only. The broker resolves and projects the trusted record; the
researcher does not echo record or result hashes. Full legacy projections remain
accepted only when exact, with fixed field-level mismatch diagnostics. This
removes transcription as an integrity input without turning a UUID into proof:
all authority still comes from the validated producer-owned receipt.

## 3. Immutability and resource bounds

The dedicated `findings-broker` identity owns candidate and amendment spools.
Its same-named private group is root-created and exact-member validated; the
only permitted explicit member is `findings-broker`. The service retains
`agent` as its runtime primary group solely for the client socket and names the
private group explicitly as supplementary authority for root-adjudicated state.
It stages records in strictly named private temporary files, publishes them by
atomic no-overwrite hard link, and persists both publication and temporary-file
removal with directory `fsync`. A subsequent request safely removes only
trusted broker-owned temporary records left by a crash. Unexpected or corrupt
final records fail closed. Original records are never edited. Amendments append
evidence and qualifications while preserving the original.

The service accepts at most 64 KiB per request, 256 active candidates, sixteen
candidates per run, 1,024 amendments globally, and sixteen amendments per
finding. Enumeration fails closed on unexpected entries. The agent can connect
to the broker socket but cannot read or modify broker state.

## 4. Independent adjudication

Only the root operator tool may create adjudication events. Version 1 recognizes
the small state set `candidate`, `needs_evidence`, `disputed`, `validated`,
`rejected`, and `withdrawn`. Duplicate, supersession, and dispute semantics are
relations, not overloaded states.

Every event records the named human/architect role, conflict note, rationale,
verification method, consulted evidence hashes, previous-entry hash, sequence,
and entry hash. Validation requires inspected evidence; a claim that requires
execution additionally requires independent re-execution. Report evidence is
re-hashed and snapshotted before validation, so a changed report fails closed.
Snapshots form a verified append-only set, allowing later validation to add a
newly consulted report without weakening prior snapshots. Every terminal event
freezes the complete evidence-digest inventory; reopening requires an evidence
digest that is present now and absent from that terminal inventory. For report
references, the content hash must also be new, so copying old bytes to a new
path cannot manufacture substantive reopen evidence.

Terminal candidates may be disposed from active capacity only by moving the
candidate, amendments, and a disposition record into a root-owned mode-0700
archive. Disposal is not deletion and does not rewrite the journal.

## 5. Authority and non-claims

Candidate submission does not:

- prove the claim or exploitability;
- accept the proposed severity;
- authorize disclosure, external transmission, ticket creation, or remediation;
- establish that static reachability is runtime reachability; or
- make a shared-root adjudicator organizationally independent.

The operator is the research lead and final decision-maker. The architect is
and may adjudicate with an explicit conflict note. GLM remains the independent
instrument user and candidate author. The shared root of trust is recorded as
a limitation rather than described as third-party independence.

## 6. Telemetry and disclosure boundary

Lifecycle telemetry is content-free by construction. The exporter accepts only
fixed event, operation, UUID, SHA-256, support label, and allowlisted error
tokens. Claims, paths, evidence, reproduction details, severity rationales, and
unexpected strings are discarded; malformed metadata causes the event to be
dropped rather than copied into Azure.

Actual or suspected vulnerability reports belong only under the host
`vulnerability-reports/` quarantine, whose contents are ignored by Git. The
tracked README is the only exception. Candidate records and live reports are
not synchronized to either source-code remote.

## 7. Operator workflow

```text
./scripts/labctl findings
./scripts/labctl finding show FINDING_UUID
./scripts/labctl finding apply REQUEST.json
```

The request file avoids placing rationale or evidence hashes in shell history.
It must be a local regular non-symlink JSON file no larger than 16 KiB, is copied
to a unique remote path, validated again by the root tool, and removed after the
operation.

## 8. Acceptance criteria

Acceptance requires unit tests for immutable submission, replay, typed evidence,
execution-claim validation, amendment semantics, hash chaining, report mutation,
relations, disposal, corrupt-record listing, MCP authority, and content-free
telemetry; exact deployed hashes; socket/state ownership checks; agent denial
from state and adjudication; live negative and positive candidate probes; the
complete containment suite; rollback evidence; and independent white-box review.

## 9. Acceptance evidence

Candidate identifiers, adjudication journals, policy hashes, reviewer reports, corrupt-state probes, and checkpoint identifiers are retained in ignored local records.
