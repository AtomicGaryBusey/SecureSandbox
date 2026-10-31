# CodeGraph and Findings Ergonomics DDD

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Problem and decision

The original findings contract required a researcher to reproduce the complete
seven-field `static_graph_reachability` projection. Four plausible partial
projections all failed with the same `evidence_schema_invalid` token, and a
single mistyped 64-character graph digest was indistinguishable from any other
schema error. This made transcription part of the integrity boundary.

Successful reachability analysis now publishes a service-owned immutable
analysis record before returning its result. The result includes an opaque,
deterministic version-5 analysis UUID and an exact `finding_evidence_pointer`:

```json
{"class":"static_graph_reachability","source_id":"SOURCE_UUID","analysis_id":"ANALYSIS_UUID"}
```

That three-field object is the preferred findings projection. The findings
broker resolves the record and imports the graph digest and evidence semantics
itself. A caller may still submit the historical seven-field projection, but
every field must equal the service-owned record.

## 2. Authority and publication

The networkless `codegraph-query` identity owns
`/var/lib/secure-sandbox/codegraph-analyses`. The agent may read records for
transparency but cannot create, replace, or remove them. Each record binds:

- its opaque analysis UUID;
- a SHA-256 digest of the complete sealed graph and selector binding;
- the registered source UUID and sealed CodeGraph index digest; and
- the fixed static evidence labels: not measured, not exhaustive, and based on
  a caller-selected entrypoint.

Publication writes canonical bytes to a private temporary file, fsyncs it,
uses an atomic no-overwrite hard link, fsyncs the directory, and removes the
temporary. An existing identical record is replay-safe; a collision with
different bytes fails closed. The query returns success only after publication.
The registry admits at most 4,096 final records. Safe producer-owned crash
remnants are removed at service start; unexpected entries fail closed.

The findings broker accepts only a trusted regular record with the expected
owner, non-writable mode, single link, bounded size, exact schema, exact UUID,
and valid digest fields. It separately confirms that the registered source and
currently sealed graph manifest still match the projection. The UUID is only a
locator; it has no authority without this resolution.

## 3. Accepted projections and diagnostics

`static_graph_reachability` accepts exactly two shapes:

1. preferred pointer: `class`, `source_id`, `analysis_id`;
2. compatibility projection: those three fields plus
   `codegraph_index_sha256`, `measured_execution`, `exhaustive`, and
   `caller_selected_entrypoint`.

Any other field set returns `analysis_projection_fields_mismatch`. A complete
projection with a wrong value returns
`analysis_projection_mismatch_<field>`. Missing, malformed, untrusted, and
unavailable analysis records have distinct fixed errors. These tokens contain
no source content or sensitive path.

## 4. Digest presentation

Canonical structured digest fields remain ungrouped lowercase hexadecimal so
existing protocols and verification remain stable. CodeGraph results also
include a `digest_display` map whose values are grouped into eight-character
chunks. Human/model-facing MCP text applies the same grouping recursively.
Grouped values are presentation-only and are never accepted as protocol
digests. Findings should copy the UUID-based `finding_evidence_pointer`, not a
digest.

## 5. Failure and compatibility behavior

Reachability results produced before this design have no authoritative analysis
record and cannot be upgraded from caller-supplied hashes. They must be rerun.
This intentionally closes the previous gap in which a syntactically valid
analysis hash was not resolved to a producer-owned record. Receipt-backed
corpus and execution evidence are unchanged.

If publication fails, CodeGraph returns a bounded rejection and emits no
unresolvable successful analysis. A graph rebuild invalidates submission
against the current sealed manifest; retaining a record does not retain the old
graph itself or convert it into evidence.

At 3,072 records, schedule quiesced maintenance. Preserve a root-owned inventory
and every record referenced by a candidate, amendment, adjudication event, or
retained report. Move only unreferenced records to root-only archive storage on
the same trusted filesystem, fsync both directories, restart the service, and
verify a retained pointer. A malformed or conflicting record is an incident,
not an automatic cleanup candidate.

## 6. Acceptance gates

Completion requires unit and live evidence for deterministic UUID generation,
atomic replay-safe publication, collision rejection, exact pointer resolution,
field-specific mismatch errors, malformed/untrusted record rejection, unchanged
canonical digests, grouped display companions, ready-to-copy MCP guidance,
service filesystem confinement, complete boundary verification, and safe
rollback backups. No active researcher session may exist during deployment.

The reviewed deployment entry point enforces that idle gate, runs the focused
CodeGraph, findings, MCP, and telemetry suites, transactionally installs both
planes, performs a fresh real reachability analysis and pointer-resolution
probe, and closes with the complete containment boundary. The guest verifier
runs through the root control path so it can read the producer-owned analysis
record while never granting that access to the agent identity.
