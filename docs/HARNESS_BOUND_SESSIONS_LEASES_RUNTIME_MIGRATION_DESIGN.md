# Harness-Bound Sessions, Leases, and Runtime Migration DDD

Status: source-complete; not deployed; no vendor generation admitted; no
legacy session migrated.

## Decision

Every run is bound to one exact, protected harness generation. The binding is
the tuple of harness ID, generation digest, manifest digest, executable digest,
inventory digest, adapter ID, adapter digest, and a canonical digest over that
tuple. Model-profile identity and harness identity remain independent and both
must match at every boundary.

A new session receives the protected active generation. A resumed session
receives the exact generation already recorded in its session catalog, whether
that generation is active or retained. It never follows the current selector.
A revoked, missing, altered, or otherwise non-runnable generation fails closed.

## Boundary flow

1. The Host controller requests a read-only, independently remeasured runtime
   binding from the protected Research generation store.
2. Session catalog v4 records the exact binding. Legacy records remain
   readable but cannot resume without explicit migration.
3. Gateway lease v2 binds the same tuple beside the existing model-profile
   identity. Reissue is idempotent only for an exact match.
4. Research lease v2 independently remeasures the named generation before
   arming and records the binding in process seed v2.
5. The Research supervisor remeasures again and derives the executable solely
   from the protected release root and generation ID. The agent-facing launcher
   supplies options, never an executable path.
6. Final Gateway summaries retain the immutable lease binding, allowing the
   evidence chain to identify the exact runtime bytes.

The former `/usr/local/bin/claude` path is no longer runtime authority for this
flow. It may remain on a not-yet-upgraded machine, but neither the launcher nor
the supervisor selects it after this DDD is deployed.

## Runtime identity

`shared/harness_runtime_binding.py` is the single canonical validator. It
rejects unknown or missing fields, malformed names or digests, and any binding
digest mismatch. `HarnessGenerationStore.runtime_binding()` accepts only an
active or retained catalog record, verifies the entire protected boundary,
remeasures its immutable release inventory, and returns the canonical tuple.
Read-only CLI operations expose either the active generation or one exact
generation; they do not mutate selectors.

## Legacy migration

Legacy sessions are not silently associated with whichever generation happens
to be active. `harness-session-migration.py` migrates one exact session only
when all of the following remain unchanged:

- canonical, user-owned mode-0600 session catalog in a user-owned mode-0700
  directory;
- exact session record and observed run-ID set;
- fresh, content-digested legacy attestation naming the executable digest;
- exact protected harness binding with the same executable digest; and
- exact five-minute plan plus Touch ID authorization with password fallback
  explicitly false.

The catalog and lock are revalidated under an exclusive lock before one record
is changed. The operation emits a content-bound receipt. Mixed v4 catalogs are
allowed during gradual migration, but any remaining legacy record stays
non-resumable. No selector, version string, path name, or “closest” generation
is an admissible inference.

The public migration CLI exposes planning only. The commit primitive is not a
public command because a caller-supplied JSON object, even with a self-digest,
cannot prove Touch ID. A later protected Host consumer must obtain the native
authorization receipt and call the primitive inside that trusted boundary.

## Install, rollback, and compatibility

Run-lease deployment now transfers, compiles, inventories, backs up, restores,
and policy-hashes the shared binding validator on Gateway and Research. It also
preflights the protected active-runtime inspector before altering either guest,
preventing a partial upgrade when the preceding generation-store DDD has not
been installed and populated. The Control Center lease projection and `labctl`
summary validator accept only Gateway lease v2.

No live deployment was performed in this DDD. The repository has no admitted
real harness generation or configured production release policy, so the
preflight intentionally blocks deployment today. Activation, first admission,
and legacy-session migration remain separately authorized operator ceremonies.

## Security properties

- A session cannot switch harness generation during resume.
- A model cannot select an executable or call a peer harness through this path.
- Gateway cannot mint a lease without a complete canonical harness identity.
- Research does not trust the Host or Gateway measurement alone.
- Mutable path aliases and current selectors are never resume authority.
- Revocation and missing retained bytes fail closed.
- Migration has no password fallback and no operator bypass.
- Rollback restores the binding validator with the rest of the run-lease
  transaction.

## Non-goals

This DDD does not admit or activate vendor bytes, deploy to the live VMs,
produce or consume a migration authorization, migrate a legacy session, add a Harnesses
GUI, install plugins, add automatic download or installation, or authorize a
second harness. Those are later, independently reviewed DDDs.

## Next DDD

The next implementation checkpoint is **Control Center Harness Lifecycle GUI**.
It will expose typed, confirmation-protected inspection and manual ceremonies
without creating automatic update authority.
