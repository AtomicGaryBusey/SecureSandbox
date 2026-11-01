# Disposable-Mac Harness Lifecycle Acceptance DDD

Status: campaign implementation and crash-boundary hardening complete; physical
disposable-Mac execution pending arrival of the dedicated machine. No live
acceptance verdict exists yet.

## Decision

Harness lifecycle acceptance is a destructive, machine-bound campaign, not a
unit-test label and not an admission shortcut. A campaign can begin only from a
fresh macOS enrollment receipt that declares the machine disposable, finds no
known production-material paths or provider credential environment, and finds
no Agents-vault service credential in the login Keychain. The receipt exports
only a digest of hardware identity; it never exports the platform UUID or
serial number.

The fixed suite contains 91 cases and 198 required observations. It covers
fresh bootstrap, provenance and archive rejection, candidate isolation, all
Touch ID outcomes, new/old/legacy session behavior, rollback, retirement,
reclamation, revocation, containment, cold boot, and paired process-loss and
power-loss cases at fifteen durable lifecycle transitions. The suite digest
binds every case, expected result, observation kind, Touch ID requirement,
reboot requirement, and destructive flag.

A complete export has only `acceptance-evidence-only` authority. Passing it
means the evidence is eligible for a separately reviewed exact-generation
admission decision. It cannot install, select, activate, admit, migrate,
download, or authorize a harness.

## Trust model

Protected facts are the campaign identity, machine digest, exact source commit,
suite digest, observation set, receipt order, final export, and the negative
claim that production material was absent. Relevant adversaries include a
candidate harness fabricating its own success, an agent omitting negative
cases, observations copied from another machine or source revision, an
operator accidentally using production credentials, and a crash that leaves
admission fenced without a recoverable transaction.

The candidate is never an accepted collector. Observations must name one of
the fixed outer collectors: protected Host, Research, privileged-control,
Touch ID broker, disposable supervisor, cold-boot supervisor, or evidence
exporter. Each observation binds the campaign, machine, source commit, case,
kind, expected outcome, subject and detail digests, time window, and an explicit
`candidate_statement_used: false`. Mixed-machine, mixed-commit, duplicated,
missing, reordered, expired, oversized, or candidate-derived evidence rejects.

The campaign format does not pretend that a JSON digest proves physical
reality by itself. Collector authenticity comes from the already protected
Host/Research release and its independently read-back receipts. The export
preserves those facts so a verifier need not trust the candidate narrative.
The immutable external evidence archive remains the retention boundary.

## Enrollment and production-material exclusion

`scripts/enroll-disposable-mac-harness-lifecycle.py` is intentionally separate
from lifecycle mutation. It requires an exact destructive-test acknowledgement,
Darwin hardware, absence of known provider credential environment variables,
absence of SecureSandbox/provider state paths, an unambiguous Keychain probe,
and no `op-service-account-agents` entry. It emits no secret and never calls
1Password.

This preflight is a lower bound, not a forensic proof that a reused Mac is
clean. The physical campaign therefore requires a factory-reset or freshly
erased dedicated Mac, a new local test account, synthetic credentials only,
and no sign-in to the operator's production 1Password, provider, cloud, or
research accounts. Any uncertainty aborts the campaign.

## Crash-boundary repair

The acceptance review found that activation and management previously wrote
the run-admission fence before the recovery journal. Power loss in that narrow
window could leave admission closed with no journal describing the exact
predecessor. The transaction now durably writes a `prepared` recovery journal
first, then writes the fence, checks runtime idleness, and advances the journal.
If runtime is not idle it removes both records durably.

Internal constructor-injected checkpoints now exist after:

1. candidate staging and plan publication;
2. prepared journal and admission fence;
3. workflow authorization and immutable release publication;
4. catalog, floor, and selector writes;
5. health evidence;
6. activated, verified, and committed workflow records; and
7. fence and journal removal.

They are not command-line arguments, protected-control operations, environment
variables, files, or model-visible knobs. Production managers use a no-op
callback. Source tests inject process loss without adding a runtime bypass.
The journal records `committed` before fence removal, allowing recovery to
distinguish a safe pre-fence crash from a committed response-loss window while
still rejecting an unexplained missing fence.

## Campaign and export protocol

The public operator CLI exposes only:

- `catalog`: render the immutable suite and its digest;
- `initialize`: consume one canonical owner-controlled enrollment receipt and
  create a bounded campaign for an exact source commit;
- `verify-campaign`: validate policy, identity, time, and self-digest;
- `status`: validate every present observation and report the next incomplete
  fixed case without creating evidence;
- `assemble`: require the exact observation filename and case/kind inventory,
  validate every observation, and create a chained receipt export; and
- `verify-export`: independently revalidate the complete export and return the
  non-admitting verdict.

There is no activate, rollback, retire, revoke, recover, poweroff, download, or
credential command. Existing protected ceremonies remain the only mutation
path. Files must be regular, single-link, owner-controlled, bounded, and
canonical. Output creation uses `O_EXCL|O_NOFOLLOW` and never overwrites prior
evidence.

Receipts are emitted in immutable suite order. Each binds the ordered
observation digests and predecessor receipt. The final export embeds the exact
campaign, all observations, all receipts, final chain head, source commit,
machine digest, suite digest, completion time, `candidate_authority: none`, and
`production_material_used: false`. Any omission prevents assembly; any later
change breaks the export digest or chain.

## Physical campaign boundary

The current development Mac must not be used to manufacture the destructive
evidence. The dedicated disposable Mac must run every case with synthetic
sessions and credentials. Touch ID approve/cancel cases require the operator
at the keyboard. Research-VM hard-power cases must keep Parallels Desktop's GUI
closed and operate only on the disposable campaign. They do not authorize an
abrupt shutdown of the macOS host; ordinary host restart safety remains in
force.

No production data, provider credential, active research session, vendor
admission, or selector change is in scope. A source test pass proves the
campaign machinery and deterministic recovery model, not the still-pending
physical observations.

## Exit criteria

This DDD is complete only when the dedicated Mac has:

1. produced a valid clean enrollment and exact-commit campaign;
2. run all 91 cases and retained all 198 fixed-collector observations;
3. completed every process-loss and Research-VM power-loss transition with
   deterministic recovery or an unambiguous committed readback;
4. passed cold-boot Host/Research/catalog/executable/policy readback;
5. assembled and independently verified the complete non-admitting export;
6. archived that export outside the candidate and disposable machine; and
7. been erased or quarantined after evidence export.

Until then the next First Exact Claude Generation Admission DDD remains
blocked by design.
