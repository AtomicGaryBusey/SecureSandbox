# Disposable-Mac Harness Lifecycle Acceptance Evidence

Status: source verification only. Physical campaign evidence is pending and no
acceptance verdict has been issued.

| Contract | Current evidence | Physical evidence required |
| --- | --- | --- |
| Clean disposable enrollment | enrollment unit tests reject wrong acknowledgement, non-macOS, provider environment, known state paths, present service credential, and ambiguous Keychain result | factory-reset machine receipt and operator clean-machine attestation |
| Bootstrap physical driver | source-tested fixed collector accepts only the next bootstrap case, rebinds the current Mac and exact clean checkout, reserves evidence before readback, verifies protected Host/Research/boundary state, repeats a metadata-only production-material scan, revalidates enrollment, and projects suite-fixed authorities from private canonical snapshots without mutation or caller-selected evidence fields | run both bootstrap cases immediately after the reviewed install and enrollment ceremonies; retain raw and projected records, including every rejected reserved attempt |
| Exact immutable campaign | campaign schema, suite digest, machine digest, source commit, lifetime, and policy validators | campaign bound to the exact deployed commit |
| Complete fixed matrix | 91 catalog cases and 198 ordered observation requirements | one outer-collector observation for every required case/kind |
| Provenance and archive attacks | fixed bad signer/chain/time/rollback/freeze/equivocation and twelve archive cases | live rejection receipts and unchanged quarantine/protected state |
| No prequalification execution or production authority | fixed qualification isolation cases and categorical candidate-collector rejection | independent process/network/file/credential observations |
| Touch ID semantics | fixed approve, cancel, expiry, replay, changed-plan, and wrong-generation cases | native broker receipts and unchanged selector readback for every rejection |
| Session generation binding | fixed future, old, and legacy session cases | Host/Gateway/Research session and runtime readbacks |
| Lifecycle management | fixed rollback, referenced-retirement rejection, zero-reference retirement/reclamation, revocation, and containment cases | exact Touch ID receipts, floors, catalog, denial, and retention readback |
| Crash ordering | journal-before-fence repair plus injected durable checkpoints | process kill and Research-VM hard power loss at every fixed transition |
| Deterministic recovery | source tests recover every durable activation checkpoint and independently verify the boundary | cold recovery receipts and post-recovery Host/Research readback |
| Disposable recovery driver | campaign-bound synthetic fixture uses the production generation store, stops at all fifteen exact durable callbacks, refuses arbitrary checkpoint input, and verifies deterministic recovery; process and power cases remain distinct | physical stopped-worker, external process-kill or Research-only hard-power, recovery, and boundary readbacks |
| Host recovery supervisor | source-tested outer driver rebinds the current Mac and clean exact source checkout, accepts only the next suite recovery case, deploys exact-commit root-owned fixture code through authenticated control, shares the Host lifecycle lock, reserves evidence before mutation, binds PID/start-time/boot identity, hard-codes the Research VM target, requires exact power acknowledgement, verifies Gateway/Target invariance, and emits fixed-authority raw artifacts without observation or admission authority | live process-loss and Research-VM power-loss artifacts for all thirty paired transition cases |
| Recovery observation projection | source-tested fixed bridge requires the next recovery case, current enrolled Mac, exact raw inventory, complete embedded checkpoint, self-digested stopped-worker and fault/cold-boot/recovery/boundary chain, private canonical snapshots, suite-fixed authorities, no caller-selected evidence fields, and crash-resumable non-overwriting publication | project each live supervisor artifact set into its three or four required observations and independently retain both raw and projected records |
| Immutable operator protocol | every case suite-binds its driver, baseline, action, interaction, egress posture, interruption checkpoint, postcondition, and reset; `next` reveals only the first incomplete case | operator follows each exact physical protocol on the dedicated Mac |
| Independent export | self-contained v4 evidence projections with bounded readback bytes, suite-fixed collectors, exact protected-artifact inventories, primary-byte source/subject binding, raw source-status validation, chained receipts, final digest, and candidate authority `none` | off-machine copy and independent `verify-export` verdict |
| Control Center visibility | fixed-path, read-only bridge validates the suite and campaign status; GUI exposes progress with authority `none` and no enroll/run/record/assemble/admit action | live campaign progress readback during the disposable-Mac run |
| No admission side effect | CLI contains no lifecycle mutation command and verdict authority is evidence-only | unchanged production environment and no vendor generation admission |

The source test matrix is necessary but insufficient. Documentation, generated
fixtures, and locally injected crash tests must not be relabeled as physical
disposable-Mac evidence.
