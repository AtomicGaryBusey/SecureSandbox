# Secure Enclave execution-approval acceptance evidence

This matrix is the retained index for the normative gates in
`SECURE_ENCLAVE_EXECUTION_APPROVAL_DESIGN.md`. A passing test is evidence only
for the named invariant; the live completion auditor and boundary verifier are
the authorities for deployed state.

| Gate | Required evidence | Retained evidence |
|---|---|---|
| 1 | Canonical v2 crypto, low-S P-256, strict base64/DER, fresh one-shot biometric context, no fallback | `AuthorizationRequestTests`: `normalizesForcedHighSSignatureAndRejectsNoncanonicalForms`, `wrapsP256X963AsDeterministicSPKIAndEnforcesCanonicalBase64`, `productionSigningIsFreshContextOneSignatureAndBiometricOnly`; `test_operator_authorization`: password fallback rejection and exact v2 parsing |
| 2 | Exact Secure Enclave creation/lookup, one result, identity match, private key non-exportability | Swift `productionKeyStoreIsNonexportableCurrentEnrollmentAndUnambiguous`; Host `test_secure_enclave_migration_advances_floor_and_retires_software_key`, `test_prepared_retry_is_lookup_only_and_cannot_substitute_key`; live generation-2 preparation/signing and completion audit; completion auditor's live Unix-peer probe proves a different executable is rejected before protocol handling; the plain ad-hoc Swift helper receives exact `errSecMissingEntitlement` with authentication UI disabled, while the same helper carrying the forged protected access-group entitlement is killed by macOS at launch before it can query |
| 3 | Missing biometric prerequisites fail without password or software fallback | Swift production policy assertions; Host `test_execution_approval_rejects_password_fallback`, `test_native_ui_cancel_never_reaches_password_broker`, `test_protocol_v2_floor_never_falls_back_to_software_signing`. Destructive machine-state variants are tracked as live-negative evidence, not inferred from these tests. |
| 4 | Host peer/release/key pinning, CAS/floor, retirement | `test_operator_authorization`, `test_host_controller_release`, completion audit (`software_key_absent:true`) |
| 5 | Exact Research verification, substitution/expiry/cancel/replay rejection | `test_execution_broker`: v2 content binding, high-S/wrong-generation/fenced rejection, cancel/substitution, expiry without consumption, atomic replay; live wrong-key/replay finalization |
| 6 | Configured user/current enrollment/reboot ambiguity fails closed | Swift current-set/passcode assertions; Host exact invoking UID/kernel peer tests; real cold boot plus completion audit. Destructive locked/enrollment-change/multi-user variants require separately retained live-negative receipts. |
| 7 | Crash/lost-response durability | Host selector/service restart tests; `test_secure_enclave_ddd_support` rename/fsync crash tests; `test_archive_execution_approval_acceptance_evidence` three injected interruption points; Research transition lost-response, fence ordering, durable reconciliation tests; detailed boundary list below |
| 8 | Rebooted exact acceptance then commit/retire | ignored local completion audit identifies the completed transaction and records `status:verified` |
| 9 | Rollback/floor rejection | `test_execution_approval_floor_blocks_v1_release_rollback`, v2 public-floor mismatch tests, forward-rotation history tests |
| 10 | No private file/export/fallback in v2 path | Swift source assertions; Host fallback tests; completion audit verifies legacy software key absent |
| 11 | Live matching identities and unchanged containment | final and independently repeated `scripts/verify-boundaries.sh` pass |
| 12 | Live cancellation, expiry, approved execution, wrong-key/replay | completion audit proves cancellation, approved execution, wrong-key/replay; `verify-live-secure-enclave-expiry.sh` produces current-generation live expiry evidence and the completion auditor validates it with `--require-live-expiry` |
| 13 | Cold boot and committed identity recovery | real Mac reboot checkpoint, distinct boot hashes, completion audit, final boundary |
| 14 | Independent implementation review | `/root/execution_approval_arch_review` final review; any NO-GO evidence gaps remain open until this matrix points to retained proof |

## Crash-boundary coverage

- Host release selector CAS and service restart: `HostControllerReleaseTests`.
- Pre-activation repair rename/fsync and selector recovery:
  `SecureEnclaveRepairCheckpointTests`.
- Research fence before broker stop and exact phase redelivery:
  `ExecutionApprovalTransitionTests`.
- Acceptance-attempt claim/consumed marker before Target, cancellation, Target
  failure, and durable receipt reconciliation: `ExecutionBrokerTests` and
  `ExecutionApprovalTransitionTests`.
- Predecessor evidence archive replace, archive-directory fsync, and
  state-directory fsync: `AcceptanceEvidenceArchiveTests`.
- Host correlation checkpoint and finalizer cancellation retry:
  `FinalizeBridgeBoundaryTests` and `FinalizationValidationTests`.
- Software-key retirement and completion publication are idempotently checked
  by Host migration tests and the live completion auditor.

## Open live-negative evidence

The completed authority is not itself rolled back to manufacture destructive
machine states. Current-generation live expiry has a reviewed, non-Targeting
harness and remains pending until its retained evidence exists. Locked
Keychain, enrollment mutation, disabled passcode/Touch ID, absent Secure
Enclave, and wrong console user require a separately reviewed negative harness
or a disposable Mac test environment. Differently signed broker-peer and
Keychain access-group isolation are now exercised live without mutating the
authority.
