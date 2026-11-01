# Protected Harness Lifecycle Authorization Consumer Acceptance Evidence

This matrix records source and local build evidence. No vendor generation or
live Research selector was changed by this checkpoint.

| Contract | Evidence |
| --- | --- |
| Exact ordered five-file activation frame | `HarnessLifecycleOperationTests.test_activation_frame_binds_exact_five_files_in_order` |
| Root-only Research staging and exact plan application | `HarnessGenerationManagerTests.test_stage_and_apply_bind_exact_reviewed_plan` |
| Stage collision cannot delete pre-existing data | `HarnessGenerationManagerTests.test_stage_rejects_trailing_data_and_removes_only_its_new_stage` |
| Changed plan or active runtime rejects | `HarnessGenerationManagerTests.test_apply_rejects_plan_mutation_and_active_runtime` |
| Host and Research references are reread independently | `HarnessGenerationManagerTests.test_management_rechecks_host_count_and_research_active_run` and Host manager catalog tests |
| Malformed or untrusted session catalogs reject | `HarnessLifecycleHostManagerTests.test_management_counts_only_exact_generation_and_rejects_untrusted_catalog` |
| Broker derives an exact Touch ID-only store receipt | `OperatorAuthorizationTests.test_harness_authorization_binds_exact_plan_and_touchid_receipt_command` |
| Protected manager rejects plan/authorization mutation before transport | `HarnessLifecycleHostManagerTests.test_plan_or_authorization_mutation_is_rejected_before_transport` |
| Apply is followed by independent status and boundary readback | `HarnessLifecycleHostManagerTests.test_apply_forwards_exact_plan_then_independently_reads_status_and_boundary` |
| Recovery binds and rereads the one journal digest | recovery tests in Host manager and operator authorization suites |
| Privileged operations are exact and Research-only | `RequestTests.test_harness_lifecycle_consumer_operations_are_exact_and_research_only` |
| Deployment is reversible and run-idle | installer/rollback source checks plus shell and Python syntax gates |
| GUI reviews exact expiring plan before Touch ID | Control Center DDD source regression and successful bundle build |
| Automatic work cannot mutate a harness | existing Control Center automatic-path regression |
| No live admission | absent real qualification and explicit DDD residual-risk statement |

The macOS build-only bundle gate completed successfully, including bundle
validation and ad-hoc signing. The Swift package test suite passed all eight
update-protocol tests. Final repository, publication, and secret gates are
recorded by the DDD's final commit and publication handoff.
