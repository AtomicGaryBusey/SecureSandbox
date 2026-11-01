# Protected Harness Generation Store Acceptance Evidence

This matrix describes source-level acceptance only. No live Research selector
or vendor harness generation was changed.

| Contract | Authoritative evidence |
| --- | --- |
| Immutable root-owned generation inventory | `HarnessGenerationStoreTests.test_activation_publishes_immutable_exact_generation` |
| Exact catalog/selector/inventory readback | `GenerationStore.verify_boundary` and tamper tests |
| Five-minute Touch ID plan; no password fallback | authorization validator and synthetic/password rejection test |
| Synthetic fixture has no admission authority | qualification validator and DDD source regression |
| Admission closes around mutation | Research watchdog fence test |
| Health failure restores exact predecessor | health-failure test and workflow event chain |
| Process-loss recovery is deterministic | activation/management process-loss tests plus pre-workflow and interrupted-publication cleanup tests |
| Rollback cannot lower admission floor | two-generation rollback test |
| Retirement requires zero references and retains bytes | retirement/reference test |
| Revocation is monotonic and removes active selection | active-revocation test |
| Read-only public inspection surface | CLI source regression |
| No live admission | absent policy/candidate plus explicit design non-goals |

The complete repository publication gate and security review are recorded in
the DDD's final commit and publication handoff.
