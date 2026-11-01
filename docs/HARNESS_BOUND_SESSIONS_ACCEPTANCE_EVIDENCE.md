# Harness-Bound Sessions Acceptance Evidence

This matrix is source-level evidence. No live guest was changed.

| Contract | Evidence |
| --- | --- |
| Canonical exact runtime identity | `shared/test_harness_generation_store.py` and `gateway/test_run_lease.py` |
| New session uses active generation | controller behavior tests and DDD source regression |
| Resume uses recorded generation | session catalog/controller behavior tests |
| Legacy resume fails closed | explicit legacy-unbound controller path and migration tests |
| Gateway lease carries exact binding | Gateway lease issue, reuse, and mismatch tests |
| Research independently remeasures | watchdog binding mismatch test |
| Executable derives from protected generation | process supervisor executable measurement test |
| Agent supplies no executable path | launcher/process DDD regression |
| Exact Touch ID migration, no password fallback | migration success, rejection, and drift tests |
| No current-selector inference | migration non-inference test |
| Transactional install and rollback coverage | shell syntax plus deployment/rollback DDD regression |
| No live admission or migration | design non-goals and protected-store preflight |

The repository publication and secret gates, changed-boundary security review,
exact commit, and both remote tips are recorded in the final handoff.
