# Control Center Harness Lifecycle GUI Acceptance Evidence

This is source-level evidence. No release policy, remote, live guest, vendor
artifact, protected selector, or session was changed.

| Contract | Evidence |
| --- | --- |
| Dedicated typed Harnesses settings surface | `HarnessSettingsView.swift`, `HarnessModels.swift` |
| Metadata-only automatic checking, off by default | `HarnessStore.swift`, settings toggle and notification tests/source review |
| No automatic artifact or installation path | store capability separation and DDD regression |
| Candidate evidence and compatibility review | signed release catalog model and review sheet |
| Catalog independently reverified against floor | `HarnessStore.releases()` and lifecycle unit test |
| Exact manual quarantine acquisition | fixed bridge action, SHA-256 validation, confirmation alert |
| Separate evidence re-verification | fixed bridge action and `not_admitted_not_executable` client guard |
| Synthetic fixture only, authority none | qualification bridge/client guards and conformance tests |
| Protected inspection is read-only | `privileged_control.py` allowlist and read-only generation CLI |
| Missing protected consumer fails closed | typed unavailable status and disabled mutation controls |
| Touch ID invariant remains exact | `requires_touch_id: true`, `password_fallback: false`; no GUI substitute |
| No live admission or activation | non-goals plus absent mutation bridge |

The repository publication and secret gates, changed-boundary security review,
exact commit, and both remote tips are recorded in the final handoff.

