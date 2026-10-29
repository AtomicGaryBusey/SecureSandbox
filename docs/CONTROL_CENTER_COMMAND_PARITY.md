# Control Center command parity

This is the implementation inventory for the operator commands in
`scripts/labctl`. **Live** means the app currently invokes a bounded,
versioned bridge or the installed protected launcher. **Prepared** means the
UI and bridge are coded but protected deployment or live acceptance remains.
**Planned** means no GUI action exists yet. The app must not imply that a
planned action is available.

| CLI operation | GUI home | State | Required next acceptance |
| --- | --- | --- | --- |
| `status` | Overview | Live | Confirm offline and degraded presentation |
| `start`, `stop` | Overview | Prepared | Live cold start/stop, operator review, phase progress, independent readback |
| `sessions` | Sessions | Live | Verify large registry and search |
| `session label` | Sessions | Live | Exercise a private label edit |
| `session unlabel` | Sessions | Live | Exercise explicit removal and catalog readback |
| `claude`, `claude --resume` | Session Terminal | Prepared | Verify live PTY, Touch ID, lease closure, and window close behavior |
| `source plan` | Sources | Live | Verify branch and tag resolution, expiry, and rejected URLs |
| `source apply` | Sources | Prepared | Deploy plan readback through protected dispatcher and test one-time import |
| `source npm-plan` | Sources | Prepared | Verify exact package/version plan, provenance review, status, and import |
| `sources` | Sources | Live | Verify offline and long catalog states |
| `corpus index`, `codegraph index` | Sources | Planned | Index identity, phase progress, sealed result readback |
| `dependencies plan`, `status`, `apply`, `list` | Sources / Maintenance | Planned | Exact dependency plan and sealed bundle review |
| `findings` | Findings | Live | Verify support and adjudicated states |
| `finding show` | Findings | Live | Verify long text, amendments, and event history |
| `finding apply` | Findings | Planned | Keep explicit root authorization and append-only receipt |
| `artifacts`, `artifact` | Evidence | Prepared | Verify live Azure archive authentication, content-bound catalog, preview, and selected text export |
| `transcript` | Evidence | Planned | Run linkage and selected verified export |
| `logs` | Activity | Live | Verify metadata-only projection and offline state |
| `lease status`, `renew`, `reconcile` | Activity / Maintenance | Planned | Run selection, fixed renewal bounds, close/readback |
| `time-sync` | Maintenance | Live | Confirm clock-attention state |
| `time-sync --apply` | Maintenance | Planned | Idle gate and verified resynchronization |
| `snapshots` | Recovery | Live | Confirm each retained milestone before apply |
| `snapshots --apply` | Recovery | Planned | Stopped-stack/free-space preflight and retained readback |
| `verify` | Maintenance | Live | Exercise bounded progress and complete boundary result |
| `safety-audit` | Maintenance | Planned | Read-only posture summary |
| `memory proposals` | Maintenance | Planned | Proposal list and provenance inspector |
| `key-load` | Maintenance | Planned | Explicit 1Password identity repair without exposing key material |
| `admin`, `target` | Maintenance | Planned | Separate break-glass terminals and distinct warnings |
| `panic` | Maintenance | Planned | Emergency control with exact affected-VM summary and readback |

Coordinated full backup and restore are new operations, not existing
`labctl` commands. The DDD also needs their authenticated manifest,
quarantine, rollback, and cold acceptance before release.
