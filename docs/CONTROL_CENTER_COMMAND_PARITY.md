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
| `sessions`, `session runs` | Sessions | Prepared | Deploy v2 run-link writer; historical counts remain without invented links |
| `session label` | Sessions | Live | Exercise a private label edit |
| `session unlabel` | Sessions | Live | Exercise explicit removal and catalog readback |
| `claude`, `claude --resume` | Session Terminal | Prepared | Verify live PTY, Touch ID, lease closure, and window close behavior |
| `source plan` | Sources | Live | Verify branch and tag resolution, expiry, and rejected URLs |
| `source apply` | Sources | Prepared | Deploy plan readback through protected dispatcher and test one-time import |
| `source npm-plan` | Sources | Prepared | Verify exact package/version plan, provenance review, status, and import |
| `sources` | Sources | Live | Verify offline and long catalog states |
| `corpus index`, `codegraph index` | Sources | Prepared | Live idle-state build, index identity, sealed result readback, unclear-outcome recovery |
| `dependencies plan`, `status`, `apply`, `list` | Sources | Prepared | Verify exact package plan, missing-source refresh, one-time assembly, and sealed bundle readback |
| `findings` | Findings | Live | Verify support and adjudicated states |
| `finding show` | Findings | Live | Detail now shows bounded evidence entries and adjudication history; inspect long amendment and history cases |
| `finding apply` | Findings | Prepared (transition/relation/reopen) | Live root-authorized actions and journal readback; disposition form remains |
| `artifacts`, `artifact` | Evidence | Prepared | Verify live Azure archive authentication, content-bound catalog, preview, and selected text export |
| `transcript` | Evidence | Live | Verify a large run and selected native export; linked run fixture rendered 145 records |
| `logs` | Activity | Live | Verify metadata-only projection and offline state |
| `lease status`, `renew` | Session Runs / Evidence | Prepared | Live active lease and independent Research watchdog readback |
| `lease reconcile` | Selected Run Lease | Prepared | Deploy Research completed-record lookup, then live local-close/Gateway summary review and durable Research readback |
| `time-sync` | Maintenance | Live | Confirm clock-attention state |
| `time-sync --apply` | Maintenance | Prepared | Live idle-run rejection and independently verified resynchronization |
| `snapshots` | Recovery | Live | Typed dry-run preview verifies policy, counts, free space, stopped stack, and GUI state; live apply preflight is unavailable |
| `snapshots --apply` | Recovery | Prepared | Whole-stack locked preflight, destructive review, and retained-ID readback; live milestones/free space unavailable |
| `verify` | Maintenance | Live | Exercise bounded progress and complete boundary result |
| `safety-audit` | Maintenance | Prepared | Verify full protected posture after deployed release matches reviewed source |
| `memory proposals` | Maintenance | Prepared | Live metadata readback, provenance inspector |
| `key-load` | Maintenance | Prepared | Explicit 1Password identity reload and readback of both SSH agent sockets; live post-reboot acceptance |
| `admin`, `target` | Maintenance | Prepared | Separate direct SSH windows use fixed installed config and destination; live terminal acceptance |
| `panic` | Maintenance | Prepared | Destructive confirmation, exact affected-VM summary, and independent Parallels readback; live emergency acceptance pending |

Archived tool-result browse and selected export now use verified transcript
records with per-result digests. Future runs have session links in the v2
private catalog; large-run export streaming remains. Coordinated full backup
and restore are new operations, not
existing `labctl` commands. Their live cold acceptance remains before release.
