# Control Center command parity

This is the implementation inventory for the operator commands in
`scripts/labctl`. **Live** means the app currently invokes a bounded,
versioned bridge or the installed protected launcher. **Prepared** means the
UI and bridge are coded but protected deployment or live acceptance remains.
**Planned** means no GUI action exists yet. The app must not imply that a
planned action is available.

| CLI operation | GUI home | State | Required next acceptance |
| --- | --- | --- | --- |
| `status` | Overview | Live | Live versioned readback passed with all three VMs running and reachable; confirm offline and degraded presentation |
| `start`, `stop`, `lifecycle-progress` | Overview | Prepared | Real cold Stop verified all three stopped; Start restored all three running/reachable but its boundary gate failed six checks, so live Start acceptance remains after protected deployment |
| `sessions`, `session runs` | Sessions | Prepared | Deploy v2 run-link writer; historical counts remain without invented links |
| `session label` | Sessions | Live | Exercise a private label edit |
| `session unlabel` | Sessions | Live | Exercise explicit removal and catalog readback |
| `claude`, `claude --resume`, `claude --source`, `claude --lease-profile` | Session Terminal / Sources | Prepared | Review chooses short, standard, or extended Gateway lease; deploy registered-source working directory context and verify live PTY, Touch ID, lease closure, and window close behavior |
| `source plan` | Sources | Live | Live `octocat/Hello-World` `master` plan returned a resolved 40-character commit and expiry; query, subpath, and non-GitHub URLs were rejected; verify tag resolution |
| `source apply` | Sources | Prepared | The sheet now retains the plan and attempted-submit latch across restart, reads Gateway status, and recovers completed source identity; deploy protected dispatcher and test one-time import |
| `source npm-plan` | Sources | Prepared | Verify exact package/version plan, provenance review, status, and import |
| `sources` | Sources | Live | Live 11-source catalog passed; verify offline and long catalog states |
| `corpus index`, `codegraph index` | Sources | Prepared | Live idle-state build, index identity, sealed result readback, unclear-outcome recovery |
| `dependencies plan`, `status`, `apply` | Sources | Prepared | Verify exact package plan, missing-source refresh, one-time assembly, and sealed bundle readback |
| `dependencies list` | Sources | Live | Native sealed-bundle browser decodes current empty catalog; verify nonempty bundle detail after assembly |
| `findings` | Findings | Live | Live 13-finding catalog passed; verify support and adjudicated states |
| `finding show` | Findings | Live | Detail shows bounded evidence and history with fresh-readback JSON export; inspect long cases and live save panel |
| `finding apply` | Findings | Prepared | A live 16,385-byte request was rejected at the 16 KiB bridge limit; deploy archive-marker readback and verify root-authorized transition, relation, reopen, and disposition |
| `artifacts`, `artifact` | Evidence | Prepared | Live 73-item Azure catalog passed; verify selected preview and native text export |
| `transcript` | Evidence | Live | Live selected export verified 145 records, SHA-256, and mode 0600; live run above 8 MiB remains |
| `logs` | Activity | Live | Live 100-record metadata projection passed; verify offline state |
| `lease status`, `renew` | Session Runs / Evidence | Prepared | Live active lease and independent Research watchdog readback |
| `lease reconcile` | Selected Run Lease | Prepared | Deploy Research completed-record lookup, then live local-close/Gateway summary review and durable Research readback |
| `time-sync` | Maintenance | Live | Confirm clock-attention state |
| `time-sync --apply` | Maintenance | Prepared | Live idle-run rejection and independently verified resynchronization |
| `snapshots` | Recovery | Live | Typed dry-run preview verifies policy, counts, free space, stopped stack, and GUI state; live apply preflight is unavailable |
| `snapshots --apply` | Recovery | Prepared | Whole-stack locked preflight, destructive review, and retained-ID readback; live milestones/free space unavailable |
| `verify` | Maintenance | Live | Live bridge returned 126 passed and six bounded failed-check names; rerun after protected deployment to establish boundary acceptance |
| `safety-audit` | Maintenance | Prepared | Verify full protected posture after deployed release matches reviewed source |
| `memory proposals` | Maintenance | Prepared | Live empty catalog readback and provenance inspector implemented; verify nonempty live record after protected deployment |
| `key-load` | Maintenance | Prepared | Explicit 1Password identity reload and readback of both SSH agent sockets; live post-reboot acceptance |
| `admin`, `target` | Maintenance | Prepared | Separate direct SSH windows use fixed installed config and destination; live terminal acceptance |
| `panic` | Maintenance | Prepared | Destructive confirmation, exact affected-VM summary, and independent Parallels readback; live emergency acceptance pending |

Archived tool-result browse and selected export now use verified transcript
records with per-result digests. The catalog reads a bounded verified
transcript file and keeps only selected result content in memory, so runs above
the 8 MiB preview ceiling can still expose tool results. A live archived run
returned 10 results and an independently matched selected digest. Future runs have session links in the v2
private catalog; a selected live export passed, while a run above the preview
limit still awaits live acceptance. Coordinated full backup
and restore are new operations, not
existing `labctl` commands. Their live cold acceptance remains before release.
