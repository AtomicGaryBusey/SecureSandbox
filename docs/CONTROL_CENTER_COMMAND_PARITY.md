# Control Center command parity

This is the implementation inventory for the operator commands in
`scripts/labctl`. **Live** means the app currently invokes a bounded,
versioned bridge or the installed protected launcher. **Gated** means the
reviewed implementation is deployed and its fail-closed live precondition has
been verified, but a legitimate production record or safety prerequisite does
not currently exist; the lab does not manufacture one merely for acceptance.
**Prepared** means live acceptance still requires an explicit disruptive
operator decision. **Implemented, not deployed** means the source, bridge, and
local build exist but the installed app has not received or live-accepted the
change. **Planned** means no GUI action exists yet. The app must not imply that
a gated, prepared, implemented-but-not-deployed, or planned action is currently
available.

| CLI operation | GUI home | State | Required next acceptance |
| --- | --- | --- | --- |
| `status` | Overview | Live | Live versioned readback passed in running and stopped states; intentionally stopped guests show unreachable without a control-identity warning; degraded fixture compiles |
| `start`, `stop`, `lifecycle-progress` | Overview | Live | App-driven Stop and cold Start showed phase, verified final results, and independent three-VM readback; the post-Start boundary suite passed 133 checks with no failures |
| `sessions`, `session runs` | Sessions | Live | Historical session browsing and an eight-run count passed; mixed v2 catalogs preserve old counts without invented links. A GUI resume of an existing one-turn session added its new run to the v2 catalog and read back the exact linked run without inventing historical IDs |
| `session label` | Sessions | Live | Native temporary private label save and catalog readback passed |
| `session unlabel` | Sessions | Live | Native explicit removal restored the unlabeled catalog row |
| `claude`, `claude --resume`, `claude --source`, `claude --lease-profile` | Session Terminal / Sources | Live | New, source-bound, and registered-session resume PTYs launch through fixed separate arguments; `/quit`, renewed-lease finalization, explicit cancellation, and red-X teardown pass. Close acceptance retains the off-window PTY while the controller closes its exact SSH child, then independently reads back a closed Gateway lease and committed Research lifecycle with zero requests |
| `source plan` | Sources | Live | Live branch and public release-tag plans returned resolved 40-character commits and expiries; query, subpath, and non-GitHub URLs were rejected |
| `source status`, `source apply` | Sources | Live | After Gateway source-controller deployment, the GUI read back a planned immutable commit, imported `octocat/Spoon-Knife` once, and showed its published source identity and catalog row |
| `source npm-plan` | Sources | Live | Exact-version provenance review, independent planned/completed status, one-time npm import, and source-catalog readback passed for `rc@1.2.8`; exact repository/commit duplicates are now rejected before submission and surfaced as the existing Sources entry |
| `sources` | Sources | Live | Live 11-source catalog passed; verify offline and long catalog states |
| `corpus index`, `codegraph index` | Sources | Live | Builds remain one-shot per sheet; typed status probes now reconcile ambiguous outcomes without rebuilding. Live readback recovered ai-passport's sealed corpus (27 documents) and CodeGraph (246 nodes) indexes by exact digest, and a fresh left-pad source returned `not_indexed` without starting work |
| `dependencies plan`, `status`, `apply` | Sources | Live | Unscoped-package contract repair was deployed; an exact `left-pad@1.3.0` plan, independent status, zero-dependency sealed apply, exact set-digest match, and catalog readback passed with lifecycle execution disabled |
| `dependencies list` | Sources | Live | Native sealed-bundle browser decodes the nonempty live catalog and projects root package, direct count, creation time, bundle ID, and grouped set digest |
| `findings` | Findings | Live | Live 13-finding catalog passed; verify support and adjudicated states |
| `finding show` | Findings | Live | Detail shows bounded evidence and history; native JSON save with matching provenance digest and mode-0600 files passed; inspect long cases |
| `finding apply` | Findings | Gated | The current adjudication package and archive readback are deployed; 84 isolated mutation/bridge/deployment tests pass and a live 16,385-byte request was rejected at the 16 KiB limit. Positive transition, relation, reopen, and disposition acceptance requires an operator-reviewed finding; all current candidates are substantive evaluation records |
| `finding disposition-status` | Findings | Gated | The protected read-only archive-marker command is deployed and boundary verification passes its root-only control; a real terminal archive will be verified when an operator legitimately disposes an adjudicated finding |
| `artifacts`, `artifact` | Evidence | Live | Live 73-item verified Azure catalog passed; one-pass identity retrieval reduced the measured CLI catalog read to about 7 seconds; selected preview and native text export with provenance passed, including independent original/rendered digests and mode-0600 files |
| `transcript` | Evidence | Live | Live selected export verified 145 records, SHA-256, and mode 0600. Tool-result browsing reads the independently verified private transcript rather than the 8 MiB whole-preview response; a future naturally large run remains scale coverage, not a protocol prerequisite |
| `logs` | Activity | Live | Live 100-record metadata projection passed; verify offline state |
| `lease status`, `renew` | Session Runs / Evidence | Live | A short-profile zero-request run read back closed; a second active lease renewed by the minimum five minutes with the same lease identity and independently verified renewal count. The renewed-session cleanup repair is deployed and red-X teardown independently closed and committed a later zero-request run |
| `lease reconcile-plan`, `reconcile`, `completed` | Selected Run Lease | Live | A renewed run intentionally exposed invalid final-summary handling; native plan bound the closed Gateway summary digest, reconcile committed the matching Research lifecycle, and a separate completed readback matched run, lease, and digest |
| `time-sync` | Maintenance | Live | Confirm clock-attention state |
| `time-sync --apply` | Maintenance | Live | Native apply completed and independently verified all three guest clocks |
| `snapshots` | Recovery | Live | Typed dry-run preview verifies policy, counts, free space, stopped stack, and GUI state; fresh cold readback had adequate free space and correctly reported that the restored VM set has no policy milestones |
| `snapshots --apply` | Recovery | Gated | Whole-stack locked preflight, destructive review, and retained-ID readback are implemented and tested; live apply correctly remains unavailable because the current VM set has no required retained milestones |
| `verify` | Maintenance | Live | After protected deployment, cold Start, and the accepted restore, the complete boundary suite passed 133 checks with no failures or gate notices |
| `safety-audit` | Maintenance | Live | The current 16-payload protected release, complete boundary suite, exact guest policy hashes, and recent off-host evidence passed; host-direct tier 0 remains separately visible and does not weaken the isolated launch-path result |
| `memory proposals` | Maintenance | Gated | Live empty catalog readback passed and the provenance inspector has focused fixtures. A nonempty inspection requires a naturally submitted untrusted proposal; none currently exists |
| `key-load` | Maintenance | Live | Explicit post-reboot identity reload verified both dedicated SSH agent sockets without exposing key material |
| `admin`, `target` | Maintenance | Live | Each exact fixed PTY command used by the native windows opened its intended Research or Target administrator prompt and exited cleanly without running a guest command |
| `panic` | Maintenance | Live | Live bridge acceptance stopped Research and Target, disconnected Gateway net0, reasserted automatic gamepad sharing off after Parallels changed it, and independently verified containment; the following Start reconnected and re-hardened Gateway before a complete 133-check boundary pass |
| Model profile catalog save | Settings → Models | Live | The ignored mode-0600 catalog, closed adapter schemas, 64 KiB/16-profile bounds, native edit/reload, and inert-save contract pass local tests and bundle validation |
| Model profile activation | Settings → Models | Live | Exact GUI and Touch ID review binds the independently agreed current authority, adapter, vendor/model, mode, origin, provider/OAuth IPv4 pins, credential scheme/reference, settings, broker ceilings, pricing, lease bounds, profile revision, and plan digest. Safe-mock activation first created the explicit Research binding; a separate production ceremony restored the reviewed profile with encrypted broker-only credentials and pinned provider addresses. Durable Host/Gateway/Research receipts agree, admission fences reopened only after exact readback, profile-bound lease validation passes, and a verified cold Stop/Start preserved production authority through a complete post-boot boundary pass with the attested authorization-icon Host release. |
| Native vendor stack catalog save | Settings → Models → Native Vendor Harness + Model Stack | Signed preflight; fenced | The installed notarized `0.2.0` build `2` reached this surface but a direct broker query rejected before classification because dynamic and static Security.framework flags were mixed. The tested source repair keeps live audit-token validation authoritative and applies whole-bundle checks separately. The same checkpoint replaces the overflowing fixed-width mode selector with a responsive compact/stacked layout. The Host and app repairs await reinstall, broker readback, and visual acceptance; saving remains inert and grants no login or activation authority. |
| Native vendor sign-in, program attestation, and stack activation | Settings → Models → Native Vendor Harness + Model Stack | Implemented, not deployed | Source separates Claude's vendor-owned opaque login from OpenAI SIWC Host custody, labels the CVP/Daybreak declaration as operator-declared rather than provider-verified, uses exact Touch ID plans for every mutation, and independently rereads provider, egress, catalog, process, and recovery state. Touch ID requires an explicit click—Return never authorizes—and the broker holds the exact request inodes through biometric review and commit. Swift-parent/Python-supervisor liveness, one-shot invalidation, process-group teardown, the exact privileged-stream handshake, and strict longest-path deadlines `1440 < 1500 < 1560 < 1620` close cancellation and abandoned-UI authority. Exact Developer ID packaging, protected three-plane deployment, admitted harness generations, provider login/entitlement, and hostile live credential probes remain `unverified`; disabled or ambiguous state grants no authority. |
| Native vendor session start, typed interaction, and stop | Settings → Models → Native Vendor Harness + Model Stack | Implemented, not deployed | A fresh plan binds the complete Research-measured runtime authority and exact lease. Claude uses a one-attachment no-capture terminal; Codex uses only the schema-pinned typed app-server protocol with Daybreak Blue on every qualified turn. Each vendor child re-arms its parent-death SIGKILL after credential drop and remains stopped until an exact pidfd-backed owner scope, owner/supervisor dependency edges, group-wide SIGKILL policy, transient fragment path, and kernel-enforced 256-task/4-GiB/zero-swap/300%-CPU ceilings are proved. Each Codex run also requires a fresh PID/start launcher receipt, a receipt-bound private fd-7 gate, a projection permit capped by the exact session lease, an exact proxy-only environment, journaled scratch device/inode custody, and fresh hostile qualification of the same process. The whole transient cgroup remains frozen through the final quiet drain and typed READY write and thaws only on successful READY. Window close, EOF, cancellation, expiry, owner loss, and explicit stop converge on exact process, projection, lease, egress, owner/vendor cgroup, and stable absence readback. Signed installation, real Linux/systemd behavior, visual/close-path acceptance, and disposable/live provider evidence remain pending. |
| Native OpenAI projection identity import and closure reconciliation | Settings → Models → Native Vendor Harness + Model Stack → Exact projection custody recovery | Implemented, not deployed | Identity import and final reconciliation are distinct direct-root-broker plans and distinct Touch ID ceremonies. Import is content-free and read-only; reconciliation exact-binds PID/start generation, executable, session authority, stack, Host release, guest absence, and egress closure before one ledger row can clear. The v2 helper ledger never persists a zero-PID pending row, and Host activation now rejects an unexpected legacy v1 ledger before the candidate release can become current. Cancellation and parent/supervisor loss invalidate the held request and reap projection/SSH descendants; an absent reply remains ambiguous until durable status is queried, with no manual-kill or journal-deletion recovery. Signed/notarized installation and crash-window/disposable acceptance remain pending. |
| Protected native deployment and catalog recovery | Settings → Models → Native Vendor Harness + Model Stack → Protected native deployment | Host floor migrated; guests pending | The one-time Host Developer ID/coordination-floor migration completed for the exact installed release retained in protected local evidence; no native catalog or guest runtime was promoted. The app reads exact deployment and catalog gates from the root-peer-authenticated broker, identifies the current Host separately from historical publication provenance, reviews canonical plan/package/predecessor digests, and authorizes apply or broker-admitted resume/rollback with fresh Touch ID. Catalog recovery can replay only retained exact authority. Installation and recovery require quiescent readback for native run scopes, bounded Claude command services, and exact owner scopes; unexpected units fence the operation with no manual-delete bypass. The mutation branch nests the 3,900s root operation inside 4,140s ceremony, 4,200s API, and 4,320s Swift deadlines; the separate 4,020s direct-recovery branch is bounded by the Swift deadline. The current source descendant, protected guest deployment, and three-plane acceptance remain pending. |
| Control Center update check | Settings → Updates / app menu | Implemented, production-gated | Manual and opt-in scheduled checks can fetch only bounded signed metadata. The current installed development build reports the channel as unprovisioned until the Developer ID/notarization and GitHub release trust roots exist; it offers no bypass. |
| Control Center update download/install/rollback | Settings → Updates | Implemented, production-gated | Exact release identity, impact, compatibility, artifact and envelope digests are reviewed before a separate manual download. The helper repeats signature, digest, Developer ID, hardened-runtime, Gatekeeper, monotonic-floor, fixed-path, and fresh Touch ID checks before atomic replacement. Production acceptance requires two notarized releases and the approved GitHub endpoint. Automatic download and installation do not exist. |

Archived tool-result browse and selected export now use verified transcript
records with per-result digests. The catalog reads a bounded verified
transcript file and keeps only selected result content in memory, so runs above
the 8 MiB preview ceiling can still expose tool results. A live archived run
returned results and an independently matched selected digest. A native
selected-result JSON save matched its recorded byte count and SHA-256, with
mode-0600 content and provenance files. Future runs have session links in the v2
private catalog; a selected live export passed. A naturally occurring run
above the whole-preview limit remains additional scale coverage because the
tool-result path verifies its private transcript independently. The transcript CLI now uses one archive
identity lookup per run while preserving per-chunk digest and chain checks;
a live 286-record read completed in about 6 seconds. Artifact, finding, selected tool result,
and transcript saves can now add a bounded, mode-0600 provenance sidecar
without replacing an existing one. Coordinated full backup and restore are
new operations, not existing `labctl` commands. A fresh aligned cold backup on
the operator's encrypted external APFS volume completed with an authenticated
terminal record covering 64 files and 27.88 GB. Routine status refresh checks
the signed completion metadata; Recovery's Verify & Preview action separately
rehashed every archived file and confirmed the stopped stack and matching host
configuration. Two earlier live restore attempts exercised complete automatic
rollback and independently restored the original stopped VM registrations.
The fresh Touch ID UI development profile and reviewed controller are now
deployed, and a cold Start passed all 133 boundary checks before the aligned
backup. Restore admission requires four hours of signing-profile transaction
headroom above the boundary verifier's 48-hour floor, and rollback status
preserves the lifecycle's bounded failure reason. After approved temporary
cache offload restored the required reserve, one aligned-generation restore
reached authenticated `verified` / `accepted` completion. Independent status
found all three replacement VMs running and reachable, the complete boundary
suite passed 133 checks, and a subsequent verified Stop read back all three
VMs stopped. Accepted-generation retirement remains separate. Recovery now
has a bounded retirement preview, destructive confirmation, lifecycle-locked deletion,
authenticated durable readback, and lost-terminal-status reconciliation for
both a rolled-back candidate and the previous generation after acceptance. A
live preview verified the accepted restore's previous generation as 77 entries
and 27.88 GB; deletion remains pending separate explicit operator confirmation.
Status-key
readback retries bounded transient 1Password CLI failures without exposing
vault diagnostics. Earlier disposable encrypted APFS preflight fixtures were
detached and removed after their checks.
