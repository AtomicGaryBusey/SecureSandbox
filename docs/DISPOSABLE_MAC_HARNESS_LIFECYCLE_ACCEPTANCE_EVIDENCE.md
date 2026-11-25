# Disposable-Mac Harness Lifecycle Acceptance Evidence

Status: every superseded exact-commit campaign on the disposable Neo remains
retained without deletion. The current live campaign is bound to exact public
source `1965de0...`; it has 40 of 91 cases complete and 198 validated
root-owned observations. The first Touch ID case has not been prepared or
authorized. No complete acceptance verdict has been issued.

## Current physical checkpoint — 2026-11-23

The Neo's three original VM identities were preserved while all five virtual
network adapters were migrated to the supported `e1000` backend. Independent
readback proved the exact MAC/topology bindings, private non-NAT networks,
disconnected Gateway Shared adapter, absent migration journal, and unchanged
VM bundle identities. The acceptance-only bootstrap then reached its required
steady state: Gateway and Research running and reachable, Target stopped and
unreachable, Gateway Shared disconnected, and no production model or provider
material present.

The exact protected `1965de0...` release completed both bootstrap cases, all
sixteen provenance cases, all twelve archive cases, and all ten Research
qualification cases. Production ordering independently reports 40/91 complete
with `touchid-approve-exact-plan` next. The campaign and all existing raw and
projected evidence remain unchanged.

The first protected authorization preparation failed closed before it created
a case directory, plan, broker request, or Touch ID authorization. The same
read-only `harness-generation-status` call succeeds as the admitted login user,
but the root execution path fails at the Gateway proxy with
`gateway_proxy_rejected` and SSH status 255. Source review confirmed a
fresh-Mac integration defect: the signed Host SSH configuration gives the
login user mutable `%d` trust paths, while the root authorization daemon invokes
the same client without an enrolled machine-trust projection or a privilege
drop to the admitted operator. The VM and Research service are healthy; this is
not a guest reachability failure.

Do not work around the defect by copying or symlinking mutable user files into
`/var/root`, weakening `vm_maintenance`, changing the campaign source, or
retrying the Touch ID case. The campaign-preserving repair is a compatible
signed Host release followed by a separate exact Touch ID-only machine SSH
trust enrollment. The enrolled store contains only canonical public keys and
exact HostKeyAlias records in immutable root-owned generations; private keys
remain solely in the ephemeral operator-owned agents. The repaired control
client validates the fixed signed configuration, machine/operator binding,
trust generation, public-key fingerprints, host-key aliases, and agent-socket
ownership before it drops ordinary SSH children to the enrolled operator UID.
The signed Gateway ProxyCommand enters the same validator and drops its fixed
Parallels resolver to that operator, so immutable campaign drivers that invoke
OpenSSH directly as root cannot bypass the projection and never run
`vm_maintenance` as root.
Publication, notarized Host installation, trust enrollment, independent root
Research readback, and resumption of case 41 remain pending.

The first attended install of the transferred `4595cea...` candidate consumed
Touch ID request `a56117ee...` and plan `277c3b22...`, then failed before a
transition with `native_credential_console_user_unavailable`. Its canonical
failed receipt has empty stderr and retained stdout digest `9fa4b402...`.
Independent public readback proves current release `a585d8f7...`, previous
release `b3d6600...`, and no PENDING record. The exact receipt-bound recovery
correctly rejected `runtime_metadata_receipt_recovery_error_mismatch`; the
receipt is spent and replay is forbidden.

The environmental contradiction is independently reproduced on macOS 27.2.1:
`/dev/console` is a root-owned character device while both `scutil` and direct
SystemConfiguration inspection identify the completed on-console
`alextester` session as UID 501/GID 20. Disconnecting Screen Sharing does not
change either fact. The source repair keeps a non-root `/dev/console` as the
established authority and requires any available dynamic-store identity to
agree. Only a root-owned device node activates the fallback, which requires
two identical structured dynamic-store reads and a known non-root account with
matching UID/GID. Nil, root/loginwindow, unknown-account, unstable-read,
non-character-device, and explicit mismatch cases fail closed in that
root-owned fallback. An established non-root device owner tolerates only two
consecutive nil structured reads; structured errors, malformed identities,
one-sided nil, and disagreements fail closed. The structured reads now use an
absolute, fixed-input `/usr/sbin/scutil` child
with a closed environment, 16-KiB output ceiling, and two-second timeout. This
replaced an initially tested direct framework call after the exact publication
suite proved that call could block indefinitely in a nested verifier process.
Seven focused tests pass; the
complete Host manager suite passes all 302 applicable tests
with two intentional skips (301 in the sandbox plus the one temporary-socket
test rerun outside it). A transferred inert copy of the patched manager returns
`dynamic: (501, 20)` and `admitted_uid: 501` on the live Neo. Publication,
notarization, fresh authorization, and independent installed readback remain
pending.

The portable-fingerprint successor was then published as exact commit
`1e4f7a7...` to both authorized remotes and built as Developer ID/notarized
submission `b2de8d6c...`. Neo transfer verification retained the exact
candidate, after which the password gate staged inert successor release
`9030aa65...` without changing either selector, the launcher, or the stable
Host pair. Fresh Touch ID request `df7c8644...`, bound to target plan
`795209ce...`, reached the staged broker but its protected manager child
returned status 1 before transition publication. The canonical receipt is
`failed`, has empty stderr, and stdout digest `9fa4b402...`; exhaustive mapping
of the exact manager rejection records resolves that digest only to
`native_credential_console_user_unavailable`. Receipt-bound recovery rejected
`runtime_metadata_receipt_recovery_error_mismatch`, as designed. Independent
readback still proves current `a585d8f7...`, previous `b3d6600f...`, the prior
STABLE pair and terminal, and no PENDING record. The request is spent and must
not be replayed.

A later read-only root probe of those exact staged manager bytes returned the
canonical `scutil` UID 501/GID 20 identity and admitted UID 501. The same
immutable implementation therefore passes after the failed request, proving a
transient identity sampling window rather than a permanent root parser defect.
The next successor retains the previously selected hard-timeout `scutil`
boundary and adds a four-sample, fixed-interval stabilizer: only two
consecutive identical validated identities pass; unavailable, malformed,
changed, or oscillating samples reset the pair, and exhaustion fails closed.
The one-time source-slice digest now binds the query, stabilizer, and console
cross-check together. Python 3.13 on the release Mac and Python 3.9.6 on the
Neo independently produce digest `a65ee73f...`; the Neo's unprivileged
candidate probe returns UID 501/GID 20. Twelve focused console/recovery tests
and the complete 310-test Host-controller suite pass with two intentional
skips. The candidate transferred to the Neo is byte-identical to the release
Mac source (`3e9f954c...`). Its independently authorized root probe under Apple
Python 3.9.6 returned EUID 0, stable identity UID 501/GID 20, admitted UID 501,
the exact `a65ee73f...` repair digest with `digest_matches: true`, and exit 0.
Canonical publication, a fresh notarized successor, and physical activation
remain pending.

## Current physical checkpoint — 2026-11-19

The exact `0abefb4...` protected release completed both bootstrap cases, all
sixteen provenance cases, all twelve archive rejection cases, and
`qualification-no-preexecution`. Independent production validation reports
31/91 cases complete and the exact next case
`qualification-zero-production-authority`. The first qualification raw set
contains the canonical Research, quarantine, authority, and production scan
records; its two projected observations are root-owned mode 0444 and validate
against the production ordering path.

The next authenticated Research deployment returned status 1 two seconds after
the prior request was accepted. The Host supervisor had already reserved the
operator-owned case directory, but Research created no corresponding case
directory or worker output. A bounded authenticated diagnostic proved that
the four active-run markers and Claude process were absent, the staged and
installed seven-file release closures matched byte-for-byte, the Research
campaign matched, and the only installed qualification fixture remained the
completed first case. The content-free Research control audit binds the prior
accepted request and the later `command_failed/status_1` request. Production
ordering remains on the second case. The campaign must not be retried or have
its reservation removed.

The repair makes future supervisor rejection canonical: it records one
source/campaign/case-bound `control-rejection.json` with authority `none`, no
production-material use, unresolved Research state, and `retry_permitted:
false`, then returns a stable content-free error instead of an escaping Python
traceback. A distinct append-only retention command handles this newly observed
31-case/36-observation layout. Before its first mutation it verifies the clean
published descendant on both authorized remotes, machine identity, immutable
predecessor, and diagnostic source against the descendant's exact Git blob. It
then validates the bounded supervisor output and control-audit capture, writes
exactly one derived rejection record into the otherwise empty reservation,
validates every prior protected observation and retained raw file, and
atomically moves the entire campaign without overwrite. Its
publication, protected successor installation, live retention, and fresh
campaign replay remain pending.

## Prior physical checkpoint — 2026-11-18

The exact `91169ee...` ten-driver release is installed and ready. A clean
campaign replay completed bootstrap, provenance, and archive with exactly 34
root-owned, mode-0444, single-link observations. The repaired Research
qualification path then completed `qualification-no-preexecution` through
authenticated privileged control and produced the complete canonical
Research, quarantine, authority, and production-material raw set. This proves
the former `systemd-run --wait`/`RemainAfterExit` deadlock is fixed.

The outer wrapper mistakenly invoked the source qualification projector as the
operator. It published exactly two canonical mode-0600 files owned by UID 501.
Production ordering correctly rejected them with `input_file_untrusted` and
the wrapper stopped before the next case. Nothing was chmodded, rewritten,
deleted, or relabeled. The repair preserves source projection as test-only and
adds an exact-installed-release root projection mode: it pins the operator's
campaign, raw, and observation directories by descriptor; revalidates all
prior root observations and the complete four-record raw set; stages canonical
snapshots; and publishes only root-owned mode-0444 records with exclusive
creation and resumable validation.

A distinct no-delete retention mode accepts only this precise mixed-custody
state: the exact 30/34 protected prefix, the four operator-owned qualification
raw records, and exactly the two suite-assigned operator-owned projections.
Its isolated diagnostic loads the exact protected predecessor, revalidates the
raw-to-observation bindings, and must independently reproduce
`input_file_untrusted`. It records protected Host and Research state as
retained in place and atomically renames the entire campaign without overwrite.
The projector/retention descendant `a224353...` passed the complete local
publication gate twice, was published to both authorized remotes, and was
installed on the Neo as a root-owned mode-0555 release with a root-owned
single-link mode-0444 manifest. Independent readiness reported all ten drivers
available. Its first real retention invocation failed closed before plan
publication or rename because the isolated `91169ee...` predecessor applied a
one-hour live-consumption window to raw records collected earlier in the same
campaign. Readback proved the live pathname, 36 observations, four raw
records, and absent destination unchanged.

The compatibility repair independently derives one common `observed_at` from
the three stable canonical auxiliary records, bounds it to the campaign and
current time, passes it explicitly into the isolated child, and requires that
child to re-read the same value before the predecessor validates every record
and digest. Current time still stamps the retention diagnostic. A read-only
physical probe of the complete repaired parent/child path against the actual
Neo evidence reproduced canonical `input_file_untrusted` and bound all four
raw and both projected-observation hashes. Publication, protected installation,
one fresh retention attempt, independent verification, and a fresh replay
remain pending.

## Prior systemd-wait checkpoint

The fresh `469c3e4...` campaign physically replayed both bootstrap cases, all
sixteen provenance cases, and all twelve archive cases. Independent inventory
readback found exactly 34 observations, each root-owned, mode 0444,
single-linked, and accepted by the production ordering validator. Its first
qualification request reached the authenticated Research root dispatcher, but
the protected installer returned status 120 after exactly 120 seconds. The
installed systemd-run help proves why: `--wait` waits until the service is
stopped again, while the driver also set `RemainAfterExit=yes` and deferred its
stop to the `finally` block that could run only after `--wait` returned. The
Host reservation remains empty and no qualification observation exists. The
campaign must not be retried.

The source repair removes only `--wait`, retains default blocking start-job
behavior, and continues to prohibit `--no-block`. Thus the Type=oneshot worker
must finish before readback while the retained successful unit remains
`active/exited`. The progressed-campaign retention diagnostic now binds this
third historical path as
`authenticated-control-systemd-wait-deadlock`; the direct-admin and normalized
readback forms remain valid only for their exact retained predecessors.
Focused qualification and retention tests pass. Publication, no-delete
retention of `8fb982a9...`, successor installation, and fresh replay remain
pending.

## Retained normalized-readback checkpoint

The `cf46041...` successor release was published to both authorized remotes,
installed root-owned on the Neo, and passed the complete ten-driver readiness
readback. The prior `4bbd26aa...` campaign was retained by its no-delete
ceremony and independently verified. A fresh campaign `a4b764b6...` then
physically replayed both bootstrap cases, all sixteen provenance cases, and all
twelve archive cases. Independent inventory readback found exactly 34
observations, each root-owned, mode 0444, single-linked, and accepted by the
production ordering validator.

The repaired qualification supervisor did use authenticated privileged
control. Research accepted the `securectl` identity, ran the root dispatcher,
installed the exact `cf46041...` seven-file closure, and successfully completed
the isolated `qualification-no-preexecution` worker with zero restarts and exit
status zero. The Host correctly projected no observation because the outer
Research driver rejected systemd's physical readback. On this VM, systemd
normalizes `IPAddressDeny=any` to `0.0.0.0/0 ::/0` and reports
`ControlGroup=` empty after removing the completed transient cgroup. The driver
incorrectly required the literal `any` and a nonempty cgroup path. This is a
systemd-readback compatibility defect, not a failed qualification outcome.
The raw Host reservation remains empty; the exact campaign must not be retried.

The source repair accepts only the two exact semantic deny-all renderings. It
accepts an empty `ControlGroup` only when the deterministic exact-unit cgroup
path is absent, and records whether the cgroup was present or already removed;
a present cgroup still must have no processes and `populated 0`. The existing
progressed-campaign retention diagnostic now distinguishes the historical
direct-admin defect from this authenticated-control systemd-readback defect
while preserving both old verifier forms. Focused qualification and retention
tests passed. The campaign was then retained by its no-delete ceremony and
independently verified; exact successor `469c3e4...` was installed and the
fresh `8fb982a9...` replay produced the current checkpoint above.

## Retained direct-admin predecessor checkpoint

The retained predecessor campaign `4bbd26aa...` physically completed both bootstrap cases, all sixteen
provenance cases, and all twelve archive cases. Independent inventory readback
found exactly 34 observations, each root-owned, mode 0444, single-linked, and
accepted by the production ordering validator. Gateway and Research remain
running, Target remains stopped, and Shared remains disconnected. Those states
must not be changed merely to simplify source repair.

The first qualification attempt reserved only the private empty
`raw/qualification/qualification-no-preexecution` directory and then failed
closed with `supervisor_command_rejected`. It created no qualification
observation. Source and installed-release analysis proved the historical Host
supervisor deployed the root-only Research driver through authenticated
control, but then attempted to execute that driver through the unprivileged
`sandbox-research-admin` SSH identity. The Research driver correctly requires
effective UID zero, and the admin identity has no passwordless sudo. This is a
control-path defect, not a failed qualification outcome, and the case must not
be retried under its old exact source.

The repair makes authenticated privileged control the sole deployment and
execution boundary. The Host sends the exact campaign, source, fixed
qualification case, installer, and payload closure in one authenticated deploy
request. The root-side installer validates the case against the ten fixed
qualification IDs, revalidates and installs the exact release, and immediately
executes the protected driver as root. Direct Research-admin execution is
removed. Focused qualification and retention tests pass, including a regression
that makes any direct command path fail.

Because an exact-source campaign cannot consume that repair, the existing
atomic no-overwrite retention tool now has a distinct progressed-campaign
ceremony. It requires the exact 30-case/34-observation prefix, revalidates the
production next-case result, requires every prior observation to remain
root-owned mode 0444, checks the two historical bootstrap raw bundles, and
requires the qualification reservation to remain empty. An isolated diagnostic
loads the exact protected predecessor, proves its historical direct-admin path
and root-only driver requirement, and binds the reservation identity and source
hashes. The plan records the Host and Research campaign-keyed protected state
as retained in place; the retention operation does not delete, overwrite, or
reuse either protected state tree. The operator campaign directory moved
atomically without overwrite to its UUID under the retained-campaign root and
passed its separate read-only verifier. Its successor release installation and
fresh replay produced the retained normalized-readback checkpoint above.

The exact `35dd424` protected ten-driver release is installed root-owned on the
Neo. Its complete manifest passed independent readiness with ten available
drivers and zero missing, rejected, or errored closures. Pre-install and
post-install stopped-inventory bridge receipts passed the exact consumer, and
all failed predecessor bridge attempts remain retained. The wiped Neo's two
ephemeral SSH identities were restored directly into separate agents from the
Agents vault without writing private key material to disk; public fingerprint
readback passed before any lifecycle attempt.

The first ordinary campaign startup rejected before VM mutation because the
wiped Neo correctly lacked the local vault tooling required by `labctl
key-load`; the in-memory identity restoration closed that prerequisite. The
next ordinary startup also rejected before mutation because Parallels Desktop
27.1.0 removes its per-user service when its GUI exits while all VMs are
stopped. Independent readback proved all three VMs remain stopped, the GUI and
service absent, and `prl_bglaunch` unsuitable because it launches the GUI
client. The source repair adds only an explicit Gateway-first service bootstrap
under the existing lifecycle lock, then requires GUI absence and exact
Gateway-only readback before the ordinary closed-GUI controller can continue.
The first published physical execution started only Gateway and proved the
exact intermediate inventory, then rejected because Parallels returned
`User canceled (-128)` to its Apple-event quit. SIGTERM also left the bound PID
resident. Exact-PID SIGKILL removed only that GUI and independent `prlctl`
readback proved the service plus unchanged Gateway-only state survived. The
ordinary controller then started Research and Target and proved authenticated
reachability plus zero clock skew, but correctly rejected when the broader
production boundary verifier found this factory-reset acceptance baseline is
not a deployed production lab. That rejection is retained and must not be
relabelled as acceptance evidence. The protected collector has not been
invoked and its raw destination remains absent.

Source follow-up now preserves that production rejection while defining the
distinct acceptance baseline it exposed. The fixed acceptance start binds the
exact campaign, current clean commit, next `bootstrap-clean-install` case, and
complete protected driver inventory before mutation; requires Gateway egress
already disconnected before its first power-on; starts only Gateway and
Research; leaves Target stopped; rejects active or unreconciled Research run
state; and validates the existing protected Host, zero-generation Research
store, and independent boundary readbacks without reserving or projecting any
evidence. The collector independently rereads that exact GUI-closed VM,
uplink, and reachability inventory and embeds its self-digested campaign-bound
stack readback inside the Host raw receipt; direct collection from a connected,
Target-running, or ambiguous stack rejects. Regular stop sends exact
authenticated poweroff requests to Target and Research, dispatches Gateway's
request last, immediately disconnects and rereads Gateway `net0`, and then
requires independent stopped-state readback for all three. An earlier guest
failure also isolates Gateway before rejection. This provides the no-egress
all-stopped baseline without any Parallels VM-stop action. Post-power
reconnection and emit-time state drift are terminal
failures rather than repairable success. This implementation was published and
physically started on the Neo.
That first stop safely disconnected Gateway egress, then failed closed before
any VM stopped because its guest-control shutdown still depended on the now-
disconnected Shared adapter. Independent readback retained all three VMs
running and `net0` disconnected. The first corrective descendant selected
local `--acpi`, then physical replay exposed Parallels 27.1.0's undocumented
120-second forced-stop fallback: the controller rejected after its own bounded
readback, but the still-pending vendor transition later force-stopped Target.
Independent readback found Target stopped, Research and Gateway running, and
`net0` still disconnected. Physical probing of the next descendant then proved
that `--noforce` is a Parallels-Tools consent path: with Tools deliberately
absent it reports that guest shutdown is unavailable and leaves the VM running.
The current source descendant therefore prohibits every `prlctl stop` form and
returns to the already-authenticated guest poweroff operation with corrected
ordering. Target and Research stop before the Shared transport is removed;
Gateway's request is dispatched last, its uplink is immediately isolated, and
all completion remains subordinate to independent readback. A later immutable
review found one more low-severity edge: an inventory failure after valid
preflight could reject without invoking isolation. The current source routes
every post-preflight lifecycle exception through the same verified disconnect
path and tests both proven and unproven isolation. Source fault tests pass;
publication and physical replay remain pending.

The first immutable security review of that source follow-up reproduced one
low-severity source-binding defect: an absolute-path controller could verify a
different clean current working directory instead of the checkout that supplied
its executing modules. The repaired preflight passes its own resolved `ROOT`
to the existing clean-checkout verifier, and a regression requires that exact
argument. A foreign clean checkout can no longer lend its commit proof to
modified controller bytes. A fresh review of the repaired bytes remains a
publication condition.

The fresh replacement-campaign preflight exposed a Parallels 27.2.1 platform
boundary: `prlctl` becomes unavailable immediately after `prl_client_app`
exits, even while the dispatcher remains resident. Repeated read-only trials
proved the inverse as well: the exact stopped three-VM inventory is readable
while the GUI session exists and unavailable immediately after that client
terminates. No post-install preflight receipt or replacement campaign was
published. The source repair adds an explicit stopped-only bridge with a
120-second canonical receipt binding the exact commit and public tip, enrolled
machine, operator, stable GUI PID, all three stopped VMs, clean GUI exit, and
absent VM runtime processes. Morning preflight never silently falls back to
the bridge and independently revalidates its bindings and process absence. A
physical pre-install attempt then exposed an unnecessary post-install-only
consumer restriction: on this Parallels version that made exact protected
release upgrades impossible. The consumer now accepts the same zero-authority
all-stopped receipt before or after installation and independently derives the
only permitted next action from the exact protected-release readback.
Physical execution of the repaired boundary remains pending publication and
installation of its exact release.

The first `bootstrap-clean-install` collector rejected during preflight before
reserving its raw-evidence destination. Decomposition proved the campaign and
machine bindings valid and the invoking checkout clean at its exact public
commit. The installed supervisor had instead forced Git's working directory to
its immutable root-owned driver release, which intentionally has no `.git`
metadata. The repair makes the invoking checkout an explicit subprocess
boundary, requires it to be the physical repository top level, and verifies
the exact campaign HEAD plus a clean diff there. It does not treat the
protected release as a checkout or relax the root-owned driver manifest. The
same resolved checkout is carried into later recovery-source staging so that
every exact `git cat-file` read uses the repository already bound by preflight,
not the installed driver root. The focused acceptance suite passes, including
installed-layout and recovery-staging regressions. The rejected campaign
remains retained; no raw case directory was claimed and it must not be retried
with a driver that is not its exact source commit. The original clean-machine
preflight correctly rejects while that initialized campaign occupies the live
evidence pathname. A dedicated retention-only repair tool now accepts only
this zero-observation, zero-raw-evidence condition; binds the old campaign,
hardware, predecessor protected release, clean published descendant and the
disposable-Mac authorized remote tip; writes its plan into the campaign; and atomically moves the whole
directory without overwrite to the fixed retained-evidence root. It exposes no
delete/reset path. A separate read-only verifier resolves post-rename process,
fsync, or readback ambiguity from the exact retained campaign and plan without
moving anything again. The clean-machine preflight becomes applicable only
after the old campaign is durably retained under its UUID.
The first physical invocation published its immutable plan and then rejected
before the move because the tool had applied the private-leaf `0700` mode to
the legitimate owner-controlled `0755` SecureSandbox application-support
parent. No raw evidence moved and the campaign remained at its live pathname.
The compatibility correction admits only `0700` or non-group/non-other-writable
`0755` for that one parent; campaign, raw, handoff, retained, and plan objects
remain on their strict private modes. Because that plan is bound to the exact
earlier replacement commit, the repair now preserves it byte-for-byte and
extends it with an append-only, self-digested supersession chain. Every link
binds the prior authority digest, old and new descendant commits, remote tip,
machine, operator, campaign, inventory, and destination; forks, gaps,
collisions, non-descendants, and altered prior records are rejected.

The replacement release installed and a fresh locally recorded campaign
initialized at `9307776`. A read-only
prerequisite probe stopped before raw-evidence reservation because the Research
lifecycle inspector was absent. Its first transactional deployment then rolled
back to the same clean absence after exposing an installed-layout import bug:
source layout resolved `<repo>/shared`, while the installed closure correctly
places dependencies in the inspector's sibling `shared/` directory. The repair
recognizes the repository layout explicitly; otherwise it requires the complete,
non-symlinked sibling dependency closure and ignores unrelated grandparent
directories. Installed-layout and fail-closed dependency regressions cover the
boundary. The campaign remains
zero-observation and zero-raw-evidence pending exact-source repair.

The replacement import repair installed and initialized a fresh exact-source
campaign, but the next transactional Research deployment stopped before raw
evidence reservation at its first installed inspector readback. The installer
had created only the two top-level store directories, while the deliberately
non-mutating inspector correctly rejected the missing canonical empty-store
closure. The repair initializes that closure through the lifecycle manager,
using a dedicated command that accepts only two trusted, exactly empty roots.
It rejects any partial prior executable closure or nonempty store, reads the
new boundary back as exactly zero-generation, then asks the read-only inspector
for independent verification before checking that recovery is not pending.

The published ten-driver correction passed the
complete local release gate (2,639 tests, three expected skips), reached both
authorized `public-release` tips, and was installed as a new protected
ten-driver release on the Neo. Its fresh campaign was initialized with zero
observations. Transactional Research deployment then succeeded: protected
readback reported control role `research`, a verified zero-generation store,
open admission, no pending recovery, and an independently matching verified
boundary.

The first one-shot `bootstrap-clean-install` collection reserved its private
raw case directory and rejected with `bootstrap_host_receipt_invalid` before
writing an artifact. Source and live shape analysis found no Host verification
failure: the production verifier returns six security bindings added after the
collector's obsolete five-field release allowlist—stable pair, candidate
authority, release-tree identity, Developer ID team, Developer ID floor, and
the floor's establishing release. The repair requires all of those fields and
the exact authorized team instead of weakening the production receipt. The
reserved directory remains untouched and the collector has not been retried.
The new reserved-bootstrap retention ceremony admits only that exact empty
reservation and fixed error, retains the whole failed campaign without
deletion, and must be independently verified before another campaign starts.
Its plan embeds a diagnostic produced by rerunning, in a fresh isolated Python
process with an allowlisted environment, the exact installed
predecessor's read-only Host verification and reproducing the same rejection;
the classification is therefore not based only on operator recollection.

That failed campaign was retained and independently verified. A corrected
ten-driver protected release was installed and a fresh exact-source campaign
initialized. Its read-only Research prerequisite again proved role `research`,
an open zero-generation store, no pending recovery, and an independently
matching boundary. The first collector then succeeded once and wrote the exact
three raw clean-install records. The source projector also produced all three
validly bound observations, but—as designed for a non-authoritative source
surface—created them operator-owned mode `0600`. Production `next` correctly
rejected those files with `input_file_untrusted`, because physical observations
must be root-owned mode `0444`.

This is retained failure evidence, not a reason to repair permissions in
place. The correction adds an exact-installed-release root projection ceremony
and leaves source projection untrusted. A third no-delete retention ceremony
accepts only this exact three-raw/three-observation layout, replays the
predecessor's raw and observation validators in an isolated interpreter, and
requires the same production rejection before moving the complete campaign.
No file is overwritten, deleted, `chown`ed, or `chmod`ed. After independent
verification, a fresh campaign can collect once and use the protected
projector to create root/read-only observations.

Security review of the first protected-projector patch found a same-UID parent
substitution race between pathname validation and root publication. The
projector now keeps the validated raw and observation directory descriptors
open through inventory, creation, and fsync, uses only descriptor-relative
file operations for protected inputs and outputs, and requires final named-path
identity equality. A regression renames and replaces the parent after opening
it and proves the root write remains confined to the original descriptor.

The next exact-source campaign installed protected release `b3e178f`, passed
its ten-driver postflight, and
collected `bootstrap-clean-install` exactly once. Its first protected
projection failed closed before publication with
`bootstrap_protected_release_required`. Root-context readback isolated the
defect: the projector reused source-checkout readiness against the immutable
runtime release, so it demanded the Host installer source file even though
that file is intentionally outside the provenance and archive runtime
closures. The corrected preflight validates every fixed protected-driver
manifest and payload closure directly from the exact release instead. It does
not weaken inventory, ownership, digest, source-commit, or root-execution
requirements. Regression coverage proves both that build-only source is not
required at runtime and that any invalid protected closure still rejects.
Because that correction belongs to a different exact protected release, it
does not resume the predecessor campaign. A fourth no-delete ceremony accepts
only the exact three-raw/zero-observation layout, reproduces the predecessor's
two missing source-only readiness dependencies, verifies all ten driver
closures from both the predecessor and replacement root-owned releases, and
binds both manifest digests into its plan. The failed campaign and zero-byte
command result are retained unchanged and independently verified; a fresh
replacement-bound campaign must recollect before protected projection.

The operator-attended `7fec2bd` Touch ID request was consumed but did not
select its candidate. Receipt-bound recovery rejected an initial non-canonical
launchd snapshot while the restored predecessor KeepAlive process was being
replaced. Independent readback proved the verified predecessor selected,
`previous` absent, and its daemon running as PID 69540. The spent request is
non-replayable. The staged read-only stabilization repair requires two identical
canonical initial snapshots before any bootout decision; focused regressions
and all 376 Host/deploy tests pass (2 skipped). A sealed Codex Security diff
scan reviewed all nine changed source and test files and completed with zero
findings.

The next reviewed `c9e6da1` request was also consumed without selecting its
candidate. Its transition terminalized `source_restored`; independent readback
proved the same predecessor selected and verified, `previous` absent, and the
restored daemon running as PID 71627. Physical evidence localized the remaining
ambiguity after the single successful bootstrap, before stable-running
readback. The next staged barrier never resubmits that successful bootstrap,
waits through only the exact non-canonical snapshot, requires two canonical
running observations of one PID, and rejects PID change, canonical regression,
absence, unexpected state, or timeout. All 379 Host/deploy tests pass (2
skipped).

The repaired `82685df` recovery later terminalized `target_committed`.
Independent readback proved the exact current and predecessor selectors, new
authorization-daemon generation, immutable current release, clean exact-public
checkout, absent pending transition, and closed Parallels GUI. Separate
canonical and reviewed-autoinstall Touch ID requests published both protected
images; both independently return `promoted_verified`, with no mutable ISO or
partial remaining. The first dry `neo-8gb` plan then rejected before
authorization because the protected seeds embedded a stale public control
payload. The signing-time repair validates exact captured seed bytes against
the archived control sources and identity-stable private key/netplan inputs,
binds the regenerated seed hashes, passes a real-byte preimage build and 422
Host/deploy/VM tests (2 skipped), and has a sealed zero-finding Codex Security
diff review. A new signed Host candidate and attended Host upgrade are required
before the VM plan may be retried; no request is live.

The pre-ceremony gate now retains and explicitly records an honest failed Host
bootstrap's exact empty coordination hierarchy as
`empty-coordination-residue`. Descriptor-pinned ownership, exact modes,
extended-ACL absence, empty contents, and repeated name identities are required;
any deviation still rejects, and initial clean-machine enrollment remains strict.
Post-install preflight separately recognizes only the descriptor-pinned closed
synthetic control shape: empty `controller-state` plus
`authorization-requests/active.lock`, with fixed ownership, modes, ACL absence,
object types, single-link zero-byte lock, and repeated identity/content readback.
The final lock comparison also binds mutation-sensitive size, link count,
modification time, and change time on both the open descriptor and its name.
It does not broadly exempt SecureSandbox application state.

The first exact-plan `vm-create` ceremony on Parallels Desktop 27.1 accepted
Touch ID, entered the privileged executor, and failed terminally without
leaving a VM. The immutable private authorization receipt binds the exact
request, failed status, exit 1, and output digests without publishing
machine-specific receipt identifiers.
Independent inventory proved zero VMs. Retained Parallels logs prove the
Gateway was created and hardened through removal of its default USB and sound
devices, after which the driver attempted to remove `serial0`; Parallels 27.1
had not instantiated that optional default. Identity-bound cleanup then stopped
and deleted only the newly created Gateway. The compatibility repair now reads
the VM's exact hardware inventory, fails closed on malformed inventory, and
removes only optional devices that are actually present. Absence is therefore
an already-satisfied hardening condition, while final configuration readback
still rejects any retained USB, sound, or serial device. Focused VM maintenance
and provisioning suites pass 43 tests. A new exact Host release and fresh
authorization request remain required; the failed request is spent and will
not be replayed.

The repaired Host release was then installed and independently verified on the
Neo. A fresh exact-plan `vm-create` ceremony accepted Touch ID and again
terminalized without retaining a VM. This time the Gateway passed optional
device hardening and failed at its first `control-net` attachment. Independent
inventory again proved zero VMs, and retained Parallels evidence showed that
the freshly erased host had never recreated the required `control-net` and
`lab-net` definitions. The operator subsequently created both exact `/27`
host-only planes in Parallels 27.1. Readback with the GUI closed binds host
addresses `.2`, DHCP addresses and disabled-range starts `.1`, range ends
`.30`, mask `255.255.255.224`, and disabled Mac adapter, DHCPv4, DHCPv6, NAT,
and host IPv6 assignment for both planes. Quitting the Parallels application
briefly made its service unavailable on this installation, but a later
read-only `prlctl` probe recovered and returned the exact empty inventory with
the application fully quit. The lifecycle-safe gate therefore remains a fully
closed GUI plus successful live inventory readback; a transient post-quit
failure is not grounds to spend or replay an authorization.

The provisioning repair now treats those private planes as a pre-authorization
input. Planning pins the root-owned, non-writable, ACL-free Parallels parent
and network configuration without following links, requires stable named and
opened identities and bytes, rejects duplicate UUIDs and overlapping enabled
host-only planes, validates the complete exact topology, and includes the two
network UUIDs and closed settings in the reviewed plan. The ordinary requester
binds a canonical network digest into the Touch ID request; the broker
independently validates the closed nested schema and honest expected addresses;
and the privileged coordinator rereads the topology after dropping privilege
before comparing the digest, again before each named-network attachment, and
after final VM configuration. Missing, malformed, changed, overlapping,
DHCP/NAT-enabled, or host-attached planes therefore reject before a one-time
authorization can be spent or terminalize and identity-clean the exact partial
creation.

The exact repaired Host release then committed on the Neo and independently
verified its new current selector, predecessor selector, launcher pair,
candidate authority, release tree, payload closure, and absent pending state.
Its first network-bound VM request and two cancellation-only diagnostics all
failed before an authorization window with zero VMs retained. A capture of the
mode-0600 request plus UI result localized the rejection to `notCanonical`:
Python ordered `dhcp4_enabled` before `dhcp_ip`, while Foundation
`.sortedKeys` on macOS 27.2 reversed them. The source repair replaces that
implementation-defined Swift ordering with an explicit Python-compatible
ASCII canonical encoder shared by request validation, parameter binding, and
execution-approval signing. Physical eligibility now requires a signed and
notarized release containing that repair, a successful cancellation test, and
only then a fresh exact-plan VM-create authorization; all failed request nonces
are spent and will not be replayed. The first release build failed closed
before signing because its intentionally closed source inventory had not added
the new encoder file. The inventory now records, snapshots, and attests every
Swift source, with a regression requiring each source to occur in all three
closed lists, in the Xcode compile phase, and in the Host payload verifier's
complete shipping-source set before another release can be built or selected.
The first physical install of that complete candidate reached and accepted
Touch ID, then the immutable predecessor rejected the expanded source manifest
with the exact `authorization_ui_source_manifest_invalid` output and restored
the original verified pair. Receipt recovery rejected that unenumerated error
without mutation. The recovery allowlist now admits its exact output hash only
after the successor manager validates the complete candidate and reconstructs
the same authorized target plan; arbitrary manifest failures remain closed.

The first fresh request for that recovery repair launched the signed
authorization process on the Neo, but macOS 27.2 retained zero windows. Unified
logging and process readback proved the process was foreground-registered while
AppKit reported `No windows open yet`; terminating the UI produced a terminal
`touchid_ui_result_missing` failure, left the installed pair unchanged, and
spent that request without recovery or mutation. LaunchServices can complete
application launch while the request-bound broker challenge is still being
parsed, before the delegate observes `applicationDidFinishLaunching`. The UI
now idempotently schedules its one presentation before entering
`NSApplication.run()`, retains the delegate callback as a second trigger, and
reasserts the same window after foreground registration with content-free
lifecycle telemetry. The exact Developer ID/notarized `4f9b44e` diagnostic
candidate then passed the Neo visibility probe with the application frontmost
and exactly one on-screen window. The probe itself now accepts CoreGraphics'
documented `NSNumber` PID bridge rather than assuming an `Int32`, while still
requiring the exact frontmost process and one window before another real
authorization request.

That exact repaired Host release was published to both authorized remotes,
transferred, admitted, selected with Touch ID, and independently verified on
the Neo. Its cancellation-only VM ceremony produced the canonical cancelled
receipt with zero VMs and no maintenance transaction. The following fresh
real ceremony accepted Touch ID and terminalized as failed; independent
inventory again proved zero VMs and no maintenance transaction, so the spent
request is not replayable. Matching its immutable stderr digest against the
closed executor error vocabulary localized the failure to
`vm_resource_readback_invalid`. A narrowly named no-disk diagnostic VM then
captured Parallels Desktop 27.1's live detailed inventory and was absent again
before source repair. Parallels now emits `memory size=2560Mb auto=off`, while
the strict reader accepted only the older `memory 2560Mb` spelling. The reader
now accepts exactly those two explicit forms, still requires exactly one CPU
and one memory observation, and still rejects missing or conflicting values.
The apparent Host-pair terminal concern was ruled out: both independent
manager verification and the installed broker validate the canonical immutable
terminal and its self-digest; the retained `host_pair_terminal_invalid` lines
were emitted during the completed pair transition, before stable publication,
and the KeepAlive broker is now running. The strict compatibility repair was
published as `4ca4ab6`, passed a sealed zero-finding Codex Security diff scan,
was signed and notarized, and was installed and independently verified on the
Neo. Its cancellation-only ceremony passed. A following fresh real ceremony
accepted Touch ID and created all three exact stopped VMs; independent readback
verified their UUIDs, CPU, memory, disk, private-network attachments, shared
adapter, and device hardening with no residual maintenance transaction.

The first lifecycle start then correctly started only Gateway and stopped when
the fresh guest did not become control-reachable. The Ubuntu installer reached
its final privileged-control late command and failed there, leaving Gateway's
partial disk and the stopped Research and Target shells intact. The console's
Subiquity recovery input path stopped accepting Return and virtual-terminal
events. Parallels was therefore shut down, all three VMs independently read
back as stopped, and an APFS copy-on-write clone of the failed Gateway was made
before further diagnosis. The clone's transferred Parallels extent matched its
source byte length and SHA-256; conversion to a sparse raw image exposed a
valid GPT and ext4 target without mutating the retained original.

Offline inspection proved the complete control payload, `securectl` account,
authorized key, sudoers policy, role, and SSH policy were installed. Booting
only the copied image under a restricted local ARM64 QEMU overlay then produced
a verified `control-self-check` through the installed forced-command channel.
The failure was the install-time service-state probe: in Curtin's offline
chroot, `systemctl is-active ssh.service` returns exit zero, emits no stdout,
and writes `Running in chroot, ignoring command 'is-active'` to stderr. The
installer discarded stderr and rejected the resulting `0:` state. The repair
now accepts only an independent successful `systemd-detect-virt --chroot`
determination as the offline case; a non-chroot retains the exact active reload
and repeated active readback, inactive case, and fail-closed rejection of
unknown detector or service states. Executable regressions cover chroot,
inactive, active/reload, empty state outside chroot, detector failure, and
post-reload regression. Focused privileged-control, seed, VM-maintenance, and
acceptance-contract suites pass 119 tests.

During serial-console diagnosis, the existing Gateway password was
unintentionally echoed into a local diagnostic transcript. It was immediately
treated as compromised and replaced using 1Password's in-vault password
generator without exposing the replacement. The failed disk remains retained
evidence only and must not be promoted or reused; the next signed seed must be
built from the rotated credential before the exact three-VM set is
reprovisioned through its protected maintenance path.

The first repair was published as `2f3551d`, passed the 2,606-test canonical
gate and a zero-finding immutable-range security review, and was signed and
notarized with freshly rebuilt seeds. Both public remotes independently
resolved to that commit. The exact candidate was admitted on the Neo and its
ordinary Touch ID transition durably committed release `384ffa56...`; the
caller lost the final broker response while launchd replaced the broker, but
the terminal transition, stable pair, selector, running daemon, and independent
installed-release verifier all agreed on `target_committed` and `verified`.

The first reprovision dry run then exposed a local ignored-state overwrite:
the Neo's `runs/control_key.pub` had been replaced during forensic work by a
different public key carrying the `(stdin)` comment. The rejected key was
retained as evidence, while the active file was restored to the public-key
digest embedded identically in the prior and new signed Host seeds and matching
the release Mac's approved Agents-vault record. A fresh dry plan passed, and a
separate Touch ID ceremony recoverably quarantined the old VM set and published
three exact stopped replacements with the protected installer and rotated
seeds. Independent readback proved new UUIDs, the `neo-8gb` layout, private
networks, exact media hashes, and no dangling reprovision transaction.

Gateway's second physical install still failed the final privileged-control
late command. A read-only console capture and byte-verified APFS evidence clone
proved the repaired script was present, but real Curtin does not necessarily
make `systemd-detect-virt --chroot` return success even though its systemctl
invocation is explicitly offline and refuses the query. The next repair
therefore accepts that second offline form only when both independent signals
match: `SYSTEMD_OFFLINE=1` and the exact C-locale `/usr/bin/systemctl` response
`Running in chroot, ignoring command 'is-active'`. Absolute systemd paths,
positive conventional-chroot handling, live active/reload/repeated readback,
inactive handling, and fail-closed rejection of every contradictory detector,
environment, status, or output remain intact. Focused suites again pass 119
tests, including acceptance and rejection of the paired Curtin signals.

The next physical Gateway install completed the repaired late command and
powered itself off.  Its stopped-device readback then exposed a separate
operator-path mismatch: protected reprovisioning correctly attaches each seed
from the exact immutable Host release, while the media-removal helper still
expected an obsolete checkout-local seed path.  Media removal now consumes the
installed immutable release manager's verified release ID and payload digest,
requires the exact root-owned mode-`0444` ACL-free protected seed, rehashes it,
and accepts only that exact path in the stopped VM readback before deleting
either optical device.  A checkout-local seed can no longer authorize media
removal.

Before the first post-install boot, independent inspection of the newly signed
Host payload and stopped VM topology exposed two coupled clean-machine
portability defects: the Host SSH configuration still embedded the release
Mac's absolute `/Users/aharmon` paths, and Parallels-assigned random NIC MACs
did not match the fixed MAC identities in the signed netplan seed.  The release
source is now closed over tracked canonical netplans and a tracked canonical
SSH configuration.  VM creation assigns and independently reads back the exact
per-device MAC identities; seed construction and verification consume the same
tracked netplans; and OpenSSH `%d/SecureSandbox/...` paths bind keys and known
hosts to the admitted operator's home without post-signature rewriting.  The
ignored local SSH and netplan files no longer contribute release authority.

The exact canonical MACs were then applied to the stopped physical VM set and
independently read back. Booting only Gateway exposed one further portability
defect before any Research or Target installation: Parallels Shared DHCP
assigned `10.211.55.5`, while the signed Host SSH payload had assumed
`10.211.55.16`. The Parallels Shared configuration contains no reservation for
that assumed address and advertises a dynamic `/24` scope. Gateway was stopped
again, and independent readback proved all three guests stopped before source
repair. A source-tree physical probe of the repaired resolver then started only
the exact Gateway and resolved `10.211.55.6`, proving that Parallels had already
changed the lease between boots. Its cleanup trap stopped Gateway, removed the
temporary probe, and independent readback again proved all three guests
stopped. The portable repair removes the fixed address. Its signed, immutable
SSH proxy validates the exact running Gateway bundle, canonical NIC/MAC
topology, absent installer media, stable root-owned Shared-network
configuration, and one in-scope DHCP IPv4 address before invoking the fixed
system netcat binary. Stable HostKeyAlias values preserve strict host-key
authentication across DHCP changes.

The first three-guest boot on that release then supplied a stronger Parallels
Tools readback than the earlier Gateway-only probe: one Shared IPv4 and IPv6
address plus the legitimate static control-plane IPv4 and link-local IPv6
address. The immutable resolver rejected rather than guessing because its
original cardinality check counted every IPv4 across both canonical NICs. The
repair preserves the complete inventory's duplicate/type checks, filters IPv4
candidates through the already descriptor-validated Shared subnet, and requires
exactly one address within its DHCP bounds. Source regression coverage uses the
Neo's exact two-NIC address shape. No Research host key was accepted and Target
remained stopped when this boundary was discovered.

Research and Target subsequently completed their old-release-bound unattended
installers and powered themselves off. Their retained mode-`0600` install and
media-removal logs are independently digestible evidence: Research install
`69015414...f54`, Research media removal `78beed9c...5fa`, Target
install `88e151b9...20e`, and Target media removal `c94a2eff...d1e`.
Readback after media removal proves the exact three UUIDs stopped, each guest
booting only from its installed disk, no optical device remaining, and the
canonical CPU, memory, private-network, and MAC identities unchanged. The
exact `62fa802` signed and notarized portable-Host candidate was then
transferred and admitted on the Neo. Its attributed Touch ID request entered
the protected transition, and the ordinary caller lost the terminal result
during daemon handoff.
Independent public verification now identifies target release `e91436af...`
as the selected, immutable, internally verified Host release with the expected
candidate authority and complete dynamic-Gateway payload. Its root-authored
immutable terminal independently binds the original request ID and digest,
pre-transition target-plan digest, exact target release, committed pair,
authorization receipt, finalization, and protected-service evidence with
status `target_committed`. A manually reconstructed runtime-metadata recovery
invocation used a target-plan digest recomputed after that commit and rejected
before mutation, as it must: no post-commit digest can simultaneously equal
the original receipt's pre-transition plan and a plan derived from the new
STABLE source pair. The deploy wrapper now resolves this response-loss state
from the exact STABLE-bound terminal before considering receipt recovery; an
unrelated terminal falls through, while any same-request mismatch or
`source_restored` result fails closed. No new authorization was issued, and no
stack boot, host-key enrollment, boundary qualification, driver install, or
91-case campaign had begun at this checkpoint.

| Contract | Current evidence | Physical evidence required |
| --- | --- | --- |
| Fixed-driver readiness | closed ten-driver inventory separates source completeness from physical availability; checkout files alone yield zero available drivers. Availability requires a canonical self-digested suite manifest and exact payload bytes beneath a fixed root-owned exact-commit release. The installer manifest and post-publication verifier enumerate all ten drivers, and a source test requires its payload block to equal the union of all contract-declared driver closures, including clean-machine bootstrap. Initialization rejects any incomplete or unprotected inventory with no bypass | install all ten exact-commit drivers under the reviewed protected manifest and obtain readiness `ready` before campaign initialization |
| Pre-ceremony authorization gate | source-tested read-only gate binds enrollment to current hardware, requires clean `public-release` at the credential-free public GitHub authority, and resolves its literal pinned HTTPS endpoint outside repository/global/system Git configuration so local remote substitution and URL rewrites cannot nominate publication authority. The private Hobby mirror is verified by the trusted publication workflow rather than importing its production credential onto the clean Mac. Before queuing a password, the gate independently rejects any missing, symlinked, non-root-owned, group/other-writable, extended-ACL-bearing, or identity-changing component in the fixed `/private/var/db` bootstrap hierarchy and binds each accepted object's device, inode, UID, GID, mode, and explicit ACL absence into its canonical receipt. Its descriptor-relative no-overwrite mode-0600 writer requires a private operator-owned ACL-free mode-0700 parent, fsyncs both file and directory, and retains separate pre-install and post-install receipts only with an expected transition. Its receipt consumer revalidates canonical stable bytes, self-digest, exact closed field set, operator, authority, transition, retained absence and boundary facts, protected-install state, remote tip, and source commit before emitting only the bound commit used by root installation or campaign initialization. Even a correctly re-digested receipt fails if a producer fact is omitted, added, or semantically inconsistent. The root ceremony clones into a new root-owned, non-overwritable bootstrap directory directly beneath that hierarchy and verifies the preflight commit before executing repository content. Every sudo subprocess starts with an empty allowlisted environment, all privileged Python verifiers use isolated mode, and the installer validates the complete fixed hierarchy plus its exact root-owned path before repeating the isolated exact-tip check, fetching into a fresh root-owned bare repository, and consuming no Git configuration, hook, index, object, or payload path from the operator-writable checkout. The exact published bootstrap transition received a complete Codex Security diff review; its two conditional P3 findings were remediated in source and focused regression tests. The strengthened preflight gate received complete no-reportable-findings Codex Security diff reviews, and its later exact-commit attestability hardening closed the policy-suppressed TOCTOU candidate anyway. The installed-state extension's diff review found one P3 same-inode mutation window in the lock's final readback; the final comparison now binds mutation-sensitive metadata, and a deterministic regression mutating the already-open inode fails closed while the exact legitimate zero-byte state remains accepted. The gate repeats credential/state-path absence checks, requires a closed Parallels GUI and exact three-VM inventory, distinguishes wholly absent from partial/invalid protected installation, and can queue only that root-owned bootstrap or unauthenticated campaign initialization. It always keeps all eleven Touch ID cases unavailable | run the gate immediately before installation and again after installation on the enrolled disposable Mac; retain both canonical self-digested receipts and consume their bound commits for the corresponding transition |
| Clean disposable enrollment | enrollment unit tests reject wrong acknowledgement, non-macOS, provider environment, known state paths, present service credential, and ambiguous Keychain result. The immutable original receipt remains historical proof after expected synthetic installation state makes re-enrollment impossible. Fresh preflight still repeats the current material scan and machine binding. Bootstrap, qualification, runtime, and management scans consume one shared provider-path inventory, including Google `credentials.db` and Azure's MSAL cache, with source tests rejecting drift and both formerly omitted markers | factory-reset machine receipt and operator clean-machine attestation |
| Clean-destination product bootstrap | physical preparation exposed that the former first Host install rebuilt and notarized native products on the destination, which would import Developer ID and Apple notarization credentials into the disposable trust domain. The transfer path now stages only public signed/notarized candidate evidence, executes no transferred content, bounds inventory/depth/size, rejects links, special files, unsafe modes, ACL-bearing inputs, unexpected entries, unstable files, existing destinations, tampering, and ambiguous eligible candidates, and retains partial/rejected trees only under the inert `.candidate.*` class. The retained-parent descriptor remains open through exact-identity publication; rejected canonical publication returns to the same inert identity without recursive cleanup. Physical Neo transfer and destination staging verify the exact candidate. Retained private attempt logs exposed first the missing clean-machine launcher scaffold and then `bootstrap_manager_digest_mismatch`, both before protected target publication. The repaired plan binds a candidate-derived six-payload predecessor and keeps the current privileged-loader manager identity separate from the older candidate manager. A fixed diagnostic launcher now records source commit, terminal, PID, command output, signals, and final status without logging administrator input or relying on scrollback. The corrected Neo bootstrap completed, and an independent public verification by the installed immutable manager validated the exact selected release, launcher, pair, payload closure, native candidate authority, and Developer ID team floor. The first physical installer acquisition then downloaded the exact pinned ISO but failed closed before authorization because the clean public checkout correctly omitted ignored binary `.gpg` inputs and the acquisition path had not reconstructed them. The repaired path acquires the exact digest-pinned release signature and archive keyring from fixed official HTTPS endpoints, rejects rather than replaces divergent inputs, and uses exclusive durable publication before protected signature verification. Its first clean-Neo run exposed a zsh-specific defect before authorization: a local variable named `path` shadowed zsh's command-search array, so the next unqualified `stat` lookup failed after the signature download. After that repair, exact trust-input and ISO hashes passed but the immutable verifier failed closed because its transferred `gpgv` still referenced five development-Mac Homebrew dylibs absent on the clean Neo. The portable repair retains the established payload-name floor by appending a deterministic five-library capsule to the existing hash-bound `gpgv` payload, materializes it into a root-owned closed release-tree subdirectory, and makes the verifier independently hash and load only that release-local closure. Release construction recursively proves those files are the complete non-system Mach-O dependency graph and rejects package drift that could restore ambient loader authority. Real-byte preimage testing launches the appended executable and validates Canonical's signature. The original ISO, private partials, and every failed-attempt log remain retained as failure evidence. | publish and install the portable exact Host release, acquire and verify the pinned installer, create and independently read back the exact stopped three-VM `neo-8gb` layout, qualify its resource/boundary behavior, and retain those physical records before campaign initialization |
| Credential-free ordinary Host upgrade | the first post-bootstrap Neo deploy attempt failed closed before broker authorization because ordinary deployment still invoked the release-Mac builder and demanded Developer ID/notarization credentials. Ordinary deployment now shares the transferred-candidate selector. The next Neo attempt exposed that byte-identical native products can leave both an older and current candidate cryptographically valid; the selector therefore requires the candidate's signed commit, source archive, source tree, and signing configuration to match the current clean checkout before considering payload compatibility. Exactly one match is bound into the target plan; malformed or same-provenance ambiguous inventory remains closed, historical candidates remain inert evidence, and only a machine with no exact-provenance match can enter the credential-gated local-build path. The exact `b4f4842` candidate resolved on the clean Neo without signing/notarization credentials and produced a real on-screen authorization window. An intentionally unapproved run expired without mutation; a diagnostic cancellation then exposed that the immutable predecessor broker incorrectly attempted to open a root-private floor marker. The repair uses stable pathname ACL inspection without opening the marker. A two-gate recovery is bound to the exact defective predecessor: password authority may only stage the exact fixed signed/notarized release while proving selectors, launcher, and pair unchanged, after which the ordinary broker still requires Touch ID for the atomic transition. The first recovery launch retained another fail-closed pre-notice result: its login-user preflight attempted to read the root-private native-stack floor. The repaired preflight uses the canonical public floor projections, stable pair, immutable release, candidate authority, launcher identity, and exact broker digest; only the sudo-isolated manager may read the private floors. The first successful password stage proved the successor remained non-selected, then ordinary authorization failed closed because the staged broker still opened the separate native-stack private floor. That repair validates stable private-marker metadata plus the root-owned public enforcement projection, while the privileged manager retains the content/digest cross-check. The attempt also proved that SSH-PTY password prompts are not operator-visible; the retained local-Terminal launch reached password staging and the ordinary authorization request. With Touch ID enrolled, the exact `7a2b7f2` ceremony reached and accepted the attributed biometric gate, then retained a terminal failed receipt for the canonical `native_host_release_tree_identity_inventory_invalid` result. Independent public verification proved `current`, launcher, stable pair, and source tree unchanged, the target tree and authority complete and byte-consistent, the target still inert, and no transition active. The recovery allowlist now admits only that exact stdout digest or the prior exact signed-app tree mismatch while preserving the original Touch ID authority, archiving the failed receipt root-only, and reproving the unchanged source pair, candidate, target plan, and absent transition; arbitrary errors and active transitions remain terminal. A later exact published recovery consumed a fresh Touch ID request, targeted its exact signed release, and created a protected transition. Target daemon activation failed during launchd's post-bootout same-label cleanup window, and the canonical terminal result was `source_restored`. Independent readback proved the exact source release, stable pair, and launcher unchanged; `previous` absent; the source daemon running; and the target still inert. The immutable failed receipt and transition evidence are retained and must not be replayed. The repair adds a bounded same-plist launchd admission barrier: a nonzero bootstrap can retry only after two separated exact-absence readbacks, while a zero bootstrap must progress to two stable running readbacks with the same PID and can never be resubmitted. Nonzero registered state, zero-plus-absence, unexpected state, changing PID, oversized output, or timeout fails closed. The complete Host/deploy suite passes 370 tests with 2 skipped, and a sealed Codex Security scan covered the exact diff with zero findings. The first physical run of that repair encountered a temporary non-canonical launchd state snapshot after stable removal and before label reuse, again terminated `source_restored`, and independently proved the source selector and daemon restored. The refined barrier waits through only that specific state-unproven observation within ten seconds, then requires two consecutive exact-absence readbacks before its first bootstrap; registered state remains an immediate failure and a successful bootstrap is never repeated. Physical replay localized the same cleanup observation to the earlier post-bootout stop fence, before target selection. The corrected fence keeps pre-bootout inspection strict, retains the captured process-generation proof, and requires two consecutive exact-absence readbacks before plist unlink or target selection. The complete suite now passes 374 tests with 2 skipped, and a sealed Codex Security diff scan found no reportable issue. | publish and transfer the exact stop-fence repair, run a fresh visible two-gate recovery, and independently verify the selected release and unchanged trust floors |
| Clean-destination source derivation | the read-only pre-prompt check exposed that the full release-Mac provenance helper required ignored `Signing.local.xcconfig`, correctly absent from the Neo. The candidate-specific helper now accepts only the signing-configuration digest already authenticated by the signed candidate receipt, independently rederives the clean `public-release` commit and deterministic Git archive, recomputes the combined source-tree identity, and never reconstructs or imports the local signing file. Physical read-only selection on the Neo resolved the unique exact `b4f4842` candidate while retaining older candidates as inert evidence | repeat the derivation for the published recovery candidate and retain its exact selector receipt before authorization |
| Bootstrap physical driver | source-tested fixed collector accepts only the next bootstrap case, rebinds the current Mac and exact clean checkout, reserves evidence before readback, verifies protected Host/Research/boundary state, repeats a metadata-only production-material scan, revalidates enrollment, and projects suite-fixed authorities from private canonical snapshots without mutation or caller-selected evidence fields. A distinct no-argument acceptance start now requires a pre-disconnected Gateway, starts only Gateway and Research, leaves Target stopped, and validates the same protected readbacks without reserving evidence | publish and install the exact protected closure; physically verify the isolated acceptance-start final inventory, then run both bootstrap cases immediately after the reviewed install and enrollment ceremonies; retain raw and projected records, including every rejected reserved attempt |
| Exact immutable campaign | campaign schema, suite digest, machine digest, source commit, lifetime, and policy validators. Initialization now consumes both the historical clean-machine enrollment and a no-more-than-one-hour-old canonical post-install preflight bound to its digest, machine, operator, exact public commit, complete protected driver inventory, VM states, and current production-material scan. Tests accept an old original enrollment only through that fresh bridge and reject stale, cross-enrollment, and cross-commit preflights. The default and documented lifetime is the bounded fourteen-day maximum rather than the impractical former seven-day window | campaign bound to the exact deployed commit and completed, assembled, and exported before fixed expiry |
| Complete fixed matrix | 91 catalog cases and 198 ordered observation requirements | one outer-collector observation for every required case/kind |
| Provenance and archive attacks | all sixteen provenance fixture cases execute against an isolated production `HarnessStore`. Each of the twelve signed synthetic archive carriers enters the real `HarnessStore.acquire` boundary after digest verification and before quarantine creation; the bounded ustar preflight rejects without extraction or execution, and an independent full-state inventory proves the protected store and empty quarantine are unchanged. Existing-generation acquisition and explicit verification also reread and digest-check archive bytes before applying the same current preflight, so legacy quarantine state cannot receive a current success receipt without current policy. The root-only Host installer reads exact-commit immutable Git objects under a publication lock, binds both driver inventories, post-verifies both, and remains non-admitting | root-owned protected-Host execution on the disposable Mac and live provenance/archive rejection receipts with retained before/after readbacks |
| Qualification protected driver | source-tested core binds all ten lifecycle acceptance qualification cases to the complete ordered thirty-case synthetic plan and report, pins the only fixture, rejects fact overrides, and remains explicitly ineligible by itself. The root-only Research wrapper installs the exact seven-file closure and executes it as a transient dynamic user with private/deny-all network policy, `AF_UNIX` restriction, strict protected filesystem, private home/tmp/devices, no-new-privileges, two-task ceiling, credential-environment removal, exact unit readback, zero-restart verification, empty post-run cgroup, and boot binding. The protected Host supervisor accepts only the next case, verifies the exact manifest and enrolled Mac, reserves evidence before deployment, repeats the production-material/Keychain scan, proves the Host fixture stayed inert and unchanged, deploys only manifest bytes, and records no admission, activation, selector, or session mutation. The fixed projector revalidates the complete four-record mixed-authority set and publishes only suite-assigned observations with non-overwriting resume | install the exact Host/Research releases and execute all ten cases on the disposable Mac; retain raw and projected records |
| No prequalification execution or production authority | fixed qualification isolation cases and categorical candidate-collector rejection | independent process/network/file/credential observations |
| Touch ID semantics | fixed approve, cancel, expiry, replay, changed-plan, and wrong-generation cases; source-tested signed-broker acceptance route is Touch-ID-only and operator-UID bound, dispatches only to the exact-commit fixed consumer, and has no caller-selected state or executable path. The consumer uses per-case root-owned state plus a real but empty campaign-only `GenerationStore`, proves it remains unchanged, journals ledger/result publication, recovers interrupted publication, consumes replay authorization once before rejecting its protected second use, and finalizes expiry as a failed receipt instead of leaving ambiguous `executing` state. The protected wrapper admits only the exact next case, installed manifest, enrolled machine, fixed operator campaign root, fixed Research status command, exact Host release/plan/campaign/generation receipt fields, and unchanged before/after Research selector. Its fixed projector revalidates the complete chain, uses exact authenticated Research status bytes as the primary Research artifact, keeps Host-composed summaries labeled privileged control, and publishes suite-assigned read-only observations with resumable non-overwrite semantics | install the exact source-complete authorization closure and run all six native ceremonies on the disposable Mac; retain the protected broker, plan, result, and unchanged Research selector evidence |
| Session generation binding | fixed future, old, and legacy session cases | Host/Gateway/Research session and runtime readbacks |
| Lifecycle management | fixed rollback, referenced-retirement rejection, zero-reference retirement/reclamation, revocation, and containment cases | exact Touch ID receipts, floors, catalog, denial, and retention readback |
| Crash ordering | journal-before-fence repair plus injected durable checkpoints | process kill and Research-VM hard power loss at every fixed transition |
| Deterministic recovery | source tests recover every durable activation checkpoint and independently verify the boundary | cold recovery receipts and post-recovery Host/Research readback |
| Disposable recovery driver | campaign-bound synthetic fixture uses the production generation store, stops at all fifteen exact durable callbacks, refuses arbitrary checkpoint input, and verifies deterministic recovery; process and power cases remain distinct | physical stopped-worker, external process-kill or Research-only hard-power, recovery, and boundary readbacks |
| Host recovery supervisor | source-tested outer driver rebinds the current Mac and clean exact source checkout, accepts only the next suite recovery case, deploys the complete exact-commit root-owned fixture dependency closure—including the archive preflight imported by the lifecycle module—through authenticated control, shares the Host lifecycle lock, reserves evidence before mutation, binds PID/start-time/boot identity, hard-codes the Research VM target, requires exact power acknowledgement, verifies Gateway/Target invariance, and emits fixed-authority raw artifacts without observation or admission authority | live process-loss and Research-VM power-loss artifacts for all thirty paired transition cases |
| Recovery observation projection | source-tested fixed bridge requires the next recovery case, current enrolled Mac, exact raw inventory, complete embedded checkpoint, self-digested stopped-worker and fault/cold-boot/recovery/boundary chain, private canonical snapshots, suite-fixed authorities, no caller-selected evidence fields, and crash-resumable non-overwriting publication | project each live supervisor artifact set into its three or four required observations and independently retain both raw and projected records |
| Cold-boot persistence driver | source-tested fixed driver requires the next suite case and exact acknowledgement, verifies the enrolled Mac and exact protected manifest, reserves evidence before mutation, shares the lifecycle lock, hard-codes only the Research VM, proves a changed Research boot identity while Gateway/Target remain unchanged, restores the initial VM inventory, and revalidates protected Host/Research/catalog/selector/runtime/policy readbacks through closed self-digested schemas and fixed-authority non-overwriting projection | run all four cases after committing the synthetic generation; retain pre/post boot, intermediate/final VM inventory, raw readbacks, and projected observations |
| Immutable operator protocol | every case suite-binds its driver, baseline, action, interaction, egress posture, interruption checkpoint, postcondition, and reset; `next` reveals only the first incomplete case | operator follows each exact physical protocol on the dedicated Mac |
| Independent export | self-contained v4 evidence projections with bounded readback bytes, suite-fixed collectors, exact protected-artifact inventories, primary-byte source/subject binding, raw source-status validation, chained receipts, final digest, and candidate authority `none` | off-machine copy and independent `verify-export` verdict |
| Protected export driver | source-tested final-case driver rereads every prior root-owned observation in fixed order, binds filename/observation/file digests, proves closed candidate-independence facts, projects only evidence-exporter observations, assembles and locally revalidates the complete export, and refuses overwrite, non-private output, or a destination on the disposable Mac's filesystem device | run into an empty private off-host volume, retain export and local consistency verdict, then copy to a second machine and run independent `verify-export` |
| Control Center visibility | fixed-path, read-only bridge validates the suite and campaign status; GUI exposes progress with authority `none` and no enroll/run/record/assemble/admit action | live campaign progress readback during the disposable-Mac run |
| No admission side effect | CLI contains no lifecycle mutation command and verdict authority is evidence-only | unchanged production environment and no vendor generation admission |

## Interrupted ordinary Host recovery evidence

On November 16 the operator reported that the Neo had been updated to macOS
27.2.1, matching the Air. This is retained as operator-reported environment
state only; the next Neo-local continuation must independently read back and
bind the OS build before it can become physical campaign evidence.

The resumed Neo-local readback independently confirmed macOS 27.2.1 build
`26B131`, model `Mac17,5`, the exact stopped three-VM inventory, the retained
campaign bound to source `b3e178f`, three raw bootstrap records, and zero
observations. The exact `6389010` replacement
protected release installed and all ten closures verified. Its first
no-delete retention attempt failed closed before plan publication because the
isolated predecessor diagnostic reused the production one-hour raw freshness
window after a roughly three-hour pause. The live campaign and every raw byte
remain unchanged. The repair validates the canonical Host and Research
receipts at their identical historical observation time while independently
rejecting future or mismatched time; it does not weaken the live projector.
The real-byte candidate diagnostic then reached the legacy readiness check and
exposed that its unprivileged process saw all root-owned predecessor payloads
as wrong-owner source, rather than reproducing the original root projector's
two intentionally absent Host installers. The isolated diagnostic now fixes
only the legacy UID probe while the current verifier still proves both actual
root-owned manifest closures.

On November 16, a release-Mac install of reviewed commit `72e625a` lost its
caller response after publishing an exact ordinary PENDING pair, and the
operator cancelled the subsequent administrator-password prompt. The generic
wrapper had admitted only receipt-free bootstrap PENDING records, leaving the
otherwise recoverable ordinary journal without a reusable attributed entry
point. Its preflight now accepts install or rollback PENDING records, verifies
the target by direct immutable release ID and v2 authority, and requires the
exact target launcher either live or in the root-owned mode-0555 generation
store; it never reads the private journal.

Exact recovery of transition `9618bc0a...` committed release
`1bab11df...`, removed the journal only after STABLE readback, retained
immutable terminal `94c46a3a...` with status `target_committed`, and passed
the complete 35-payload public signed-pair verifier. The complete
deploy-wrapper suite passes 101 tests. This closes the reusable recovery entry
point on the release Mac; equivalent Neo execution and retained readback remain
physical acceptance work. Follow-up hardening makes the operator notice name
the ordinary source release and prior STABLE digest instead of falsely calling
it receipt-free bootstrap, and applies only the existing uniform APFS
device-number normalization to target-tree preflight so a reboot cannot strand
an otherwise unchanged authorized transition.

A later Neo request at published checkpoint `bfa25f2` lost its caller response
after the exact ordinary public PENDING fence was durable but before target
mutation. Password recovery first reproduced the intended
`host_pair_transition_expired` refusal: current, launcher, and source authority
remained selected, the target remained inert, and the private journal stayed
intact. The repair preserves that generic refusal but permits the separately
attributed password ceremony to terminalize only the exact installed source
pair as `source_restored` with `authorization_expired`. It validates source
authority from the installed public record rather than stale private candidate
custody, never selects the target, and requires the wrapper to independently
cross-bind the returned source to the same transition-bound STABLE and source
terminal. Physical execution of that repaired ceremony remains pending.

The first physical execution of that ceremony stopped fail-closed before
finalization with
`host_pair_transition_recovery_unproven:native_host_candidate_authority_stale`.
Independent readback again proved the private journal and public PENDING fence
intact, the source selected, and the target inert. The failure localized a
second private-custody lookup in the source restoration's final pair readback:
the initial installed-source check already used public authority, but the final
readback silently returned to private retained-candidate custody. The reviewed
repair carries public-only mode through that final readback only for the fully
attributed expired-source closeout. Ordinary activation compensation retains
its private-custody final gate. The hostile regression reproduces stale private
source custody, proves the attributed closeout succeeds without selecting the
target, and separately proves ordinary compensation remains PENDING and fails
closed on the same stale custody. A later exact recovery physically closed that
transition without target selection and retained the required source terminal,
STABLE, journal-absence, and service readbacks.

A subsequent ordinary upgrade initially remained fenced after its first
attributed closeout stopped fail-closed while launchd added empty-state
metadata to a newly bootstrapped demand-only Native Credential Helper. The
repair accepts inactivity only after two consecutive identical canonical
definitions and tolerates solely `runs` absent-to-zero and `job state`
absent-to-`uninitialized` maturation. A deterministic regression proves that
`runs` zero-to-one fails immediately rather than converging. The complete Host
release-manager suite passes 296 tests with two intentional skips.

The retained recovery for transition `20739d26...` subsequently completed on
the Neo and published immutable terminal `ca20bbd9...`
as `target_committed` with no error. Its diagnostic wrapper failed only after
printing that result because it assigned zsh's read-only `status` parameter.
Independent readback verifies STABLE pair `ce60aa73...`,
current release `44fe71d6...`, predecessor `9afc9bee...`, exact candidate
authority `d7e16671...`, exact tree `a6f9aa31...`, exact launcher
`58b16587...`, absent private journal, and a complete 35-payload public Host
verification result. This closes that transition; it does not constitute a
91-case campaign verdict.

The signed/notarized `d64fa0c` stabilization candidate then activated through
a fresh attributed Touch ID request. Transition `e468dd1d...` published
immutable `target_committed` terminal `ee0348f...` with no error. Independent
readback proves release `bd5c8e55...` selected, predecessor `44fe71d6...`
retained, STABLE pair `cf263657...`, candidate authority `6cd048fa...`, tree
identity `aedd7983...`, unchanged launcher `58b16587...`, all 35 payloads,
absent journal, running authorization service, and canonical inactive Native
Credential Helper definition. The caller's ambiguous response offered an
administrator-password recovery prompt over an inaccessible SSH PTY; it was
cancelled only after independent state readback proved the protected
transition had already committed. No retry or recovery mutation followed.

The live campaign remained the exact empty `35dd424` campaign `21a27ec8...`.
Its first ordinary no-delete retention
attempt rejected before plan publication or rename with
`retention_predecessor_driver_invalid`; the live campaign is unchanged and no
retained destination exists. The ordinary retention verifier had incorrectly
asked the clean descendant checkout's current source files to satisfy the old
campaign commit before verifying the immutable protected predecessor. The
first repair verified the exact root-owned protected release rather than the
descendant source and was published as `3bf0b63...`. Its physical replay again
rejected before plan publication or rename because the descendant verifier
required the predecessor's historical seven-payload bootstrap closure to equal
the expanded ten-payload closure. The campaign remains unchanged at its live
path and no retained destination exists. The next repair authenticates the
historical verifier and shared contract against their exact predecessor Git
blobs before isolated execution, then requires all ten historical driver
classes to return one canonical manifest. A disposable detached Neo worktree
ran that read-only verifier against the real root-owned predecessor and returned
manifest digest `815b9e22...`; the worktree was removed and the live checkout
remained clean. Thirty-three focused tests and 174 acceptance-family tests
pass. Codex Security setup validation accepted the working tree, but its scan
launcher incorrectly rejected the same resolvable worktree; no sealed scan is
claimed for this second repair. Publication and physical no-delete replay
remain pending.

The source test matrix is necessary but insufficient. Documentation, generated
fixtures, and locally injected crash tests must not be relabeled as physical
disposable-Mac evidence.

## Isolated lifecycle control transport discovery

The replacement campaign at exact published source `f447613` was initialized
after its ten-driver protected release and stopped-inventory postflight both
verified. Its first `acceptance-bootstrap-start` invocation rejected before
mutation because the operator wrapper had closed Parallels although the
stopped-service bridge requires one stable GUI session. The corrected wrapper
established one GUI PID, exact all-stopped inventory, and disconnected Gateway
uplink. Its transition then started Gateway and rejected with
`parallels_closed_service_readback_invalid` after closing the GUI. No raw case
directory or observation was created.

Independent recovery readback found Gateway running, Research and Target
stopped, and Gateway `net0` disconnected. A retained Parallels console capture
proved Ubuntu had fully booted, but protected Gateway control remained
unreachable. Source and installed-transport analysis proved the contradiction:
the Host proxy selected only Gateway's Shared DHCP address although the
acceptance invariant required that adapter physically disconnected. A bounded
recovery reconnected only Gateway `net0`, obtained authenticated protected
control, dispatched poweroff, immediately disconnected `net0`, and independently
verified all three VMs stopped with the uplink disconnected. Parallels GUI and
all VM runtimes were then proved absent. The campaign remains empty and this
rejection is not acceptance evidence.

The source repair introduces an exact non-NAT Host endpoint on `control-net`,
Gateway-only SSH admission for that address, direct static Host proxying to
Gateway, root-owned topology validation, and a predecessor-preserving guest
firewall migration. The protected one-shot Host driver additionally binds its
exact release, one stable GUI PID, lifecycle lock, exact intermediate VM/uplink
inventory, canonical reusable request UUID, fixed deployed files, canonical
guest result, and unchanged final inventory. It deliberately does not claim
poweroff, Shared disconnection, successor activation, or private-plane
reachability.

The 203-test acceptance family passes after the protected provenance closure
was corrected to carry its transitive `harness_archive_preflight` import. The
focused isolated-network, Gateway transaction, migration, VM-maintenance, and
DDD contract tests pass. All 296 Host release tests executed; one temporary
Unix-listener test was denied by the command sandbox, then passed alone with
that local socket permission. No product assertion failed. Physical network
reconfiguration, signed Host activation, empty-campaign retention, exact
protected-release installation, guest migration, and replay remain pending;
no campaign verdict is claimed.

The disposable Neo subsequently completed exact network reconfiguration and
readback: `control-net` is the enabled, non-NAT Host plane and `lab-net` remains
Host-disabled, with DHCP, NAT, and IPv6 disabled as designed. The empty
`d5322a07...` campaign was atomically retained without deletion and independently
verified from source `f447613...` to published replacement `45cc17b...`; its
live pathname is absent. The exact `45cc17b...` protected acceptance release
was installed and its stopped-inventory postflight verified. The active signed
predecessor Host release `bd5c8e55...` was also independently reverified.

The first protected guest migration used the fixed request UUID abbreviated
`89311c21...` and terminalized as
`migration_control_rejected` before Host dispatch. A same-environment
read-only controller probe reproduced `KeyError: 'HOME'`, and Gateway audit
readback proves the UUID was never reserved or observed. This is not migration
acceptance evidence and does not consume the UUID under the reusable-request
contract. Authenticated recovery powered off Gateway, immediately disconnected
Shared, and independently proved Gateway, Research, and Target stopped with
all uplinks disconnected and Parallels closed. The repair supplies only a
passwd-derived, ownership-validated operator HOME; it does not accept caller
environment authority. At that checkpoint, because the retained plan
terminated at `45cc17b...`, the append-only post-retention supersession
ceremony still had to bind the published descendant before one retry of the
same UUID. No campaign verdict was claimed.

The passwd-derived-HOME descendant was published and the retained authority
chain was extended to exact commit `3e58666...`. Apple accepted and notarized
the exact protected candidate, whose release was installed and independently
verified on the Neo. Replaying `89311c21...` then reached Gateway; its audit
contains the exact deploy request as `started` followed by `command_failed`
with status 1. The UUID is therefore consumed and will not be reused. A
hash-identified root-read-only diagnostic proved the failure was pre-mutation:
the admin-source record and migration directory were absent, nftables had no
live filter table, and `/etc/nftables.conf` was the exact root-owned mode-0755
empty Ubuntu skeleton with SHA-256 abbreviated `60dac93f...`.
No backup, successor rule, or other migration state existed. Authenticated
shutdown returned Gateway to stopped; Research and Target remained stopped;
the Parallels GUI was closed. The next source repair admits only that exact
legacy baseline, derives `10.211.55.2` from the stable root-owned Parallels
Shared-network descriptor, binds it into the canonical guest result and exact
successor hash, and rejects any other legacy state. This remains source work,
not a successful migration or campaign verdict.

Exact published commit `08907f8...` subsequently completed the legacy-baseline
migration on the disposable Neo. Although the Host wrapper reported an
ambiguous result, Gateway audit and a separate root-read-only diagnostic proved
the exact successor nftables bytes, root-only backup, admin-source record, and
live Host-control rule. Gateway then powered off through authenticated control,
Shared `net0` was disconnected, and all three stopped states were independently
read back. Apple-accepted signed Host release `ed989c9d...` activated after
Touch ID; its immutable release manager independently verified the release,
Team ID, payload map, release-tree identity, previous-release selector, and
absence of pending transaction markers despite a client-side recovery-plan
mismatch.

With Shared still disconnected, the successor proxy reached Gateway's
privileged dispatcher at `172.30.10.1`. Two optional read-only operations
returned authenticated role-bound missing-file errors on the preserved legacy
guest, then the universal authenticated `poweroff` operation succeeded. Direct
Host TCP access to Research `172.30.10.2:22` remained unavailable. Canonical
closure receipt `b1529b26...` proved all VMs stopped, the GUI closed, and VM
runtimes absent. Final preflight `e6169778...` verified exact source
`08907f8...`, source/protected driver counts 10/10, and initialized fresh empty
campaign `a267b113...`.

That campaign's first `acceptance-bootstrap-start` created no observation and
rejected as transition `efed98d9...`: after the bridge started Gateway and
terminated the GUI, Parallels reported the service unavailable and left Gateway
suspended. Independent recovery proved Research and Target stopped, Shared
disconnected, the campaign observation directory empty, and no GUI or VM
runtime alive. A bounded physical experiment then changed only Gateway from
vendor defaults `same`/`ask` to `headless`/`keep-running`; after the exact
TERM/KILL GUI sequence, Gateway remained running, the VM runtime remained
present, and `prlctl` still reported the exact intermediate inventory. The
source repair now makes that policy a creation/readback/start invariant. This
is defect evidence, not an accepted campaign observation or verdict.

Exact descendant `d4c004f...` was published to both authorized remotes under a
one-user, one-push GitHub ruleset bypass that was immediately removed; live
readback again showed active enforcement with zero bypass actors. The Neo's
empty `a267b113...` campaign was retained without deletion and independently
verified, the exact protected ten-driver release installed, and fresh campaign
`6845c998...` initialized with zero observations. Its first bootstrap replay
physically proved the headless/keep-running repair: Gateway and Research kept
running, Target stayed stopped, and Parallels remained readable after the GUI
closed. The transition then rejected with
`acceptance_stack_control_unreachable` at the cold-boot readiness window.
Immediately afterward both `172.30.10.1:22` and `172.30.10.2:22` were reachable
and both exact protected control-status calls succeeded. Ordinary `labctl stop`
then exposed a second stale assumption by rejecting a running stack solely
because Shared was already disconnected. Recovery did not reconnect Shared:
exact authenticated private-control poweroff succeeded for Research and
Gateway, and independent Parallels readback proved all three VMs stopped. The
repair doubles the bounded cold-boot probe budget and permits an already-
isolated stop only after every running guest's protected private-control path
is proven. This remains defect evidence, not campaign acceptance evidence.

Exact `6ccfd5b...` then physically proved the private-control stop repair, but
its fresh bootstrap replay rejected with the same zero-observation control
classification after the expanded window. Readback isolated the actual vendor
dependency: with Parallels Guest Tools absent, the headless running Gateway had
live TCP at fixed `172.30.10.1:22`, while Parallels exposed only link-local
IPv6. The protected proxy correctly rejected because its exact Parallels
address attestation was absent. Opening one bounded GUI session caused the
exact fixed IPv4 to appear immediately; it remained in readback after normal
GUI closure, both protected control paths authenticated, and repaired
`labctl stop` powered Research and Gateway off without reconnecting Shared.
The next repair therefore keeps the bootstrap's already-bound GUI PID alive
until Gateway's unchanged protected proxy authenticates, then terminates that
exact PID and continues under the existing lock. It does not weaken address,
topology, VM-identity, or SSH-host-key verification. Campaign `dc6e469a...`
remains empty; this is defect evidence, not an accepted observation.

## Pre-close-control physical replay and protected bootstrap evidence

The exact pre-close-control source was published to both authorized remotes,
installed as the protected ten-driver release, and bound into a fresh
campaign. The first
all-stopped bootstrap transition exhausted its 120 probes just before Gateway
control became healthy. Independent readback proved direct Gateway TCP live,
then the fixed Parallels IPv4 and protected control appeared with the already
bound GUI still open. Re-entry from that exact safe intermediate state
succeeded: Gateway and Research were running and reachable, Target remained
stopped, Shared was disconnected, and the transition emitted its canonical
verified record. This demonstrates a bounded-window defect, not permission to
weaken topology, address, VM-identity, SSH-host-key, or control attestation.

The one-shot `bootstrap-clean-install` collector then succeeded. Its raw bundle
and the root protected projector's canonical projection were retained by
digest, and the projector published three root-owned mode-0444 observations. A
diagnostic wrapper
incorrectly expected group `wheel` rather than the contractually valid group
`staff` and exited nonzero after projection; the immutable projected bytes and
production suite validation independently advanced the next case to
`bootstrap-no-production-material`.

That next collector reserved its exact empty raw directory, then rejected
before collection with `bootstrap_home_untrusted`: the operator home was an
operator-owned directory at exact mode 0750. No evidence was removed or
rewritten. Verified `labctl stop` returned Gateway, Research, and Target to
stopped, kept Shared disconnected, and closed Parallels. The source repair
adds a dedicated no-delete retention ceremony for exactly this mixed
projected-plus-empty-reservation layout, moves the mode-0700 home requirement
into morning preflight before campaign initialization, and extends the same
fixed Gateway probe to 240 attempts. Until that descendant is published,
installed, and the retained campaign independently verifies, no new campaign
or accepted verdict is claimed.

## Historical-time retention and stale projection checkpoint

The later qualification-owner-projection campaign `ac5211ec...` was retained
without deletion after exact successor `01f0a14...` independently validated
its historical raw time, reproduced `input_file_untrusted`, and preserved all
30 completed cases, 36 observations, and four raw records. The retained path,
plan, inventory, and absent live path independently verified. Exact protected
release `01f0a14...` then passed all ten driver readbacks and fresh post-install
preflight initialized campaign `496eca88...` with zero observations.

Its first bootstrap transition timed out just before Gateway control became
readable. The fixed safe-intermediate re-entry then emitted a verified record:
Gateway and Research running and reachable, Target stopped and unreachable,
Shared disconnected, and Parallels GUI closed. One clean-install collection
succeeded and wrote exactly three canonical operator-owned mode-0600 raw
records. The exact protected root projector was launched once but returned
`bootstrap_host_receipt_invalid` before publishing an observation. Independent
readback confirms the observation directory remains empty and all raw bytes
remain in place.

The Host receipt's `observed_at` is epoch `1795086630`; privileged projection
occurred more than four hours later. Its schema, status, campaign, source,
case, release schema, authorized Developer ID Team `389K3H8Y32`, and stack
schema all match the fixed contract. The collector itself invoked the same
validator before publication, proving the bundle passed at collection time.
The unchanged projection validator therefore correctly rejected the stale
receipt through its one-hour live-consumption bound. This is retained failure
evidence, not an acceptance observation and not grounds to weaken freshness.

The successor adds only a literal stale-projection retention mode. Its isolated
exact-predecessor diagnostic must revalidate the fixed raw set at the common
historical time, reproduce the current stale rejection, prove age greater than
3600 seconds, require zero observations, and verify all predecessor and
replacement protected drivers before a no-overwrite move. Collection and
projection retain their live one-hour gate.

Physical execution at exact published replacement `7bbdd61...` passed that
contract. Independent readiness first reported all ten protected drivers
available. The one permitted retention bound campaign `496eca88...`, source
`01f0a14...`, historical epoch `1795086630`, stale age `20135` seconds,
diagnostic `83f903a5...`, plan `27b82095...`, and result `08abf158...`. It
reproduced `bootstrap_host_receipt_invalid`, retained the exact three raw
records with zero observations, and moved the campaign without overwrite.
Independent verification returned the same complete canonical result and
proved the former live campaign path absent. No collection or projection was
replayed.

The same physical result also proves that the one-hour gate cannot remain the
campaign's final split-phase resumability policy. The campaign is intentionally
valid for as long as fourteen days, and ordinary operator absence or an
overnight pause must not force recollection, deletion, or restart. Source now
implements one shared canonical continuation artifact across bootstrap,
crash-resumed provenance and archive, qualification, cold boot, and export.
It binds the historical time, current campaign/next-case admission, machine,
exact protected manifest, raw hashes and custody, and later projection time;
the final observation validator requires it only when the interval exceeds one
hour. It grants no mutation or authorization authority and never restamps the
historical subject state as current. Hostile tests reject missing, unexpected,
tampered, wrong-driver, cross-raw, cross-time, and noncanonical continuation
evidence. Operator-owned raw custody is derived from the exact stable file
descriptors that supplied the validated bytes rather than a second pathname
resolution. The complete focused acceptance family passes 221 script tests,
27 DDD contract tests, and 25 shared-contract tests. Publication, protected
installation, and one physical delayed projection remain pending before fresh
bootstrap.

## Bounded root-ceremony operator path

The physical campaign exposed a usability defect in the source-side launch
workflow: each otherwise consecutive, noninteractive provenance or archive
case was opened in a fresh Terminal TTY, defeating the ordinary same-TTY sudo
timestamp and forcing a separate administrator-password interaction. This did
not strengthen the immutable protected-driver, fixed-next-case, evidence-
custody, or fail-closed boundaries.

The new bounded ceremony helper keeps one visible operator TTY while retaining
separate privilege boundaries per exact case. Focused tests prove that it admits
only the three fixed noninteractive and non-destructive driver families, queries
the protected next-case implementation before and after every child, emits no
root shell or `sudo -v` invocation, creates private logs exclusively, keeps
qualification collection unprivileged and projects it through a separate
fixed sudo child, stops at the Touch ID boundary, never retries rejection, and
rejects a next case that does not advance. The helper itself has no evidence
authority. The Neo physically completed all remaining provenance and archive
cases through the first published burst and advanced from 12 to 30 accepted
cases. Qualification use of the extended helper remains pending and is not yet
a physical verdict. The complete acceptance-script discovery passes 236
tests, the DDD contract passes 29 tests, and the shared acceptance
contract passes 14 tests at this checkpoint.

## Canonical qualification-control rejection checkpoint

Campaign `be598ae2...`, bound to exact protected release `d7dcf8b8...`, used
the first published bounded ceremony runner to complete every remaining
provenance and archive case, advancing from 12 to 30 accepted cases. The
extended runner then collected and projected
`qualification-no-preexecution`, producing two new root-owned observations and
advancing to 31/91 cases. Its next authenticated Research deployment returned
status 1 before Research created the second case. The Host supervisor retained
an operator-owned canonical `control-rejection.json` for
`qualification-zero-production-authority` with `retry_permitted:false`; the
runner stopped and did not retry.

A bounded authenticated diagnostic, supplied with the exact seven-file
protected qualification closure and campaign, proved no active-run markers,
no Claude process, no Research case output, an unchanged installed release,
an exact Research campaign, and only the completed first fixture. Its control
audit binds the prior accepted request and the later
`command_failed/status_1` request. An earlier diagnostic missing that staged
closure was retained as rejected diagnostic evidence and is not used.

The retention repair now supports both the historical empty-reservation/
traceback layout and the current canonical supervisor-rejection layout. For
the current layout it preserves `control-rejection.json` byte-for-byte and
appends a separately self-digested `retention-diagnostic.json` binding the
supervisor output, Research audit, reviewed diagnostic source, and original
rejection digest. Six focused retention tests pass, including non-overwrite of
the supervisor record. The first physical retention invocation rejected before
mutation because its validator incorrectly required the matched `started` and
`command_failed` audit events to share one wall-clock second; the authentic
Neo events are ordered one second apart under the same request UUID. The
validator now accepts exactly one matched start at or before the failure while
rejecting reversed ordering and duplicate or missing starts. Seven focused
retention tests pass. Publication and physical no-delete retention remain
pending; this campaign must not be retried.

The no-delete retention then completed and independently verified on the Neo.
Protected successor `9df22af...` installed, its post-install preflight passed,
and fresh campaign `05ce4187...` completed both bootstrap cases plus every
provenance and archive case and `qualification-no-preexecution`, reaching
31/91 cases and 36/198 observations. Its next qualification deployment failed
with the same canonical `qualification_research_command_rejected` and retained
a no-retry supervisor record. Reproduction on a fresh campaign exposed the
underlying deterministic defect: the Research installer validated an exact
seven-file/four-directory release, then invoked Python from that release
without disabling bytecode writes. The successful first case could add
`__pycache__`; the next deploy then rejected its expanded release inventory
before creating the next case output. The successor makes release directories
mode `0555` and runs both installed-release Python entrypoints with `-B` plus
`PYTHONDONTWRITEBYTECODE=1`. Physical retention, successor installation, and a
fresh replay remain pending; neither rejected campaign may be retried.

## Parallels 27.1.0 cross-VM transport incident checkpoint

Exact protected Host release `1965de0...` installed successfully and its
post-install preflight initialized campaign `ae9227fd...` with zero raw
reservations and zero observations. Three exact bootstrap attempts then
terminalized before campaign evidence with
`gateway_control_unreachable_before_gui_close`. Each retained the same
intermediate state: Gateway running, Research and Target stopped, and Gateway
Shared disconnected. No case was accepted or relabeled.

Gateway reached an Ubuntu 26.04.1 login prompt but exposed only link-local IPv6
through Parallels; its fixed `172.30.10.1` control address was unreachable.
Changing the documented keyboard optimization mode, recreating the GUI,
restarting the guest, and rebooting the Neo did not restore console input or
network transport. A Research-only comparison reproduced the missing IPv4 on
both NICs, proving the symptom crosses VM configuration. During that comparison
Parallels Desktop 27.1.0 build 58756 crashed in the retained
`CVmGenericNetworkAdapter::getLinkRateLimit()` family while Research continued
headlessly.

All three VMs were independently restored to stopped. A read-only APFS clone
of Research was converted off-machine for forensic inspection. The ext4 image
was cleanly unmounted; its required netplan file is root-owned mode 0600 and
contains the exact expected MAC and IPv4 bindings. Rotated guest logs prove
netplan and `systemd-networkd` selected both generated units and repeatedly
observed carrier. The private Parallels diagnostic separately records idle
virtio queues, an unavailable USB-keyboard monitor, and failed vCPU kicks. The
combined evidence localizes the unresolved failure below the guest
configuration boundary without claiming a final vendor diagnosis.

The stopped boundary also exposed that `labctl stop` restored ephemeral SSH
identities before its first inventory. Source now moves that readiness gate
under the lifecycle lock and invokes it only when at least one guest is
running. Focused tests prove an all-stopped/disconnected stack yields a
verified receipt without an identity source, while a running stack with failed
identity readiness performs no guest or adapter mutation.

The repair was published as `b3bddb3...` to both authorized remotes, installed
on the Neo as the root-owned mode-0555 protected release with a mode-0444
manifest, and physically replayed from the exact clean `public-release`
checkout. Both `op-agents` and the checkout's key-converter interpreter were
absent. With the Parallels GUI and stale Mounter process absent, `labctl stop`
returned a verified complete record with no action failures, all three guests
stopped, and Gateway `net0` disconnected. A separate direct `prlctl` inventory
then reported the same three stopped VMs and disconnected adapter. The
canonical proof was retained on the Neo as
`credential-free-stopped-readback-b3bddb3.json` at
`2026-11-23T02:08:30Z`; its retained private SHA-256 begins `296e82a...`.
Campaign `ae9227fd...` remains live and empty with zero reservations and zero
observations. This closes the credential-free stopped-readback regression; it
does not resolve the independent Parallels guest transport failure. Bootstrap
remains paused pending a reversible alternate NIC-backend qualification or a
vendor-fixed Parallels build on a disposable clone.

## Parallels e1000 disposable-clone qualification checkpoint

The reversible alternate-backend experiment succeeded without mutating any of
the three production VM bundles. Stopped clones of Gateway, Research, and
Target retained the exact private-network names and MAC identities while every
private adapter changed from `virtio` to `e1000`; the Gateway clone's inherited
Shared adapter remained disabled and disconnected. All three clones booted.
Strict host-key checking then proved Gateway at `172.30.10.1`, Research at both
`172.30.10.2` and `172.30.20.1`, and Target at `172.30.20.2`. Gateway reached
Research over ICMP and SSH, Research reached Target over ICMP and SSH, and
Target returned three of three packets to Research with carrier present.

Each clone was then stopped through ACPI and independently read back as
stopped. The three production originals remained stopped throughout, and
their configuration hashes exactly matched their pre-experiment values. No
clone was deleted. Campaign `ae9227fd...` still has no observation entries, no
raw files, and no nonempty raw directory. The canonical proof and its exact
SHA-256 sidecar are retained in the Neo's private acceptance handoff. This
qualifies the e1000 private transport repair, not the campaign itself.

Source now makes `e1000` an explicit plan and authorization fact, creates the
Gateway Shared adapter and every private adapter with that backend, rejects
backend drift during post-create, proxy, provisioning, recovery, and boundary
readback, and uses the same backend for temporary provisioning adapters. The
separate production migration is dry by default and operator-authorized. Its
durable fixed-prefix transaction accepts only the exact stopped identities and
known topology, requires absent Parallels GUI and mounter processes plus a
disconnected Gateway Shared adapter at the mutation boundary, changes one
adapter at a time, independently re-reads the full topology after each step,
and never boots, unregisters, moves, or deletes a VM.
Physical migration and post-migration boundary replay remain pending;
bootstrap must not resume against the old virtio bundles.

## Console-user repair activation checkpoint

Exact commit `43c3b24...` was published to both authorized remotes, passed the
canonical public-release suite, and was built as Developer ID/notarized
submission retained in the private acceptance evidence. The transferred candidate
verified on the Neo with generation-tree SHA-256 `7e9c4628...` and Host
preimage SHA-256 `e8d9a190...`. Two unattended authorization requests expired
without mutation. A later attended generic request
with request digest `13d764...` was approved, then failed before
transition publication. Its root-private receipt is terminal `failed`, exit
status 1, empty stderr, and stdout digest `9fa4b402...`, which the bounded
read-only receipt inspector resolves exactly to
`native_credential_console_user_unavailable`. The installed selectors remain
current `a585d8f7...`, previous `b3d6600f...`; no PENDING record or public
terminal exists. The request is spent and must not be replayed.

This proves the predecessor manager cannot install its own console-user repair:
it evaluates the obsolete `/dev/console` rule before ordinary target
selection. Source now adds a distinct exact-predecessor two-gate recovery bound
to current release `a585d8f7...`, authorization broker `4cfef1c0...`, and
release manager `909c32c1...`. Its password phase stages only a verified
signed/notarized successor and candidate authority while proving both selectors,
the stable launcher, and Host-pair record unchanged. Only the staged successor
broker may create the following fresh Touch ID request. Publication, a new
signed candidate, and physical replay remain pending.

The first exact two-gate candidate was published as commit `c228a02...`, built
and notarized on the trusted release Mac, transferred into Neo-local custody,
and accepted by the transfer verifier. Its password gate rejected before
staging or Touch ID with `console_user_broker_recovery_successor_invalid`.
Independent calculation proved the reviewed function bodies were identical,
but the initial attribute-free `ast.dump` fingerprint differed between the
release Mac's Python 3.13 and Apple's Python 3.9 on the Neo. Current, previous,
the stable Host pair, and the public terminal remain unchanged with no PENDING
record. Source now locates the unique query, stabilizer, and console cross-check
functions through the AST and hashes their exact original source slices; both
Python versions produce the same digest. A fresh published and notarized
candidate remains required.

Portable-fingerprint commit `1e4f7a7...` then passed the password stage and
staged inert release `9030aa65...`. Its fresh Touch ID request `df7c8644...`
failed before transition publication with the exact receipt-mapped
`native_credential_console_user_unavailable`; selectors, STABLE, and launcher
remain unchanged and PENDING is absent. A later root probe of the same staged
manager succeeds, establishing a transient structured-identity window. The
next source-slice gate covers the fixed `scutil` query, a four-sample bounded
stabilizer requiring two consecutive identical identities, and the final
console cross-check. An independently authorized Neo root probe of the exact
transferred successor source returned the expected digest, stable UID 501/GID
20 identity, admitted UID 501, and exit 0 under Apple Python 3.9.6. Publish and
notarize that successor before another fresh request; never replay either spent
request.

The next physical replay exposed an operator-experience regression in the
recovery wrapper rather than a reason to weaken any receipt check. Password
staging exited before Touch ID; an ambiguous broker result then opened a second
password recovery, and an unrecognized protected receipt required a third
root-only inspector. The final inspector was cancelled without reading or
changing the retained receipt. Source now replaces that sequence for this
exact recovery with a single fifteen-minute, non-refreshable privileged
supervisor. It emits a canonical staged record, waits on one inherited pipe
across the login-user Touch ID broker, accepts only close or the exact
request/digest/target-plan inspection-and-recovery message, and emits a bounded
non-secret receipt summary even when the existing recovery allowlist rejects
the error. It cannot accept a command or path and never opens a root shell or
uses `sudo -v`. Focused tests prove exact receipt validation, plan binding,
single staging, terminal rejection reporting, and closure of the successful
broker path without a second `sudo` invocation. Publication and the next
physical one-password replay remain pending; spent request `99051dc0...` must
not be replayed.

Commit `0244902...` was then published to both authorized remotes, signed and
notarized, transferred to the Neo, and staged as target release `2802ef47...`.
The attended recovery proved the batching objective: one administrator password
started the supervisor, the fresh attributed Touch ID request
`d17728de...` was approved, the same root process
returned the bounded receipt result, and no second password prompt occurred.
The install still failed before PENDING with exact stdout digest
`9fa4b402...`; the existing allowlist correctly returned
`recovery-rejected` / `runtime_metadata_receipt_recovery_error_mismatch` and
did not convert the unknown error into authority. Independent readback proved
current `a585d8f7...`, previous `b3d6600f...`, STABLE, and launcher unchanged,
PENDING and TERMINAL absent, and the target retained inert. The request is spent.

Twelve immediate login-context samples then reported stable
`State:/Users/ConsoleUser` identity `alextester` UID 501/GID 20 while the same
immutable manager failed inside the system authorization-service context. Code
review localized the remaining ambient lookup to the outer mutation admission
fence and the inner service transition. Source now carries the already
Touch-ID-attested operator UID through the displayed plan, protected receipt,
fixed command, release-manager custody checks, controller fence, transition,
rollback, and runtime-metadata recovery. Tests make `console_user_uid()` raise
during an authorized live-service install and prove the operation still reaches
its intended service failure, while UID substitution and custody mismatch fail
closed. Publication, a fresh signed candidate, and physical replay remain
pending; request `d17728de...` must never be replayed.

Commit `23fd1736...` was published to both authorized remotes, signed and
notarized, transferred to the Neo, and staged inert as release `c6ced4ff...`.
One administrator password started the bounded supervisor and fresh request
`5511db67...` entered the broker, but no Touch ID window appeared. Unified-log
readback proved the exact staged broker had launched
`SecureSandboxAuthorizationUI.app` from selected predecessor `a585d8f7...`;
that mixed-generation UI exited after 187 ms, before any LocalAuthentication
activity. No protected/public receipt, request file, PENDING, or TERMINAL was
created, and independent readback proved `current`, `previous`, STABLE, and the
launcher unchanged. The ambiguous request is spent and non-replayable.

Source now treats the broker and native UI as an inseparable immutable-release
pair. An installed broker derives the UI only from its own resolved 64-hex
directory beneath the fixed Host releases root; only source-tree tooling
retains the `current` fallback. Focused tests prove exact-release selection,
selected-directory symlink resolution, lookalike-tree rejection, and source
fallback. The complete unrestricted combined suite passes 511 tests with two
expected skips. The managed security-diff scanner refused the valid checkout
at setup with its worktree/HEAD error and produced no canonical scan; manual
trust-boundary review found no reportable issue. The exact committed publication
gate remains required before release. Publish, notarize, transfer, and stage a
new successor, independently prove its broker/UI co-location, and use a fresh
password plus a fresh Touch ID request. Never replay `5511db67...`.

The first `c4cde8e...` physical recovery attempt then stopped at its
non-authorizing preflight notice: the background System Events process existed
for the full 90-second bound, but no dialog rendered on the Neo's physical
display. It timed out as `operator_cancelled`; the log and process readback
prove no password supervisor, Touch ID request, receipt, PENDING, TERMINAL, or
selector mutation followed. A separate harmless visibility probe using the
Terminal application as dialog owner rendered immediately on that same
physical display. Source now makes Terminal the notice owner while preserving
Cancel as both default and cancel button and retaining the 90-second fail-closed
timeout. Focused regression coverage rejects a return to System Events.

The first prompt-free production migration plan rejected before mutation on a
protected seed-control-key mismatch. This exposed an irrelevant inherited
dependency: the topology-only operation had reused create/reprovision's media
schema even though it never reads or attaches an installer or seed. Source now
omits those media authorities only for backend migration while retaining the
exact VM, layout, Parallels binary, network, MAC, process, disconnected-uplink,
and transaction bindings. Physical replay remains pending publication and
installation of that correction.

Terminal-notice successor `a83cb54...` was published to both authorized
remotes, signed and notarized, transferred to the Neo, and staged as immutable
release `19bf21aa...`. Fresh request `f0425b7a...` launched the correct sibling
UI from that exact staged release, proving the broker/UI pairing fix. The UI
exited after approximately 292 ms before application lifecycle entry or
LocalAuthentication. No request file, receipt, PENDING, or TERMINAL remained;
`current` stayed `a585d8f7...` and `previous` stayed `b3d6600f...`. The request
is spent and must never be replayed.

Source review established the fail-closed cause: the selected predecessor's
system broker authenticates Touch ID peers only against its own immutable
release, so it rejected the staged successor UI before protocol processing.
The repair retains that boundary and gives the staged broker one root-custodied,
target-plan-bound connection. Negative coverage proves a mismatched plan cannot
reach execution. Publication, notarization, transfer, and a fresh physical
request remain required.

The published `7b97395...` successor was signed, notarized, transferred, and
destination-verified on the Neo. Its fresh console-user recovery staged exact
successor release `a8fcb549...` and bound readiness to target-plan SHA-256
`8b800927...`, then failed closed before creating a Touch ID request because
the recovery listener rejected canonical macOS `/private/var/run`: that
root:daemon directory is mode 0775, while the first policy rejected every group
write bit. Independent readback found `current` still `a585d8f7...`, `previous`
still `b3d6600f...`, no install transition, no launcher-pair transition, no
terminal record, and no remaining recovery process. No biometric nonce was
created or spent.

The correction recognizes only the resolved canonical runtime directory when
it is a directory owned by root, belongs to group root or daemon, and is not
world-writable. Tests admit root:daemon 0775 and reject both root:daemon 0777
and root:staff 0775; the existing wrong-plan and Control Center rejection tests
continue to pass. Physical publication, notarization, transfer, and one fresh
password/Touch ID ceremony remain required.
