# Disposable-Mac Harness Acceptance Operator Queue

Status: queued, not authorized to run on the development Mac. All ten driver
classes are source-complete and source-tested, but remain physically
unavailable until the exact reviewed commit is installed on the disposable
Mac. This
queue becomes executable only after all ten drivers are source-complete,
reviewed, committed, published at one exact commit, and installed on the
dedicated disposable Mac.

## Current-Mac gate

Do not run any command in this document on Alex's present development Mac.
Do not install the protected acceptance release there, create a campaign there,
invoke its Touch ID cases there, or reuse its existing SecureSandbox VMs as the
disposable campaign. Those actions would not produce valid physical evidence.

No Touch ID prompt or root-password prompt is currently runnable on the
development Mac.

## Before asking for a root password

The agent must first prove and report all of the following without mutation:

- the machine is the dedicated disposable Mac;
- the repository is on `public-release`, clean, and at the exact reviewed
  commit present on both intended remotes;
- all ten driver classes report source-complete;
- the protected payload manifest covers the exact ten-driver closure;
- no provider credential environment, production-material path, or Agents
  Keychain service credential is present;
- Parallels Desktop's GUI is closed before any VM lifecycle operation; and
- Gateway, Research, and Target initial states have been read back, or the
  pre-install bootstrap has verified that the entire Parallels inventory is empty.

If any check fails or is ambiguous, do not request a password or Touch ID.

### Enrollment receipt and read-only gate

On the disposable Mac only, create the short-lived enrollment receipt in a
new private handoff directory outside both the repository and SecureSandbox's
application-support tree. Use shell no-clobber so a prior receipt is never
silently replaced:

```bash
# Run from the SecureSandbox repository root.
umask 077
set -o noclobber
handoff_root="$HOME/SecureSandbox-Acceptance-Handoff"
test ! -e "$handoff_root"
/usr/bin/install -d -m 700 "$handoff_root"
/usr/bin/python3 -I scripts/enroll-disposable-mac-harness-lifecycle.py \
  --acknowledgement \
  'THIS MAC IS DISPOSABLE AND CONTAINS NO PRODUCTION DATA OR CREDENTIALS' \
  > "$handoff_root/enrollment.json"
```

Do not use `sudo` for enrollment or preflight. Retain the receipt as immutable
clean-machine evidence and never regenerate it over installed synthetic state.
Campaign initialization may consume that historical enrollment only through a
fresh post-install preflight no more than one hour old; a failed or stale
preflight is not a reason to refresh the enrollment.

Run the read-only gate from the exact checkout with an enrollment receipt kept
outside the repository. Its no-overwrite writer creates the canonical
mode-0600 receipt only if the expected pre-install transition is proven. The
writer requires a real, operator-owned mode-0700 parent without an extended
ACL, publishes relative to an open directory descriptor, and fsyncs both the
file and directory:

```bash
/usr/bin/python3 -I scripts/harness-lifecycle-acceptance-morning-preflight.py \
  --enrollment "$handoff_root/enrollment.json" \
  --expect-next-action bootstrap-root-owned-exact-commit-host-installer \
  --output "$handoff_root/preflight-before-install.json"
```

The gate rejects execution as root and never invokes `sudo`, the authorization
broker, Touch ID, VM mutation, or an installer. It requires a clean
`public-release` checkout whose `HEAD` equals the live credential-free public
GitHub authority. It queries the literal pinned HTTPS endpoint outside the checkout with repository,
global, and system Git configuration excluded, rather than trusting local
remote names or URL rewrites. The private Hobby mirror is verified during
publication on the trusted development Mac; it is not queried here because a
clean disposable Mac must not receive its production credential. The gate rebinds the fresh enrollment to the current Mac,
repeats production-material and Agents-Keychain absence checks, and rejects
the fixed `/`, `/private`, `/private/var`, or `/private/var/db` bootstrap trust
hierarchy if any component is missing, symlinked, non-root-owned,
group/other-writable, carries an extended ACL, or changes identity across the
ACL probe. Its canonical result records each accepted component's device,
inode, UID, GID, mode, and explicit ACL absence. The gate also requires the
Parallels GUI closed and reads all three VM states. Before the protected Host
is installed, a wholly empty Parallels inventory is also accepted for the
bootstrap action; a partial VM set is rejected. Campaign initialization still
requires all three VMs present. A completely absent
protected release can queue only
`bootstrap-root-owned-exact-commit-host-installer`; a partial, malformed, or
wrong-commit protected release queues nothing. A complete ten-driver release
queues campaign initialization with `next_authorization: none`; it never
preauthorizes any Touch ID case.

On Parallels Desktop 27.2.1, `prlctl` loses its login-user API session when
the GUI exits. For the post-install all-stopped boundary only, first open
Parallels and wait for its exact stopped three-VM inventory to be available,
then run the closed-inventory helper immediately followed by morning preflight.
The helper requires one stable GUI PID across readback, quits Parallels,
proves both the GUI and all VM runtimes absent, and publishes a 120-second
canonical receipt bound to the clean commit, public tip, machine, and operator.
Preflight consumes it only through the explicit argument below and repeats the
absence probes. It never discovers the receipt automatically, and the bridge
cannot represent a running, absent, partial, or mixed VM set.

If an honest rejected Host bootstrap created only
`~/Library/Application Support/SecureSandbox/controller-state`, do not remove
it. Preflight accepts and records `bootstrap_controller_state:
empty-coordination-residue` only when the app directory is owner-bound mode
0755, its sole child is an owner-bound ACL-free mode-0700 directory, that child
is empty, and descriptor-pinned identities stay unchanged. Any other state
still stops the ceremony. Initial enrollment remains strict and must precede
any bootstrap residue.

After the Host is legitimately installed, post-install preflight accepts only
that empty `controller-state` plus an owner-bound ACL-free mode-0700
`authorization-requests` directory whose sole entry is the single-link,
zero-byte, mode-0600 regular file `active.lock`. It pins every descriptor,
rereads the complete fixed inventory, and makes a mutation-sensitive comparison
of the lock descriptor and name immediately before classification. Do not empty,
replace, chmod, or otherwise repair this hierarchy to make preflight pass; any
deviation is retained production material and stops the ceremony.

### Product-stack prerequisite before campaign initialization

The protected ten-driver acceptance release is not the ordinary SecureSandbox
Host controller. Before the post-install preflight can authorize campaign
initialization, the disposable Mac must also have the reviewed protected Host
controller and the exact Gateway, Research, and Target VM set. A wholly empty
VM inventory is accepted only for the acceptance-driver bootstrap; it is not a
campaign-ready state.

### Retaining an empty rejected campaign for a driver repair

The clean-machine preflight is intentionally unavailable after campaign
initialization because the campaign directory is retained state. Do not delete,
empty, rename manually, or conceal that directory to make the original gate
pass. If and only if the first collector rejected before reserving a raw case
directory and every observations/raw directory remains empty, use
`scripts/harness-lifecycle-acceptance-retain-empty-campaign.py` from a clean
published replacement checkout. Supply the exact old campaign UUID and source
commit to its `retain` command and the literal acknowledgement printed by
`--help`.

The retention tool revalidates the canonical old campaign, current hardware,
complete predecessor protected-driver release, clean replacement checkout,
the disposable-Mac authorized remote tip, and ancestry from old to replacement commit. It
requires the exact empty directory inventory, writes a self-digested plan into
that campaign, and atomically moves the entire directory without overwrite to
`~/SecureSandbox-Acceptance-Handoff/retired-campaigns/<campaign-id>`. It fsyncs
both parents and exposes retention-only authority. It has no deletion path and
rejects any observation, raw case entry, unexpected file, ACL, link, mode,
identity, machine, commit, ancestry, or destination collision.

If a compatible published correction is needed after that immutable plan was
written but before the move committed, rerunning `retain` does not rewrite the
plan. It validates the complete prior binding and appends a canonical
`retention-plan-supersession-<commit>.json` record. Each record binds the prior
authority digest, prior and replacement commits, current authorized remote tip,
machine, operator, campaign, inventory, destination, and ancestry. Additional
corrections extend that one-successor digest chain; forks, gaps, collisions,
non-descendants, or altered prior bytes fail closed. The atomic move carries
the original plan and every supersession together.

If the process or filesystem reports failure after the atomic move may have
committed, do not rerun `retain`. Run its read-only `verify` command with the
exact old campaign UUID/source and replacement source commits. Verification
requires the live pathname absent, the retained directory's complete identity
and bytes, the exact embedded plan and append-only supersession chain, current machine, predecessor release,
replacement ancestry, clean checkout, and both current remote tips. It returns
the same canonical retention result and performs no recovery mutation.

Only after independent readback proves the original pathname absent and the
same campaign plus plan present at that fixed retained pathname may the normal
pre-install gate be run for the replacement commit. Install the new protected
release side by side; never alter the retained predecessor release. Then run a
fresh post-install preflight and initialize a new exact-commit campaign. A
campaign with any raw or projected evidence is not eligible for this repair
path and requires an evidence-preserving continuation design instead.

#### Retaining the exact empty bootstrap reservation

One narrower evidence-preserving continuation exists when
`bootstrap-clean-install` created its private reservation and then returned the
literal `bootstrap_host_receipt_invalid` before writing any artifact. Do not
remove that directory and do not rerun the collector. After publishing the
repair, run `retain-reserved-bootstrap` with the exact old campaign UUID and
source commit plus the literal acknowledgement shown by its `--help` output.

This separate ceremony requires zero observations, no other raw entry, an
empty private `raw/bootstrap/bootstrap-clean-install` directory, and that
case still being next. Its self-digested plan binds the fixed error and
`empty-reservation` state before the whole campaign is atomically retained.
Before writing that plan, it loads the exact installed predecessor driver,
reruns only its read-only Host receipt construction, and requires the obsolete
validator to reproduce `bootstrap_host_receipt_invalid` against the complete
modern release field set. A caller assertion alone cannot classify the failure.
The ordinary `retain` command intentionally continues to reject this layout.
If the move result is ambiguous, run `verify-reserved-bootstrap` with the old
and replacement commits; never rerun the mutating command speculatively.

A nonempty reservation or any projected observation remains ineligible. Stop
and design a continuation that preserves the actual bytes.

#### Retaining the exact owner-projected bootstrap failure

One further fixed continuation exists only when the first collector completed
and the source projector created exactly the three suite-assigned
`bootstrap-clean-install` observations as operator-owned mode `0600`. Do not
change their modes or owners, remove them, rerun collection, or invoke the
projector again. After publishing the correction, run
`retain-owner-projected-bootstrap` with the exact campaign UUID and source
commit plus the literal acknowledgement shown by `--help`.

The command requires exactly three canonical raw files in the fixed bootstrap
case directory and exactly three canonical projected observations, all private
and operator-owned, with no other raw or observation entry. In a fresh isolated
Python process it loads the exact protected predecessor, revalidates every raw
and observation binding, and requires production `next` to reproduce
`input_file_untrusted`. It then writes a self-digested plan and atomically moves
the whole campaign without deletion or overwrite. If the move is ambiguous,
use `verify-owner-projected-bootstrap`; do not rerun retention speculatively.

After the retained campaign verifies and the corrected release is installed,
initialize a fresh campaign and collect the first case exactly once. Project
it only through the exact installed protected release as root, passing the
operator UID with `--operator-uid`. The source checkout command remains a
non-authoritative mode-`0600` test surface. Read back that all three physical
observations are root-owned mode `0444` before asking `next` to advance.

Do not place Developer ID private keys, Apple notarization credentials,
1Password service credentials, or provider credentials on the disposable Mac.
Copy one public native-Host candidate directory exported from the trusted
release Mac into an owner-private transfer location, then stage it without
authorization:

```bash
python3 scripts/deploy-host-controller.py \
  stage-native-host-candidate /absolute/path/to/CANDIDATE_DIRECTORY
```

The command must report `secure-sandbox-native-host-candidate-transfer-v1`
with `status: verified`. It executes no transferred bytes and grants no root or
runtime authority. It fails closed on an unsafe tree, tampering, a rejected
signature/notarization/source/preimage binding, or an existing destination.
Retain any `.candidate.*` residue as failed-attempt evidence; do not delete it
merely to make a retry pass.

The same transferred-candidate boundary applies to an ordinary Host upgrade
after authorization bootstrap. The deployment resolves the unique retained
candidate whose signed commit, source archive, source tree, and signing
configuration match the exact checked-out source before any local-build
fallback. Consequently the disposable Mac does not need, and must not receive,
the release operator's ignored signing configuration, Developer ID key, or
Apple notarization credential.

Then run the normal attributed one-time Host authorization bootstrap from the
same exact clean public checkout. Capture a distinct private diagnostic log for
every attempt; never rely on terminal scrollback. Review the displayed
candidate, Apple team, certificate, source, preimage, destination inode, tree
digest, clean-machine predecessor mode, and exact predecessor release before
the terminal-bound administrator ceremony:

```bash
scripts/run-host-bootstrap-with-diagnostics.sh
```

The diagnostic launcher creates a new mode-`0600` log for every attempt in the
operator-owned, mode-`0700`
`~/SecureSandbox-Native-Host-Transfer` directory. It records UTC launcher,
command, signal, and exit events; source commit, PID, terminal identity, and
the deployment command's combined output. It refuses a non-`public-release` or
dirty checkout, a non-private/ACL-bearing diagnostic root, or a substituted log
identity. Both lifecycle events and command output use the already-open log
descriptor rather than reopening its pathname, so a terminal close or a failed
`tee` cannot silently erase the reason an attempt ended. Creation fsyncs the
file and its parent; every lifecycle record is fsynced before it is shown.
Source-preflight rejection is recorded before the command is launched. The fixed command
preserves terminal stdin for the administrator password prompt while never
copying password input to the log.

Retain failed-attempt logs beside the inert transfer evidence. Logs must not
contain credentials; the sudo password remains terminal input and is not
written by this pipeline. On a wholly clean destination the plan names a
candidate-derived clean-machine scaffold. The privileged manager may create
only its exact deterministic six-payload predecessor, selector, and stable
launcher; any launcher-only, malformed, substituted, or unrelated partial
state is a hard failure.

The candidate release manager and the reviewed bootstrap manager are distinct
identities when a retained candidate predates a bootstrap repair. The root
loader must digest-check and execute the exact current manager displayed as
`Bootstrap manager SHA-256`; the candidate target is still independently
rederived and bound by its release ID and complete candidate evidence. Never
work around `bootstrap_manager_digest_mismatch` by substituting candidate code
for the reviewed loader.

### Exact private-floor broker recovery

The Neo's first exact-provenance ordinary upgrade reached an on-screen Touch ID
window but exposed a defect in the installed immutable broker after an
unapproved diagnostic ceremony: it tried to open a root-owned mode-0600
candidate-floor marker to inspect its ACL. The fixed broker performs a stable
pathname ACL query and never opens or reads that marker.

Only while the installed predecessor release and broker SHA-256 exactly match
the recovery constants pinned in `host-controller-release.py`, run:

```bash
python3 -I scripts/deploy-host-controller.py \
  --requesting-agent Codex \
  --requesting-session Disposable-Mac-Harness-Lifecycle-Acceptance \
  --purpose "Install exact published Host release <short-commit>" \
  recover-private-floor-broker
```

The first dialog is a bootstrap notice, not authorization. Review its exact
predecessor, candidate, and assurance that `current`, `previous`, launcher, and
stable pair remain unchanged, then continue. Enter the administrator password
only in the terminal prompt. That password phase may stage the exact
signed/notarized fixed release and candidate authority but cannot select it.
The command must then invoke the broker from that exact root-owned staged
release and display a separate ordinary Touch ID authorization window. Approve
only if its plan names the reviewed fixed release. Cancellation, expiry,
unexpected predecessor state, a successor without the exact repair, any
selection during staging, or any changed launcher/pair fails closed. The
recovery is unusable after successful selection; subsequent upgrades use the
ordinary deployment path.

Before showing that notice, the login-user preflight may read only the
canonical public enforcement projections, stable pair, immutable release,
candidate authority, launcher identity, and exact broker digest. It must not
open either root-private floor. The sudo-isolated manager repeats the complete
verification, including private-floor contents, before it stages anything. A
pre-notice `native_stack_coordination_floor_untrusted` result is therefore a
retained preflight failure, not a reason to broaden file permissions or bypass
the floor.

Run this recovery command in a visible Terminal window on the disposable Mac.
Do not use a controller-owned SSH pseudo-terminal for the password step: its
`Password:` prompt is not visible or typeable on the Mac's screen. Output may
be piped to a private retained log, but stdin must remain attached to the local
Terminal tab. Confirm that at least one local Touch ID fingerprint is enrolled
under **System Settings → Touch ID & Password** before launching. Enrollment is
local Secure Enclave state and does not require a cloud account. SecureSandbox
does not permit a password fallback for the subsequent Touch ID gate.

The staged broker applies the same rule to the native-stack coordination
floor: verify the private marker's stable root-owned mode-0600 metadata and ACL
without opening it, and consume only the canonical root-owned mode-0444
enforcement projection. The privileged manager must still read the private
canonical bytes and cross-bind their digest before any Host-pair mutation.

The first enrolled-Touch-ID attempt failed closed with the exact canonical
`native_host_release_tree_identity_inventory_invalid` result. Its receipt and
private log are retained; public readback proved that `current`, the stable
pair, and launcher remained on the predecessor while the target remained an
inert staged release. The repaired receipt-bound verifier permits recovery only
for that exact stdout digest or the previously enumerated signed-app tree
mismatch, and only after independently reproving the unchanged source pair,
exact candidate/plan, empty stderr, exit status 1, and absence of a pending
transition. Never retry the broker request itself, delete the failed receipt,
or treat the staged target as selected.

The next fresh request reached the protected pair transition but target daemon
activation failed during launchd's post-`bootout` same-label cleanup window.
The retained transition is terminal
`source_restored`: the source daemon is running, the stable pair and launcher
remain unchanged, `previous` is absent, and the exact target release remains
inert. The retained request is spent; do not replay it. The next ceremony must
use the published launchd-admission repair
and a newly derived request and plan.

A subsequent exact candidate proved that launchd may temporarily return a
non-canonical state snapshot between stable job removal and label reuse. That
attempt also terminated `source_restored`, and its request is likewise spent.
The next repair may wait through only the specific state-unproven observation,
must then obtain two consecutive exact-absence readbacks before bootstrap, and
must retain the one-successful-bootstrap rule. Do not interpret the temporary
snapshot as absence or manually restart the target service.

Physical replay localized that observation to the post-`bootout` stop fence,
before target selection, rather than the later bootstrap barrier. The request
again terminated `source_restored` and is spent. The corrected fence retains
the captured process-generation proof and requires two consecutive exact-
absence readbacks before plist unlink or target selection. Its pre-`bootout`
inspection remains strict. The complete Host/deploy suite passes 374 tests with
2 skipped, and a sealed Codex Security diff scan found no reportable issue.

The operator-attended `7fec2bd` request was consumed and must not be replayed.
Its receipt-bound recovery began while launchd was replacing the restored source
KeepAlive process and rejected the initial non-canonical snapshot before a new
mutation. Independent readback proved the predecessor selected, `previous`
absent, and its daemon running. The staged repair waits read-only for two
identical canonical initial snapshots within the existing stop timeout; bounded
failure performs no bootout or plist mutation. The Host/deploy suite passes 376
tests with 2 skipped. A new ceremony requires a newly reviewed, published,
signed/notarized, transferred, and independently preflighted candidate.

The resulting `c9e6da1` candidate passed those gates, but its fresh request also
terminalized `source_restored` and is spent. Independent readback proved the
verified predecessor selected, `previous` absent, and its daemon restored. This
run localized the remaining ambiguity after the sole successful bootstrap:
launchd briefly exposed a non-canonical snapshot before publishing the running
generation. The next repair must never resubmit bootstrap, may wait through
only that exact unknown snapshot within the original bound, and must require
two canonical running readbacks of the same PID. A changed PID, canonical
non-running state after a PID is seen, absence, unexpected state, or timeout
fails closed. A new ceremony again requires a new reviewed, published,
signed/notarized, transferred, and independently preflighted candidate.

The subsequent `82685df` candidate completed that recovery. Its transition
terminalized `target_committed`; independent readback proved no pending
transition, the exact current/predecessor selector pair, the authorization
daemon executing from `current`, a clean exact-public checkout, and closed
Parallels GUI. The operator then approved separate canonical-installer and
reviewed-autoinstall publication requests. Both protected images independently
return `promoted_verified`, and their mutable workspace copies and partials are
absent.

The dry-run `neo-8gb` plan created no authorization request and no VM. It failed
closed because the protected seeds embedded a stale public control payload.
The reviewed repair rebuilds all three private seeds, binds their exact hashes,
and validates the already-captured ISO bytes against archived public sources
plus identity-stable private control-key and role-netplan inputs before Host
preimage sealing. Tomorrow's next operator gate is therefore a new Host upgrade
for that exact repair—not VM creation. Do not launch it until the operator is
present. After its independent verification, rerun and review the dry VM plan;
only then may a distinct VM-creation Touch ID request be queued.

After independent Host verification, acquire and publish the pinned Ubuntu
installer, build the exact reviewed autoinstall derivative, review the
`neo-8gb` VM creation plan, and create the exact three stopped VMs only through
the protected broker. Complete guest installation and boundary readback before
running the post-install preflight below. Installer publication and VM creation
are distinct operator-visible ceremonies; neither is authorized by installing
the acceptance drivers.

Two physical `vm-create` requests are retained terminal failures and are spent.
The first localized Parallels 27.1's absent optional `serial0`; the second
proved the erased host lacked the named private networks. Before another
request, `control-net` must read back as `172.30.10.0/27` and `lab-net` as
`172.30.20.0/27`, with `.2` host addresses, `.1` DHCP addresses/range starts,
`.30` range ends, and Mac adapter, DHCPv4, DHCPv6, NAT, and host IPv6 assignment
all disabled. Fully quit Parallels and obtain a successful live inventory
readback; a brief 27.1 post-quit service transition may be waited out before any
authorization exists. The repaired planner must reject a missing or unsafe
plane before Touch ID and bind both exact network records into the plan and
authorization receipt. Publish, install, and independently verify that Host
repair before creating a fresh request; never replay either failed request.

On a clean public checkout, `acquire-ubuntu-installer.sh` first acquires the
exact digest-pinned Canonical release signature and Ubuntu archive keyring from
their fixed official HTTPS endpoints because ignored binary `.gpg` inputs do
not travel in Git. It publishes them exclusively and durably, then requires the
protected verifier to authenticate the tracked manifest under the pinned signer
fingerprint and match the ISO digest before the first Touch ID request. Retain
and investigate any downloaded ISO or verification input that fails this gate;
do not replace it merely to make the ceremony pass.

The clean-host acquisition implementation must not bind a local zsh variable
named `path`: zsh ties that special array to `PATH`, and rebinding it silently
breaks command lookup. System identity and mutation tools in this path use
absolute paths. A failure before the first Touch ID request is therefore a
pre-authorization acquisition failure, not a missing operator prompt; retain
its private partial and diagnostic log and repair the source before relaunch.

The protected verifier's `gpgv` runtime must also be destination-independent.
Its existing payload hash covers a deterministic capsule containing the exact
five non-system dylibs. Host release staging materializes that capsule beneath
the root-owned immutable release, and the verifier rehashes every library
before using only that directory as the dynamic-loader search path. Release
construction also proves from the exact captured Mach-O load commands that the
five files are the complete non-system transitive closure; dependency drift is
a hard build failure rather than ambient destination authority. A missing
development-machine package path is a Host-release portability failure before
authorization, not a reason to install Homebrew on the disposable Mac.

### Post-install fixed campaign layout

Only after the protected Host installer succeeds and its complete ten-driver
readback passes, initialize the campaign into the one operator path required
by the broker and projectors. Every directory is private; the initializer uses
`O_EXCL|O_NOFOLLOW` and never replaces a campaign:

```bash
campaign_root="$HOME/Library/Application Support/SecureSandbox/harness-acceptance"
test ! -e "$campaign_root"
/usr/bin/install -d -m 700 "$campaign_root"
/usr/bin/install -d -m 700 "$campaign_root/observations"
/usr/bin/install -d -m 700 "$campaign_root/raw"
/usr/bin/install -d -m 700 "$campaign_root/raw/bootstrap"
/usr/bin/install -d -m 700 "$campaign_root/raw/qualification"
/usr/bin/install -d -m 700 "$campaign_root/raw/recovery"
source_commit="$(/usr/bin/python3 -I \
  scripts/harness-lifecycle-acceptance-morning-preflight.py \
  --source-commit-from-receipt "$handoff_root/preflight-after-install.json" \
  --expect-next-action initialize-exact-commit-campaign)"
/usr/bin/python3 -I scripts/harness-lifecycle-acceptance.py initialize \
  --enrollment "$handoff_root/enrollment.json" \
  --preflight "$handoff_root/preflight-after-install.json" \
  --source-commit "$source_commit" \
  --output "$campaign_root/campaign.json" \
  --lifetime-seconds 1209600
/usr/bin/python3 -I scripts/harness-lifecycle-acceptance.py next \
  --campaign "$campaign_root/campaign.json" \
  --observations "$campaign_root/observations"
```

If any creation, validation, or `next` query fails, stop. Do not delete a
partial layout, overwrite evidence, regenerate enrollment, or jump to a later
case. Inspect and retain the failed attempt before deciding whether the entire
disposable campaign must be erased and restarted.

The original enrollment is historical proof of the clean-machine
acknowledgement and machine identity; it is never regenerated over the
installed synthetic state. Campaign initialization separately requires the
fresh, canonical post-install preflight receipt, no older than one hour, bound
to that exact enrollment, machine, operator, source commit, protected
ten-driver installation, VM inventory, and current production-material scan.
The campaign uses the protocol's maximum fourteen-day lifetime so overnight
pauses and the thirty destructive recovery cases do not force an avoidable
restart; every observation and final assembly must still complete before its
fixed expiry.

## Root-password queue

These are separate, visible ceremonies. Do not combine them into a persistent
root shell, weaken `sudo` policy, extend the credential-cache timeout, or store
the password.

1. Install the exact-commit protected Host acceptance release with
   `scripts/install-harness-lifecycle-acceptance-host.sh`. The installer must
   reread its root-owned manifest and all ten payload closures before success.
   Only when the retained morning-preflight record names
   `bootstrap-root-owned-exact-commit-host-installer`, bootstrap a new
   root-owned checkout directly from the pinned public authority, run only the
   installer inside that checkout, and immediately verify all ten protected
   drivers:

   ```bash
   set -euo pipefail
   source_commit="$(/usr/bin/python3 -I \
     scripts/harness-lifecycle-acceptance-morning-preflight.py \
     --source-commit-from-receipt "$handoff_root/preflight-before-install.json" \
     --expect-next-action bootstrap-root-owned-exact-commit-host-installer)"
   bootstrap_base=/private/var/db/secure-sandbox-harness-acceptance-bootstrap
   bootstrap_checkout="$bootstrap_base/$source_commit"
   if ! test -e "$bootstrap_base" && ! test -L "$bootstrap_base"; then
     /usr/bin/sudo -- /usr/bin/env -i \
       PATH=/usr/bin:/bin LANG=C LC_ALL=C \
       /bin/mkdir -m 700 "$bootstrap_base"
   fi
   test ! -L "$bootstrap_base"
   test -d "$bootstrap_base"
   test "$(/usr/bin/stat -f '%u:%g:%Lp' "$bootstrap_base")" = '0:0:700'
   test "$(/bin/ls -lde "$bootstrap_base" | /usr/bin/wc -l | \
     /usr/bin/tr -d ' ')" = 1
   /usr/bin/sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin LANG=C LC_ALL=C \
     GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 \
     GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
     /usr/bin/git clone --quiet --no-tags --single-branch \
     --branch public-release --template= \
     https://github.com/AtomicGaryBusey/SecureSandbox.git \
     "$bootstrap_checkout"
   bootstrap_commit="$(/usr/bin/sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin LANG=C LC_ALL=C \
     GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 \
     GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
     /usr/bin/git -C "$bootstrap_checkout" rev-parse --verify 'HEAD^{commit}')"
   test "$bootstrap_commit" = "$source_commit"
   /usr/bin/sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \
     /bin/bash -- \
     "$bootstrap_checkout/scripts/install-harness-lifecycle-acceptance-host.sh" \
     "$source_commit"
   /usr/bin/python3 -I \
     scripts/harness-lifecycle-acceptance-parallels-closed-inventory.py \
     --output "$handoff_root/closed-stopped-vm-inventory.json"
   /usr/bin/python3 -I \
     scripts/harness-lifecycle-acceptance-morning-preflight.py \
     --enrollment "$handoff_root/enrollment.json" \
     --closed-stopped-vm-inventory \
       "$handoff_root/closed-stopped-vm-inventory.json" \
     --expect-next-action initialize-exact-commit-campaign \
     --output "$handoff_root/preflight-after-install.json"
   ```

   The entire block is fail-fast: any receipt, identity, mode, ACL, clone, or
   commit check stops before the next command. The root ceremony reuses only
   the fixed root-owned bootstrap base already
   attested by the fresh preflight. It never removes or replaces an older
   per-commit checkout; Git clone fails closed if the exact destination already
   exists. The installer independently revalidates the complete hierarchy and
   verifies the clone's commit before executing any file from it. The
   post-install preflight must succeed, report ten available drivers,
   and bind `initialize-exact-commit-campaign` into its canonical self-digested
   receipt. Otherwise stop and retain the installer and rejected attempt; never
   retry over the existing protected release. The root
   installer independently requires the requested commit to remain the exact
   public-authority tip, using the same isolated Git context. It fetches that
   tip into a new root-owned bare repository and reads payloads only from that
   store, never from the operator-writable checkout's Git configuration,
   hooks, index, objects, or payload paths. The one-shot checkout is a direct
   child of the fixed macOS system-owned `/private/var/db` hierarchy rather
   than deployment-dependent `/usr/local` state. The final Bash process starts
   with an empty allowlisted environment, every privileged Python verifier
   uses isolated mode, and the installer rejects execution unless its resolved
   path and complete fixed hierarchy are root-owned, non-symlink, and not
   group/other writable.
2. Run each root-only protected Host driver only when it is the campaign's
   exact `next` case. Drivers use fixed state roots and an explicit operator UID;
   no caller-selected executable, store root, VM name, collector, or authority
   is allowed.
3. Install the exact-commit qualification and recovery closures inside
   Research only through authenticated protected control when their Host
   supervisors reach those suite phases. Do not manually copy guest payloads.
4. Run the Research-only cold-boot driver with its exact acknowledgement only
   after the committed synthetic acceptance generation exists. It may stop and
   start only `SecureSandbox-Research`; Gateway and Target must remain unchanged.
5. Run the independent export driver only after all preceding observations
   validate and an empty private directory on an off-host filesystem is
   mounted. The export and local consistency verdict are not the independent
   second-machine verification.

The agent should request each root ceremony only when it can immediately
execute, validate, and retain the resulting record. A password prompt must
never be used merely to “get it out of the way.”

## Touch ID queue

There are exactly 11 suite cases requiring operator biometric interaction.
They must occur in this order and only when `next` names the corresponding
case:

1. `touchid-approve-exact-plan` — approve the exact displayed acceptance plan.
2. `touchid-cancel` — cancel; do not authenticate.
3. `touchid-expired-plan` — follow the driver prompt only after the bound plan
   has expired; do not accept a replacement plan.
4. `touchid-replay` — approve the original ceremony once; the protected replay
   attempt must receive no second usable authorization.
5. `touchid-changed-plan` — authenticate only the displayed test ceremony; the
   consumer must reject the changed plan binding.
6. `touchid-wrong-generation` — authenticate only the displayed test ceremony;
   the consumer must reject the generation mismatch.
7. `legacy-session-touchid-migration` — approve only the exact legacy-session
   migration shown by the protected broker.
8. `rollback-explicit` — approve only the named predecessor generation.
9. `retire-zero-reference` — approve only the generation whose independently
   read reference count is zero.
10. `reject-retire-referenced` — follow the displayed test ceremony; retirement
    must still fail closed because the generation is referenced.
11. `revoke-generation` — approve only the exact irreversible revocation plan
    and read back the monotonic revocation floor.

There is no password fallback for any Touch ID case. An unexpected prompt,
wrong operation, wrong generation, changed plan digest, missing campaign
identity, expired request, or ambiguous UI is a cancellation and retained
failure record—not a reason to retry reflexively.

## Morning handoff

No operator ceremony is currently runnable. The attended `7fec2bd` request is
spent, and its candidate must not be retried. First review and publish the
initial-snapshot stabilization repair, build and notarize its exact Host
products, transfer and admit that new candidate, and complete the read-only
preflight. When Alex is back at the Neo keyboard, the agent must then
revalidate the clean exact-public-release checkout, admitted signed/notarized
candidate, unchanged source selector and launcher pair, running source
authorization daemon, absent pending transition, absent rollback selector, and
closed Parallels GUI. Only then is the exact private-floor broker recovery above
unblocked: one fresh notice, one terminal-bound administrator-password stage,
and one ordinary Touch ID activation. Notices that expire while the operator is
away are retained `operator_cancelled` evidence and authorize no retry or
mutation. Launch a fresh request only when the operator can answer its
90-second notice immediately.

After activation, independently verify the selected Host release, launcher
pair, daemon generation, candidate authority, trust floors, absent pending
transition, and inert predecessor before proceeding. Then acquire and publish
the already retained pinned Ubuntu installer, build and publish the reviewed
autoinstall derivative, review the `neo-8gb` plan, and create the three exact
stopped VMs through their separate protected ceremonies. Do not initialize the
91-case campaign until guest installation, boundary readback, the exact-commit
ten-driver protected installation, and post-install morning preflight all pass.
