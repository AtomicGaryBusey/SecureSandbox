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
- Gateway, Research, and Target initial states have been read back.

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
install -d -m 700 "$handoff_root"
scripts/enroll-disposable-mac-harness-lifecycle.py \
  --acknowledgement \
  'THIS MAC IS DISPOSABLE AND CONTAINS NO PRODUCTION DATA OR CREDENTIALS' \
  > "$handoff_root/enrollment.json"
```

Do not use `sudo` for enrollment or preflight. Retain the receipt as campaign
evidence; it expires for campaign initialization after 24 hours and must not be
refreshed merely to hide a failed or stale attempt.

Run the read-only gate from the exact checkout with an enrollment receipt kept
outside the repository:

```bash
scripts/harness-lifecycle-acceptance-morning-preflight.py \
  --enrollment "$handoff_root/enrollment.json"
```

The gate rejects execution as root and never invokes `sudo`, the authorization
broker, Touch ID, VM mutation, or an installer. It requires a clean
`public-release` checkout whose `HEAD` equals the live credential-free public
GitHub authority. It queries the literal pinned HTTPS endpoint outside the checkout with repository,
global, and system Git configuration excluded, rather than trusting local
remote names or URL rewrites. The private Hobby mirror is verified during
publication on the trusted development Mac; it is not queried here because a
clean disposable Mac must not receive its production credential. The gate rebinds the fresh enrollment to the current Mac,
repeats production-material and Agents-Keychain absence checks, requires the
Parallels GUI closed, and reads all three VM states. A completely absent
protected release can queue only
`bootstrap-root-owned-exact-commit-host-installer`; a partial, malformed, or
wrong-commit protected release queues nothing. A complete ten-driver release
queues campaign initialization with `next_authorization: none`; it never
preauthorizes any Touch ID case.

### Post-install fixed campaign layout

Only after the protected Host installer succeeds and its complete ten-driver
readback passes, initialize the campaign into the one operator path required
by the broker and projectors. Every directory is private; the initializer uses
`O_EXCL|O_NOFOLLOW` and never replaces a campaign:

```bash
campaign_root="$HOME/Library/Application Support/SecureSandbox/harness-acceptance"
test ! -e "$campaign_root"
install -d -m 700 "$campaign_root"
install -d -m 700 "$campaign_root/observations"
install -d -m 700 "$campaign_root/raw"
install -d -m 700 "$campaign_root/raw/bootstrap"
install -d -m 700 "$campaign_root/raw/qualification"
install -d -m 700 "$campaign_root/raw/recovery"
source_commit="$(/usr/bin/git rev-parse --verify 'HEAD^{commit}')"
scripts/harness-lifecycle-acceptance.py initialize \
  --enrollment "$handoff_root/enrollment.json" \
  --source-commit "$source_commit" \
  --output "$campaign_root/campaign.json"
scripts/harness-lifecycle-acceptance.py next \
  --campaign "$campaign_root/campaign.json" \
  --observations "$campaign_root/observations"
```

If any creation, validation, or `next` query fails, stop. Do not delete a
partial layout, overwrite evidence, regenerate enrollment, or jump to a later
case. Inspect and retain the failed attempt before deciding whether the entire
disposable campaign must be erased and restarted.

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
   source_commit="$(/usr/bin/git rev-parse --verify 'HEAD^{commit}')"
   bootstrap_base=/private/var/db/secure-sandbox-harness-acceptance-bootstrap
   bootstrap_checkout="$bootstrap_base/$source_commit"
   sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin LANG=C LC_ALL=C \
     /bin/mkdir -m 700 "$bootstrap_base"
   sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin LANG=C LC_ALL=C \
     GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 \
     GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
     /usr/bin/git clone --quiet --no-tags --single-branch \
     --branch public-release --template= \
     https://github.com/AtomicGaryBusey/SecureSandbox.git \
     "$bootstrap_checkout"
   bootstrap_commit="$(sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin LANG=C LC_ALL=C \
     GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 \
     GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
     /usr/bin/git -C "$bootstrap_checkout" rev-parse --verify 'HEAD^{commit}')"
   test "$bootstrap_commit" = "$source_commit"
   sudo -- /usr/bin/env -i \
     PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \
     /bin/bash -- \
     "$bootstrap_checkout/scripts/install-harness-lifecycle-acceptance-host.sh" \
     "$source_commit"
   scripts/harness-lifecycle-acceptance.py readiness \
     --source-commit "$source_commit"
   ```

   The root ceremony verifies the clone's commit before executing any file from
   it. The readiness result must be `ready`, report ten available drivers, and
   permit campaign initialization. Otherwise stop and retain the installer and
   readiness output; never retry over the existing protected release. The root
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

When Alex is back at the keyboard, the agent must first report which queue
entry is actually unblocked. Until the disposable Mac arrives and the final
reviewed commit is published and installed there, the correct report is:

> No operator ceremony is runnable yet. The ten driver classes are
> source-complete but physically unavailable; do not authenticate or enter a
> root password on the development Mac.
