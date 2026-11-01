# Disposable-Mac Harness Acceptance Operator Queue

Status: queued, not authorized to run on the development Mac. The interactive
authorization, runtime, and management drivers remain source-incomplete. This
queue becomes executable only after all ten drivers are source-complete,
reviewed, committed, published at one exact commit, and installed on the
dedicated disposable Mac.

## Current-Mac gate

Do not run any command in this document on Alex's present development Mac.
Do not install the protected acceptance release there, create a campaign there,
invoke its Touch ID cases there, or reuse its existing SecureSandbox VMs as the
disposable campaign. Those actions would not produce valid physical evidence.

No Touch ID prompt or root-password prompt is currently queued for the
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

## Root-password queue

These are separate, visible ceremonies. Do not combine them into a persistent
root shell, weaken `sudo` policy, extend the credential-cache timeout, or store
the password.

1. Install the exact-commit protected Host acceptance release with
   `scripts/install-harness-lifecycle-acceptance-host.sh`. The installer must
   reread its root-owned manifest and all ten payload closures before success.
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
entry is actually unblocked. Until the disposable Mac arrives and the three
remaining interactive drivers are complete, the correct report is:

> No operator ceremony is runnable yet. Continue source implementation; do not
> authenticate or enter a root password on the development Mac.
