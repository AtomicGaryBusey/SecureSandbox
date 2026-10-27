# Privileged Control Plane v1

## Status and security claim

Privileged Control Plane v1 replaces automated delivery of reusable guest sudo passwords and root execution from `labadmin`-writable `/tmp` paths. The host authenticates as a separate `securectl` SSH identity. `securectl` has no interactive command surface: sshd forces one root-owned entry point, and sudoers permits exactly one noninteractive transition to the root-owned dispatcher.

This is an authority boundary, not a claim that host compromise is survivable. The dedicated control key and the deployment operation are intentionally administrative capabilities. A host process able to use that key and submit a deployment can install root code on the selected guest. Routine operations do not inherit that power: they are role-checked argv dispatches with no shell.

## Threat model

The boundary assumes the Mac host, its protected controller release, the dedicated control private key, guest kernel, sshd, and root-owned control-plane files are trusted. It treats `labadmin`, `agent`, guest `/tmp`, agent workspace content, shell startup files, and ordinary deployment payload paths as potentially hostile.

Production operator workflows execute both the client and SSH configuration from the root-owned active host-controller release, not from the mutable repository. The repository copies remain the reviewed source used to build releases and to compare expected guest dispatcher bytes. This binding prevents an ordinary workflow from silently substituting an unreviewed client implementation or local SSH execution directive; it does not make a compromised Mac account safe, because that account can use the administrative control key directly.

The design specifically prevents a compromised `labadmin` account from:

- reading a reusable sudo password from automated stdin;
- replacing a staged installer or payload between validation and privileged use;
- invoking the control dispatcher locally;
- selecting a different runtime command, role, or argument shape;
- adding SSH startup hooks to the control identity.

It does not protect against theft or misuse of the host-held control key, malicious code deliberately authorized through the deployment API, a guest-root compromise, or a malicious hypervisor.

## Identities and SSH path

Each guest has a dedicated `securectl` account. Its password is random, undisclosed, and unusable because SSH password and keyboard-interactive authentication are disabled. Its home and authorized-key file are root-owned. The control key is distinct from the provisioning key and is held in the 1Password Agents vault; only its public half is written beneath `runs/`.

`config/sshd-control.conf` applies a root-owned `AuthorizedKeysFile`, forces `privileged_control_entry.py`, and disables forwarding, TTY, user rc, user environment, X11, and interactive commands. The only accepted original command is `request`.

The entry point clears its environment and invokes only:

```text
/usr/bin/sudo -n -- /usr/local/libexec/secure-sandbox/privileged_control.py dispatch
```

The sudoers rule grants that exact transition only to `securectl`. It disables sudo's pseudo-terminal for this identity because the protocol carries binary tar bytes; it does not relax sudo policy for `labadmin` or `agent`.

The installed self-check evaluates sudo's effective policy as `labadmin`, after invalidating any cached credential, rather than parsing a particular sudoers fragment. This catches equivalent passwordless grants such as `NOPASSWD`, `!authenticate`, or membership in an `exempt_group`, including grants introduced outside the known SecureSandbox fragments. An indeterminate sudo-policy result fails closed.

The existing `labadmin` aliases remain available for manual break-glass work and as restricted ProxyJump hops. Control aliases use end-to-end SSH to the destination. A compromised jump host can deny the connection but cannot read or alter its authenticated plaintext without defeating SSH host/key authentication.

## Protocol and runtime operations

Every request is a bounded big-endian length-prefixed canonical JSON header followed by an explicitly sized optional payload. The dispatcher rejects malformed schema, truncation, trailing bytes, oversized headers or bodies, unknown operations, wrong-role operations, and invalid argument shapes.

Routine `run` requests map an operation name to an absolute argv prefix. No shell parses runtime arguments. A separate, one-entry `pipe` allowlist carries the bounded source-import frame to the Research importer; the request header binds its exact SHA-256, and no ordinary operation can receive stdin. The allowlists are per role. Identifiers, digests, profiles, timestamps, and backup generations use full-match validators. The dispatcher supplies a small fixed environment.

Accepted, rejected, and nonzero commands append a content-free root-only audit record. The record contains the role, operation or installer name, outcome, error class, timestamp, and canonical request digest. It does not record arguments, request payloads, source content, credentials, package names, or model traffic.

Every client request carries a UUID. Before any side effect, the dispatcher durably creates a root-only receipt and fsyncs a `started` audit event. A repeated UUID is rejected, including after a lost SSH response or an ambiguous crash. Completion is atomically recorded before the final audit event. Failed clients print the UUID, and `--request-id` can deliberately replay that UUID to confirm rejection while `control-audit-tail` exposes its content-free disposition. This provides at-most-once execution per request identity. A newly generated identity is a new authorization, not a retry; after an ambiguous failure an operator must inspect the audit rather than rerun the command. The bounded receipt ledger fails closed at 4,096 entries and must be retired only through a separately reviewed administrative procedure.

The host client also enforces a real wall-clock deadline around SSH and request
streaming. SSH runs in its own process group; expiry sends TERM, waits a fixed
grace period, and then attempts KILL for the whole group even when the group
leader has already exited. The failure reports the request UUID and is treated
as an ambiguous outcome, so callers inspect the receipt/audit state rather
than issuing the operation under a fresh identity. Package-restoration readiness
probes use this client deadline directly; raw administrative SSH postconditions
use the same bounded process-group watchdog.

Resume authorization uses one root-side `session-refresh-contains` operation. The session registry holds an exclusive root-owned lock while it discovers journals, atomically publishes the new registry, and tests the requested UUID against that same successful discovery snapshot. A discovery failure cannot fall back to a stale registry, and a concurrent launch cannot interleave a separate refresh and membership check.

## Authenticated deployment

Deployment is an explicit root-equivalent operation. The client snapshots regular single-link local files with `O_NOFOLLOW`, detects concurrent mutation, computes SHA-256, and sends a deterministic inventory with an uncompressed bounded tar payload. A secret may be read from client stdin into one mode-0600 virtual file; it is never placed in a host pathname or command argument.

The guest rejects links, special files, traversal, duplicates, undeclared members, inventory mismatch, size/digest/mode mismatch, more than 256 files, a file over 128 MiB, a request over 256 MiB, an invalid installer, and trailing protocol input.

Verified files are created with exclusive, no-follow opens beneath a root-only staging parent. The installer child receives a private mount namespace in which its request directory is bind-mounted over `/tmp`. The parent remains mode `0700`; only the request directory mounted inside the child namespace is changed to normal sticky-temporary-directory mode `01777`. This permits deliberately deprivileged installer children such as APT's `_apt` signature verifier to use `/tmp` without exposing the mount to unrelated guest processes. Bundle members retain their independently authenticated modes, including mode `0600` for a virtual secret input. Existing installers may therefore use `/tmp/name` without observing the shared guest `/tmp`; those names resolve only to authenticated root-owned inodes for the lifetime of the child. The parent cleans the staging tree after exit.

Large non-secret artifacts do not weaken the fixed 128 MiB per-file or 256 MiB per-request bounds. The pinned Claude binary, for example, is transported as three deterministic sub-limit parts and reassembled in a root-private temporary file; the installer then verifies the original whole-file SHA-256 before installation.

## Bootstrap and migration

Installing this boundary through an already-compromised `labadmin` channel cannot prove the new root files are honest. Migration is fail-closed:

1. Create a distinct Ed25519 `SecureSandbox-Control` key in the Agents vault.
2. Reprovision each guest from the verified installer and seed, before loading any hostile model or source.
3. Put the control installer, dispatcher, entry point, SSH policy, sudoers policy, public key, and exact role netplan into the fresh NoCloud seed. Bounded base64 payloads are reconstructed beneath `/target/root` by validated autoinstall `late-commands`, installed before the first boot, and removed after successful installation; no unsupported `write_files` key is placed in the autoinstall mapping. The seed performs no network package acquisition. `verify-autoinstall-seed.py` independently checks the ISO inventory, role metadata, password-hash form, absence of private-key material, exact embedded payload and netplan bytes and modes, control public key, installation order, and cleanup before `create-vms.sh` can attach the seed.
4. Run `configure-guest.sh` with `SECURE_SANDBOX_CONTROL_PUBLIC_KEY_FILE` set. Configuration refuses to complete without it.
5. Load both keys with `labctl key-load`.
6. Add the three `*-control` aliases from `config/ssh_config.example` to the untracked local `config/ssh_config`; each uses the separate control agent socket and the existing administrative route only as a ProxyJump.
7. Run `verify-privileged-control-live.py`, then the full containment suite. The live verifier checks all three roles first-person: forced-command enforcement, exact installed hashes and root ownership, effective sshd restrictions, sudoers syntax, role denial, malformed framing, at-most-once replay rejection, audit creation, local `labadmin` passwordless-sudo denial, and rejection of a well-framed deployment whose declared content digest is false. The allowlisted `control-self-check` operation performs the guest-local portion as root, fails on any ownership, mode, hard-link, account, effective-sshd, sudoers-syntax, or passwordless-`labadmin` discrepancy, and returns only hashes and policy metadata for host comparison.
8. Rotate the old `labadmin` passwords. No automated runtime path may know or read them.
9. Take a coordinated cold checkpoint only after all three guests and the immutable host controller pass.

For an already bootstrapped v1 lab,
`python3 scripts/privileged-control-operation.py deploy` performs the reviewed
update path. The operation holds the host controller's launch-admission
coordination lock for the complete deployment and rejects any existing active
controller marker. The lock-owning Python operation directly performs every
deployment step; there is no separately invocable shell driver or forgeable
environment flag that can bypass serialization. SIGHUP, SIGINT, and SIGTERM
are deferred while an authenticated child is active. Child creation is signal-
masked and each child starts in a separate process group, so a terminal closure
cannot release the lock while that child continues; the operation stops before
the next step and returns the conventional signal-derived status.
Consequently a Claude launch cannot begin between the idle proof and the
session-policy replacement. The operation first verifies the protected host-controller release
and upgrades Research's root-owned dispatcher so a pre-fix installation can
provide the corrected idle probe. Before any broader state change, it requires
Research to prove that no lifecycle marker or Claude process is active. It then
uses only the protected client and role-bound control aliases to install the
dispatcher on the other guests, installs the matching lock-aware session
registry and Claude launcher policy on Research, and executes the live
adversarial verifier. The operation
is content-bound and idempotent: after an interruption, rerunning it replaces
the same root-owned files and revalidates the complete three-guest state.

The stopped pre-v1 VMs are not silently upgraded and must not be used as evidence that the new boundary is deployed.

`reprovision-vms.sh` makes this replacement explicit and recoverable. Its default mode only verifies and prints the plan. `--apply` accepts only the three stopped VMs at their exact expected bundle paths, unregisters and moves those bundles into ignored local quarantine without deleting them, then invokes all-or-nothing fresh creation with the verified installer and role seeds. If fresh creation fails, newly created VMs are removed and the original bundles are moved back and re-registered. A successful run retains the originals until post-acceptance retirement is separately authorized.

Installer availability is also a pre-mutation gate. `reprovision-vms.sh`
authenticates the signed Canonical manifest and re-hashes the root-private
installer before unregistering any VM. The pristine Canonical image is not
itself an unattended installer: its default GRUB entry does not carry the
`autoinstall` kernel argument. `build-autoinstall-installer.sh` therefore
replays the Canonical boot layout while replacing only the reviewed GRUB
configuration. It fixes the GPT GUID, ISO timestamps, ownership, modes, and
Rock Ridge timestamps so two builds are byte-identical. The root-owned
verifier accepts the derivative only at the reviewed whole-image SHA-256
embedded in its release-bound source and only while both the exact pinned
Canonical base digest and its signed manifest verify. A legitimately signed
same-name respin therefore fails closed until a separately reviewed release
updates both bindings. A compromised or
changed local remastering tool can cause a fail-closed mismatch but cannot
substitute boot media accepted by provisioning.

If the protected store is empty,
`acquire-ubuntu-installer.sh` resumably downloads the fixed ARM64 image from
Canonical over HTTPS, verifies the pinned signature and SHA-256, promotes the
exact authenticated bytes, builds and promotes the content-bound autoinstall
derivative, re-verifies both protected copies, and only then removes redundant
mutable images. A failed acquisition, remaster, or protected verification
leaves all VMs untouched.

Clean-image package provisioning that cannot be satisfied by the verified ISO
is an explicit maintenance boundary, not normal runtime behavior. A role-bound
installer may use a temporary hypervisor shared adapter only while its exact
MAC is matched by a temporary netplan. Before DHCP or downloads, it atomically
loads a temporary nftables policy with default-drop input, forward, and output
chains; only loopback, established traffic, DHCP, DNS to the fixed shared-network
resolver, and HTTP(S) through that exact interface are permitted. Cleanup must
reload the normal role policy and prove three live default-drop chains; a reload
or validation failure rejects the installation while the restrictive maintenance
policy remains. Cleanup restores DNS state, removes the netplan, rediscovers the
interface by MAC, forces it down, flushes its addresses, and refuses success
while any IPv4 default route remains. The host then stops the guest, physically removes the adapter,
restarts it, and verifies both the VM device inventory and guest routes before
continuing. Repository signature verification remains in APT's `_apt` sandbox;
provisioning does not use an `APT::Sandbox::User=root` bypass.

The protected installer and its dedicated directories are root-owned and
non-writable. The two dedicated directories use traverse-only `0711` modes so
the unprivileged Parallels process can open the already-known, digest-named
`0444` ISO without gaining write authority or directory enumeration. The
verifier rejects any other effective store modes. A migration-only access
repair authenticates the signed manifest and hashes the protected ISO both
before and after changing those directory modes.

## Evidence semantics

Source review and unit tests establish code-level properties of framing, validation, extraction, dispatch, and host-controller use. They do not establish guest state. A guest is `deployed` only after clean bootstrap and first-person checks. A checkpoint is `accepted` only after live negative and legitimate controls pass on all roles.
