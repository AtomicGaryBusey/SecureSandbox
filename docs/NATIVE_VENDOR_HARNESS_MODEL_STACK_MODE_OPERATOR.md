# Native vendor stack operator guide

Status: source workflow candidate; protected installation, provider login,
credential projection, and live provider acceptance remain unavailable until
their independent gates report verified.

This guide covers the operator ceremonies for
[Native Vendor Harness + Model Stack Mode](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_DESIGN.md).
It does not turn a source build, a saved settings row, a model-catalog result,
or an operator declaration into live authority. The
[acceptance matrix](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_ACCEPTANCE_EVIDENCE.md)
is authoritative when this guide and a runtime status differ.

## What the mode does

Brokered Provider Profile remains the default mode. Native mode is a narrow
exception for one closed vendor tuple:

- unmodified Claude Code, Anthropic subscription sign-in, the operator's CVP
  Defense declaration, and `claude-mythos-5-1`; or
- exact admitted Codex, OpenAI Sign in with ChatGPT, Daybreak Blue, and one
  code-admitted model (`gpt-6-sol`, `gpt-6-luna`, or `gpt-6.1-sol`).

There is no mix-and-match surface. A Claude credential cannot be offered to
Codex, an OpenAI credential cannot be offered to Claude, and neither credential
can be reused by a brokered profile, plugin, tool, peer harness, or another
session.

## Read the state literally

Control Center reports independent facts for harness admission,
authentication, account/workspace binding, access program, model,
network policy, activation, and live session state. Do not interpret one green
fact as a generic “connected” result.

- `configuration-required` means the row lacks an admitted exact harness
  generation.
- `login-required` means it lacks the opaque account/workspace binding.
- `content-ready` means only that the saved row is structurally complete.
- `operator-external` means SecureSandbox bound a fresh Touch ID declaration
  but the provider did not independently attest that fact.
- `provider-enforced` requires a bounded successful provider operation under
  the exact account, workspace, program selection, and model.
- `unverified` grants no authority.

If an action is disabled, reports `unverified`, or cannot produce independent
readback, stop. Do not substitute a shell login, paste a token, edit a receipt,
weaken a code-signing requirement, widen egress, or retry around the fence.
The original `c8a67ee..459b10a` security scan confirmed one high, three medium,
and one low finding. Commits `51f4205`, `2f9493b`, `9eb755c`, and `05229db`
source-remediate them, but the fixes remain pending an exact-tip remediation
scan. “Source-remediated” is not a protected-installation or live-provider
status.

## Protected deployment and recovery

Native mode remains unavailable until the exact protected Host release has
deployed matching Gateway and Research packages. The deployment status must
name one plan, Host release, catalog digest, exact previous and candidate
package digests, and independent closed-state evidence for both guests.
Installer return codes and transport replies are not sufficient evidence.

In **Settings → Models → Native Vendor Harness + Model Stack**, read the
**Protected native deployment** panel before touching a stack:

1. Both **Gateway + Research** and **Catalog publication gate** must say
   `Ready`, and the panel must show one current Host release. If either query
   is unavailable, invalid, active, mismatched, or recovery-required, all
   stack mutations remain disabled.
2. **Review Deployment…** presents the exact current Host release, catalog,
   Gateway and Research packages, predecessors, payload container, plan digest,
   and expiry. Touch ID authorizes only those bytes. It never downloads or
   installs an unreviewed update automatically.
3. If deployment stops, use **Review Deployment Recovery…** and choose only an
   action the fresh broker plan offers. If no action is offered, stop; there is
   no force-clear path.
4. If catalog publication is active, use **Review Catalog Recovery…** to replay
   only its retained exact authority. An `Invalid` gate is deliberately not
   recoverable from the GUI.

The inspection channel itself is fail closed: Control Center requires the
broker's root peer identity, descriptor-inheritance gate, and bounded socket
options before it trusts any status. An unavailable or untrusted inspection is
not equivalent to an empty, stopped, or ready state.

The Host release shown in an older public catalog record is historical
publication provenance. After a Host upgrade it can differ from the panel's
current Host release. New promotion and projection-recovery plans must name the
current panel release; do not edit or reinterpret the historical record.

The normal order is Gateway candidate, exact Gateway probe, Research
candidate, exact two-plane probe, then Research lifecycle-fence release last.
A lost reply is resolved by the protected status operation; do not rerun a
guest installer manually. The only admissible recovery observations are exact
prior/prior, candidate/prior, or candidate/candidate. Any mixed, unknown,
pending, active-service, changed-watchdog, wrong-catalog, or wrong-predecessor
state leaves the deployment in recovery-only mode.

If Research fails after Gateway commits, SecureSandbox may invoke the exact
Gateway compensation retained by that deployment and then require prior/prior
readback. If compensation or its readback fails, leave the Research lifecycle
fence and Host journal untouched. Never delete a fence, release manifest,
pending record, transaction archive, or legacy-bootstrap terminal; never call
the generic guest deployment channel directly to work around recovery.

The first migration from an exact legacy guest release uses a fixed ephemeral
Research fence bootstrap carried through the existing authenticated deployment
channel. It installs no dispatcher or controller and is not a general recovery
shell. A legacy or absent predecessor that does not exactly match the reviewed
plan is an admission failure, not a prompt to label the guest absent.

Host migration also establishes a coordination floor shared by the stable
launcher, Host release manager, deployment driver, and catalog promoter. Do
not edit or remove `native-stack-coordination-minimum.json`, its public
enforcement projection, `current`, either retained coordination predecessor,
an active-controller marker, or a digest-named launcher backup. The supported
recovery path holds the Host lock and proves the exact predecessor, launcher,
floor, and durable native state before it resumes. Manual filesystem repair can
turn a recoverable crash into an unprovable state and is intentionally not a
bypass.

The only pre-floor Host release that the migration recognizes is the complete,
exact `d8653cb` release with all seven pinned payload digests. The manager first
suspends its exact authorization broker and checks its unchanged process
generation and direct children. If it reports an active historical operation,
the manager resumes that same broker generation: let the operation finish and
then retry the ordinary migration. Do not kill the broker or child, drain or
delete a lock, or unlink any retained state. If the broker has no child, the
manager boots it out and performs two system-wide process inventories before
holding both historical locks through the transition. A near-match release,
detached orphan, changed process, or incomplete inventory has no override.
Source tests cover those cases, but the first real stopped-job `launchctl`
migration remains a protected-installation acceptance gate and is not claimed
by this guide.

## Prepare a stack

1. In **Settings → Models**, select **Native Vendor Harness + Model Stack**.
2. Create or edit one admitted vendor row. Select only the intended model and
   reviewed settings.
3. Select the exact admitted harness generation. A local executable path or a
   version string is not generation evidence.
4. Save the row. Saving is inert: it must not authenticate, open egress,
   activate the stack, or launch a harness.
5. Review the separate readiness facts. Continue only when the next ceremony
   is enabled by protected readback.

Changing vendor, harness generation, account, workspace, program, tier, model,
or settings creates a different stack revision. An existing session remains
permanently bound to its original revision and cannot follow the change.

## Sign in to Anthropic

1. Choose **Open Claude Code sign-in** and review the exact Touch ID plan.
2. Confirm the displayed vendor, harness generation, login-only network phase,
   expiry, and plan digest. Approve once with Touch ID.
3. Interact only with Claude Code's own opaque, no-capture terminal and
   Anthropic-owned browser flow. SecureSandbox must not display or request an
   Anthropic token, authorization code, cookie, raw account label, or
   credential-store path.
4. After the vendor flow exits, allow the bounded status ceremony to derive
   purpose-separated account/workspace digests inside Research. Review those
   digests before binding them to the stack.
5. Declare CVP Defense only in its separate Touch ID ceremony. That declaration
   is `operator-external`; Mythos availability does not independently prove the
   CVP tier.
6. Run the bounded, no-tools Mythos qualification when offered. Only its
   content-free digest may become provider/model evidence.

The admitted Claude generation must be version 2.1.248 or later. Every
qualification and research session must show the fixed restricted/no-tools
policy: `--restricted`, managed plus explicit settings only, no built-in tools,
blanket and MCP tool denial, no permission bypass, and no cloud session. If the
exact launch-policy readback is unavailable or differs, do not start the run.

Cancel, terminal close, timeout, lost UI attachment, ambiguous status, or
account drift must close login egress and leave the stack fenced.

## Sign in to OpenAI

1. Choose **Continue with ChatGPT** and review the exact Touch ID plan and
   stable SecureSandbox host identity.
2. Complete OpenAI's visible system-browser flow. Do not paste a token or
   authorization response into SecureSandbox.
3. Verify the returned opaque account/workspace binding before saving it. The
   signed Host credential helper owns the rotating refresh token; Research and
   Control Center must never receive it.
4. Run **Verify Daybreak/model**. Catalog availability is only a hint. A
   bounded completed turn must name the selected model and explicitly carry
   `cyberAccessProgram: daybreakBlue` before the result can be labeled
   `provider-enforced`.

Before a Codex session reports READY, SecureSandbox must observe a fresh
content-free launcher receipt for that exact PID/start generation and release
only that receipt through the private fd-7 gate while the session-capped permit
and lease are current. The fresh hostile qualification must match that process,
its exact descriptor and environment proof, the reviewed fixed uppercase
`HTTP_PROXY`/`HTTPS_PROXY` values, and the exact transient cgroup. Any direct
route, inherited proxy state, `NO_PROXY`, `ALL_PROXY`, lowercase proxy alias, or
old qualification receipt fences the session. Qualification scratch is
journaled by exact device/inode, and the whole cgroup remains frozen through
the final quiet drain and typed READY write; only successful READY may thaw it.

Any state, nonce, PKCE, callback, client, workspace, token-rotation, expiry, or
program mismatch fails closed. There is no API-key or alternate-account
fallback.

## Activate and start a session

Activation and session start are two different Touch ID decisions.

1. **Activate** reviews the exact closed stack and makes that revision eligible
   for later use. It must not project a credential or start a harness.
2. **Start session** reviews a new plan binding the session, source and source
   manifest, persona, outer-tool catalog, extension set, stack revision,
   account/workspace, program/tier, model/settings, harness generation,
   network policy, lease profile, and expiry.
3. Approve only if every displayed identity matches the intended run. A second
   click cannot reuse the authority. Touch ID authorization requires an
   explicit click on the labeled button: pressing Return never approves a
   native mutation, and Cancel/Escape remains the safe keyboard action.
4. Claude opens only its opaque no-capture terminal under the fixed
   restricted/no-tools launch. Codex opens only the schema-pinned typed
   app-server surface; raw JSON-RPC is never an operator terminal.

A session cannot call another available model or native stack. Resume requires
exact equality across the complete bound identity. There is no automatic
fallback when a model, entitlement, credential, generation, or network policy
becomes unavailable.

During review, the broker holds the exact request-directory and request-file
inodes through the biometric decision and commit reread. Replacing or unlinking
the request revokes it. Swift-parent and Python-supervisor liveness pipes revoke
the same authority if Control Center, its API, or its authorization wrapper
disappears. The longest sign-in path is strictly nested at
`1440 < 1500 < 1560 < 1620` seconds; an outer timeout cannot leave an authorized
inner mutation live. The privileged SSH stream accepts request bytes only after
its exact unbuffered readiness handshake.

## Stop, log out, or recover

- **Stop session** uses a separate exact-session Touch ID plan and must reap the
  bound process tree, expire the lease, close egress, purge connections, and
  independently read back absence.
- **Log out** (Anthropic) and **Disconnect** (OpenAI) are destructive,
  confirmed ceremonies. They first stop bound sessions and close egress, then
  invoke the vendor-specific logout/revocation path, and finally prove the old
  binding is unusable. There is no bypass after an ambiguous result.
- Window close, UI EOF, helper loss, process crash, lease expiry, reboot, or
  watchdog failure must converge on the same closed state. Generic **Recover
  Fenced Stack** cannot clear projection custody.
- Cancellation, timeout, or owner loss terminates the complete owned process
  group, closes the privileged stream, reaps nested SSH/projection children,
  and invalidates the one-shot authorization request. Treat the result as
  ambiguous until the ordinary durable status operation proves the terminal
  state. Do not kill a leftover process manually, delete a request/journal, or
  retry the mutation merely because the UI disappeared.
- For an OpenAI projection fenced after a crash, enter the original **Start
  operation** shown on the reviewed session plan in **Exact projection custody
  recovery**. If the Host journal lacks the helper-committed identity, review
  **Import Identity…** first. It discloses only the exact content-free PID,
  start generation, executable digest, and session authority already in the
  signed helper ledger; it is read-only and custody remains fenced.
- After identity import, or when identity was already journaled, review
  **Reconcile Closed Projection…** as a separate Touch ID ceremony. Verify the
  exact operation/session/stack, PID and start generation, executable digest,
  Host release, guest-absence evidence, egress-closure evidence, and expiry.
  Only this action can clear the one exact ledger row, and only after the Host
  and helper independently prove closure. PID absence, age, or expiry alone is
  never sufficient.
- A stale, replayed, cross-stack, cross-release, extra-field, wrong-kind, or
  digest-mismatched plan fails closed. Rebuild a fresh plan; there is no bypass
  or manual deletion procedure.

Do not delete credential stores or receipts manually. If recovery remains
fenced, retain the evidence and resolve the failed boundary before attempting a
new login.

## Prepare Apple distribution trust

This is a local operator setup, not an agent credential handoff. Complete it on
the release Mac before the one-time Developer-ID floor migration:

1. In **Xcode → Settings → Accounts**, add the Apple Developer Program account
   that owns the intended team. Allow Xcode to obtain the Developer ID
   provisioning profile used by the authorization app's protected Keychain
   capability.
2. Confirm that Keychain exposes a valid **Developer ID Application** identity
   with `security find-identity -v -p codesigning`. The certificate name or
   SHA-1 identity is public build metadata; its private key must remain in
   Keychain.
3. Create a dedicated app-specific password in the Apple account, then store it
   directly in the login Keychain with:

   ```bash
   xcrun notarytool store-credentials SecureSandboxNotary \
     --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID
   ```

   Enter the app-specific password only at `notarytool`'s local secure prompt.
   Never put it in chat, a repository file, an environment variable, shell
   history, or retained evidence.
4. Verify the saved profile without exposing its secret:

   ```bash
   xcrun notarytool history --keychain-profile SecureSandboxNotary
   ```

5. Build the exact Host-product carrier by naming only the public signing
   identity and Keychain profile:

   ```bash
   SECURE_SANDBOX_DEVELOPER_ID='Developer ID Application: …' \
   SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE=SecureSandboxNotary \
     ./scripts/build-native-host-products.sh
   ```

The build must obtain an accepted clean notary log, staple and validate the
ticket, pass Gatekeeper and disk-image verification, and emit one immutable
DMG plus its canonical inventory and content-free audit receipt. The protected
release manager independently repeats the signature, ticket, Gatekeeper,
mounted-inventory, member-hash, entitlement, identifier, and common-Team-ID
checks. The receipt is never install authority by itself.

## Distribution and update safety

Native mode is usable only with the exact Developer ID-signed, hardened,
notarized Host components and exact admitted Linux harness generation. A new
harness or SecureSandbox release invalidates the prior measured identity until
its own admission and activation complete.

The first Developer ID deployment over the existing Development-signed Host is
a named one-time migration, not an ordinary update. Review the exact old and
new release IDs, both authorization-manifest digests, stable-launcher hashes,
and Apple Team ID in its terminal-bound notice. The migration stops both Host
services and removes the executable current selector before establishing the
permanent Team-ID floor. If it is interrupted, leave the floor and recovery
marker untouched and repeat only the same migration command. Never relink the
old release, delete the floor, substitute a certificate, or bypass signature
verification. A fenced installation with no current selector is the intended
safe failure state.

Later certificates may rotate only within the already established Team ID.
Any Team-ID mismatch, missing floor, invalid designated requirement, absent
hardened runtime, failed notarization, or split Host service readback bricks the
install/update path closed until a separately reviewed recovery exists.

SecureSandbox may check for updates and notify the operator. It never downloads
or installs an update automatically. An invalid signature, certificate,
notarization result, digest, provenance envelope, or monotonic version check
blocks the update with no override.

## Evidence to retain

Retain only canonical, content-free receipts and digests named in the
acceptance matrix. Never retain tokens, authorization codes, browser data, raw
account labels, prompt/response content, or vendor credential files as DDD
evidence. Source tests do not replace protected installation, cold-boot,
hostile credential-probe, physical-key, provider-account, or live provider
evidence.
