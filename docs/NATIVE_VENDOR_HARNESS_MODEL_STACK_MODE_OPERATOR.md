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
   click cannot reuse the authority.
4. Claude opens only its opaque no-capture terminal under the fixed
   restricted/no-tools launch. Codex opens only the schema-pinned typed
   app-server surface; raw JSON-RPC is never an operator terminal.

A session cannot call another available model or native stack. Resume requires
exact equality across the complete bound identity. There is no automatic
fallback when a model, entitlement, credential, generation, or network policy
becomes unavailable.

## Stop, log out, or recover

- **Stop session** uses a separate exact-session Touch ID plan and must reap the
  bound process tree, expire the lease, close egress, purge connections, and
  independently read back absence.
- **Log out** (Anthropic) and **Disconnect** (OpenAI) are destructive,
  confirmed ceremonies. They first stop bound sessions and close egress, then
  invoke the vendor-specific logout/revocation path, and finally prove the old
  binding is unusable. There is no bypass after an ambiguous result.
- Window close, UI EOF, helper loss, process crash, lease expiry, reboot, or
  watchdog failure must converge on the same closed state. Use only the
  read-only recovery/reconciliation action offered by Control Center. Recovery
  cannot invent a successful receipt or resume expired authority.

Do not delete credential stores or receipts manually. If recovery remains
fenced, retain the evidence and resolve the failed boundary before attempting a
new login.

## Distribution and update safety

Native mode is usable only with the exact Developer ID-signed, hardened,
notarized Host components and exact admitted Linux harness generation. A new
harness or SecureSandbox release invalidates the prior measured identity until
its own admission and activation complete.

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
