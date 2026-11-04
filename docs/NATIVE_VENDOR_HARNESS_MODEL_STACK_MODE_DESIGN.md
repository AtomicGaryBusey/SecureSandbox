# Native Vendor Harness + Model Stack Mode DDD

Status: architecture accepted; implementation in progress; no live login,
provider-account mutation, harness admission, or production activation has
occurred

## Decision

SecureSandbox will support a second, explicitly selected run mode named
**Native Vendor Harness + Model Stack Mode**. It admits an exact vendor harness,
the vendor's documented user-authentication path, one provider account or
workspace, one access-program tier, and one model as a single indivisible stack.

The existing **Brokered Model Profile Mode** remains the default. Native mode is
not a generic OAuth option and does not allow arbitrary harness/provider
composition. A new stack pairing exists only after reviewed code admits it.

The first two candidate stacks are:

1. unmodified Claude Code + Anthropic subscription OAuth + the operator's exact
   CVP Defense authority + `claude-mythos-5-1`; and
2. pinned Codex app-server/CLI + OpenAI Sign in with ChatGPT + the operator's
   exact Daybreak Blue authority + one explicitly selected supported model,
   initially `gpt-6-sol` or `gpt-6-luna`.

Saving a stack never authenticates, activates, opens network access, or starts a
harness. Login, activation, account switching, model switching, logout, and
credential destruction are separate protected ceremonies. A session is bound
permanently to the exact stack revision it starts with.

## Why this mode exists

The completed multi-harness design assumed every harness could use the common
Gateway model broker and therefore prohibited login inside Research. That is
still the strongest provider-neutral design, but it excludes entitlements that
vendors deliberately expose only through their native harness and user OAuth.

Two current vendor facts justify a narrow exception:

- Anthropic permits an end user to sign in to the unmodified Claude Code binary
  with their own subscription even when a platform hosts that binary. Anthropic
  forbids a third-party application from collecting, storing, or intermediating
  Claude subscription credentials, and requires the sign-in to complete through
  Anthropic's own flow.
- OpenAI explicitly documents OAuth token sharing for open-source, locally
  hosted applications, including driving the official Codex app-server with a
  ChatGPT-plan access token. OpenAI requires accurate caller attribution and an
  exact user/workspace registration.

Those are different custody contracts. SecureSandbox must model the difference
instead of pretending all OAuth tokens are interchangeable bearer strings.

## Relationship to prior decisions

This DDD narrowly amends the completed Multi-Harness Admission and
Plugin-Ecosystem Isolation DDD:

- its blanket ban on harness OAuth remains in force for brokered mode,
  core-only qualification, plugins, extensions, and every unregistered pairing;
- provider credentials remain Gateway-only in brokered mode;
- native mode is admitted only for an exact vendor harness whose vendor permits
  the selected login and hosting arrangement;
- native credentials can never be projected into another harness, extension,
  tool service, brokered profile, or peer session; and
- native mode does not enable vendor marketplaces, ambient project settings,
  hooks, connectors, remote MCP, self-update, peer harnesses, or plugins.

The Harness Lifecycle and Verified Upgrade system remains the authority for the
exact executable generation. Native login never authorizes installation or
upgrade. A harness update invalidates the stack binding until the new generation
passes its own admission and the operator activates a revised stack with Touch
ID.

## Two security contracts

| Property | Brokered model profile | Native vendor stack |
| --- | --- | --- |
| Upstream credential owner | Gateway broker | Vendor-specific; vendor harness for Claude, SecureSandbox Host for OpenAI SIWC |
| Model API connection | Gateway terminates and reconstructs | Vendor-documented native path; opaque TLS for Claude, documented Codex app-server path for OpenAI |
| Independent request/model validation | Gateway enforces exact adapter and model | Root-owned adapter plus attested vendor harness; provider-side policy where available |
| Cross-vendor model use | Supported through reviewed adapters | Prohibited; vendor, harness, auth, program, and model are one stack |
| Harness login | Disabled | Required only by the admitted stack contract |
| Credential visible to model tools | No | Must remain no; proof mechanism differs by vendor |
| Assurance on compromised harness | Gateway still rejects alternate model/provider calls | Weaker unless provider-side controls independently reject them; this difference is displayed and audited |
| Fallback | Another separately activated brokered profile | None; auth, entitlement, or policy failure fences the stack |

Native mode is therefore not “brokered mode with OAuth.” It has a different
trust boundary and must never inherit the stronger broker-independent claims.

## Closed stack identity

The tracked example catalog is
`config/native-vendor-stacks.example.json`. The ignored operator catalog will
use schema `secure-sandbox-native-vendor-stack-catalog-v1`.

Every entry binds:

- stable stack ID and display name;
- `mode: native-vendor-harness-model-stack`;
- vendor ID;
- exact harness ID, adapter ID, and admitted generation digest;
- vendor-specific authentication mode and fixed credential-custody owner;
- SHA-256 bindings for the authenticated account subject and workspace;
- exact access program and tier;
- exact model ID, display label, and closed settings; and
- one reviewed network-policy ID.

The catalog stores no access token, refresh token, authorization code, PKCE
verifier, cookie, email address, raw subject, or raw workspace identifier. A
catalog with missing account/workspace digests is valid to stage but reports
`login-required` and cannot activate.

The initial pairing registry is code, not data:

| Vendor | Harness | Authentication | Custody | Program | Models |
| --- | --- | --- | --- | --- | --- |
| Anthropic | `claude-code` | `anthropic-claude-subscription-oauth` | unmodified vendor harness | CVP Defense | `claude-mythos-5-1` |
| OpenAI | `codex` | `openai-sign-in-with-chatgpt` | SecureSandbox Host, access token projected only to Codex app-server | Daybreak Blue | `gpt-6-sol`, `gpt-6-luna` |

Adding a model, tier, authentication mode, harness, adapter, or network policy
requires reviewed source and tests. A settings edit cannot manufacture a new
pairing.

## Anthropic / Claude Code custody contract

Claude subscription OAuth is admitted only under all of these conditions:

1. The executable is the exact admitted, unmodified Claude Code generation.
2. The operator personally uses Claude Code's own login UI and Anthropic-owned
   authorization flow. SecureSandbox does not render a Claude login form,
   exchange the authorization code, parse the token, copy the credential file,
   or place a subscription token in 1Password, Keychain, arguments, environment
   constructed by the Host, logs, receipts, or the Gateway.
3. The native adapter does not set `ANTHROPIC_API_KEY`,
   `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, or gateway mode. It does not
   disable or replace a built-in Claude authentication method.
4. Claude Code uses end-to-end TLS to Anthropic through a destination-restricted
   opaque tunnel or equivalent routed egress. The Gateway may enforce
   destination, connection count, byte/time ceilings, and lifecycle, but it
   cannot terminate TLS or observe credentials or content.
5. The vendor credential store is in a dedicated native-stack home and is not
   mounted into brokered sessions, other harnesses, outer tool services, source
   worktrees, Target, exports, or evidence collectors.
6. Root-owned managed policy restricts the available model set to the selected
   model and the launch vector names it exactly. This is defense in depth, not
   an independent guarantee against a malicious vendor binary.
7. Login status is observed only through a bounded, content-free vendor status
   surface. Evidence retains digests and state, never account labels or tokens.
8. A logout/account-change ceremony stops every bound run, closes native
   egress, invokes the native logout path, proves the old binding is no longer
   usable, and only then permits local credential-store retirement.

Anthropic's current terms permit hosting an unmodified Claude Code binary for
an end user who signs in with their own subscription, while prohibiting token
intermediation. If Anthropic changes or clarifies that contract, admission
fails closed until this DDD is reviewed again.

## OpenAI / Codex custody contract

The OpenAI stack uses OpenAI's documented Sign in with ChatGPT flow for
open-source, locally hosted applications:

1. Control Center generates a stable opaque host identity before first sign-in.
   Prefer the RFC 9278 JWK-thumbprint URI of a dedicated Secure Enclave public
   key. The host identity is not a credential.
2. First registration uses OpenAI's `dynamic_agent_client`, the accurate
   `SecureSandbox` agent name, a fresh state, nonce, and PKCE verifier, and the
   exact loopback callback. The issued client ID is bound to the selected user
   and workspace.
3. Client ID, opaque account/workspace bindings, token metadata, and credential
   material are separate. Refresh and access tokens live only in an app-specific
   macOS Keychain item protected for the signed Control Center installation.
4. Access tokens last one hour. Refresh tokens rotate on every successful
   refresh and currently expire after thirty days. A refresh failure fences the
   stack; there is no API-key or other-account fallback.
5. Only the short-lived access token is projected to the exact admitted Codex
   app-server process, using OpenAI's documented Responses-provider
   configuration. The refresh token never leaves the Host.
6. Initialization uses stable, honest client identity values. Every turn names
   the exact model and includes `cyberAccessProgram: daybreakBlue`; omission is
   not interpreted as equivalent. `store` remains false where the underlying
   documented path requires it.
7. Codex model catalogs are discovery hints, not entitlement evidence. A
   bounded successful inference under the exact account, workspace, model, and
   Daybreak selection is required before activation can claim live readiness.
8. The app-server access-token environment is stripped from every tool child,
   hook, plugin, MCP process, diagnostic, crash report, and transcript. If that
   cannot be independently demonstrated for the exact Codex generation, the
   stack is not admitted.

Daybreak remains internal, operator-only authority. Native mode cannot expose
it to another user, customer, remote service, plugin, peer harness, or
unattended downstream product workflow.

## Credential and tool separation

Native authentication introduces a bearer credential into the vendor harness
trust domain. That is a material change from brokered mode.

The production topology must provide a credential compartment with these
properties:

- only the selected vendor harness process can access its native credential or
  projected access token;
- tool subprocesses receive a newly constructed environment that excludes all
  credential and OAuth variables;
- source, execution, findings, memory, and corpus tools remain outer services
  with their existing identities and never share the harness home;
- ambient credential files, user settings, project settings, plugins, hooks,
  skills, agents, connectors, and peer executables remain absent;
- the provider tunnel is unavailable to tools and descendants that are not the
  registered harness process tree; and
- qualification includes a hostile model/tool attempt to read, inherit, copy,
  encode, or transmit the credential.

For Claude, the control plane cannot inspect the vendor credential to prove
this boundary. Proof must come from filesystem/process/network observation and
negative tests. For OpenAI, the Host can prove the refresh token never left
Keychain and can bind each short-lived projection to one app-server process.

## Network architecture

Native Claude traffic must remain TLS end-to-end between Claude Code and
Anthropic. The Gateway implements an opaque, destination-restricted tunnel; it
does not act as an Anthropic-compatible reverse proxy and does not see or
replace authorization headers.

The tunnel contract is closed per stack and phase:

- `login`: only documented vendor authentication and callback-support
  destinations, for one expiring operator-authorized ceremony;
- `inference`: only the documented vendor inference destination set;
- `status/logout`: only the minimum destinations needed for native status or
  revocation; and
- `closed`: no provider egress.

Each phase has connection, byte, duration, DNS, address, and redirect bounds.
Resolved addresses are independently checked as public and pinned for the
connection. An authentication flow cannot widen inference egress, and a
successful login automatically returns the tunnel to `closed` until stack
activation.

OpenAI SIWC authorization occurs in the visible macOS system browser. The Host
exchanges and refreshes tokens only with fixed OpenAI origins; Codex app-server
receives inference egress only. Neither vendor flow may use an embedded web
view that could observe credentials.

## Model, program, and session binding

A native session binds all of the following into its protected catalog,
Gateway lease, Research lease, process record, and final summary:

- mode and stack digest;
- vendor and network-policy IDs;
- harness, generation, manifest, executable, inventory, and adapter digests;
- authentication mode and credential-custody class;
- opaque account and workspace binding digests;
- access-program ID, tier, and requirements version;
- exact model ID and settings; and
- persona, tool catalog, extension set, source, and session identities.

Resume requires exact equality. Native-to-brokered, brokered-to-native,
cross-vendor, cross-account, cross-workspace, cross-program, cross-tier,
cross-model, or cross-generation resume is rejected. Import may create a new
session only after a separately designed content-only migration; it never
reuses vendor session authority.

Native mode has no automatic fallback. If OAuth expires, entitlement changes,
the model disappears, a provider requires re-verification, the harness updates,
the network policy becomes stale, or status is ambiguous, admission closes and
the user is told which boundary needs attention.

## Human authorization

Touch ID authorizes SecureSandbox actions, not vendor identity. Vendor OAuth
authorizes the provider account, not SecureSandbox policy. Both are required
and neither substitutes for the other.

Touch ID is required to:

- begin a native sign-in ceremony;
- bind the resulting account/workspace digest to a staged stack;
- activate or roll back a stack;
- change model, effort, program, tier, account, workspace, or harness
  generation;
- log out or destroy local credential state; and
- reopen a fenced stack after independently verified recovery.

The authorization display names the exact harness generation, vendor,
credential-custody class, account/workspace digests, access program/tier,
model, network policy, session impact, and plan digest. It explicitly states
that native mode gives the vendor harness credential authority and lacks the
Gateway's independent request-body enforcement.

## Control Center behavior

Settings gains a top-level mode selector:

- **Brokered Provider Profile**; or
- **Native Vendor Harness + Model Stack**.

Native stack rows show separate state for harness admission, authentication,
account/workspace binding, program entitlement, model entitlement, network
policy, activation, and live run. The GUI must never collapse these into one
green “connected” state.

Provider-specific actions are explicit:

- Anthropic: `Open Claude Code sign-in`, `Verify native status`, `Log out`;
- OpenAI: `Continue with ChatGPT`, `Verify Daybreak/model`, `Disconnect`.

The GUI shows no token, credential path, raw subject, raw workspace ID, browser
callback code, or arbitrary provider error body. Ambiguous results retain the
fence and offer read-only reconciliation.

## Threat model

| Threat | Required response |
| --- | --- |
| Catalog pairs Claude OAuth with Codex or another harness | Code-level pairing registry rejects it |
| Harness switches model after activation | Root-managed single-model policy, exact launch/turn parameter, provider-side restriction where available, post-turn model observation; residual compromised-harness risk is disclosed |
| Claude token crosses the SecureSandbox control plane | Opaque TLS and vendor-owned credential store; any token observation is a critical failure |
| OpenAI refresh token reaches Research | Keychain-only refresh custody; only one-hour access token projected to one process |
| Tool inherits an access token | Clean environment and separate tool service; hostile inheritance tests must prove absence |
| OAuth login silently selects another account/workspace | Fresh state/nonce/PKCE, exact callback, independent subject/workspace binding, Touch ID review before activation |
| Model catalog is mistaken for entitlement | Require bounded successful inference under exact stack; catalog alone is non-authoritative |
| Daybreak silently turns off | Explicit `daybreakBlue` on every turn and readback; omission or mismatch fails |
| CVP/Daybreak authority leaks to another user or harness | Per-stack credential store, exact session binding, no peer executable or shared home |
| Login opens broad Internet access | Expiring phase-specific tunnel allowlist; inference remains closed until activation |
| Harness update reuses old OAuth authority | Generation mismatch fences stack; requalification and Touch ID reactivation required |
| Provider changes OAuth/terms | Source/version review gate and fail-closed admission floor |
| User double-clicks disconnect or account removal | Confirmation, one-attempt latch, idempotent transaction, independent readback |

## Implementation sequence

1. **Canonical stack contract.** Add the closed catalog, pairing registry,
   canonical digest, login-required state, hostile cross-pairing tests, and
   documentation. This phase grants no runtime authority.
2. **Lease and session binding.** Extend the protected session catalog, Gateway
   and Research leases, process records, watchdog, summaries, and migration
   rules with mode and stack identity.
3. **Credential compartment and opaque tunnel.** Build phase-specific egress,
   process-tree admission, clean child environments, credential-store
   isolation, recovery, and negative observation.
4. **Claude native adapter.** Admit one exact unmodified Claude Code
   generation, native sign-in/status/logout ceremony, single-model managed
   policy, Mythos/CVP binding, and credential non-observation evidence.
5. **OpenAI native adapter.** Implement SIWC dynamic registration, Secure
   Enclave host identity, Keychain token rotation, Codex app-server protocol,
   Daybreak Blue on every turn, and token inheritance negatives.
6. **Control Center.** Add typed stack settings, status decomposition,
   confirmation dialogs, exact Touch ID plans, and recovery UX.
7. **Disposable acceptance.** Exercise approve/cancel/replay, wrong account,
   wrong workspace, wrong model, program off, refresh expiry, logout,
   revocation, network loss, crash at every transition, reboot, cross-harness
   token probes, and exact resume denial.
8. **Live acceptance.** Only after source and disposable acceptance, perform
   one no-content entitlement request and one bounded operator-authorized
   session for each provider. No test claims provider certification.

## Completion contract

The DDD is not complete until design, source, GUI, operator documentation,
roadmap, tests, protected deployment, cold-boot readback, hostile credential
probes, and live provider acceptance agree. Claude and OpenAI stacks complete
independently; success for one vendor does not waive the other's custody
contract.

Publication cannot claim the stronger broker-independent model enforcement for
native mode. Evidence must state which guarantees are provider-enforced,
attested-harness-enforced, outer-control-enforced, operator-external, or still
gaps.

## Primary vendor sources

- Anthropic, [Claude Code legal and compliance](https://code.claude.com/docs/en/legal-and-compliance)
- Anthropic, [Use Claude Code with Pro, Max, or Ultra](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-max-or-ultra-plan)
- Anthropic, [Claude Mythos 5.1](https://platform.claude.com/docs/en/models/mythos-5-1/overview)
- Anthropic, [Manage model access](https://support.claude.com/en/articles/15694740-manage-model-access-for-your-organization)
- OpenAI, [Sign in with ChatGPT for open-source apps](https://developers.openai.com/siwc/token-sharing-open-source)
- OpenAI, [SIWC registration and sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- OpenAI, [Codex app-server with ChatGPT OAuth](https://developers.openai.com/siwc/token-sharing-open-source/codex-app-server)
- OpenAI, [SIWC self-hosted VMs](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms)
- OpenAI, [SIWC token reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference)
- OpenAI, [Using Daybreak in Codex CLI](https://help.openai.com/en/articles/20001607-using-daybreak-in-codex-cli)
- OpenAI, [Daybreak Trusted Access overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview)
