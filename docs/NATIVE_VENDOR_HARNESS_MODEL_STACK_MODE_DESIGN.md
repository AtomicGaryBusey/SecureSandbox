# Native Vendor Harness + Model Stack Mode DDD

Status: source DDD complete; protected installation, exact live
harness admission, provider login, provider-account mutation, production
activation, and live provider/hardware acceptance remain unverified

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
   currently `gpt-6-sol`, `gpt-6-luna`, or `gpt-6.1-sol`.

Saving a stack never authenticates, activates, opens network access, or starts a
harness. Login, activation, account switching, model switching, logout, and
credential destruction are separate protected ceremonies. A session is bound
permanently to the exact stack revision it starts with.

Stack activation and session launch are also separate. `activate` records that
one closed stack is eligible for later use; it never projects a credential,
starts Codex or Claude, or invents a session authority. Each actual native run
requires a later Touch ID-bound `session-start` plan carrying the complete
runtime authority (session, source, persona, outer-tool catalog, extension set,
harness generation, stack, model, and account/workspace bindings). A matching
`session-stop` closes that one process tree and its grant. Entitlement
qualification uses a distinct action-scoped, non-resumable authority and can
never be resumed as a research session.

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

Before any protected schema can carry native authority, the content-complete
stack is projected into
`secure-sandbox-native-stack-runtime-binding-v1`. That self-digested binding
repeats the exact vendor, harness ID/generation/adapter, authentication and
custody classes, opaque account/workspace digests, program/tier, model and
settings digest, network policy, and complete stack revision. Its constructor
re-runs the closed pairing validation and rejects staged stacks that still need
configuration or login. It must also match the independent protected harness
runtime binding on harness ID, generation, and adapter. The binding module is
content-only and grants no authority by itself. The source candidate now
carries it through the protected session plan, complete runtime authority,
Host/Gateway/Research leases, process generation, egress grant, public UI
handle, and final teardown readback. Every consumer repeats the exact stack and
harness-generation comparison; no consumer may infer a missing binding from the
current catalog selector.

A second discriminated wrapper,
`secure-sandbox-model-stack-runtime-binding-v1`, makes brokered and native
authority mutually exclusive at the schema boundary. Brokered authority binds
the existing profile, revision, adapter, vendor, model, and the previously
omitted `mock` or `production` provider mode. Native authority embeds the exact
native stack runtime binding. Relabeling one variant as the other, adding a
fallback, or mutating provider mode invalidates the digest. This wrapper is the
single model-stack identity carried by the source candidate's session, runtime,
lease, process, egress, and final-summary schemas.

The catalog stores no access token, refresh token, authorization code, PKCE
verifier, cookie, email address, raw subject, or raw workspace identifier. A
catalog with missing account/workspace digests is valid to stage but reports
`login-required` and cannot activate.

A staged stack may also omit its harness generation and then reports
`configuration-required`. Only a stack with an exact generation and both opaque
account/workspace bindings reports `content-ready`; that label means only that
the canonical content is complete. It is not evidence of harness admission,
authentication, entitlement, network readiness, or activation.

The local `config/native-vendor-stacks.json` is ignored, owner-only mode 0600,
canonical JSON in a non-group-writable owner-controlled directory, and written
by atomic replacement plus directory fsync. The bounded
`scripts/native-vendor-stack-config.py` surface can report or stage catalog
content only. It has no login, token, network, harness-admission, activation,
or runtime operation.

The initial pairing registry is code, not data:

| Vendor | Harness | Authentication | Custody | Program | Models |
| --- | --- | --- | --- | --- | --- |
| Anthropic | `claude-code` | `anthropic-claude-subscription-oauth` | unmodified vendor harness | CVP Defense | `claude-mythos-5-1` |
| OpenAI | `codex` | `openai-sign-in-with-chatgpt` | SecureSandbox Host, access token projected only to Codex app-server | Daybreak Blue | `gpt-6-sol`, `gpt-6-luna`, `gpt-6.1-sol` |

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
6. The admitted version is Claude Code 2.1.248 or later and every inference or
   qualification launch uses `--restricted`. Restricted mode loads only
   managed settings plus the explicit `--settings` file, confines file access,
   removes command/code tools and WebFetch unless explicitly restored, rejects
   bypass-permissions mode, and refuses cloud sessions. SecureSandbox restores
   none of them: `--tools ""` disables built-in tools, and the closed
   `--disallowedTools` deny set covers both all tools and `mcp__*`. This is
   repeated even though restricted mode already removes the dangerous defaults.
7. Root-owned managed policy restricts the available model set to the selected
   model and the launch vector names it exactly. This is defense in depth, not
   an independent guarantee against a malicious vendor binary.
8. Login status is observed only through a bounded, content-free vendor status
   surface. Evidence retains digests and state, never account labels or tokens.
9. A logout/account-change ceremony stops every bound run, closes native
   egress, invokes the native logout path, proves the old binding is no longer
   usable, and only then permits local credential-store retirement.

For the admitted Claude Code generation, the compartment may parse Claude's
own bounded `auth status --json` record because that record includes the raw
account and organization labels needed to detect an accidental account switch.
Those labels remain inside the dedicated native-harness process. It derives
purpose-separated HMAC-SHA-256 account, workspace, and subscription-class
bindings using a per-installation Research secret, zeroes/discards the record,
and emits only the digests and state. The Host, Gateway, GUI, catalog, logs, and
evidence never receive the raw email, organization UUID/name, subscription
label, configuration path, or projects path. An unknown field or auth method is
ambiguous and cannot activate.

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
5. Only the short-lived access token may be projected to the exact admitted
   Codex app-server process, using a dedicated non-PTY pipe and OpenAI's
   documented Responses-provider configuration. The refresh token never leaves
   the Host. The one-shot permit is capped by the exact session lease as well as
   its own requested expiry; the launcher must consume it and cross the private
   fd-7 gate before either authority expires. Production projection remains
   disabled until the live isolation gates below pass.
6. Initialization uses stable, honest client identity values. Every turn names
   the exact model and includes `cyberAccessProgram: daybreakBlue`; omission is
   not interpreted as equivalent. `store` remains false where the underlying
   documented path requires it.
7. Codex model catalogs are discovery hints, not entitlement evidence. A
   bounded successful inference under the exact account, workspace, model, and
   Daybreak selection is required before activation can claim live readiness.
8. Codex currently receives the access token in its initial environment. An
   ordinary `exec` resets macOS/Linux dumpability assumptions, and a same-UID
   process may otherwise read the initial environment through `/proc`, ptrace,
   `process_vm_readv`, inherited descriptors, or a core artifact. Merely
   stripping the variable from tool-child environments is not sufficient.
   Admission therefore requires a single-occupant UID, a pinned user/PID
   namespace with a fresh restricted `/proc`, no dump/core path, and hostile
   live canary tests for each of those read mechanisms against the exact fresh
   Codex PID/start generation in every session. A prior process-isolation
   receipt cannot qualify a new process. Until those tests and readbacks pass,
   custody status is
   `retained` or `session-projected`; it never claims credential absence or
   tool inaccessibility.
9. The token frame never traverses a PTY. A signed projection consumer writes
   it to the dedicated Research stream before any human bytes. A separate
   schema-pinned Host app-server client is the only terminal surface: it
   initializes with `experimentalApi`, verifies the selected model's
   `availableAccessPrograms.cyber` includes `daybreakBlue`, fixes approvals and
   sandbox/network policy, and places `cyberAccessProgram: daybreakBlue` on
   every turn. It rejects process/spawn, thread/shell-command, settings,
   approval, raw JSON, ANSI/OSC, and every unknown method or field. SwiftTerm
   never connects to raw app-server stdio.
10. Projection custody is not terminal merely because the token pipe closes or
    a process ID disappears. The helper journals the exact consumer process
    generation before releasing credential bytes, retains that direct child
    until it can reap it without a PID-reuse race, and accepts only the fixed
    content-free completion frame for the same operation and session authority.
    That frame is emitted only after independent Research process absence and
    Gateway egress closure. Missing acknowledgement leaves durable ambiguous
    custody. The v2 Keychain ledger never persists a zero-PID reservation: the
    actor reserves only in memory, the gated consumer is spawned without any
    credential bytes, and one atomic Keychain replacement publishes the full
    PID/start/provider/stack/ticket/policy/qualification row before release.
    Helper death before that replacement therefore leaves no durable phantom
    custody; helper death after it remains exactly recoverable. Crash recovery
    then uses two different short-lived, replay-claimed Touch ID ceremonies.
    The first may import only the content-free identity already committed by
    the helper and cannot clear custody. The second binds that identity to
    independently read-back guest absence and egress closure before clearing
    exactly one ledger row. Neither ceremony can relabel an ordinary session
    action or infer success from PID absence, expiry, or age.
11. The launcher emits a content-free receipt binding its exact PID/start time,
    token digest, environment proof, projection permit, runtime authority, and
    session before vendor execution. The controller validates that receipt
    against independent `/proc` start-time readback, then writes only the
    receipt digest to the private fd-7 gate. The resulting temporal authority
    chain is exact: the projection permit is session-capped, fd-7 release occurs
    while both permit and lease are current, qualification is for that same
    generation, and typed READY cannot outlive the session lease.
12. Qualification reserves its exact scratch path in a root journal before
    creation, records the created device/inode before use, deletes only that
    empty inode before publishing a terminal pass, and reconciles unfinished
    reservations after interruption. Before READY, the controller freezes the
    complete exact transient cgroup and stably inventories every PID/start
    member. It remains frozen across the final quiet drain and READY write. Only
    a successful READY path may thaw it; failure leaves the cgroup frozen for
    exact outer teardown.

OpenAI's current SIWC Models and inference Responses example uses
`gpt-6.1-sol`. The pairing
registry therefore admits it as a third explicit reviewed model alongside
`gpt-6-sol` and `gpt-6-luna`. It is not an alias, automatic migration, fallback,
or wildcard: the stack, plan, app-server thread, every turn, UI readback, and
completion evidence must all name the same selected model. A later example or
catalog change grants nothing until reviewed source changes the registry.

Daybreak remains internal, operator-only authority. Native mode cannot expose
it to another user, customer, remote service, plugin, peer harness, or
unattended downstream product workflow.

## Controller lifetime and transient-scope containment

Native credential authority must not outlive the exact root controller that
admitted it. Before every vendor fork, the controller records its own PID. The
child arms `PR_SET_PDEATHSIG(SIGKILL)` and immediately verifies `getppid()`
both before and after the complete `setgid`/`setuid` transition. The second arm
is mandatory because Linux clears the parent-death signal when effective or
filesystem credentials change. A changed parent exits before descriptor setup,
`SIGSTOP`, or vendor execution.

The controller also forks a descriptor-minimal root watcher. The watcher keeps
only a pidfd for the exact controller, arms the same parent-death signal, checks
the parent-race window, and enters
`secure-sandbox-native-owner-<run-id>.scope` alone. The credential-bearing
vendor child enters a fresh `secure-sandbox-native-run-<run-id>.scope` that has
`BindsTo`, `After`, and `PartOf` edges to both
`native-harness-supervisor.service` and that exact owner scope. Consequently,
supervisor loss or exact-controller loss stops the complete vendor cgroup; a
forked or `setsid` descendant cannot detach from the lifetime edge.

The vendor scope is admitted only after exact readback of
`KillMode=control-group`, `KillSignal=SIGKILL`, `SendSIGKILL=yes`, the
lease-bounded runtime, `Transient=yes`, and
`FragmentPath=/run/systemd/transient/<unit>`. Each session is capped at 256
tasks, 4 GiB memory, zero swap, and 300% CPU over an explicit 100 ms period.
Configured systemd properties alone are not evidence: descriptor-relative,
no-follow reads from the exact cgroup must independently equal
`memory.max=4294967296`, `memory.swap.max=0`, `pids.max=256`, and
`cpu.max="300000 100000"` before the child may resume.

Teardown retries owner release only while exact live custody remains, proves
two stable unit/cgroup/process-generation absence snapshots, and reports any
cleanup anomaly after the remaining descriptors and session state are closed.
Lifecycle stop and installer/recovery quiescence cover run scopes, bounded
Claude command services, and owner scopes in that order. No manual unit
deletion or configured-but-unenforced resource fallback exists.

## Credential and tool separation

Native authentication introduces a bearer credential into the vendor harness
trust domain. That is a material change from brokered mode.

The production topology must provide a credential compartment with these
properties; the current helper intentionally rejects projection until all are
implemented and live-qualified:

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
- the Codex app-server environment has exactly the fixed uppercase
  `HTTP_PROXY` and `HTTPS_PROXY` values for the reviewed proxy, with no direct
  route, `NO_PROXY`, `ALL_PROXY`, lowercase proxy aliases, or inherited ambient
  network configuration; and
- qualification includes a fresh per-session hostile model/tool attempt to
  read, inherit, copy, encode, or transmit the credential, bound to the exact
  launcher receipt, PID/start generation, descriptor set, cgroup, environment,
  and scratch inode.

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
receives inference egress only through the fixed Research proxy. Its launch
environment contains only the reviewed uppercase `HTTP_PROXY` and
`HTTPS_PROXY` bindings; direct provider routing, `NO_PROXY`, `ALL_PROXY`,
lowercase proxy aliases, and inherited proxy state are prohibited. Neither
vendor flow may use an embedded web view that could observe credentials.

## Model, program, and session binding

A native session binds all of the following into its protected catalog,
Gateway lease, Research lease, process record, and final summary:

- mode and stack digest;
- vendor and network-policy IDs;
- harness, generation, manifest, executable, inventory, and adapter digests;
- authentication mode and credential-custody class;
- opaque account and workspace binding digests;
- access-program ID, tier, and an exact reviewed requirements-snapshot version
  (initially `anthropic-cvp-defense-2026-10-31` or
  `openai-daybreak-blue-2026-10-31`);
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
- start or resume one exact native session, and stop it when session closure
  changes live credential or network authority.

The authorization display names the exact harness generation, vendor,
credential-custody class, account/workspace digests, access program/tier,
model, network policy, session impact, and plan digest. It explicitly states
that native mode gives the vendor harness credential authority and lacks the
Gateway's independent request-body enforcement.

The Host authorization broker authenticates Control Center from the live audit
token's dynamic code object, not a PID-to-path lookup or a replaceable bundle
pathname. The running peer must satisfy the exact Control Center identifier,
team, Apple generic anchor, Developer ID Application certificate extension, and
hardened-runtime requirement. A filesystem path is supporting evidence only
and cannot authorize a ceremony.

Touch ID mutation buttons are deliberately not default keyboard actions.
Return never authorizes a native-stack mutation; the operator must click the
exact labeled button, while Escape/Cancel remains the safe keyboard action. The
broker opens and holds the exact request-directory and request-file inodes from
the initial challenge through the post-biometric commit reread. Unlink,
replacement, hard-link substitution, directory replacement, or cancellation
therefore revokes the ceremony instead of rebinding it to new bytes.

Authority also depends on a live ownership chain. Swift holds a parent-liveness
pipe to the Control Center API, which holds a separate supervisor-liveness pipe
to the authorization wrapper and broker. EOF, cancellation, timeout, or owner
loss enters normal unwind, invalidates the one-shot request, terminates the
owned process group including descendants, and reports an ambiguous result
until durable status is reread. The longest native sign-in chain is strictly
nested at `1440 < 1500 < 1560 < 1620` seconds for broker, unprivileged wrapper,
API supervisor, and Swift bridge respectively. The privileged SSH stream uses
an exact unbuffered readiness handshake before request bytes; cancellation
closes the stream and reaps the nested SSH process rather than treating
transport closure as success.

The stack-action schema cannot be reused for session launch. The session-start
display additionally names the canonical session/runtime-authority digest,
source and source-manifest digests, persona, outer-tool catalog, extension set,
projected-token lifetime (OpenAI only), and the one process generation. A
credential helper rejects `activate` if it is relabeled as projection and
rejects projection without the distinct `session-start` authorization ticket.
Control Center supplies only the intended stack, source/resume selection, and
lease profile. Protected Research independently measures the session policy,
persona, outer-tool catalog, extension set, source manifest, and harness
binding that form the plan; the GUI cannot nominate or invent those digests.
Authorized launch repeats the same readback before opening any credential or
egress authority.

## Protected cross-plane deployment

Native mode is deployed as one Host-coordinated, fail-closed transaction over
two independently authenticated guest planes. The Host release constructs
deterministic Gateway and Research packages from fixed, dependency-closed
inventories. A canonical deployment plan binds their complete package digests,
the exact protected Host release, the native-stack catalog digest, the exact
previous package on each plane, one deployment identifier, and a bounded
expiry. Neither guest may infer a predecessor from loose file presence or
accept a candidate merely because its installer returned zero.

Before mutation, an independently authenticated probe holds the same ordered
installer and policy barriers as the mutator. It classifies each plane as
exactly `absent`, `legacy`, or `protected`; verifies the complete name, mode,
content, release, catalog, service, watchdog-process, and default-closed policy
state; and rejects a pending or mixed installation. The installer repeats that
predecessor comparison beneath the same barriers. This closes both stale-plan
overwrite and lost-response races: a probe cannot report the old generation
while an earlier installer is still able to publish the new one.

Research acquires a durable lifecycle fence for the exact plan before either
candidate is admitted. A first deployment from an exact legacy or truly absent
Research state uses only the already authenticated generic deployment channel
and an ephemeral, fixed bootstrap consumer. That consumer installs no
dispatcher or controller, admits no protected/candidate predecessor, and
creates the same canonical fence as the installed controller after exact
catalog, closed-state, pending-run, grant, and predecessor readback. Rollback
to a legacy predecessor uses a separate rollback-only bootstrap release path;
it publishes an immutable release terminal before removing the fence and
cannot release a candidate state.

The Host journal permits only three forward observations: exact prior/prior,
candidate/prior, or candidate/candidate. It installs Gateway first, proves its
candidate release and restarted watchdog process, installs Research, and then
independently proves both exact releases, catalog, services, watchdogs, and
closed policies. Only after those readbacks may Research release the lifecycle
fence, last. Transport completion or SSH exit status is never deployment
evidence; a lost reply is resolved by a fresh authenticated probe and the
durable Host journal.

If Research cannot converge, the Host re-arms Gateway's exact retained
transaction preimage and invokes ordinary crash-safe recovery. Rollback is
complete only after independent prior/prior readback. Any unknown state,
unexpected predecessor, failed compensation, unavailable probe, or ambiguous
fence transition leaves Research fenced in recovery-only mode. There is no
operator bypass and no success label for a partially converged deployment.

Host selection and native deployment share an irreversible coordination
floor. The authoritative root-owned mode-0600 record binds the minimum
coordination epoch and feature set; a root-owned mode-0444 enforcement
projection binds its exact digest so the unprivileged stable launcher can
enforce the same minimum without receiving write authority. The launcher takes
the Host shared lock, then the controller lock, then verifies the exact release
and contract before publishing an active marker. Host migration instead holds
the Host exclusive lock, fences services, retains the exact predecessor and an
immutable digest-named old-launcher backup, unlinks and fsyncs `current`, and
only then replaces the launcher and publishes the floor. Crash replay accepts
only those exact retained identities. Removing or editing the floor,
projection, selector, active marker, predecessor, or launcher backup is not a
recovery operation and must fail closed.

There is exactly one compatibility path from a release that predates this
floor. It admits only the complete `d8653cb` payload inventory with the seven
pinned digests for its authorization broker, authorization service, release
manager, catalog promoter, deployment coordinator, shared support module, and
deployment payload container. A near match, extra or missing payload, or other
historical release is not migratable. Before mutation, the manager suspends the
exact launchd broker, proves its PID and start generation are unchanged and its
Darwin status is stopped, and takes a bounded direct-child census while the
broker cannot fork. Any child aborts the transition and resumes that exact
broker generation so the operation can finish. Only an empty census permits
bootout; two subsequent UID-scoped process inventories must then prove that no
process, including a detached orphan, is bound to the old release, predecessor,
or launcher. The old manager and promotion locks remain held across selector
removal, floor publication, and candidate installation. This exception is
available only to the schema bootstrap; ordinary Host mutations never inherit
it as general legacy authority.

## Developer ID signing floor

Every privileged Host product in this mode—the authorization UI, native
credential helper, protected backend, and projection consumer—must carry the
hardened runtime, an Apple-generic Developer ID Application signature, its
exact designated identifier, and one common Apple Team ID. The installed Host
release manager retains a canonical root-owned mode-0600 Team-ID floor. Normal
install, verification, rollback, and service activation reject a missing
floor, a below-floor release, a different team, an unrecognized identifier, or
an invalid live signature. Certificate renewal within the same Team ID is
allowed; changing the Team ID is a separate future recovery design, never
trust-on-first-use.

The existing Development-signed installation crosses this floor only through
one explicit terminal-bound migration. That ceremony binds the exact immutable
predecessor release, exact candidate release, old and new authorization
manifests, stable launcher hashes, and operator-reviewed Team ID before any
mutation. It stops both Host services, writes a non-executable exact
predecessor recovery marker, removes the executable `current` selector, and
only then publishes the permanent floor. A failed or interrupted install
therefore leaves no below-floor current release. Retry may inspect only that
distinct marker, while the root manager revalidates the floor and all original
bindings. Successful Developer ID activation removes the marker. Floor
publication itself uses a fsynced pending inode plus no-replace hard link and
can reconcile only the proven same-inode post-link crash state.

The four products cross the source-to-root boundary in one Developer-ID-signed,
Apple-notarized, stapled read-only DMG. A canonical inner manifest binds the
complete no-extra-file inventory, paths, modes, sizes, and hashes. The source
release identity binds the exact post-staple DMG bytes, an identical outer
manifest, and a content-free notarization receipt. At installation, the root
manager snapshots those exact bytes, verifies the DMG's designated requirement,
stapled ticket, Gatekeeper assessment, and image integrity, mounts it read-only,
rejects links or special/extra entries, and independently verifies every member
hash and all four live code-signing requirements. The receipt records the
submission and clean-log digest for audit correlation only; its status fields
cannot substitute for the stapled ticket or any independent verification.

## Control Center behavior

Settings gains a top-level mode selector:

- **Brokered Provider Profile**; or
- **Native Vendor Harness + Model Stack**.

Native stack rows show separate state for harness admission, authentication,
account/workspace binding, program entitlement, model entitlement, network
policy, activation, and live run. The GUI must never collapse these into one
green “connected” state.

The native surface begins with a protected deployment panel. It queries the
root broker directly over a root-peer-authenticated Unix socket for the exact
Gateway/Research deployment state and catalog-publication gate. Every
per-stack mutation remains disabled until both independently report `ready`
under one current Host release. Missing, invalid, active, mismatched, or
recovery-required state is a fence—not a warning. A new deployment review
shows the exact current Host release, catalog, package and predecessor digests,
payload container, bounded expiry, and self-digested plan response before a
fresh Touch ID. Recovery offers only the broker-admitted `resume` and/or
`rollback` actions for the exact active journal. Catalog recovery replays only
the retained root authority named by the active gate. There is no force clear,
manual package selection, or bypass control.

The public catalog status records immutable publication history. Its
`host_release_id` therefore remains the release that published those bytes and
may legitimately differ after a Host upgrade. New catalog promotions,
projection recovery, deployment, and sessions bind the separately
authenticated *current* Host release; they never reinterpret historical
provenance as current authority. The UI holds its parent mutation fence while
any review sheet is open so the reviewed plan cannot race another local
mutation.

Long protected operations use two bounded client branches. On the mutation
branch, the root operation receives 3,900 seconds only after authorization;
the ceremony-inclusive authorization client receives 4,140 seconds, the
Control Center API client 4,200, and the Swift bridge 4,320. The separate
direct-broker recovery/query branch receives 4,020 seconds beneath the same
4,320-second Swift boundary; it is not nested inside the authorization client.
The ceremony clock starts before human approval, while the root mutation clock
starts only after approval, so the 180-second request TTL and 60-second result
margin cannot consume the root operation's full budget. The outer runner uses
a monotonic deadline, a short TERM grace, checked SIGKILL of the local bridge,
and forced pipe closure. A TERM-ignoring bridge or descendant retaining stdout
cannot block the UI indefinitely; an ambiguous outcome is recovered only from
durable broker state.

Ordinary native-stack action ceremonies use a separate deadline family from
protected deployment. The longest sign-in path preserves the strict temporal
ordering `1440 < 1500 < 1560 < 1620` seconds from root broker through wrapper,
API, and Swift. Swift-parent and Python-supervisor liveness descriptors revoke
the request and reap the complete owned descendant group if an outer owner
closes first. Exact request inodes remain held through commit, and the
privileged stream must complete its exact readiness handshake before payload
delivery.

The first source checkpoint added a segmented Models settings surface for the
existing Brokered Provider Profile mode and this Native Vendor Harness + Model
Stack mode. The native editor exposes the two code-admitted pairings and only
their allowed model/settings choices. It renders generation, account/workspace,
authentication, custody, program/tier, network policy, and content readiness as
separate facts. Saving remains inert. The source candidate adds protected
provider actions, program-attestation review, separate activation and session
plans, an opaque no-capture Claude terminal, and a typed schema-pinned Codex
surface. Those controls remain unavailable in production until the exact
signed Host build, protected guest release, harness generation, and live
readbacks pass. The app must never turn `content-ready` into a connected or
activated indicator.

Provider-specific actions are explicit:

- Anthropic: `Open Claude Code sign-in`, `Verify native status`, `Log out`;
- OpenAI: `Continue with ChatGPT`, `Verify Daybreak/model`, `Disconnect`.

The GUI shows no token, credential path, raw subject, raw workspace ID, browser
callback code, or arbitrary provider error body. Ambiguous results retain the
fence. OpenAI projection recovery is deliberately not the generic stack
`recover` action: Control Center first obtains a canonical content-free identity
plan directly from the authenticated root broker and presents a read-only
**Import Identity** Touch ID review. It then obtains a fresh, separate
reconciliation plan showing the exact PID/start generation, executable digest,
guest-absence evidence, egress-closure evidence, stack, session authority, Host
release, and expiry. Only **Reconcile Closed Projection** may clear custody.
Every plan/result is exact-field, canonical, self-digested, request-bound, and
selected-stack/release-bound; stale, replayed, cross-kind, or substituted data
fails closed.

The operator ceremony and fail-closed recovery sequence is documented in the
[native vendor stack operator guide](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_OPERATOR.md).

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
| A new Codex process reuses an old isolation receipt | Require fresh PID/start launcher receipt, session-capped permit, fd-7 gate, and hostile qualification for every session |
| Codex bypasses the inspected provider path | Exact proxy-only environment, direct-route denial, no bypass variables, and per-session root/tool observation |
| App-server writes after qualification but before READY | Freeze and stably inventory the whole exact transient cgroup through final drain and READY; thaw only after successful READY |
| Root controller dies while a credential-bearing child has forked or called `setsid` | Pre/post-credential parent-death arming plus exact owner pidfd watcher; bind the complete vendor cgroup to the exact owner scope and supervisor with `BindsTo` + `After` |
| systemd reports limits that the kernel is not enforcing | Require exact descriptor-relative cgroup-v2 control-file values before `SIGCONT`; missing, disabled, malformed, or changed controllers fail closed |
| Cancelled or abandoned UI later commits | Explicit-click-only authorization, held request inodes, parent/supervisor liveness, one-shot invalidation, and complete process-group reap |
| Provider changes OAuth/terms | Source/version review gate and fail-closed admission floor |
| User double-clicks disconnect or account removal | Confirmation, one-attempt latch, idempotent transaction, independent readback |

## Implementation sequence

1. **Canonical stack contract — source candidate implemented.** The closed
   catalog, pairing registry, canonical digests, inert staging, login-required
   state, and hostile cross-pairing tests grant no runtime authority.
2. **Lease and session binding — source candidate implemented.** The canonical
   session plan and runtime authority bind session, source and source manifest,
   persona, outer-tool catalog, extension set, exact native stack, harness
   generation, account/workspace, program/tier, model/settings, network policy,
   and lease profile. Host, Gateway, and Research repeat those comparisons;
   history cannot be silently resumed under the current selector.
3. **Credential compartment and opaque tunnel — source candidate
   implemented.** Vendor/phase-specific grants, timed kernel sets, exact UID
   and mark rules, separate Gateway and Research watchdogs, conntrack purge,
   durable deny recovery, and structural ruleset verification default closed.
4. **Claude native adapter — source candidate implemented.** The bounded
   login/status/logout controller, opaque no-capture channel, purpose-separated
   account/workspace bindings, single-model managed policy, CVP declaration,
   owner-bound transient scope, post-credential parent-death arm, kernel
   resource-limit readback, and terminal teardown are present. Live
   unmodified-generation admission, real Linux controller-death/descendant
   behavior, vendor login, and hostile credential non-observation remain
   acceptance gates.
5. **OpenAI native adapter — source candidate implemented.** SIWC registration,
   Secure Enclave host identity, signed Keychain helper contract, rotating
   refresh custody, one-shot access-token projection, exact launcher, hardened
   process namespace, schema-pinned app-server firewall, global token-reflection
   quarantine, explicit Daybreak Blue turn binding, run journal, fresh
   PID/start launcher receipt, private fd-7 launch gate, session-capped permit,
   exact proxy-only environment, journaled qualification scratch, and
   cgroup-frozen pre-READY qualification are present. The same owner watcher,
   dependency-bound SIGKILL scope, and kernel-enforced per-session ceilings
   apply before app-server resume. Live signed-component, provider, real
   Linux/systemd, and hostile process-isolation gates remain unverified.
6. **Control Center — source candidate implemented.** Typed stack settings,
   decomposed assurance state, program-attestation review, exact Touch ID
   login/activation/change/logout/recovery/session plans, opaque Claude
   terminal, typed Codex surface, deterministic close, and distinct projection
   identity-import/reconciliation reviews, Return-key nonauthorization, held
   request-inode custody, strict `1440 < 1500 < 1560 < 1620` deadline nesting,
   parent/supervisor liveness, exact privileged-stream readiness, and bounded
   descendant cleanup are present in source.
   One prior signed/notarized GUI preflight reached this surface and one Host
   Developer ID/coordination-floor migration completed. The exact current
   source descendant, fixed broker readback, responsive-layout visual
   acceptance, four-product carrier, protected guest deployment, and provider
   use remain separate gates.
7. **Protected deployment — source candidate under final verification.**
   Deterministic exact packages, typed predecessor and release identities,
   shared installer/probe barriers, Research lifecycle fencing, a durable Host
   cross-plane journal, release-last commit, and exact compensation close the
   source path. The hermetic Host, broker/API, Swift, and Research-adapter
   suites are green. The immutable `c8a67ee..459b10a` scan confirmed one high,
   three medium, and one low finding; `51f4205`, `2f9493b`, `9eb755c`, and
   `05229db` source-remediate them. A later immutable scan through `133d1a5`
   found one high controller-lifetime gap and one medium missing-resource-limit
   gap; `d5393bf` adds the owner-bound lifetime and kernel-enforcement contract.
   Final immutable scan `e0e3cb96` closed all
   235 review items with zero findings; the full scan history is retained in
   the acceptance evidence. Exact-candidate publication gates are still
   pending. The bounded 2026-11-05 preflight established one protected Host
   floor migration and a separately notarized GUI, but not the exact current
   four-product carrier or source descendant. Protected guest execution,
   reboot readback, and retained live evidence remain separate gates.
8. **Disposable acceptance — not run.** Exercise approve/cancel/replay, wrong account,
   wrong workspace, wrong model, program off, refresh expiry, logout,
   revocation, network loss, crash at every transition, reboot, cross-harness
   token probes, exact resume denial, controller `SIGKILL` after vendor
   fork/`setsid`, post-UID-drop parent-death behavior, real transient-unit
   rendering, owner-bound `BindsTo` teardown, and kernel cgroup ceilings.
9. **Live acceptance — not run.** Only after source and disposable acceptance, perform
   one no-content entitlement request and one bounded operator-authorized
   session for each provider. No test claims provider certification.

## Completion contract

This DDD has two explicit completion boundaries. **Source DDD complete** means
the design, source, GUI, operator documentation, roadmap, focused and aggregate
tests, changed-boundary security review, publication checks, and identical
reviewed remote commit agree, while every unavailable environmental gate is
still recorded as `unverified` and grants no activation authority. **Production
acceptance complete** additionally requires the exact notarized protected
installation, protected deployment and cold-boot readback, hostile credential
probes, physical/disposable fault campaign, admitted harness generations, and
live provider qualification and sessions. Source completion must never be
presented as production acceptance.

Claude and OpenAI production stacks complete independently; success for one
vendor does not waive the other's custody contract. A failed or unavailable
external gate leaves only that production stack unavailable and does not
retroactively erase reviewed source evidence.

Publication cannot claim the stronger broker-independent model enforcement for
native mode. Evidence must state which guarantees are provider-enforced,
attested-harness-enforced, outer-control-enforced, operator-external, or still
gaps.

## Primary vendor sources

- Anthropic, [Agent containment best practices for CVP participants](https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants)
- Anthropic, [Cyber Verification Program security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements)
- Anthropic, [Claude Code legal and compliance](https://code.claude.com/docs/en/legal-and-compliance)
- Anthropic, [Use Claude Code with Pro, Max, or Ultra](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-max-or-ultra-plan)
- Anthropic, [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference)
- Anthropic, [Claude Mythos 5.1](https://platform.claude.com/docs/en/models/mythos-5-1/overview)
- Anthropic, [Manage model access](https://support.claude.com/en/articles/15694740-manage-model-access-for-your-organization)
- Anthropic, [Workload Identity Federation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation) (future programmatic CVP access; not the subscription-login path admitted here)
- OpenAI, [Sign in with ChatGPT for open-source apps](https://developers.openai.com/siwc/token-sharing-open-source)
- OpenAI, [SIWC registration and sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- OpenAI, [SIWC models and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- OpenAI, [Codex app-server with ChatGPT OAuth](https://developers.openai.com/siwc/token-sharing-open-source/codex-app-server)
- OpenAI, [SIWC self-hosted VMs](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms)
- OpenAI, [SIWC token reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference)
- OpenAI, [Using Daybreak in Codex CLI](https://help.openai.com/en/articles/20001607-using-daybreak-in-codex-cli)
- OpenAI, [Daybreak Trusted Access overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview)
- OpenAI, [Expanding Daybreak as the cyber-defense window narrows](https://openai.com/index/expanding-daybreak-as-the-cyber-defense-window-narrows/)
- Apple, [Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- Apple, [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- Apple, [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
