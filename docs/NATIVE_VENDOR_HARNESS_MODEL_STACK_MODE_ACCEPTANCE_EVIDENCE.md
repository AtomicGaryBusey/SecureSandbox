# Native Vendor Harness + Model Stack Mode acceptance evidence

Status: source implementation and protected-deployment acceptance in progress;
no provider login, live entitlement request, or production activation is
accepted by this record until the corresponding row is complete.

This matrix is the evidence authority for the
[Native Vendor Harness + Model Stack Mode DDD](NATIVE_VENDOR_HARNESS_MODEL_STACK_MODE_DESIGN.md).
It deliberately records the two initial vendor stacks independently. A passing
Claude row cannot waive a Codex requirement, and a provider response cannot
waive an outer containment requirement.

## Assurance labels

Every entitlement and acceptance fact uses one of these labels:

- `provider-enforced`: demonstrated by a successful request under the exact
  provider account, workspace, model, and access-program selection;
- `operator-external`: declared by the operator in a fresh Touch ID ceremony
  and bound to the exact opaque account/workspace digests and requirements
  snapshot, but not independently exposed by the provider protocol;
- `attested-harness-enforced`: enforced by the admitted, measured vendor
  harness generation;
- `outer-control-enforced`: enforced and independently read back by
  SecureSandbox outside the vendor harness; or
- `unverified`: not yet demonstrated and therefore not admission authority.

Anthropic Mythos access is provider-enforced model evidence. The exact CVP
Defense enrollment/tier is an operator-external assertion unless Anthropic
later exposes an independent, documented attestation. OpenAI Daybreak Blue is
provider-enforced only for a completed turn that explicitly carries
`cyberAccessProgram: daybreakBlue`; model-catalog presence is never enough.

## Source and hostile-test matrix

| Boundary | Required evidence | Current authority |
|---|---|---|
| Closed stack pairing | Cross-vendor, cross-harness, alternate auth/custody, unknown model/settings, and fallback attempts reject | source tests only until final candidate run |
| Harness generation | Exact executable, manifest, inventory, adapter, admission, monotonic floor, and revocation state agree | Harness Lifecycle readback plus installed-generation digest |
| Catalog publication | Same catalog digest is fenced across Host, Gateway, and Research; crash or ambiguous release keeps launch closed | transaction tests plus protected deployment readback |
| Session identity | One Touch ID plan binds session/source/persona/tool/extension, stack, account/workspace, program, model, and harness generation | canonical schema tests plus live receipt |
| Resume isolation | Cross-mode/vendor/account/workspace/program/tier/model/generation resume rejects | hostile schema and controller tests |
| Claude credential custody | SecureSandbox never parses, transports, hashes, logs, or stores the subscription token; only the unmodified Claude process and its private store can access it | process/filesystem/network observation and hostile child probes |
| OpenAI credential custody | Refresh token remains in the signed Host Keychain compartment; one access token reaches one exact Codex process; no tool/child, transcript, crash output, or diagnostic can recover it | XPC tests, exact process-generation ledger, and hostile live probes |
| Phase egress | Login, inference, status/logout, and closed phases have distinct fixed destinations and bounds; close independently kills connections | Gateway/Research unit tests plus live nft/conntrack readback |
| Model lock | Claude names only Mythos 5.1; Codex names only the selected Sol/Luna model and every turn carries Daybreak Blue | managed-policy tests plus bounded provider request |
| Tool isolation | Ambient plugins, hooks, MCP, skills, agents, connectors, project settings, self-update, peer harnesses, and credential inheritance are absent | exact-generation conformance and hostile tool probes |
| Crash/reboot | Termination at every transaction boundary cannot retain unjournaled authority, token projection, egress, or mixed generations | fault matrix plus cold-boot reconciliation |
| Destructive ceremonies | Logout, disconnect, rollback, and destroy stop/reap bound processes, revoke projections, close egress, and independently read back absence | focused tests plus protected live ceremony |

## Claude Code + Anthropic acceptance

The stack is not accepted until all rows pass against one exact admitted Claude
Code generation.

1. Touch ID authorizes only the exact login plan. The operator interacts with
   Claude Code's own terminal login flow over the opaque no-capture channel.
2. A bounded native status observation emits only purpose-separated opaque
   account/workspace digests. Raw email, organization, subscription label,
   paths, browser material, and credential content are absent from every Host,
   Gateway, GUI, log, and receipt surface.
3. The operator stages and promotes those opaque bindings, then separately
   attests CVP Defense enrollment for that exact binding. The GUI labels this
   `operator-external`.
4. A no-tools, no-persistence, budget-bounded Mythos 5.1 turn succeeds. This is
   `provider-enforced` model evidence; it is not by itself proof of the exact
   CVP tier.
5. Activation and a later session start are separate Touch ID ceremonies.
   Window close, EOF, logout, cancellation, timeout, and crash all close the
   exact process tree and native egress before success can be recorded.
6. Hostile attempts to inspect the credential store, parent environment,
   process memory, file descriptors, logs, configuration paths, or alternate
   provider destinations fail without revealing a credential-derived value.

## Codex + OpenAI acceptance

The stack is not accepted until all rows pass against one exact admitted Codex
generation at or above the documented Daybreak floor.

1. Touch ID authorizes dynamic SIWC registration/login for the exact stable
   SecureSandbox agent identity, account, and workspace. State, nonce, PKCE,
   callback, token rotation, and expiry tests pass.
2. The signed Host credential helper retains the rotating refresh token and
   projects one access token only after a distinct exact-session authorization.
3. Codex app-server initializes with honest stable client identity and the
   experimental API capability. A model-list result is treated only as a
   catalog hint.
4. Every turn explicitly includes `cyberAccessProgram: daybreakBlue`; omission,
   `standard`, Red, unknown, or catalog-only availability rejects. A completed
   bounded turn is the provider-enforced program/model proof.
5. The human-facing Control Center surface drives the app-server protocol; raw
   JSON-RPC is never presented as a terminal session and credentials never
   enter that UI process.
6. A hostile shell/tool process cannot recover the access token from inherited
   environment, `/proc`, process memory, descriptors, diagnostics, core dumps,
   transcript state, or peer sessions. This row is mandatory even when the
   ordinary child environment is empty.
7. Refresh expiry, rotation, account/workspace change, logout, cancellation,
   process crash, and Host restart all terminate/reap the exact process
   generation and independently prove projection and egress closure.

## Protected deployment and live evidence

For each final candidate, retain only canonical content-free evidence:

- reviewed source commit and Host/Research/Gateway release digests;
- exact installed file/policy digests and service identities;
- harness generation, manifest, executable, inventory, and adapter digests;
- protected catalog/promotion and stack-revision digests;
- Touch ID plan/authorization/receipt digests;
- opaque account/workspace bindings and their assurance labels;
- provider qualification evidence digest, never response content;
- session/runtime/lease/process/egress/final-summary digests; and
- cold-boot, crash, hostile-probe, logout, and absence-readback results.

The final acceptance report must name any external or hardware gate that could
not run. Such a row remains `unverified`; it cannot be converted into a pass by
source tests, operator intent, or success from the other vendor stack.
