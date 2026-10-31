# Attested Model Profile Configuration DDD

Status: implementation and physical live acceptance complete; publication pending

## Decision and scope

SecureSandbox will let the operator stage model-provider profiles in an ignored,
mode-0600 settings file and edit the same profiles in the native Control Center
Settings window. A separately reviewed activation binds one profile to the live
Gateway and Research policy. Activation requires exact Touch ID authorization;
saving a profile never changes live authority.

The first release supports three fixed upstream adapters:

- Anthropic Messages, for Anthropic-compatible providers and models such as
  Claude Mythos or the existing Abliteration service;
- OpenAI Responses, including the separately approved Daybreak cyber access
  program; and
- Google Cloud's OpenAI-compatible Chat Completions surface, including
  allowlisted Gemini Flash Cyber deployments.

An adapter is reviewed code, not a string naming a plugin. A profile cannot add
paths, headers, executable hooks, transformations, certificate authorities, or
credential loaders. A provider whose protocol does not fit a deployed adapter
remains unavailable until a new DDD extends and accepts that adapter set.

Harness installation and upgrade are deliberately outside this DDD. Claude Code
remains the only deployed harness and continues to speak the bounded Anthropic
Messages interface to the Research loopback relay. The separate Harness
Lifecycle and Verified Upgrade DDD covers Claude Code and future harness
generations.

## Safety claims

This DDD must establish all of the following:

1. The model, harness, session content, source trees, and provider responses
   cannot create, edit, activate, or select a profile.
2. The local settings file contains no credential value. It stores only a
   syntactically bounded `op://Agents/...` reference.
3. Saving or importing settings is inert. Only an unexpired plan whose exact
   canonical digest is visible in the Touch ID ceremony can activate.
4. The active Gateway broker has exactly one allowed upstream model, origin,
   address set, credential, and adapter. Inactive credentials are not loaded
   into the broker service.
5. Every issued run lease binds the profile ID, profile revision SHA-256,
   adapter, vendor ID, exact upstream model ID, pricing, policy SHA-256, and
   relay identity.
6. Every session is permanently bound to its first profile revision. Resuming
   it under another revision is rejected before a lease is issued or a harness
   process starts.
7. A request model must equal the lease model and the sole active broker model.
   Client-supplied provider routing, policy selection, server-side tools,
   arbitrary headers, and alternate endpoints are rejected.
8. Activation is refused while a run is active, while lease/lifecycle recovery
   is pending, or when Gateway and Research do not agree on their current
   profile generation.
9. Activation is transactional. Lost response, partial deployment, restart, or
   failed readback leaves admission closed until recovery completes or rolls
   back to the exact prior generation.
10. Audit and evidence records identify profile and activation digests but never
    prompts, responses, credential values, or secret-derived digests.

These claims constrain authority and evidence. They do not claim that a model
is aligned, that a vendor enforces its advertised controls, or that provider
logs are complete.

## Trust and threat model

### Trusted

- the reviewed public-release source and protected Host controller release;
- the signed Touch ID authorization application and non-exportable operator
  identity;
- root-owned Gateway and Research control dispatchers and active profile state;
- the dedicated 1Password `Agents` vault reference resolver;
- fixed adapter code and exact TLS verification through the system trust store.

### Untrusted

- model and harness output, including requests to switch models;
- all session, source, finding, transcript, and tool-result content;
- editable settings before validation and activation;
- DNS answers, provider responses, redirects, usage claims, and error bodies;
- a stale or compromised inactive profile;
- GUI state, cached catalogs, process stdout, and transport success without
  independent readback.

### Explicit threats

- prompt injection asks the harness to select another configured model;
- a request substitutes a different `model`, endpoint, access program, or tool;
- an edited profile changes between review and activation;
- DNS rebinding or redirects move traffic beyond reviewed address pins;
- a provider response smuggles remote tool execution or malformed streaming
  frames through a protocol translation;
- an active session survives a global profile switch and begins using the new
  model;
- a credential for one vendor is sent to another vendor;
- an activation partially updates Gateway, Research, firewall, lease pricing,
  or policy hashes;
- a lost response causes the operator or GUI to submit the mutation twice;
- rollback reactivates an unreviewed or revoked profile generation;
- logs, exports, settings, or process arguments expose provider credentials.

## Configuration contract

The ignored file is `config/model-profiles.json`, with a tracked
`config/model-profiles.example.json`. Its top-level schema is
`secure-sandbox-model-profile-catalog-v1` and contains at most 16 profiles.
Canonical JSON is UTF-8, sorted, compact, newline-terminated, and at most 64 KiB.

Each profile contains only:

- `profile_id`: stable lowercase identifier;
- `display_name`, `vendor_id`, and `vendor_name`: bounded printable labels;
- `adapter`: one of `anthropic-messages-v1`, `openai-responses-v1`, or
  `google-openai-chat-v1`;
- `upstream_origin`: an HTTPS origin with no userinfo, path, query, fragment, or
  non-443 port;
- `deployment`: a closed adapter-specific object (empty for direct Anthropic
  and OpenAI profiles; Google project and location identifiers for Google
  Cloud);
- `model_id` and `model_name`: the exact API value and bounded display label;
- `credential`: a fixed adapter-compatible scheme and an `op://Agents/...`
  reference;
- `settings`: an adapter-specific, closed set of typed values;
- `limits`: broker request/response/token/time/rate ceilings;
- `pricing`: positive integer micro-US-dollar rates per million input and output
  tokens; and
- the existing `short`, `standard`, and `extended` lease limit sets.

Supported credential schemes are closed per adapter:

| Adapter | Credential schemes | Upstream request path |
| --- | --- | --- |
| `anthropic-messages-v1` | `bearer`, `anthropic-api-key` | `/v1/messages` |
| `openai-responses-v1` | `bearer` | `/v1/responses` |
| `google-openai-chat-v1` | `google-service-account-json` | `/v1beta1/projects/{project}/locations/{location}/endpoints/openapi/chat/completions` |

The profile cannot choose a header name. Adapter code maps the scheme to the
single reviewed header. The Google adapter accepts only
`https://aiplatform.googleapis.com`, a bounded project ID, and an allowlisted
location; it constructs the path itself. It exchanges a validated service-
account assertion only with the fixed `https://oauth2.googleapis.com/token`
endpoint, keeps the short-lived access token only in broker memory, and never
logs either credential. The OAuth signer is a pinned reviewed dependency and
the firewall separately pins both Google endpoints. Token counting remains
local and conservative when an upstream adapter lacks an exactly compatible
count endpoint.

Settings are deliberately narrow:

- common: `maximum_output_tokens`;
- Anthropic: optional fixed `anthropic_version` from the deployed allowlist;
- OpenAI Responses: `reasoning_effort` from a deployed enum and
  `cyber_access` from `standard`, `daybreak_blue`, or `daybreak_red`;
- Google Chat: `reasoning_effort` from `minimal`, `low`, `medium`, or `high`;
- optional temperature is stored as integer thousandths in the range 0–2000,
  avoiding non-finite or non-canonical JSON numbers.

Unsupported fields, duplicate IDs, aliases that resolve to another profile,
environment-variable interpolation, relative origins, private/non-global
addresses, and secret-looking literal credential values are rejected.

## Profile lifecycle

### 1. Stage

The GUI or CLI validates the entire proposed catalog and atomically replaces the
ignored file with owner-only permissions. A staged save returns the catalog
SHA-256 and profile revision SHA-256. It grants no network or model authority.

### 2. Plan

The Host planner:

1. opens the catalog without following symlinks and revalidates its ownership,
   mode, size, schema, and canonical encoding;
2. reads the active Host, Gateway, and Research generations independently;
3. refuses an active run, incomplete lifecycle, unresolved prior transaction,
   or generation disagreement;
4. resolves the exact origin to global IPv4 addresses and rejects any mixed,
   private, loopback, multicast, link-local, reserved, or IPv6 answer;
5. verifies that the credential reference is in the `Agents` vault without
   loading the secret;
6. creates a mode-0600, five-minute plan bound to the catalog/profile digests,
   resolved addresses, current generation, controller release, adapter, model,
   limits, pricing, and expected tracked implementation hashes.

The review projection contains no credential value. It shows the profile,
vendor, adapter, origin, model ID, provider and OAuth address pins, credential
reference, settings, limits, pricing, independently agreed current-generation
digest, proposed activation ID, and plan digest. The current-generation digest
is part of the plan; activation refuses if live Gateway/Research authority no
longer matches it after admission is fenced.

### 3. Stage credential

Only after the operator opens activation review does the Host resolve the
credential with `op-agents`. The value is piped directly to the Gateway root
stager, encrypted with the Gateway host key, and stored under the proposed
activation ID. It is never written to this repository, a Host temporary file,
an argument, stdout, stderr, audit, or plan. Staging does not modify the live
service drop-in, firewall, broker configuration, or active pointer.

### 4. Touch ID activation

The protected Host controller accepts a `model-profile-activate` authorization
operation whose parameters are only the plan ID and exact plan SHA-256. The
native prompt displays the security-relevant review fields from the re-opened
canonical plan. Password fallback is forbidden.

The protected model-profile manager reopens and rehashes the plan, confirms its
expiry and current-generation preconditions, then coordinates Gateway and
Research through fixed control identities. The editable repository supplies no
command, path, or executable choice.

### 5. Transaction and readback

Activation writes a durable Host transaction before the first mutation:

1. fence new run admission on Gateway and Research;
2. stage and validate the exact generated Gateway broker configuration, lease
   profiles, firewall, and service credential drop-in;
3. stage and validate the exact Research active-profile record and managed
   harness environment projection;
4. atomically activate Gateway, reload firewall/service state, and read it back;
5. atomically activate Research and read it back;
6. recompute both policy hashes and require generation/digest agreement;
7. perform bounded mock/health checks that never consume the production model;
8. commit the Host activation receipt and reopen run admission.

Any failure keeps admission fenced and enters explicit recovery. Recovery reads
the durable phase and either finishes the same exact activation or restores the
previous exact generation. It never creates a new plan or silently chooses a
profile.

Boundary verification treats the activated lease profile as profile-bound
state, not as a copy of the repository's bootstrap default. It reuses the
source-pinned production lease parser to validate the complete active file,
then requires its adapter, model, vendor, profile ID, and profile revision to
match the independently read active-model receipt. This preserves configurable
pricing and lease ceilings without allowing the lease authority to drift from
the Touch ID-approved profile revision.

### 6. Inactive generations

The previous accepted generation and its encrypted credential may be retained
for bounded rollback. Retention does not make it callable: the live service
loads only the active credential and the firewall permits only active address
pins. Retirement is a separate reviewed destructive operation.

## Session and lease binding

The Host session-run catalog advances to v3. Each session record adds immutable
`model_profile_id` and `model_profile_sha256` fields on its first trusted run.
Legacy sessions have no trustworthy historical profile binding and therefore
cannot resume until the operator explicitly assigns the currently active legacy
profile through a separate reviewed migration action; no profile is inferred.

Before a new or resumed launch, the controller obtains a typed active-profile
readback from Gateway and Research. For a new session it records that revision.
For a resume it requires an exact match before requesting a lease. The Gateway
lease includes the same identity, and Research requires its root-owned active
record to match the lease before starting Claude Code.

Claude Code receives only one model ID in all four managed default-model
variables. Those variables are root-derived from the active record, not from
the editable settings file or user environment. Tool subprocess scrubbing and
managed settings continue to deny model, base-URL, and credential variables.

## Adapter boundary

All adapters accept one already-validated internal Anthropic Messages request
and return one bounded internal response/event stream. Translation is a closed
pure-data operation with exhaustive fixtures.

- Unknown content blocks, roles, finish reasons, stream events, usage shapes,
  tool choices, or tool-result relationships fail closed.
- Image, audio, video, URL retrieval, provider-hosted tools, code execution,
  computer use, file search, web search, remote MCP, and redirects remain
  forbidden even if a provider supports them.
- Only Claude Code's declared local custom tools are translated. Tool calls are
  returned to Claude Code for local policy enforcement; they are never executed
  by the provider or Gateway.
- The broker rejects client attempts to provide access-program, reasoning,
  thinking, provider, endpoint, credential, or routing settings. It injects the
  activated profile settings after validation.
- Streaming translators enforce absolute byte, event-count, line-size, JSON,
  ordering, and deadline bounds. An incomplete or unfamiliar upstream stream is
  an error, not a partial success.
- Usage settlement accepts only adapter-verified cumulative usage. Missing or
  ambiguous usage remains conservatively charged at the reservation.

## GUI design

The existing dedicated Settings scene gains a `Models` tab; appearance and
export preferences remain in `General`.

The Models tab contains a native sidebar-detail layout:

- lightweight profile rows show display name, vendor, and active/staged state;
- the detail form edits only schema fields supported by the selected adapter;
- credential input is visibly a 1Password reference, never a secret field;
- validation errors are inline and saving shows the resulting revision digest;
- the active profile and its independently read-back generation are distinct
  from the staged selection;
- `Review Activation…` opens a sheet with exact origin, address pins, model ID,
  adapter, settings, limits, pricing, current/proposed generations, and grouped
  digests;
- `Activate with Touch ID` is available only for a fresh valid plan and becomes
  a one-attempt latch before submission;
- cancellation, expiry, ambiguous result, partial deployment, and recovery are
  distinct states. An ambiguous result offers status readback and never a blind
  retry.

The app uses the versioned local bridge for all file and live-state operations.
It does not invoke `op`, SSH, DNS, or privileged helpers directly.

## Audit and evidence

Content-free append-only records cover validation, plan creation, credential
staging, authorization request/result, activation phases, rollback/recovery,
profile readback, session binding, lease issue, request denial, and retirement.
Records include activation/profile/catalog digests, adapter/vendor/model IDs,
run/session/lease IDs where applicable, controller and policy identities,
outcome, phase, and bounded error code.

They exclude credential references where installation privacy requires it,
credential values and hashes, prompts, responses, tool arguments/results,
source paths, DNS resolver metadata beyond accepted address pins, and arbitrary
provider error bodies.

The Control Center projects a bounded status and history view. Installation-
specific IDs, addresses, provider account details, receipts, and acceptance
evidence remain ignored/private.

## Migration and compatibility

The current Abliteration deployment becomes an explicit `abliterated-glm`
profile whose revision is computed from the same model, origin, limits, pricing,
and credential reference already in use. Migration is one-way only after:

1. the exact legacy live state matches the migration profile;
2. there are no active runs or recovery transactions;
3. Gateway and Research policy hashes pass;
4. Touch ID approves the displayed migration digest; and
5. cold restart and boundary acceptance pass.

The migration does not invent bindings for historical sessions. Current active
sessions must close before migration, and legacy resumption remains explicitly
gated as described above.

When the deployed Gateway already has the reviewed legacy profile but Research
predates active-profile records, Research returns an explicit
`legacy_unbound` status. The activation plan binds that status together with
the exact Gateway identity. The normal exact Touch ID activation is therefore
the reviewed migration action for live authority; it does not assign a profile
to any historical session.

## Verification matrix

### Configuration

- canonical round trip; size/count/text/numeric bounds; duplicate and unknown
  field rejection; symlink/owner/mode/link-count checks;
- adapter/credential/setting compatibility; exact origin and model validation;
- literal-secret, interpolation, unsafe URL, private address, and mixed DNS
  rejection; and
- atomic save plus lost-response idempotency.

### Authorization and transaction

- save-without-authority, stale plan, changed catalog, changed DNS, changed
  active generation, password fallback, cancellation, expiry, replay, and
  forged-receipt rejection;
- phase-boundary termination across fence, staging, Gateway activation,
  Research activation, readback, commit, and admission reopen;
- exact recovery/rollback and inability to activate an unstaged credential;
- active-run, active-lease, cleanup, lifecycle, and mixed-generation refusal.

### Session isolation

- new-session binding, matching resume, cross-profile resume rejection before
  lease issue, legacy-session gating, lease/request model mismatch, model alias
  substitution, and client routing-setting rejection;
- proof that only one credential is loaded and only active address pins are
  reachable; and
- proof that model/harness/tool subprocesses cannot read configuration,
  activation state, credential environment, or alternate credential material.

### Adapters

- golden request/response/stream fixtures for Anthropic, OpenAI Responses, and
  Google Chat; tool-call and tool-result round trips; local-only tool policy;
- malformed, reordered, duplicated, oversized, incomplete, redirected, unknown,
  multimodal, hosted-tool, and missing-usage cases;
- provider error normalization without body leakage; deadline and saturation
  behavior; and conservative lease settlement.

### Native app and live acceptance

- Swift model decoding/encoding, form validation, selection stability,
  activation one-attempt latch, ambiguous-result status flow, and Settings
  window build/bundle validation;
- deployed mock-profile activation and rollback, cold Start, complete boundary
  suite, and negative cross-profile session/lease tests;
- separately authorized production activation only when a valid provider
  credential and account approval exist. No synthetic credential, paid call, or
  vendor-access claim is manufactured for DDD closure.

## Completion contract

This DDD is complete only when design, implementation, parity, roadmap, and
private evidence agree; focused and repository-wide tests pass; the native app
builds and validates; protected deployment and safe live mock activation pass;
the exact-candidate publication/secret gate passes; and the reviewed commit is
published identically to `public-release` on both remotes.

Production profiles may remain `Gated` when account approval or credentials do
not exist. Their adapters, configuration, review, and fail-closed behavior must
still be fully tested without asserting unavailable vendor acceptance.

## Provider references

- [Claude Mythos 5.1 overview](https://platform.claude.com/docs/en/models/mythos-5-1/overview)
- [OpenAI Daybreak Responses API guide](https://developers.openai.com/api/docs/guides/daybreak)
- [Gemini 3.8 Flash Cyber model documentation](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-8-flash-cyber)
