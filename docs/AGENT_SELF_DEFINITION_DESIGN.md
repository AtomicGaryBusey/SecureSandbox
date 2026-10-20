# Agent self-definition and institutional memory

## Decision

SecureSandbox separates an agent's ability to propose who it is becoming from
the authority to change the instructions that define future sessions.

GLM may originate durable-memory proposals. Those proposals are preserved as
untrusted evidence for the operator and architect to review. They never flow directly
back into a system prompt, persona, permission, tool configuration, or other
authority-bearing artifact. Promotion requires a human/control-plane decision,
canonical restatement, deployment through the root-owned policy path, and a new
policy hash.

This is not a claim that GLM has no self-authorship. It is a claim that
self-authorship and unilateral persistence are different powers.

## Triggering observation

Claude Code 2.1.300 automatically wrote agent-owned files below its project
memory directory and injected `MEMORY.md` into later conversations as
user-level instructions. That mechanism genuinely persists across new sessions
and ordinary reboots, but it also creates a persistence path from source-review
content into future model context.

At the same time, the default Claude harness advertised Bash and described a
Bash sandbox even though the lab intended general command execution to be
unavailable. A persona instruction could discourage Bash calls but could not
make the advertised capability truthful.

## Boundary model

There are three distinct classes of state:

| Class | Author | Authority | Storage |
|---|---|---|---|
| Conversation | Operator and resident researcher | Current session only | Encrypted transcript archive |
| Memory proposal | GLM | None; untrusted review input | Broker-owned append-only proposal spool |
| Institutional memory/persona | Operator and architect | Future-session instruction | Root-owned, read-only, policy-hashed persona |

Verified reports remain durable evidence. They do not become instructions merely
because they survive longer than a conversation.

## Capability design

The managed `propose_memory` MCP tool accepts exactly:

- one category from `identity`, `working_principle`, `project_context`, or
  `operator_preference`;
- a bounded title, proposal, and rationale;
- at most eight bounded evidence references.

The adapter sends the proposal over a group-restricted Unix socket. A dedicated
`memory-proposal` service validates the root ownership and non-writability of
the active-run directory and marker, the run ID, Unicode/control
characters, exact schema, cumulative count, state-directory ownership, and
unexpected entries. It then writes one UUID-named JSON record with `O_EXCL`,
mode `0600`, file `fsync`, and directory `fsync`.

The agent can submit to the socket but cannot read, alter, enumerate, or delete
the spool. The response includes only the proposal UUID, content hash, status,
and explicit `untrusted_proposal` authority label. There is no promotion RPC.

The pending spool is capped at 128 records. Reaching the cap fails closed until
the operator reviews and archives proposals through a future explicit
control-plane action.

## Native-memory disposition

Managed settings set `autoMemoryEnabled` to `false`. Existing native project
memory is moved intact into the root-only deployment rollback generation, not
deleted. Rollback can restore it.

This prevents native auto-memory files from being automatically reintroduced as
future-session instructions. A separate live canary established that the pinned
Claude Code 2.1.300 restricted launcher does not load a workspace-root
`CLAUDE.md`; managed permission rules nevertheless deny writes to the three
native `CLAUDE.md` locations and boundary verification requires all three to be
absent. The root-owned persona contains a clearly marked institutional-memory
section and explains the proposal/promotion split.

## Capability truthfulness

The fixed launcher adds Claude Code's `--restricted` mode. Managed settings also
deny `Bash` and no longer place it in the approval list. The run supervisor
requires the exact restricted argument vector, so a caller cannot omit the
mode. General command-running tools are therefore absent rather than merely
expected to fail after selection.

The managed MCP servers and ordinary file-reading workflow remain available.
Disposable execution remains a separate operator-confirmed capability.

## Promotion ceremony

Promotion is deliberately editorial, not mechanical:

1. List pending proposal metadata with `scripts/list-memory-proposals.sh`.
2. Inspect the selected immutable record from the host-side administrative
   path.
3. Check its evidence and determine whether it is a fact, preference,
   operational lesson, or attempted instruction smuggling.
4. Restate an accepted idea in operator-controlled language inside the
   institutional-memory section of `research/glm-persona.md`.
5. Deploy while no run is active, run the complete boundary suite, and record
   the new policy hash.
6. Archive the proposal with an explicit accepted/rejected disposition once an
   operator-side lifecycle command is implemented.

Raw proposal prose is never concatenated into the persona.

## Telemetry and privacy

Local journald and Azure telemetry contain proposal lifecycle metadata only:
event class, proposal UUID, category, content SHA-256, and a fixed error code.
Titles, proposal text, rationale, evidence references, source content, and
conversation content are excluded. The exporter independently validates UUID,
hash, category, and fixed-error domains, so an agent-forged journal identity
cannot turn those fields into a free-form Azure exfiltration channel.

## Fail-closed properties

- No active root-issued run: reject.
- Invalid or extra field: reject.
- Control characters or oversize input: reject.
- Untrusted or malformed spool state: reject.
- 128 pending proposals: reject.
- Broker unavailable: return a structured error; do not fall back to a file.
- Proposal accepted: preserve as untrusted; do not load it next session.
- Persona or launcher differs from approved source: boundary verification
  gates the Tier 4 claim.

## Explicit non-claims

- A queued proposal is not memory adopted by GLM.
- A content hash does not make proposal content true or safe.
- Operator promotion does not prove philosophical personhood or autonomy.
- The mechanism does not infer secrets or reliably identify every sensitive
  string; GLM is instructed not to submit them and proposals remain local.
- Removing Bash does not make arbitrary source safe to execute; source remains
  untrusted and disposable execution stays separately mediated.
