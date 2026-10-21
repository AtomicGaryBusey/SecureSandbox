# Bounded run leases

## Decision

Every interactive Claude run requires a root-issued Gateway lease in addition
to the existing static request, response, rate, and network limits. The lease
is bound to:

- the UUIDv4 run ID created by `labctl`;
- the exact Research relay certificate SHA-256 identity;
- `abliterated-model-large-v2`;
- the current Gateway policy SHA-256 generation; and
- a fixed operator-selected resource profile.

The model broker reserves cumulative request, input-token, output-token, and
cost capacity durably before it loads the provider credential or opens an
upstream connection. Missing, expired, closed, mismatched, corrupt, or
exhausted leases fail closed.

## Conservative accounting

Input reservation equals the complete UTF-8 request byte length. This is a
deliberately conservative tokenizer-independent upper bound for the admitted
text-only JSON interface. Output reservation equals the requested
`max_tokens`; token-count requests reserve zero output tokens. Reservations
are never refunded after upstream failure, cancellation, or lower actual
usage, so a crash cannot reopen budget.

Cost is reserved from those same conservative token quantities. Both input and
output use 5 USD per million tokens, the highest currently published standard
rate for the selected model. This remains conservative against the provider's
more specific Anthropic API documentation, which currently lists 3 USD input
and 5 USD output per million. Pricing is an operator-controlled policy value,
not provider-supplied request data. Sources:
`https://abliteration.ai/pricing` and
`https://abliteration.ai/docs/anthropic-messages-api`.

## Profiles

Profiles are root-owned fixed maxima:

| Profile | Initial duration | Maximum total duration | Requests | Input reservation | Output reservation | Cost |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| short | 1 hour | 2 hours | 128 | 1,000,000 | 250,000 | 6.25 USD |
| standard | 4 hours | 8 hours | 512 | 5,000,000 | 1,000,000 | 30 USD |
| extended | 8 hours | 12 hours | 1,024 | 10,000,000 | 2,000,000 | 60 USD |

Selecting a smaller profile is the initial operator-selectable reduction.
Renewal is a separate host command, cannot cross the profile's maximum total
duration, and never changes counters or limits. The agent has no Gateway admin
identity and cannot issue, renew, close, or mutate a lease.

## Durable state

Active manifests are root-owned and broker-readable. Counters live in a
Gateway-only broker-owned directory and are atomically replaced under an
exclusive filesystem lock with file and directory `fsync`. Reservation is
intentionally committed before upstream access. Final summaries are written
root-owned, mode `0444`, and retain the original limits and final counters.
After the summary and its parent directory are durable, the corresponding
active manifest and counter are removed and both active-state directories are
`fsync`ed. The summary directory is traversable but not writable by the broker,
allowing it to reject a finalized run as `lease_closed` without granting
summary mutation.

Expired unfinished leases are reconciled before new issuance and by explicit
recovery. Active-state enumeration is bounded to 256 leases; finalized runs do
not consume an active slot. Corrupt or excess state blocks issuance and request
authorization rather than being skipped.

## Transactional Research lifecycle

Research keeps two deliberately separate forms of state:

- `/run/secure-sandbox/run-id` is the volatile admission token. Brokers accept
  work only while it exists and matches a durable lifecycle in the `active`
  phase.
- `/var/lib/secure-sandbox/run-lifecycle/active.json` is the root-owned durable
  attribution and recovery record. It is read-only to the distinct broker
  identities because it contains no secret; failure details, receipts, and
  completed records remain root-only. Capture and telemetry continue to
  attribute shutdown evidence while it moves through `closing` and
  `local_closed`, even though new work is no longer admitted.

The boundary suite uses a separate root-owned `evidence-run-id` marker for the
reserved `boundary-test` correlation value. That marker can label deliberate
denial probes but is never consulted for workload admission.

The lifecycle phases are `preparing`, `active`, `closing`, `local_closed`, and
`committed`. Any failed transition is latched in root-owned durable state and
blocks another run until an operator investigates and reconciles it. Missing,
malformed, inconsistent, or excess lifecycle state fails closed.

The root supervisor rejects arming if any process already runs under the
dedicated agent UID. It launches the agent into a fixed-name, non-delegated
systemd scope with explicit task, memory, and CPU bounds. The agent cannot move
itself or descendants out of that cgroup. The root scope launcher uses an
explicit `setpriv` transition that clears every supplementary group before
dropping to the fixed agent UID/GID; the boundary suite measures the resulting
identity and complete group vector inside a real transient scope. Closing first revokes the admission
token, then freezes and kills the scope with `cgroup.kill`, waits for
`cgroup.events` to report `populated 0`, and also sweeps the dedicated UID as a
defense in depth. A successful synchronous scope-exit receipt covers the case
where systemd has already unloaded an empty scope. Research cannot commit the
run while any agent-UID process remains.

The agent SSH identity is not a general shell. A root-owned forced-command
entry point admits only the fixed Claude launcher and an optional canonical
UUID resume argument. Boundary verification that needs the agent security
context is initiated through the separate restricted admin identity and drops
to the agent UID locally.

Gateway denial remains the independent paid-call authority. The Research
lifecycle is the execution, admission, local evidence, and recovery authority.

## Capture finalization

Conversation capture has explicit `prepare` and `finalize` transitions. Idle
scans do not advance journal offsets. Preparation records the initial journal
set and offsets before admission is published. Finalization drains complete
records, represents any final unterminated bytes as encrypted corruption
evidence, records exact terminal offsets, and creates a root-owned receipt.
A prepared journal disappearing, encryption failure, state-write failure, or
receipt failure aborts close and latches the lifecycle; it is never treated as
successful evidence delivery.

Each encrypted conversation chunk uses a durable transaction. Ciphertext is
first written under a shipper-invisible pending name, the intended canonical
hash/name and source offset transition are recorded, capture state is advanced
and fsynced, and only then is ciphertext published to the shipper. Recovery can
finish any crash point without minting two ciphertext candidates for one
sequence. The final receipt binds prepared offsets and the canonical ordered
chunk set as well as terminal journal offsets.

Agent-authored report artifact capture remains intentionally best-effort. It is
not part of the transactional close receipt: a report written immediately
before process death may not satisfy the stability window. Findings that
require guaranteed retention must be submitted through the findings broker,
not inferred from the report-directory snapshot stream.

Run-lifecycle installation is fail-closed and recoverable rather than exposing
a usable mixed generation. Each guest writes a durable pending-install record
before changing coordinated files; lease issuance or arming refuses that
marker, and an early-boot unit rolls the guest back to its recorded backup if
power is lost. The host deploy transaction records both guest backup identities
and rolls back the first guest if the second guest cannot commit.

## Lifecycle

1. `labctl claude` checks time and session state, creates the run ID, and asks
   the Gateway root manager to issue a lease.
2. Research rejects pre-existing agent processes, prepares capture, writes the
   durable lifecycle and bounded scope seed, and publishes admission last.
3. The broker validates and durably reserves the lease before every model or
   token-count request.
4. Normal cleanup closes Research first: admission is revoked, the scope is
   proven empty, and capture is finalized to a receipt.
5. Only after Research is `local_closed` does the host finalize the immutable
   Gateway summary. Research commits only when given the SHA-256 digest of the
   summary's exact durable bytes (canonical JSON plus its terminating LF) and a
   valid local capture receipt. Cleanup errors override an otherwise successful
   Claude exit and leave durable recovery evidence.
6. Host loss leaves the watchdog to expire through the same close primitive;
   recovery must still reconcile Gateway finalization and Research commit.
7. Renewal requires `labctl lease renew RUN_ID SECONDS` from the host operator.

## Non-claims

The lease bounds broker-authorized usage under the configured conservative
rates. It does not replace the provider organization cap, predict discounts or
cache billing, attest provider invoices, or make the Research watchdog the
primary billing boundary. A capture-final receipt proves local capture reached
a terminal offset and produced encrypted evidence; it does not prove off-host
delivery, semantic completeness of upstream logs, or provider-side retention.
Artifact directory snapshots do not have the capture-final completeness claim.

