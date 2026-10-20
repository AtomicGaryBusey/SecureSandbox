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

## Research watchdog

A separate root-owned Research watchdog receives only the non-secret run ID,
lease ID, and expiry. A command-specific root supervisor validates the sudo
caller, exact root-issued run marker, root-owned lease, fixed Claude arguments,
and optional resume registry entry. It starts Claude as the unprivileged agent
in a separate process group and records the identity in root-owned state under
the watchdog's transaction lock. At expiry the watchdog revalidates that state,
terminates the registered group and supervisor, and removes any remaining
process owned by the dedicated agent account. It retains the lease and emits a
critical failure if termination cannot be confirmed. Gateway denial remains the
independent paid-call authority.

## Lifecycle

1. `labctl claude` checks time and session state, creates the run ID, and asks
   the Gateway root manager to issue a lease.
2. The returned non-secret descriptor is armed on Research before Claude
   starts.
3. The broker validates and durably reserves the lease before every model or
   token-count request.
4. Normal host cleanup finalizes an immutable Gateway summary and disarms the
   Research watchdog. Host loss leaves the lease to expire; recovery finalizes
   it later.
5. Renewal requires `labctl lease renew RUN_ID SECONDS` from the host operator.

## Non-claims

The lease bounds broker-authorized usage under the configured conservative
rates. It does not replace the provider organization cap, predict discounts or
cache billing, attest provider invoices, or make the Research watchdog the
primary billing boundary.

