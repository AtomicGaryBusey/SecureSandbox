# Local Broker Protocol Hardening

## Status

Implementation in progress. Deployment state and acceptance evidence are
private and must not be inferred from this document.

## Decision

Every SecureSandbox listener uses a bounded framing contract appropriate to its
transport. A peer may consume a bounded request slot, but it cannot extend that
slot indefinitely by sending one byte before each inactivity timeout. Services
that consume one-shot authority or mutate one durable journal remain
intentionally serialized; their absolute framing and finite write deadlines
bound head-of-line blocking without introducing unsafe parallel state changes.

Transport hardening does not replace the service's authorization policy. Unix
socket mode bits, Linux peer credentials, mTLS identities, bearer capabilities,
forced-command roles, and exact operation schemas remain independent layers.

## Protocol inventory

| Boundary | Framing | Identity | Concurrency decision |
|---|---|---|---|
| Host privileged control over forced-command SSH | big-endian sized canonical JSON plus sized payload | pinned SSH key and guest role | one bounded client process per request |
| Host Touch ID broker Unix socket | bounded typed message | kernel peer executable, UID, release and signing identity | serialized operator ceremony |
| Research corpus, findings, memory, and CodeGraph Unix sockets | EOF or one newline within an absolute deadline | socket group plus `SO_PEERCRED` UID | selector-multiplexed framing, bounded client set, serialized mutation/query handling |
| Research execution broker HTTP | exact `Content-Length` within an absolute deadline | loopback plus run/session and signed approval protocol | serialized one-shot consumption |
| Research model relay HTTP | exact `Content-Length` within an absolute deadline | loopback and root-issued run state | serialized forwarding with bounded upstream response |
| Gateway model broker mTLS HTTP | bounded TLS handshake and exact body framing | pinned client-certificate fingerprint and run lease | serialized lease evaluation and forwarding |
| Gateway telemetry and encrypted-conversation mTLS HTTP | bounded TLS handshake and exact body framing | pinned client-certificate fingerprint | serialized durable spool publication |
| Target disposable-execution HTTP | exact `Content-Length` within an absolute deadline | firewall-confined Research broker plus bearer capability | serialized container lifecycle |
| Managed MCP stdio adapters | one size-limited newline record | fixed launcher and managed MCP policy | one adapter process per agent session |

## Shared Unix-socket contract

The selector-based server accepts at most a fixed number of clients, limits
accept work per selector turn, and assigns each accepted connection an absolute
monotonic deadline. Slow clients are expired independently, so a complete peer
can be served while other peers are incomplete. Linux peer credentials are
checked before request bytes are parsed. Unauthorized and capacity-exhausted
connections receive only fixed error tokens. Handler failure closes only that
connection and cannot terminate the broker loop.

The server removes a predecessor socket only when it is a socket owned by the
service UID. It refuses regular files, symlinks, foreign-owned sockets, and
invalid configuration. Responses use a finite write timeout.

## Shared HTTP contract

The bounded HTTP server performs TLS handshakes on accepted sockets with a
monotonic deadline instead of wrapping the listening socket. The handler starts
an independent absolute timer before the standard library parses the request
line and headers. The timer remains active until the complete declared body has
been read. Slow headers, slow-drip bodies, premature EOF, duplicate lengths,
transfer encodings, and oversize bodies fail closed. Once framing completes,
the socket switches to a finite write timeout so a non-reading client cannot
retain the serialized service indefinitely.

The services remain HTTP/1.1-compatible for their fixed local clients but close
every response. They do not accept chunked bodies, upgrades, `CONNECT`, or
multiple requests on one connection.

## Resource and error bounds

- All request and response bodies retain service-specific byte limits.
- Unix pre-framing admission is capped and overload is explicit.
- HTTP TLS handshake, headers, body, and writes have finite deadlines.
- Upstream model calls and Target execution retain their distinct operation
  deadlines; framing timeout does not silently become an execution timeout.
- Rejections expose fixed tokens only. Telemetry contains protocol class,
  service identity, and fixed result—not request bodies, headers, credentials,
  source text, model content, or transcript ciphertext.
- A timeout before a durable mutation produces no success receipt. Existing
  one-shot/replay and transactional recovery rules remain authoritative after
  framing completes.

## Acceptance gates

1. Every listener in the inventory is either migrated to the shared contract or
   has tests proving an equivalent absolute bound.
2. Slow headers, slow-drip bodies, incomplete bodies, duplicate lengths,
   transfer encodings, oversized requests, non-reading clients, unauthorized
   Unix peers, and admission saturation are rejected without starving a valid
   request beyond the documented bound.
3. TLS handshake stalling is bounded before HTTP parsing.
4. Service-specific authorization, exact schema, replay, evidence, and durable
   publication tests remain green.
5. Install and rollback paths deploy the exact shared helpers as root-owned,
   non-writable artifacts and include them in policy hashes.
6. The complete unit suite, shell syntax checks, publication scan, deterministic
   release build, and live boundary suite pass.
7. Live acceptance exercises one slow peer and one simultaneous valid peer on
   each reachable protocol class without recording request content.

Deployment identifiers, live timings, policy hashes, and acceptance transcripts
belong only in ignored local evidence.
