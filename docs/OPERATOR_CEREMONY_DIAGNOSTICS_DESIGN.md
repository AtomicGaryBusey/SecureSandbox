# Operator Ceremony and Diagnostics

## Status

Implemented, deployed, and live boundary verified. Deployment-specific request
identifiers and live evidence belong only in ignored local records.

## Decision

Every protected authorization request binds one of two operator ceremonies:
`approve` or `cancel-test`. The ceremony is part of the canonical request bytes
and therefore part of the request SHA-256 displayed by the UI and independently
validated by the root broker. A caller cannot relabel the window after the
request is authorized.

An approval window is titled **SecureSandbox Approval Request** and offers the
normal Touch ID, explicit password-fallback where permitted, and Cancel choices.
A cancellation test is titled **SecureSandbox Cancellation Test**, says not to
authenticate, and exposes only **Cancel This Test**. The broker selects a
side-effect-free `cancel-only` challenge before consulting operation-specific
state. Only an actual click on **Cancel This Test** sends the bound cancellation
decision; expiry and window dismissal are distinct terminal outcomes. The
cancellation path contains no biometric, Secure Enclave signing, or
privileged-operation path. The privileged execution sink independently rejects
every request whose ceremony is not `approve`, including legacy and direct
broker entry points.

## Terminal diagnostic contract

The requester emits one final canonical JSON record for a terminal failure:

```json
{"action":"start_new_request_when_ready","code":"operator_cancelled","operation":"authorization-probe","outcome":"cancelled","phase":"ceremony","request_id":"…","retry":"new-request","schema":"secure-sandbox-operator-diagnostic-v1"}
```

The record contains no purpose, resource, parameters, subprocess output,
biometric data, or execution content. Child stdout and stderr are untrusted
operation data: they are never parsed as diagnostic control data, copied into a
diagnosis, or emitted on a failed requester path. Policy-significant outcomes
come only from the exact, private UI result sidecar or from broker-owned state.

`retry` is normative:

- `new-request`: the prior request is terminal and a new explicit request may
  be created after the named action.
- `wait`: another request owns the authorization lock; do not create a parallel
  prompt.
- `forbidden`: the outcome or protected state requires inspection or repair
  before any retry. In particular, a missing or invalid UI result and an
  already-consumed request require authorization-receipt inspection. An
  operation timeout is also ambiguous because termination of the requester is
  not proof that the privileged operation never began. The same rule applies to
  the whole UI/broker lifecycle timeout: it is not classified as a pre-execution
  dialog timeout and cannot authorize an automatic retry.

The diagnostic is guidance, not authority. The root receipt and component
state remain authoritative, and the requester cannot use a diagnostic to make
an ambiguous operation replayable.

## Compatibility and failure semantics

The protected Host release atomically binds the Python requester/broker, Swift
request parser, signed UI bundle, source manifest, and bundle manifest. Missing
or unknown ceremony values fail closed. Existing ordinary callers default to
`approve`; negative tests must opt into `cancel-test` explicitly.

Cancellation creates the existing private root-owned, content-free
authorization receipt and an exact root-owned public projection. The projection
binds the outer authorization request ID and digest, ceremony, operation,
protected Host release, signed UI bundle, private receipt digest, and (for an
execution-sign cancellation) the active Secure Enclave generation. Finalization
validates that projection before recording cancellation evidence. UI launch
loss, missing or malformed
result sidecars, replay, mixed release identity, and untrusted state never map
to cancellation or success. They produce `retry: forbidden` diagnostics.
The retained legacy UI protocol is accepted only for requests whose bound
ceremony is `approve`; it rejects `cancel-test` before privileged execution.

## Acceptance

Automated acceptance proves strict ceremony parsing, digest binding, distinct
copy and buttons, absence of an approval path in the cancellation branch,
expiry/cancellation separation, approve-only enforcement at the privileged
sink, mutation-free cancellation challenge selection, content-free fixed-shape
diagnostics, rejection of forged child diagnostics, conservative timeout retry
classification, authoritative cancellation-evidence binding, and all existing
authorization tests.

Live acceptance deploys one immutable Host release, approves a side-effect-free
probe, cancels a separate cancellation-only probe, validates exactly one
terminal diagnostic, and then runs the complete boundary verifier.
