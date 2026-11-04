# Native credential XPC integration gate

The native credential service has a compile-tested SwiftPM executable and a
public low-level XPC boundary. It is a per-console-user LaunchAgent/Mach
service, not an embedded XPC service and not a root daemon. That placement is
required so the system browser, Secure Enclave identity, and Data Protection
Keychain remain in the signed-in user's security session.

SwiftPM does **not** assemble the background `.app` bundle, apply its Info.plist
and entitlements, install its LaunchAgent, or perform Developer ID signing.
Production admission therefore remains closed until the following packaging and
live acceptance work is complete.

## Required signed products

Package `SecureSandboxNativeCredentialXPCService` as a background-only app using:

- `macos/ControlCenter/Sources/SecureSandboxNativeCredentialHelper/`
  `SecureSandboxNativeCredentialHelper-Info.plist`
- `macos/ControlCenter/Sources/SecureSandboxNativeCredentialHelper/`
  `SecureSandboxNativeCredentialHelper.entitlements`
- bundle identifier and Mach service label
  `org.zebeth.SecureSandbox.NativeCredentialHelper`
- hardened runtime and the same Developer ID team as the rest of SecureSandbox

The installer must render
`org.zebeth.SecureSandbox.NativeCredentialHelper.plist.template` with an exact,
absolute executable path, install it root-owned and non-writable in
`/Library/LaunchAgents`, and install the signed helper bundle at a root-owned,
non-group/world-writable path. macOS then instantiates it only in each applicable
user's Aqua bootstrap. A LaunchAgent or executable under a same-UID-writable path
is not admissible. The template deliberately cannot be installed without
rendering its path placeholder.

The helper refuses to create a listener unless its own running code has the
exact service identifier, hardened-runtime flag, team identifier, and Developer
ID Application certificate extension. The listener uses only public
`xpc_listener`/`xpc_session` APIs with Mach-service mode.

The sole client is the dedicated signed backend with bundle identifier
`org.zebeth.SecureSandbox.NativeStackBackend`. Control Center never calls the
credential service directly. The listener and each accepted session apply one
singular system code-signing requirement fixing that backend identifier, the
helper's own ten-character team, the Apple generic anchor, and the Developer ID
Application certificate extension. There is no OR-list and no PID fallback.
The backend must independently refuse to run without its hardened-runtime
Developer ID identity; distribution acceptance must verify both artifacts.

macOS 27.2 exposes no accepted peer audit token through `NSXPCConnection` or
public libxpc. The public race-free alternative used here is libxpc's
message-bound peer code-signing requirement gate. No private audit-token or PID
lookup is present.

## Public client contract

Swift clients use `NativeCredentialXPCClientContract`:

- `encodeRequest(...)` owns Swift canonical JSON and self-digest generation;
- `serviceDesignatedRequirement(teamIdentifier:)` creates the exact helper
  requirement;
- `transact(request:teamIdentifier:)` is the single client call.
  It constructs the exact helper requirement internally, opens an inactive
  Mach session, pins it before activation, and validates the exact reply; and
- `decodeReply(_:)` validates canonical bytes and the response self-digest.

The underlying C API is:

`ss_native_xpc_client_request(service_name, service_requirement, request_bytes,
request_length, &reply_bytes, &reply_length)`

with `ss_native_xpc_bytes_free` for the returned allocation. The service name is
`SS_NATIVE_XPC_SERVICE_NAME`; request and reply dictionaries contain exactly one
`Data` member named `request` and `reply`, respectively, and each value is at
most 32 KiB.

The canonical request contains exactly:

- schema, command, authorization ticket ID, plan SHA-256, operator-request
  SHA-256, stack SHA-256, and IPC-request SHA-256;
- operation ID, operation, fixed provider, optional session-authority SHA-256,
  and authorization-receipt SHA-256 inside the command; and
- explicit nulls for top-level authorization fields on ticketless read-only
  status requests.

The exact reply contains only operation ID, verified/rejected outcome, hashed
credential status or projection status, fixed error code, and response SHA-256.
No token, authorization code, provider response, PKCE value, or unbounded error
text is part of either envelope.

Stack activation never projects a credential. Refresh for entitlement
verification is pre-session and therefore carries no fabricated session digest.
`projectForSession` is reachable only with a separate `session-start` ticket
issued by the future run controller and remains the sole session-bound operation.

## Installer and acceptance gates

Before enabling mutating requests, the installer must create and maintain:

`/usr/local/var/lib/secure-sandbox/native-credential-tickets`

as a root-owned directory that is not group- or world-writable. Each ticket is
a root-owned, single-link, regular `0644` file with canonical self-digested JSON.
The current app-sandbox entitlement may deny this read even when POSIX mode
allows it. Acceptance must prove the exact signed service can read only the
ticket path it needs. If it cannot, the remaining integration work is a narrow
signed broker or sandbox-extension design; removing the app sandbox or accepting
caller-supplied ticket bodies is not an admissible workaround.

The protected backend currently originates from a root-controlled manager.
A root/system bootstrap cannot directly stand in for the console-user Mach
bootstrap. Packaging must prove that the signed backend client is invoked in
the exact console-user bootstrap without copying authority into an unsigned
shim. Until that topology is demonstrated, lookup failure is the correct
fail-closed result and production activation remains disabled.

Projection remains deliberately unavailable until the separate signed
Host-to-Research projection bridge is implemented and pinned.

Production acceptance must include:

1. rejection of unsigned, ad-hoc, wrong-team, and wrong-bundle clients;
2. helper and backend hardened-runtime, notarization, and Gatekeeper checks;
3. proof that lookup occurs only in the intended console-user bootstrap;
4. root-ticket path and Data Protection Keychain replay tests across a service
   restart;
5. connection-loss tests before and during each mutation; and
6. verification that unified logs and every IPC reply remain content-free.
