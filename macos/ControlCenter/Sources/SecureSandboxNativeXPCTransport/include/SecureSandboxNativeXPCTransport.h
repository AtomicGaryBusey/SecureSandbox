#ifndef SECURE_SANDBOX_NATIVE_XPC_TRANSPORT_H
#define SECURE_SANDBOX_NATIVE_XPC_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SSNativeXPCRequestOpaque *SSNativeXPCRequestRef;

#define SS_NATIVE_XPC_SERVICE_NAME \
    "org.zebeth.SecureSandbox.NativeCredentialHelper"
#define SS_NATIVE_XPC_REQUEST_KEY "request"
#define SS_NATIVE_XPC_REPLY_KEY "reply"
#define SS_NATIVE_XPC_PROJECTION_FD_KEY "projection_fd"
#define SS_NATIVE_XPC_MAXIMUM_DATA_BYTES (32u * 1024u)

typedef void (*SSNativeXPCRequestHandler)(
    SSNativeXPCRequestRef request,
    const uint8_t *bytes,
    size_t length,
    int32_t projection_fd,
    void *context
);

typedef void (*SSNativeXPCCancellationHandler)(
    SSNativeXPCRequestRef request,
    void *context
);

// Runs one XPCService listener. The public XPC runtime enforces the exact peer
// code-signing requirement both at the listener and on every accepted session.
// This function never consults a PID and never exposes argv or stdin commands.
int32_t ss_native_xpc_server_run(
    const char *service_name,
    const char *peer_code_signing_requirement,
    SSNativeXPCRequestHandler request_handler,
    SSNativeXPCCancellationHandler cancellation_handler,
    void *context
);

bool ss_native_xpc_request_is_cancelled(SSNativeXPCRequestRef request);

// Sends exactly one bounded Data reply. Returns false after cancellation,
// duplicate completion, or transport failure.
bool ss_native_xpc_request_reply(
    SSNativeXPCRequestRef request,
    const uint8_t *bytes,
    size_t length
);

// Completes the lifetime retained by the transport for request_handler.
void ss_native_xpc_request_release(SSNativeXPCRequestRef request);

// Deterministic, side-effect-free lifetime probe used by the transport tests.
// It simulates peer cancellation winning immediately before request dispatch.
bool ss_native_xpc_testing_cancel_before_add_retains_request(void);

// Synchronous client primitive for the separately signed Host backend. The
// service is authenticated with an exact code-signing requirement before the
// session is activated. On success, reply_bytes is malloc-owned and must be
// released with ss_native_xpc_bytes_free.
int32_t ss_native_xpc_client_request(
    const char *service_name,
    const char *service_code_signing_requirement,
    const uint8_t *request_bytes,
    size_t request_length,
    uint8_t **reply_bytes,
    size_t *reply_length
);

// Variant used only for projectForSession. projection_fd must be one connected
// non-PTY local socket. XPC duplicates the descriptor; no credential bytes are
// present in the Data envelope.
int32_t ss_native_xpc_client_request_with_fd(
    const char *service_name,
    const char *service_code_signing_requirement,
    const uint8_t *request_bytes,
    size_t request_length,
    int32_t projection_fd,
    uint8_t **reply_bytes,
    size_t *reply_length
);

void ss_native_xpc_bytes_free(void *bytes);

#ifdef __cplusplus
}
#endif

#endif
