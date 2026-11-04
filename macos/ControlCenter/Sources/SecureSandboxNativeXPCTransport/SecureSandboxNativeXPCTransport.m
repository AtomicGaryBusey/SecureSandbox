#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#import <os/lock.h>
#import <xpc/xpc.h>

#import "SecureSandboxNativeXPCTransport.h"

static const size_t SSMaximumPayloadBytes = SS_NATIVE_XPC_MAXIMUM_DATA_BYTES;

@class SSNativeXPCRequest;

@interface SSNativeXPCPeer : NSObject
@property(nonatomic, assign) SSNativeXPCCancellationHandler cancellationHandler;
@property(nonatomic, assign) void *callbackContext;
- (instancetype)initWithCancellationHandler:(SSNativeXPCCancellationHandler)cancellationHandler
                                     context:(void *)context;
- (void)addRequest:(SSNativeXPCRequest *)request;
- (void)removeRequest:(SSNativeXPCRequest *)request;
- (void)cancel;
- (BOOL)isCancelled;
@end

@interface SSNativeXPCRequest : NSObject {
    os_unfair_lock _lock;
    BOOL _cancelled;
    BOOL _completed;
}
@property(nonatomic, strong) xpc_object_t replyEnvelope;
@property(nonatomic, strong) xpc_session_t session;
@property(nonatomic, weak) SSNativeXPCPeer *peer;
- (instancetype)initWithReplyEnvelope:(xpc_object_t)replyEnvelope
                               session:(xpc_session_t)session
                                  peer:(SSNativeXPCPeer *)peer;
- (BOOL)markCancelled;
- (BOOL)isCancelled;
- (BOOL)beginReply;
@end

@implementation SSNativeXPCPeer {
    os_unfair_lock _lock;
    BOOL _cancelled;
    NSMutableSet<SSNativeXPCRequest *> *_requests;
}

- (instancetype)initWithCancellationHandler:(SSNativeXPCCancellationHandler)cancellationHandler
                                     context:(void *)context {
    self = [super init];
    if (self != nil) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _cancellationHandler = cancellationHandler;
        _callbackContext = context;
        _requests = [NSMutableSet set];
    }
    return self;
}

- (void)addRequest:(SSNativeXPCRequest *)request {
    BOOL reject = NO;
    os_unfair_lock_lock(&_lock);
    if (_cancelled) {
        reject = YES;
    } else {
        [_requests addObject:request];
    }
    os_unfair_lock_unlock(&_lock);
    if (reject) {
        [request markCancelled];
    }
}

- (void)removeRequest:(SSNativeXPCRequest *)request {
    os_unfair_lock_lock(&_lock);
    [_requests removeObject:request];
    os_unfair_lock_unlock(&_lock);
}

- (void)cancel {
    NSArray<SSNativeXPCRequest *> *pending = nil;
    os_unfair_lock_lock(&_lock);
    if (!_cancelled) {
        _cancelled = YES;
        pending = _requests.allObjects;
    }
    os_unfair_lock_unlock(&_lock);
    for (SSNativeXPCRequest *request in pending) {
        if ([request markCancelled] && self.cancellationHandler != NULL) {
            self.cancellationHandler(
                (__bridge SSNativeXPCRequestRef)request,
                self.callbackContext
            );
        }
    }
}

- (BOOL)isCancelled {
    os_unfair_lock_lock(&_lock);
    BOOL value = _cancelled;
    os_unfair_lock_unlock(&_lock);
    return value;
}

@end

@implementation SSNativeXPCRequest

- (instancetype)initWithReplyEnvelope:(xpc_object_t)replyEnvelope
                               session:(xpc_session_t)session
                                  peer:(SSNativeXPCPeer *)peer {
    self = [super init];
    if (self != nil) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _replyEnvelope = replyEnvelope;
        _session = session;
        _peer = peer;
    }
    return self;
}

- (BOOL)markCancelled {
    os_unfair_lock_lock(&_lock);
    BOOL changed = !_cancelled && !_completed;
    _cancelled = YES;
    os_unfair_lock_unlock(&_lock);
    return changed;
}

- (BOOL)isCancelled {
    os_unfair_lock_lock(&_lock);
    BOOL value = _cancelled || _completed;
    os_unfair_lock_unlock(&_lock);
    return value;
}

- (BOOL)beginReply {
    os_unfair_lock_lock(&_lock);
    BOOL allowed = !_cancelled && !_completed;
    if (allowed) {
        _completed = YES;
    }
    os_unfair_lock_unlock(&_lock);
    return allowed;
}

@end

static BOOL SSRequirementStringIsBounded(const char *value) {
    if (value == NULL) {
        return NO;
    }
    size_t length = strnlen(value, 4097);
    if (length == 0 || length > 4096) {
        return NO;
    }
    for (size_t index = 0; index < length; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20 || byte == 0x7f) {
            return NO;
        }
    }
    return YES;
}

static BOOL SSCodeRequirementIsValid(const char *value) {
    if (!SSRequirementStringIsBounded(value)) {
        return NO;
    }
    NSString *source = [NSString stringWithUTF8String:value];
    if (source == nil) {
        return NO;
    }
    SecRequirementRef requirement = NULL;
    OSStatus status = SecRequirementCreateWithString(
        (__bridge CFStringRef)source,
        kSecCSDefaultFlags,
        &requirement
    );
    if (requirement != NULL) {
        CFRelease(requirement);
    }
    return status == errSecSuccess;
}

static NSData *SSExtractRequestData(xpc_object_t message) {
    if (message == NULL || xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
        return [NSData data];
    }
    __block size_t keyCount = 0;
    __block BOOL exact = YES;
    xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t value) {
        ++keyCount;
        if (strcmp(key, SS_NATIVE_XPC_REQUEST_KEY) != 0
            || xpc_get_type(value) != XPC_TYPE_DATA) {
            exact = NO;
        }
        return true;
    });
    if (!exact || keyCount != 1) {
        return [NSData data];
    }
    size_t length = 0;
    const void *bytes = xpc_dictionary_get_data(
        message,
        SS_NATIVE_XPC_REQUEST_KEY,
        &length
    );
    if (bytes == NULL || length == 0 || length > SSMaximumPayloadBytes) {
        return [NSData data];
    }
    return [NSData dataWithBytes:bytes length:length];
}

int32_t ss_native_xpc_server_run(
    const char *service_name,
    const char *peer_code_signing_requirement,
    SSNativeXPCRequestHandler request_handler,
    SSNativeXPCCancellationHandler cancellation_handler,
    void *context
) {
    if (!SSRequirementStringIsBounded(service_name)
        || !SSCodeRequirementIsValid(peer_code_signing_requirement)
        || request_handler == NULL) {
        return 64;
    }

    NSString *requirement = [NSString stringWithUTF8String:peer_code_signing_requirement];
    if (requirement == nil) {
        return 64;
    }

    xpc_rich_error_t createError = NULL;
    xpc_listener_t listener = xpc_listener_create(
        service_name,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        XPC_LISTENER_CREATE_INACTIVE | XPC_LISTENER_CREATE_FORCE_MACH,
        ^(xpc_session_t peer) {
            int requirementResult = xpc_session_set_peer_code_signing_requirement(
                peer,
                requirement.UTF8String
            );
            if (requirementResult != 0) {
                xpc_listener_reject_peer(peer, "peer requirement unavailable");
                return;
            }

            SSNativeXPCPeer *state = [[SSNativeXPCPeer alloc]
                initWithCancellationHandler:cancellation_handler
                context:context];

            xpc_session_set_cancel_handler(peer, ^(xpc_rich_error_t error) {
                (void)error;
                [state cancel];
            });
            xpc_session_set_incoming_message_handler(peer, ^(xpc_object_t message) {
                if ([state isCancelled]) {
                    return;
                }
                xpc_object_t replyEnvelope = xpc_dictionary_create_reply(message);
                if (replyEnvelope == NULL) {
                    xpc_session_cancel(peer);
                    return;
                }
                SSNativeXPCRequest *request = [[SSNativeXPCRequest alloc]
                    initWithReplyEnvelope:replyEnvelope
                    session:peer
                    peer:state];
                [state addRequest:request];
                NSData *data = SSExtractRequestData(message);
                request_handler(
                    (__bridge SSNativeXPCRequestRef)request,
                    data.length == 0 ? NULL : data.bytes,
                    data.length,
                    context
                );
            });
        },
        &createError
    );
    if (listener == NULL || createError != NULL) {
        return 69;
    }

    int requirementResult = xpc_listener_set_peer_code_signing_requirement(
        listener,
        peer_code_signing_requirement
    );
    if (requirementResult != 0) {
        xpc_listener_cancel(listener);
        return 78;
    }
    xpc_rich_error_t activationError = NULL;
    if (!xpc_listener_activate(listener, &activationError) || activationError != NULL) {
        xpc_listener_cancel(listener);
        return 69;
    }
    dispatch_main();
}

bool ss_native_xpc_request_is_cancelled(SSNativeXPCRequestRef opaque) {
    if (opaque == NULL) {
        return true;
    }
    SSNativeXPCRequest *request = (__bridge SSNativeXPCRequest *)opaque;
    return [request isCancelled] || [request.peer isCancelled];
}

bool ss_native_xpc_request_reply(
    SSNativeXPCRequestRef opaque,
    const uint8_t *bytes,
    size_t length
) {
    if (opaque == NULL || bytes == NULL || length == 0 || length > SSMaximumPayloadBytes) {
        return false;
    }
    SSNativeXPCRequest *request = (__bridge SSNativeXPCRequest *)opaque;
    SSNativeXPCPeer *peer = request.peer;
    if (peer == nil || [peer isCancelled] || ![request beginReply]) {
        return false;
    }
    xpc_dictionary_set_data(
        request.replyEnvelope,
        SS_NATIVE_XPC_REPLY_KEY,
        bytes,
        length
    );
    xpc_rich_error_t error = xpc_session_send_message(
        request.session,
        request.replyEnvelope
    );
    return error == NULL;
}

void ss_native_xpc_request_release(SSNativeXPCRequestRef opaque) {
    if (opaque == NULL) {
        return;
    }
    SSNativeXPCRequest *request = (__bridge SSNativeXPCRequest *)opaque;
    [request.peer removeRequest:request];
}

int32_t ss_native_xpc_client_request(
    const char *service_name,
    const char *service_code_signing_requirement,
    const uint8_t *request_bytes,
    size_t request_length,
    uint8_t **reply_bytes,
    size_t *reply_length
) {
    if (!SSRequirementStringIsBounded(service_name)
        || !SSCodeRequirementIsValid(service_code_signing_requirement)
        || request_bytes == NULL
        || request_length == 0
        || request_length > SSMaximumPayloadBytes
        || reply_bytes == NULL
        || reply_length == NULL) {
        return 64;
    }
    *reply_bytes = NULL;
    *reply_length = 0;

    xpc_rich_error_t createError = NULL;
    xpc_session_t session = xpc_session_create_mach_service(
        service_name,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        XPC_SESSION_CREATE_INACTIVE,
        &createError
    );
    if (session == NULL || createError != NULL) {
        return 69;
    }
    int requirementResult = xpc_session_set_peer_code_signing_requirement(
        session,
        service_code_signing_requirement
    );
    if (requirementResult != 0) {
        xpc_rich_error_t ignoredError = NULL;
        if (xpc_session_activate(session, &ignoredError)) {
            xpc_session_cancel(session);
        }
        return 78;
    }
    xpc_rich_error_t activationError = NULL;
    if (!xpc_session_activate(session, &activationError)
        || activationError != NULL) {
        return 69;
    }

    xpc_object_t request = xpc_dictionary_create_empty();
    xpc_dictionary_set_data(
        request,
        SS_NATIVE_XPC_REQUEST_KEY,
        request_bytes,
        request_length
    );
    xpc_rich_error_t replyError = NULL;
    xpc_object_t reply = xpc_session_send_message_with_reply_sync(
        session,
        request,
        &replyError
    );
    xpc_session_cancel(session);
    if (reply == NULL || replyError != NULL
        || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
        return 69;
    }

    __block size_t keyCount = 0;
    __block BOOL exact = YES;
    xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t value) {
        ++keyCount;
        if (strcmp(key, SS_NATIVE_XPC_REPLY_KEY) != 0
            || xpc_get_type(value) != XPC_TYPE_DATA) {
            exact = NO;
        }
        return true;
    });
    if (!exact || keyCount != 1) {
        return 65;
    }
    size_t length = 0;
    const void *bytes = xpc_dictionary_get_data(
        reply,
        SS_NATIVE_XPC_REPLY_KEY,
        &length
    );
    if (bytes == NULL || length == 0 || length > SSMaximumPayloadBytes) {
        return 65;
    }
    uint8_t *copy = malloc(length);
    if (copy == NULL) {
        return 71;
    }
    memcpy(copy, bytes, length);
    *reply_bytes = copy;
    *reply_length = length;
    return 0;
}

void ss_native_xpc_bytes_free(void *bytes) {
    if (bytes != NULL) {
        free(bytes);
    }
}
