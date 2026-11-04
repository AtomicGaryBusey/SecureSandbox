import SecureSandboxNativeXPCTransport
import Testing

@Suite struct NativeXPCTransportTests {
    @Test func cancelBeforeAddRetainsUntilExplicitRelease() {
        #expect(ss_native_xpc_testing_cancel_before_add_retains_request())
    }
}
