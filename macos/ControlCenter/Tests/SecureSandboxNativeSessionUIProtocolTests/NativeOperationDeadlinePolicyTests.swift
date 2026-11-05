import Testing
@testable import SecureSandboxNativeSessionUIProtocol

@Suite struct NativeOperationDeadlinePolicyTests {
    @Test func everyCallerStrictlyOutlivesItsProtectedCallee() {
        #expect(
            NativeOperationDeadlinePolicy.rootProtectedMutationSeconds
                < NativeOperationDeadlinePolicy.directBrokerClientSeconds
        )
        #expect(
            NativeOperationDeadlinePolicy.directBrokerClientSeconds
                < NativeOperationDeadlinePolicy.controlCenterBridgeSeconds
        )
    }
}
