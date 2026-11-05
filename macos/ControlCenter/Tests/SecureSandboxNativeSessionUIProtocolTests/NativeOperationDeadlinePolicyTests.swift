import Testing
@testable import SecureSandboxNativeSessionUIProtocol

@Suite struct NativeOperationDeadlinePolicyTests {
    @Test func everyCallerStrictlyOutlivesItsProtectedCallee() {
        #expect(NativeOperationDeadlinePolicy.rootProtectedMutationSeconds == 3_900)
        #expect(NativeOperationDeadlinePolicy.authorizationClientSeconds == 4_140)
        #expect(NativeOperationDeadlinePolicy.controlCenterAPIClientSeconds == 4_200)
        #expect(NativeOperationDeadlinePolicy.controlCenterBridgeSeconds == 4_320)
        #expect(
            NativeOperationDeadlinePolicy.rootProtectedMutationSeconds
                < NativeOperationDeadlinePolicy.directBrokerClientSeconds
        )
        #expect(
            NativeOperationDeadlinePolicy.rootProtectedMutationSeconds
                < NativeOperationDeadlinePolicy.authorizationClientSeconds
        )
        #expect(
            NativeOperationDeadlinePolicy.authorizationClientSeconds
                < NativeOperationDeadlinePolicy.controlCenterAPIClientSeconds
        )
        #expect(
            NativeOperationDeadlinePolicy.controlCenterAPIClientSeconds
                < NativeOperationDeadlinePolicy.controlCenterBridgeSeconds
        )
    }
}
