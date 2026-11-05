import Testing
@testable import SecureSandboxNativeSessionUIProtocol

@Suite struct NativeHostReleaseAuthorityTests {
    private let historicalA = String(repeating: "a", count: 64)
    private let currentB = String(repeating: "b", count: 64)

    @Test func newOperationsBindCurrentNotHistoricalHost() throws {
        let authority = try NativeHostReleaseAuthority(
            currentHostReleaseID: currentB,
            historicalPublicationHostReleaseID: historicalA
        )
        #expect(authority.currentHostReleaseID == currentB)
        #expect(authority.historicalPublicationHostReleaseID == historicalA)
        try authority.requireCurrent(currentB)
        #expect(throws: NativeSessionProtocolError.self) {
            try authority.requireCurrent(historicalA)
        }
    }
}
