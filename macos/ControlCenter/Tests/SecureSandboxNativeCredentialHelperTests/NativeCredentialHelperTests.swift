import CryptoKit
import Foundation
import Testing
import SecureSandboxNativeAuthCore
@testable import SecureSandboxNativeCredentialHelper

struct NativeCredentialHelperTests {
    private let digest = String(repeating: "a", count: 64)
    private let now = Date(timeIntervalSince1970: 2_000_000_000)

    @Test func commandDecoderRejectsUnknownFieldsAndCrossOperationAuthority() throws {
        let command = try NativeCredentialCommand(
            operationID: UUID(), operation: .status, provider: .openAIChatGPT
        )
        let encoded = try JSONEncoder().encode(command)
        #expect(try NativeCredentialCommand.decodeExact(encoded) == command)
        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["access_token"] = "must-never-be-an-IPC-field"
        #expect(throws: NativeCredentialHelperError.invalidCommand) {
            try NativeCredentialCommand.decodeExact(JSONSerialization.data(withJSONObject: object))
        }
        #expect(throws: NativeCredentialHelperError.invalidCommand) {
            try NativeCredentialCommand(
                operationID: UUID(), operation: .status, provider: .openAIChatGPT,
                sessionAuthoritySHA256: digest, authorizationReceiptSHA256: digest
            )
        }
        _ = try NativeCredentialCommand(
            operationID: UUID(), operation: .login, provider: .openAIChatGPT,
            authorizationReceiptSHA256: digest
        )
        _ = try NativeCredentialCommand(
            operationID: UUID(), operation: .refresh, provider: .openAIChatGPT,
            authorizationReceiptSHA256: digest
        )
        #expect(throws: NativeCredentialHelperError.invalidCommand) {
            try NativeCredentialCommand(
                operationID: UUID(), operation: .refresh, provider: .openAIChatGPT,
                sessionAuthoritySHA256: digest, authorizationReceiptSHA256: digest
            )
        }
        #expect(throws: NativeCredentialHelperError.invalidCommand) {
            try NativeCredentialCommand(
                operationID: UUID(), operation: .logout, provider: .openAIChatGPT
            )
        }
    }

    @Test func statusIsContentFreeAndRequiresCompleteReadyAuthority() throws {
        let status = try NativeCredentialStatus(
            provider: .openAIChatGPT,
            state: .ready,
            clientIDHash: digest,
            accountSubjectSHA256: digest,
            workspaceSHA256: digest,
            scopeSHA256: digest,
            accessExpiresAt: now.addingTimeInterval(3_600),
            earliestRefreshAt: now.addingTimeInterval(300),
            refreshExpiresAt: now.addingTimeInterval(30 * 24 * 60 * 60)
        )
        let json = String(decoding: try JSONEncoder().encode(status), as: UTF8.self)
        #expect(try NativeCredentialStatus.decodeExact(Data(json.utf8)) == status)
        #expect(!json.contains("accessToken"))
        #expect(!json.contains("refreshToken"))
        #expect(!json.contains("idToken"))
        #expect(throws: NativeCredentialHelperError.invalidStatus) {
            try NativeCredentialStatus(provider: .openAIChatGPT, state: .ready)
        }
    }

    @Test func loopbackParserRequiresLiteralHostExactPathAndNoBody() throws {
        let port: UInt16 = 49_321
        let valid = Data("GET /auth/callback?code=fixture-code&state=fixture-state HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nContent-Length: 0\r\n\r\n".utf8)
        let url = try LoopbackHTTPRequestParser.callbackURL(from: valid, expectedPort: port)
        #expect(url.host == "127.0.0.1")
        #expect(url.path == "/auth/callback")
        for request in [
            "GET /auth/callback?code=x&state=y HTTP/1.1\r\nHost: localhost:\(port)\r\n\r\n",
            "GET https://auth.openai.com/auth/callback?code=x HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n",
            "GET /auth/callback?code=x HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nHost: 127.0.0.1:\(port)\r\n\r\n",
            "GET /auth/callback?code=x HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nContent-Length: 1\r\n\r\nx",
        ] {
            #expect(throws: NativeCredentialHelperError.callbackRejected) {
                try LoopbackHTTPRequestParser.callbackURL(from: Data(request.utf8), expectedPort: port)
            }
        }
    }

    @Test func loopbackCancelRetainsDescriptorIdentityThroughShutdown() throws {
        let state = LoopbackListenerDescriptorState()
        try state.install(listener: 77, port: 49_321)
        let taken = try state.take(
            deadline: Date().addingTimeInterval(60)
        )
        #expect(taken.0 == 77)

        let shutdownEntered = DispatchSemaphore(value: 0)
        let releaseShutdown = DispatchSemaphore(value: 0)
        let cancelCompleted = DispatchSemaphore(value: 0)
        let finishCompleted = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            _ = state.cancel { descriptor in
                if descriptor == 77 {
                    shutdownEntered.signal()
                }
                releaseShutdown.wait()
            }
            cancelCompleted.signal()
        }
        #expect(
            shutdownEntered.wait(timeout: .now() + 2) == .success
        )

        DispatchQueue.global(qos: .userInitiated).async {
            state.finish(active: 77)
            finishCompleted.signal()
        }
        #expect(
            finishCompleted.wait(timeout: .now() + 0.05) == .timedOut
        )
        releaseShutdown.signal()
        #expect(cancelCompleted.wait(timeout: .now() + 2) == .success)
        #expect(finishCompleted.wait(timeout: .now() + 2) == .success)
    }

    @Test func storedRecordRejectsExtensionAndEmitsOnlyHashedStatus() throws {
        let stored = try credential(savedAt: now)
        var object = try #require(JSONSerialization.jsonObject(with: stored.encoded) as? [String: Any])
        object["fallback_api_key"] = "forbidden"
        #expect(throws: NativeCredentialHelperError.credentialStoreFailed) {
            try StoredOpenAICredentials.decodeExact(JSONSerialization.data(withJSONObject: object))
        }
        let status = try stored.status(now: now)
        #expect(status.clientIDHash != stored.clientID)
        #expect(status.accountSubjectSHA256 == digest)
        let statusData = try JSONEncoder().encode(status)
        let statusText = String(decoding: statusData, as: UTF8.self)
        #expect(!statusText.contains(stored.accessToken))
        #expect(!statusText.contains(stored.refreshToken))
    }

    @Test func refreshRotationIsAtomicAndValidationFailurePreservesOldSet() async throws {
        let old = try credential(savedAt: now)
        let replacement = try credential(savedAt: now.addingTimeInterval(600), marker: "U")
        let vault = MemoryVault(old)
        let validator = FakeValidator(refreshResult: .success(replacement))
        let coordinator = makeCoordinator(vault: vault, validator: validator)
        let status = try await coordinator.refresh(now: now.addingTimeInterval(600))
        #expect(status.accountSubjectSHA256 == digest)
        #expect(try vault.load() == replacement)

        let retained = MemoryVault(old)
        let rejected = makeCoordinator(
            vault: retained,
            validator: FakeValidator(refreshResult: .failure(.providerResponseRejected))
        )
        await #expect(throws: NativeCredentialHelperError.providerResponseRejected) {
            try await rejected.refresh(now: now.addingTimeInterval(600))
        }
        #expect(try retained.load() == old)
    }

    @Test func returningLoginCannotReplaceTheBoundWorkspace() throws {
        let previous = try credential(savedAt: now)
        var object = try #require(
            JSONSerialization.jsonObject(with: previous.encoded) as? [String: Any]
        )
        object["workspaceSHA256"] = String(repeating: "b", count: 64)
        let replacement = try StoredOpenAICredentials.decodeExact(
            JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        )
        #expect(!NativeCredentialCoordinator.sameReturningAuthority(previous, replacement))
        #expect(NativeCredentialCoordinator.sameReturningAuthority(previous, previous))
    }

    @Test func failedRemoteRevocationRetainsLocalCredential() async throws {
        let stored = try credential(savedAt: now)
        let vault = MemoryVault(stored)
        let coordinator = makeCoordinator(
            vault: vault,
            transport: FakeTransport(revokeError: .providerTransportFailed)
        )
        await #expect(throws: NativeCredentialHelperError.revocationFailed) {
            try await coordinator.logout()
        }
        #expect(try vault.load() == stored)
    }

    @Test func projectionRequestIsShortLivedAndContainsNoCredentialMaterial() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let operationID = UUID()
        let requestSHA = String(repeating: "d", count: 64)
        let authority = try testProjectionAuthority(
            operationID: operationID,
            requestSHA256: requestSHA,
            stackSHA256: digest,
            runtimeAuthoritySHA256: digest,
            observedAt: 1_999_999_998,
            expiresAt: 2_000_000_060
        )
        let request = try CredentialProjectionRequest(
            operationID: operationID, sessionAuthoritySHA256: digest,
            authorizationReceiptSHA256: digest,
            authorizationTicketSHA256: String(repeating: "e", count: 64),
            stackSHA256: digest,
            operatorRequestSHA256: requestSHA,
            ticketIssuedAt: 1_999_999_999,
            ticketExpiresAt: 2_000_000_060,
            projectionAuthority: authority,
            expiresAt: now.addingTimeInterval(30), projectionChannelFD: 1
        )
        #expect(request.sessionAuthoritySHA256 == digest)
        let overlong = try CredentialProjectionRequest(
                operationID: operationID, sessionAuthoritySHA256: digest,
                authorizationReceiptSHA256: digest,
                authorizationTicketSHA256: String(repeating: "e", count: 64),
                stackSHA256: digest,
                operatorRequestSHA256: requestSHA,
                ticketIssuedAt: 1_999_999_999,
                ticketExpiresAt: 2_000_000_060,
                projectionAuthority: authority,
                expiresAt: now.addingTimeInterval(300), projectionChannelFD: 1
        )
        #expect(throws: NativeCredentialHelperError.projectionRejected) {
            try overlong.validate(now: now)
        }
    }

    @Test func ticketAuthorityRequiresExactLiveRootReleaseSelector() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "native-projection-selector-\(UUID().uuidString)", isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: false
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: root.path
        )
        let releases = root.appendingPathComponent("releases", isDirectory: true)
        try FileManager.default.createDirectory(
            at: releases, withIntermediateDirectories: false
        )
        let release = String(repeating: "1", count: 64)
        let releaseDirectory = releases.appendingPathComponent(
            release, isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: releaseDirectory, withIntermediateDirectories: false
        )
        let executable = releaseDirectory
            .appendingPathComponent("native_projection_consumer")
        let current = root.appendingPathComponent("current")
        try FileManager.default.createSymbolicLink(
            atPath: current.path, withDestinationPath: "releases/" + release
        )
        let authority = try testProjectionAuthority(
            operationID: UUID(
                uuidString: "11111111-1111-4111-8111-111111111111"
            )!,
            requestSHA256: String(repeating: "d", count: 64),
            stackSHA256: digest,
            runtimeAuthoritySHA256: digest,
            observedAt: Int64(now.timeIntervalSince1970) - 1,
            expiresAt: Int64(now.timeIntervalSince1970) + 60,
            hostReleaseID: release,
            consumerExecutablePath: executable.path
        )
        let loaded = try RootOwnedNativeProjectionConsumerResolver.resolve(
            authority: authority, releaseRoot: releases, currentURL: current,
            teamIdentifier: "ABCDE" + "FGHIJ",
            expectedOwner: geteuid(),
            expectedGroup: getegid()
        )
        #expect(loaded.executableURL == executable)
        #expect(loaded.executableSHA256 == authority.consumerExecutableSHA256)

        let replacementRelease = String(repeating: "2", count: 64)
        try FileManager.default.createDirectory(
            at: releases.appendingPathComponent(
                replacementRelease, isDirectory: true
            ),
            withIntermediateDirectories: false
        )
        try FileManager.default.removeItem(at: current)
        try FileManager.default.createSymbolicLink(
            atPath: current.path,
            withDestinationPath: "releases/" + replacementRelease
        )
        #expect(throws: (any Error).self) {
            try RootOwnedNativeProjectionConsumerResolver.resolve(
                authority: authority,
                releaseRoot: releases,
                currentURL: current,
                teamIdentifier: "ABCDE" + "FGHIJ",
                expectedOwner: geteuid(),
                expectedGroup: getegid()
            )
        }
    }

    @Test func fullPipeCannotExtendReleasePastMonotonicDeadline() throws {
        var descriptors: [Int32] = [0, 0]
        #expect(pipe(&descriptors) == 0)
        var readDescriptor = descriptors[0]
        var writeDescriptor = descriptors[1]
        defer {
            if readDescriptor >= 0 { close(readDescriptor) }
            if writeDescriptor >= 0 { close(writeDescriptor) }
        }
        let capacity = try fillPipe(writeDescriptor)
        let admittedWall = Date(timeIntervalSince1970: 2_000_000_000)
        let admittedMonotonic = ContinuousClock.now
        let deadline = try NativeCredentialReleaseDeadline(
            wallExpiresAt: admittedWall.addingTimeInterval(1),
            admittedWallNow: admittedWall,
            admittedMonotonicNow: admittedMonotonic
        )
        let wall = CredentialTestDateClock([
            admittedWall,
            admittedWall.addingTimeInterval(-3_600),
            admittedWall.addingTimeInterval(-3_600),
        ])
        let monotonic = CredentialTestInstantClock([
            admittedMonotonic,
            admittedMonotonic,
            admittedMonotonic.advanced(by: .seconds(2)),
        ])
        #expect(throws: NativeCredentialHelperError.consumerTerminationUnproven) {
            try SystemCredentialConsumerSpawner.writeExact(
                Data(repeating: 0x41, count: 8_192),
                to: writeDescriptor,
                before: deadline,
                wallClock: wall.read,
                monotonicClock: monotonic.read
            )
        }
        close(writeDescriptor)
        writeDescriptor = -1
        #expect(try drainPipe(readDescriptor) == capacity)
        close(readDescriptor)
        readDescriptor = -1
    }

    @Test func partialPipeWriteStopsAtOneMonotonicDeadline() throws {
        var descriptors: [Int32] = [0, 0]
        #expect(pipe(&descriptors) == 0)
        var readDescriptor = descriptors[0]
        var writeDescriptor = descriptors[1]
        defer {
            if readDescriptor >= 0 { close(readDescriptor) }
            if writeDescriptor >= 0 { close(writeDescriptor) }
        }
        let capacity = try fillPipe(writeDescriptor)
        let drained = try drainAtMost(
            readDescriptor, count: max(8_192, capacity / 2)
        )
        #expect(drained >= 4_096)
        let admittedWall = Date(timeIntervalSince1970: 2_000_000_000)
        let admittedMonotonic = ContinuousClock.now
        let deadline = try NativeCredentialReleaseDeadline(
            wallExpiresAt: admittedWall.addingTimeInterval(1),
            admittedWallNow: admittedWall,
            admittedMonotonicNow: admittedMonotonic
        )
        let wall = CredentialTestDateClock([
            admittedWall,
            admittedWall.addingTimeInterval(-3_600),
        ])
        let monotonic = CredentialTestInstantClock([
            admittedMonotonic,
            admittedMonotonic.advanced(by: .seconds(2)),
        ])
        let oversized = Data(repeating: 0x42, count: capacity * 4)
        #expect(throws: NativeCredentialHelperError.consumerTerminationUnproven) {
            try SystemCredentialConsumerSpawner.writeExact(
                oversized,
                to: writeDescriptor,
                before: deadline,
                wallClock: wall.read,
                monotonicClock: monotonic.read
            )
        }
        close(writeDescriptor)
        writeDescriptor = -1
        let retained = try drainPipe(readDescriptor)
        #expect(retained > capacity - drained)
        #expect(retained < capacity - drained + oversized.count)
        close(readDescriptor)
        readDescriptor = -1
    }

    @Test func cancellationAfterPartialWriteStopsBeforeRetry() throws {
        var descriptors: [Int32] = [0, 0]
        #expect(pipe(&descriptors) == 0)
        var readDescriptor = descriptors[0]
        var writeDescriptor = descriptors[1]
        defer {
            if readDescriptor >= 0 { close(readDescriptor) }
            if writeDescriptor >= 0 { close(writeDescriptor) }
        }
        let capacity = try fillPipe(writeDescriptor)
        let drained = try drainAtMost(
            readDescriptor, count: max(8_192, capacity / 2)
        )
        let wallNow = Date(timeIntervalSince1970: 2_000_000_000)
        let monotonicNow = ContinuousClock.now
        let deadline = try NativeCredentialReleaseDeadline(
            wallExpiresAt: wallNow.addingTimeInterval(30),
            admittedWallNow: wallNow,
            admittedMonotonicNow: monotonicNow
        )
        let cancellation = CredentialTestCancellation(cancelOnCheck: 3)
        let frame = Data(repeating: 0x43, count: capacity * 4)

        #expect(throws: CancellationError.self) {
            try SystemCredentialConsumerSpawner.writeExact(
                frame,
                to: writeDescriptor,
                before: deadline,
                wallClock: { wallNow },
                monotonicClock: { monotonicNow },
                continuationCheck: cancellation.check
            )
        }
        close(writeDescriptor)
        writeDescriptor = -1
        let retained = try drainPipe(readDescriptor)
        #expect(retained > capacity - drained)
        #expect(retained < capacity - drained + frame.count)
        close(readDescriptor)
        readDescriptor = -1
    }

    private func fillPipe(_ descriptor: Int32) throws -> Int {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(descriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        let bytes = [UInt8](repeating: 0x43, count: 4_096)
        var total = 0
        while true {
            let written = bytes.withUnsafeBytes {
                Darwin.write(descriptor, $0.baseAddress, $0.count)
            }
            if written > 0 {
                total += written
                continue
            }
            guard written < 0, errno == EAGAIN || errno == EWOULDBLOCK,
                  total > 0 else {
                throw NativeCredentialHelperError.consumerLaunchFailed
            }
            return total
        }
    }

    private func drainAtMost(_ descriptor: Int32, count: Int) throws -> Int {
        var bytes = [UInt8](repeating: 0, count: count)
        let result = bytes.withUnsafeMutableBytes {
            Darwin.read(descriptor, $0.baseAddress, $0.count)
        }
        guard result > 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        return result
    }

    private func drainPipe(_ descriptor: Int32) throws -> Int {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        var total = 0
        var bytes = [UInt8](repeating: 0, count: 8_192)
        while true {
            let result = bytes.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if result > 0 {
                total += result
                continue
            }
            if result < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                return total
            }
            guard result == 0 else {
                throw NativeCredentialHelperError.consumerLaunchFailed
            }
            return total
        }
    }

    private func credential(
        savedAt: Date,
        marker: Character = "T"
    ) throws -> StoredOpenAICredentials {
        let value = String(repeating: marker, count: 32)
        let stored = StoredOpenAICredentials(
            schema: StoredOpenAICredentials.schema,
            clientID: "oaiapp_fixture",
            accessToken: value,
            refreshToken: String(repeating: marker, count: 33),
            idToken: String(repeating: marker, count: 34),
            accountSubjectSHA256: digest,
            workspaceSHA256: digest,
            scopeSHA256: digest,
            accessExpiresAt: savedAt.addingTimeInterval(3_600),
            earliestRefreshAt: savedAt.addingTimeInterval(300),
            refreshExpiresAt: savedAt.addingTimeInterval(30 * 24 * 60 * 60),
            savedAt: savedAt
        )
        try stored.validate()
        return stored
    }

    private func makeCoordinator(
        vault: MemoryVault,
        validator: FakeValidator = FakeValidator(refreshResult: .failure(.refreshValidationUnavailable)),
        transport: FakeTransport = FakeTransport()
    ) -> NativeCredentialCoordinator {
        NativeCredentialCoordinator(
            hostIdentity: FakeHostIdentity(),
            callbackReceiver: { FakeReceiver() },
            browser: FakeBrowser(),
            transport: transport,
            validator: validator,
            vault: vault,
            consumer: FakeConsumer()
        )
    }
}

private final class MemoryVault: OpenAICredentialVault, @unchecked Sendable {
    private let lock = NSLock()
    private var value: StoredOpenAICredentials?

    init(_ value: StoredOpenAICredentials?) { self.value = value }
    func load() throws -> StoredOpenAICredentials? { lock.withLock { value } }
    func replace(with credential: StoredOpenAICredentials) throws { lock.withLock { value = credential } }
    func delete() throws { lock.withLock { value = nil } }
}

private struct FakeHostIdentity: NativeHostIdentityProviding {
    func hostID() throws -> String {
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + String(repeating: "A", count: 43)
    }
}

private final class FakeReceiver: AuthorizationCallbackReceiving, @unchecked Sendable {
    func begin() throws -> UInt16 { 49_321 }
    func waitForCallback(deadline: Date) async throws -> URL { throw NativeCredentialHelperError.callbackRejected }
    func cancel() {}
}

private struct FakeBrowser: VisibleBrowserOpening {
    func open(_ url: URL) async throws {}
}

private struct FakeTransport: OpenAIHTTPTransport {
    let revokeError: NativeCredentialHelperError?
    init(revokeError: NativeCredentialHelperError? = nil) { self.revokeError = revokeError }
    func exchangeCode(formBody: Data) async throws -> Data { Data("{}".utf8) }
    func refresh(formBody: Data) async throws -> Data { Data("{}".utf8) }
    func fetchJWKS() async throws -> Data { Data("{}".utf8) }
    func revoke(formBody: Data) async throws {
        if let revokeError { throw revokeError }
    }
}

private final class FakeValidator: OpenAITokenValidating, @unchecked Sendable {
    let refreshResult: Result<StoredOpenAICredentials, NativeCredentialHelperError>
    init(refreshResult: Result<StoredOpenAICredentials, NativeCredentialHelperError>) {
        self.refreshResult = refreshResult
    }
    func validateInitial(
        responseData: Data, exchange: OpenAICodeExchange, jwksData: Data, now: Date
    ) throws -> StoredOpenAICredentials { try refreshResult.get() }
    func validateRefresh(
        responseData: Data, previous: StoredOpenAICredentials, jwksData: Data, now: Date
    ) throws -> StoredOpenAICredentials { try refreshResult.get() }
}

private struct FakeConsumer: CredentialConsumerLaunching {
    func prepare(
        credential: StoredOpenAICredentials,
        request: CredentialProjectionRequest,
        now: Date
    ) async throws -> PreparedCredentialConsumer {
        let launched = LaunchedCredentialConsumer(
            processIdentifier: 42,
            processStartTimeMicroseconds: 123_456_789,
            executableSHA256: String(repeating: "b", count: 64),
            sessionAuthoritySHA256: request.sessionAuthoritySHA256,
            startedAt: now
        )
        return PreparedCredentialConsumer(
            consumer: launched,
            gate: ImmediateCredentialReleaseGate()
        )
    }
}

private struct ImmediateCredentialReleaseGate: NativeCredentialReleaseGating {
    func releaseCredential(
        before deadline: NativeCredentialReleaseDeadline,
        wallClock: @escaping @Sendable () -> Date,
        monotonicClock:
            @escaping @Sendable () -> ContinuousClock.Instant,
        continuationCheck: @escaping @Sendable () throws -> Void
    ) throws { try continuationCheck() }
    func abortWithoutRelease() {}
}

private final class CredentialTestDateClock: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Date]
    private var last: Date
    init(_ values: [Date]) {
        self.values = values
        last = values.last ?? .distantPast
    }
    func read() -> Date {
        lock.withLock {
            if !values.isEmpty { last = values.removeFirst() }
            return last
        }
    }
}

private final class CredentialTestInstantClock: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [ContinuousClock.Instant]
    private var last: ContinuousClock.Instant
    init(_ values: [ContinuousClock.Instant]) {
        self.values = values
        last = values.last ?? ContinuousClock.now
    }
    func read() -> ContinuousClock.Instant {
        lock.withLock {
            if !values.isEmpty { last = values.removeFirst() }
            return last
        }
    }
}

private final class CredentialTestCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private let cancelOnCheck: Int
    private var checks = 0

    init(cancelOnCheck: Int) { self.cancelOnCheck = cancelOnCheck }

    func check() throws {
        let cancelled = lock.withLock {
            checks += 1
            return checks >= cancelOnCheck
        }
        if cancelled { throw CancellationError() }
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
