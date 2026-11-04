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
        let request = try CredentialProjectionRequest(
            operationID: UUID(), sessionAuthoritySHA256: digest,
            authorizationReceiptSHA256: digest,
            expiresAt: Date().addingTimeInterval(30), projectionChannelFD: 1
        )
        #expect(request.sessionAuthoritySHA256 == digest)
        let overlong = try CredentialProjectionRequest(
                operationID: UUID(), sessionAuthoritySHA256: digest,
                authorizationReceiptSHA256: digest,
                expiresAt: Date().addingTimeInterval(300), projectionChannelFD: 1
        )
        #expect(throws: NativeCredentialHelperError.projectionRejected) {
            try overlong.validate(now: Date())
        }
    }

    @Test func projectionPolicyRequiresRootShapeReleaseAndResearchAttestation() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "native-projection-policy-\(UUID().uuidString)", isDirectory: true
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
        let release = String(repeating: "a", count: 64)
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
        let body: [String: Any] = [
            "executable_path": executable.path,
            "executable_sha256": String(repeating: "b", count: 64),
            "host_release_id": release,
            "research_release_id": String(repeating: "c", count: 64),
            "research_isolation_attestation_sha256": String(repeating: "d", count: 64),
        ]
        var canonicalBody = try JSONSerialization.data(
            withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes]
        )
        canonicalBody.append(0x0a)
        var document = body
        document["schema"] = RootOwnedNativeProjectionPolicy.schemaName
        document["policy_sha256"] = SHA256.hash(data: canonicalBody)
            .map { String(format: "%02x", $0) }.joined()
        var encoded = try JSONSerialization.data(
            withJSONObject: document,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        encoded.append(0x0a)
        let policy = root.appendingPathComponent("native-projection-policy.json")
        try encoded.write(to: policy)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o444], ofItemAtPath: policy.path
        )
        let observedAt = Int64(now.timeIntervalSince1970)
        let readbackBody: [String: Any] = [
            "research_release_id": String(repeating: "c", count: 64),
            "research_isolation_attestation_sha256": String(repeating: "d", count: 64),
            "observed_at": observedAt,
            "expires_at": observedAt + 120,
        ]
        var canonicalReadbackBody = try JSONSerialization.data(
            withJSONObject: readbackBody,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        canonicalReadbackBody.append(0x0a)
        var readbackDocument = readbackBody
        readbackDocument["schema"] = RootOwnedNativeResearchProjectionReadback.schemaName
        readbackDocument["readback_sha256"] = SHA256.hash(data: canonicalReadbackBody)
            .map { String(format: "%02x", $0) }.joined()
        var encodedReadback = try JSONSerialization.data(
            withJSONObject: readbackDocument,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        encodedReadback.append(0x0a)
        let researchReadback = root.appendingPathComponent(
            "native-research-projection-readback.json"
        )
        try encodedReadback.write(to: researchReadback)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o444], ofItemAtPath: researchReadback.path
        )
        let loaded = try RootOwnedNativeProjectionPolicy.load(
            url: policy, releaseRoot: releases, currentURL: current,
            researchReadbackURL: researchReadback,
            teamIdentifier: "ABCDE" + "FGHIJ", now: now,
            expectedOwner: geteuid(),
            expectedGroup: getegid()
        )
        #expect(loaded.executableURL == executable)
        #expect(loaded.executableSHA256 == String(repeating: "b", count: 64))

        let readbackTarget = root.appendingPathComponent("readback-target.json")
        try encodedReadback.write(to: readbackTarget)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o444], ofItemAtPath: readbackTarget.path
        )
        try FileManager.default.removeItem(at: researchReadback)
        try FileManager.default.createSymbolicLink(
            at: researchReadback, withDestinationURL: readbackTarget
        )
        #expect(throws: (any Error).self) {
            try RootOwnedNativeProjectionPolicy.load(
                url: policy, releaseRoot: releases, currentURL: current,
                researchReadbackURL: researchReadback,
                teamIdentifier: "ABCDE" + "FGHIJ", now: now,
                expectedOwner: geteuid(), expectedGroup: getegid()
            )
        }
        try FileManager.default.removeItem(at: researchReadback)
        try encodedReadback.write(to: researchReadback)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o444], ofItemAtPath: researchReadback.path
        )

        #expect(throws: (any Error).self) {
            try RootOwnedNativeProjectionPolicy.load(
                url: policy, releaseRoot: releases, currentURL: current,
                researchReadbackURL: researchReadback,
                teamIdentifier: "ABCDE" + "FGHIJ",
                now: now.addingTimeInterval(121),
                expectedOwner: geteuid(), expectedGroup: getegid()
            )
        }

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: policy.path
        )
        #expect(throws: (any Error).self) {
            try RootOwnedNativeProjectionPolicy.load(
                url: policy, releaseRoot: releases, currentURL: current,
                researchReadbackURL: researchReadback,
                teamIdentifier: "ABCDE" + "FGHIJ", now: now,
                expectedOwner: geteuid(),
                expectedGroup: getegid()
            )
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
    func launch(
        credential: StoredOpenAICredentials,
        request: CredentialProjectionRequest,
        now: Date
    ) async throws -> LaunchedCredentialConsumer {
        LaunchedCredentialConsumer(
            processIdentifier: 42,
            processStartTimeMicroseconds: 123_456_789,
            executableSHA256: String(repeating: "b", count: 64),
            sessionAuthoritySHA256: request.sessionAuthoritySHA256,
            startedAt: now
        )
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
