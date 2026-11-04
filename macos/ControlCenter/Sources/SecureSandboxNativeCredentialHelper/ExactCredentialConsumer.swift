import CryptoKit
import Darwin
import Foundation
import Security

public struct CredentialProjectionRequest: Equatable, Sendable {
    public let operationID: UUID
    public let sessionAuthoritySHA256: String
    public let authorizationReceiptSHA256: String
    public let expiresAt: Date

    public init(
        operationID: UUID,
        sessionAuthoritySHA256: String,
        authorizationReceiptSHA256: String,
        expiresAt: Date
    ) throws {
        self.operationID = operationID
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
        self.authorizationReceiptSHA256 = authorizationReceiptSHA256
        self.expiresAt = expiresAt
        try validateFields()
    }

    func validate(now: Date) throws {
        try validateFields()
        guard expiresAt > now, expiresAt <= now.addingTimeInterval(120) else {
            throw NativeCredentialHelperError.projectionRejected
        }
    }

    private func validateFields() throws {
        guard [sessionAuthoritySHA256, authorizationReceiptSHA256].allSatisfy({
            $0.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
        }), expiresAt.timeIntervalSince1970 > 0 else {
            throw NativeCredentialHelperError.projectionRejected
        }
    }
}

public struct LaunchedCredentialConsumer: Equatable, Sendable {
    public let processIdentifier: Int32
    public let processStartTimeMicroseconds: UInt64
    public let executableSHA256: String
    public let sessionAuthoritySHA256: String
    public let startedAt: Date
}

protocol CredentialConsumerLaunching: Sendable {
    func launch(
        credential: StoredOpenAICredentials,
        request: CredentialProjectionRequest,
        now: Date
    ) async throws -> LaunchedCredentialConsumer
}

struct CredentialConsumerPolicy: Sendable {
    let executableURL: URL
    let executableSHA256: String
    let designatedRequirement: String
    let fixedArguments: [String]

    init(
        executableURL: URL,
        executableSHA256: String,
        designatedRequirement: String,
        fixedArguments: [String]
    ) throws {
        guard executableURL.isFileURL, executableURL.path.hasPrefix("/"),
              executableURL.path != "/", executableURL.path.utf8.count <= 1_024,
              executableSHA256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
              (1...4_096).contains(designatedRequirement.utf8.count),
              fixedArguments.count <= 64,
              fixedArguments.allSatisfy({
                  (1...4_096).contains($0.utf8.count)
                      && $0.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
              }) else {
            throw NativeCredentialHelperError.projectionRejected
        }
        self.executableURL = executableURL
        self.executableSHA256 = executableSHA256
        self.designatedRequirement = designatedRequirement
        self.fixedArguments = fixedArguments
    }
}

final class SystemExactCredentialConsumerLauncher: CredentialConsumerLaunching, @unchecked Sendable {
    private let policy: CredentialConsumerPolicy
    private let lock = NSLock()
    private var usedOperationIDs: [UUID: Date] = [:]

    init(policy: CredentialConsumerPolicy) {
        self.policy = policy
    }

    func launch(
        credential: StoredOpenAICredentials,
        request: CredentialProjectionRequest,
        now: Date
    ) async throws -> LaunchedCredentialConsumer {
        try Task.checkCancellation()
        try request.validate(now: now)
        try credential.validate()
        try reserve(request, now: now)
        do {
            try verifyConsumer()
            var frame = try CredentialProjectionFrame(
                credential: credential,
                request: request
            ).encoded()
            defer { frame.resetBytes(in: 0..<frame.count) }
            let input = Pipe()
            let process = Process()
            process.executableURL = policy.executableURL
            process.arguments = policy.fixedArguments
            process.environment = [
                "HOME": "/var/empty",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            ]
            process.standardInput = input
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            do {
                try Task.checkCancellation()
                try process.run()
                try Task.checkCancellation()
                try input.fileHandleForWriting.write(contentsOf: frame)
                try input.fileHandleForWriting.close()
            } catch {
                process.terminate()
                throw NativeCredentialHelperError.consumerLaunchFailed
            }
            guard case .exact(let processStartTimeMicroseconds) =
                    nativeCredentialProcessIdentity(process.processIdentifier) else {
                try SystemNativeCredentialProjectionTerminator().terminateAndReap(
                    processIdentifier: process.processIdentifier
                )
                throw NativeCredentialHelperError.consumerLaunchFailed
            }
            return LaunchedCredentialConsumer(
                processIdentifier: process.processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds,
                executableSHA256: policy.executableSHA256,
                sessionAuthoritySHA256: request.sessionAuthoritySHA256,
                startedAt: now
            )
        } catch {
            throw error as? NativeCredentialHelperError ?? .projectionRejected
        }
    }

    private func reserve(_ request: CredentialProjectionRequest, now: Date) throws {
        try lock.withLock {
            usedOperationIDs = usedOperationIDs.filter { $0.value > now }
            guard usedOperationIDs[request.operationID] == nil,
                  usedOperationIDs.count < 4_096 else {
                throw NativeCredentialHelperError.projectionRejected
            }
            usedOperationIDs[request.operationID] = request.expiresAt
        }
    }

    private func verifyConsumer() throws {
        try verifyProtectedPath(policy.executableURL.path)
        let digest = try sha256File(policy.executableURL)
        guard digest == policy.executableSHA256 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(policy.executableURL as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { throw NativeCredentialHelperError.projectionRejected }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(policy.designatedRequirement as CFString, [], &requirement)
                == errSecSuccess,
              let requirement else { throw NativeCredentialHelperError.projectionRejected }
        var validationError: Unmanaged<CFError>?
        let flags = SecCSFlags(rawValue:
            kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode
        )
        guard SecStaticCodeCheckValidityWithErrors(staticCode, flags, requirement, &validationError)
                == errSecSuccess else {
            throw NativeCredentialHelperError.projectionRejected
        }
    }

    private func verifyProtectedPath(_ path: String) throws {
        var current = path
        var isLeaf = true
        while current != "/" {
            var info = stat()
            guard lstat(current, &info) == 0,
                  info.st_uid == 0,
                  info.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0,
                  isLeaf ? (info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG))
                         : (info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)) else {
                throw NativeCredentialHelperError.projectionRejected
            }
            isLeaf = false
            current = URL(fileURLWithPath: current).deletingLastPathComponent().path
        }
    }

    private func sha256File(_ url: URL) throws -> String {
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: url) }
        catch { throw NativeCredentialHelperError.projectionRejected }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk: Data
            do { chunk = try handle.read(upToCount: 1_048_576) ?? Data() }
            catch { throw NativeCredentialHelperError.projectionRejected }
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

private struct CredentialProjectionFrame: Encodable {
    static let schema = "secure-sandbox-credential-projection-v1"

    let schema = Self.schema
    let provider = "openai-chatgpt-plan"
    let operationID: UUID
    let sessionAuthoritySHA256: String
    let authorizationReceiptSHA256: String
    let clientID: String
    let accountSubjectSHA256: String
    let accessExpiresAt: Date
    let accessToken: String

    init(credential: StoredOpenAICredentials, request: CredentialProjectionRequest) throws {
        operationID = request.operationID
        sessionAuthoritySHA256 = request.sessionAuthoritySHA256
        authorizationReceiptSHA256 = request.authorizationReceiptSHA256
        clientID = credential.clientID
        accountSubjectSHA256 = credential.accountSubjectSHA256
        accessExpiresAt = credential.accessExpiresAt
        accessToken = credential.accessToken
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let payload = try encoder.encode(self)
        guard payload.count <= 131_072 else { throw NativeCredentialHelperError.projectionRejected }
        var frame = Data()
        var length = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(payload)
        return frame
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
