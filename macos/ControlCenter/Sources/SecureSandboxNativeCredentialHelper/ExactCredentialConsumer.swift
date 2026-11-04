import CryptoKit
import Darwin
import Foundation
import Security

public struct CredentialProjectionRequest: Equatable, Sendable {
    public let operationID: UUID
    public let sessionAuthoritySHA256: String
    public let authorizationReceiptSHA256: String
    public let expiresAt: Date
    public let projectionChannelFD: Int32

    public init(
        operationID: UUID,
        sessionAuthoritySHA256: String,
        authorizationReceiptSHA256: String,
        expiresAt: Date,
        projectionChannelFD: Int32
    ) throws {
        self.operationID = operationID
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
        self.authorizationReceiptSHA256 = authorizationReceiptSHA256
        self.expiresAt = expiresAt
        self.projectionChannelFD = projectionChannelFD
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
        }), expiresAt.timeIntervalSince1970 > 0,
            projectionChannelFD >= 0 else {
            throw NativeCredentialHelperError.projectionRejected
        }
    }
}

struct NativeCredentialConsumerTerminationEvidence: Equatable, Sendable {
    let operationID: UUID
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let sessionAuthoritySHA256: String
}

protocol NativeCredentialConsumerTerminationAwaiting: Sendable {
    func waitForTermination() async throws
        -> NativeCredentialConsumerTerminationEvidence
    func terminateAndReap() async throws
}

extension NativeCredentialConsumerTerminationAwaiting {
    func terminateAndReap() async throws {
        throw NativeCredentialHelperError.consumerTerminationUnproven
    }
}

public struct LaunchedCredentialConsumer: Equatable, Sendable {
    public let processIdentifier: Int32
    public let processStartTimeMicroseconds: UInt64
    public let executableSHA256: String
    public let sessionAuthoritySHA256: String
    public let startedAt: Date
    let termination: (any NativeCredentialConsumerTerminationAwaiting)?

    init(
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        executableSHA256: String,
        sessionAuthoritySHA256: String,
        startedAt: Date,
        termination: (any NativeCredentialConsumerTerminationAwaiting)? = nil
    ) {
        self.processIdentifier = processIdentifier
        self.processStartTimeMicroseconds = processStartTimeMicroseconds
        self.executableSHA256 = executableSHA256
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
        self.startedAt = startedAt
        self.termination = termination
    }

    public static func == (
        lhs: LaunchedCredentialConsumer,
        rhs: LaunchedCredentialConsumer
    ) -> Bool {
        lhs.processIdentifier == rhs.processIdentifier
            && lhs.processStartTimeMicroseconds
                == rhs.processStartTimeMicroseconds
            && lhs.executableSHA256 == rhs.executableSHA256
            && lhs.sessionAuthoritySHA256 == rhs.sessionAuthoritySHA256
            && lhs.startedAt == rhs.startedAt
    }
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
    private let policyProvider: @Sendable () throws -> CredentialConsumerPolicy
    private let lock = NSLock()
    private var usedOperationIDs: [UUID: Date] = [:]

    init(
        policyProvider: @escaping @Sendable () throws -> CredentialConsumerPolicy
    ) {
        self.policyProvider = policyProvider
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
            let policy = try policyProvider()
            try verifyConsumer(policy)
            var frame = try CredentialProjectionFrame(
                credential: credential,
                request: request
            ).encoded()
            defer { frame.resetBytes(in: 0..<frame.count) }
            var inputDescriptors: [Int32] = [0, 0]
            guard pipe(&inputDescriptors) == 0,
                  fcntl(inputDescriptors[0], F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(inputDescriptors[1], F_SETFD, FD_CLOEXEC) == 0 else {
                if inputDescriptors[0] > 0 { close(inputDescriptors[0]) }
                if inputDescriptors[1] > 0 { close(inputDescriptors[1]) }
                throw NativeCredentialHelperError.consumerLaunchFailed
            }
            var inputRead = inputDescriptors[0]
            var inputWrite = inputDescriptors[1]
            defer {
                if inputRead >= 0 { close(inputRead) }
                if inputWrite >= 0 { close(inputWrite) }
            }
            let environment = [
                "HOME": "/var/empty",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            ]
            var child: SystemOwnedCredentialConsumerProcess?
            var processIdentifier: Int32 = 0
            var credentialDeliveryBegan = false
            do {
                try Task.checkCancellation()
                processIdentifier = try SystemCredentialConsumerSpawner.spawn(
                    executableURL: policy.executableURL,
                    arguments: policy.fixedArguments,
                    environment: environment,
                    standardInput: inputRead,
                    standardOutput: request.projectionChannelFD
                )
                close(inputRead)
                inputRead = -1
                guard case .exact(let observedStart) =
                        nativeCredentialProcessIdentity(
                            processIdentifier
                        ) else {
                    throw NativeCredentialHelperError.consumerLaunchFailed
                }
                child = SystemOwnedCredentialConsumerProcess(
                    processIdentifier: processIdentifier,
                    processStartTimeMicroseconds: observedStart
                )
                try Task.checkCancellation()
                credentialDeliveryBegan = true
                try SystemCredentialConsumerSpawner.writeExact(
                    frame, to: inputWrite
                )
                close(inputWrite)
                inputWrite = -1
            } catch {
                if inputWrite >= 0 {
                    close(inputWrite)
                    inputWrite = -1
                }
                if let child {
                    do { try child.terminateAndReap() }
                    catch {
                        throw NativeCredentialHelperError
                            .consumerTerminationUnproven
                    }
                } else if processIdentifier > 0 {
                    do {
                        try SystemCredentialConsumerSpawner
                            .terminateUnidentifiedDirectChild(
                                processIdentifier
                            )
                    } catch {
                        throw NativeCredentialHelperError
                            .consumerTerminationUnproven
                    }
                }
                if credentialDeliveryBegan {
                    throw NativeCredentialHelperError
                        .consumerTerminationUnproven
                }
                throw NativeCredentialHelperError.consumerLaunchFailed
            }
            guard let child else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            return LaunchedCredentialConsumer(
                processIdentifier: child.processIdentifier,
                processStartTimeMicroseconds:
                    child.processStartTimeMicroseconds,
                executableSHA256: policy.executableSHA256,
                sessionAuthoritySHA256: request.sessionAuthoritySHA256,
                startedAt: now,
                termination: SystemExactCredentialConsumerTermination(
                    child: child,
                    operationID: request.operationID,
                    sessionAuthoritySHA256: request.sessionAuthoritySHA256
                )
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

    private func verifyConsumer(_ policy: CredentialConsumerPolicy) throws {
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

final class SystemExactCredentialConsumerTermination:
    NativeCredentialConsumerTerminationAwaiting, @unchecked Sendable
{
    private let child: SystemOwnedCredentialConsumerProcess
    private let operationID: UUID
    private let sessionAuthoritySHA256: String
    private let lock = NSLock()
    private var waitStarted = false

    init(
        child: SystemOwnedCredentialConsumerProcess,
        operationID: UUID,
        sessionAuthoritySHA256: String
    ) {
        self.child = child
        self.operationID = operationID
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
    }

    func waitForTermination() async throws
        -> NativeCredentialConsumerTerminationEvidence
    {
        try lock.withLock {
            guard !waitStarted,
                  NativeAuthorizationTicket.isUUID4(
                      operationID.uuidString.lowercased()
                  ),
                  child.processIdentifier > 0,
                  child.processStartTimeMicroseconds > 0,
                  NativeAuthorizationTicket.isSHA256(
                      sessionAuthoritySHA256
                  ) else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            waitStarted = true
        }
        let status = try await Task.detached(priority: .utility) {
            try self.child.waitForExitStatus()
        }.value
        guard status & 0x7f == 0,
              (status >> 8) & 0xff == 0 else {
            throw NativeCredentialHelperError.consumerTerminationUnproven
        }
        return NativeCredentialConsumerTerminationEvidence(
            operationID: operationID,
            processIdentifier: child.processIdentifier,
            processStartTimeMicroseconds:
                child.processStartTimeMicroseconds,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )
    }

    func terminateAndReap() async throws {
        try lock.withLock {
            guard !waitStarted else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            waitStarted = true
        }
        try await Task.detached(priority: .utility) {
            try self.child.terminateAndReap()
        }.value
    }
}

private struct CredentialProjectionFrame {
    static let magic = Data("SSHPRJ1\n".utf8)

    let operationID: UUID
    let sessionAuthoritySHA256: String
    let authorizationReceiptSHA256: String
    let accessExpiresAt: Date
    let accessToken: String

    init(credential: StoredOpenAICredentials, request: CredentialProjectionRequest) throws {
        operationID = request.operationID
        sessionAuthoritySHA256 = request.sessionAuthoritySHA256
        authorizationReceiptSHA256 = request.authorizationReceiptSHA256
        accessExpiresAt = credential.accessExpiresAt
        accessToken = credential.accessToken
    }

    func encoded() throws -> Data {
        let operation = Data(operationID.uuidString.lowercased().utf8)
        let session = Data(sessionAuthoritySHA256.utf8)
        let receipt = Data(authorizationReceiptSHA256.utf8)
        var token = Data(accessToken.utf8)
        defer { token.resetBytes(in: 0..<token.count) }
        guard operation.count == 36, session.count == 64, receipt.count == 64,
              (16...65_536).contains(token.count),
              token.allSatisfy({ (0x21...0x7e).contains($0) }),
              accessExpiresAt.timeIntervalSince1970 > 0 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        var frame = Self.magic
        frame.append(operation)
        frame.append(session)
        frame.append(receipt)
        var expiry = UInt64(
            accessExpiresAt.timeIntervalSince1970 * 1_000
        ).bigEndian
        withUnsafeBytes(of: &expiry) { frame.append(contentsOf: $0) }
        var length = UInt32(token.count).bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(token)
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
