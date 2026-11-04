import CryptoKit
import Darwin
import Foundation
import Security
import SecureSandboxNativeXPCTransport

struct NativeCredentialXPCSigningPolicy: Equatable, Sendable {
    static let serviceBundleIdentifier = "org.zebeth.SecureSandbox.NativeCredentialHelper"
    static let callerBundleIdentifier = "org.zebeth.SecureSandbox.NativeStackBackend"
    static let consumerBundleIdentifier =
        "org.zebeth.SecureSandbox.NativeProjectionConsumer"

    let teamIdentifier: String
    let callerRequirement: String
    let callerRequirementSHA256: String

    static func resolveCurrentService() throws -> Self {
        var code: SecCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess,
              let code,
              SecCodeCopySigningInformation(
                  // The C API accepts a live SecCode, but Swift exposes only
                  // its layout-compatible SecStaticCode parameter wrapper.
                  unsafeBitCast(code, to: SecStaticCode.self),
                  SecCSFlags(rawValue:
                      kSecCSSigningInformation | kSecCSDynamicInformation
                  ),
                  &information
              ) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == serviceBundleIdentifier,
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
              let status = values[kSecCodeInfoStatus as String] as? NSNumber,
              status.uint32Value & 0x0001_0000 != 0 else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        let policy = try make(teamIdentifier: team)
        var requirement: SecRequirement?
        let ownRequirement = try designatedRequirement(
            bundleIdentifier: serviceBundleIdentifier,
            teamIdentifier: team
        )
        guard SecRequirementCreateWithString(
                  ownRequirement as CFString, [], &requirement
              ) == errSecSuccess,
              let requirement,
              SecCodeCheckValidityWithErrors(
                  code,
                  SecCSFlags(rawValue:
                      kSecCSStrictValidate
                          | kSecCSCheckAllArchitectures
                          | kSecCSCheckNestedCode
                          // Public C constant omitted by Swift's importer.
                          | (1 << 23)
                  ),
                  requirement,
                  nil
              ) == errSecSuccess else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        return policy
    }

    static func make(teamIdentifier: String) throws -> Self {
        guard teamIdentifier.range(
            of: #"^[A-Z0-9]{10}$"#,
            options: .regularExpression
        ) != nil else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        let requirement = try designatedRequirement(
            bundleIdentifier: callerBundleIdentifier,
            teamIdentifier: teamIdentifier
        )
        let digest = SHA256.hash(data: Data(requirement.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        return Self(
            teamIdentifier: teamIdentifier,
            callerRequirement: requirement,
            callerRequirementSHA256: digest
        )
    }

    static func serviceRequirement(teamIdentifier: String) throws -> String {
        guard teamIdentifier.range(
            of: #"^[A-Z0-9]{10}$"#,
            options: .regularExpression
        ) != nil else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        return try designatedRequirement(
            bundleIdentifier: serviceBundleIdentifier,
            teamIdentifier: teamIdentifier
        )
    }

    static func consumerRequirement(teamIdentifier: String) throws -> String {
        guard teamIdentifier.range(
            of: #"^[A-Z0-9]{10}$"#,
            options: .regularExpression
        ) != nil else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        return try designatedRequirement(
            bundleIdentifier: consumerBundleIdentifier,
            teamIdentifier: teamIdentifier
        )
    }

    private static func designatedRequirement(
        bundleIdentifier: String,
        teamIdentifier: String
    ) throws -> String {
        guard [bundleIdentifier, teamIdentifier].allSatisfy({
            !$0.isEmpty && $0.utf8.count <= 255
                && $0.unicodeScalars.allSatisfy {
                    !CharacterSet.controlCharacters.contains($0)
                }
        }) else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        return "identifier \"\(requirementLiteral(bundleIdentifier))\" "
            + "and anchor apple generic "
            + "and certificate leaf[subject.OU] = \"\(requirementLiteral(teamIdentifier))\" "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    }

    private static func requirementLiteral(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}

private struct RejectAllAuditTokenCallers: NativeCredentialCallerIdentityValidating {
    func validate(_ evidence: CallerAuditEvidence) throws {
        throw NativeCredentialXPCError.callerIdentityRejected
    }
}

private struct NativeXPCRequestHandle: @unchecked Sendable {
    let rawValue: SSNativeXPCRequestRef
    var key: UInt { UInt(bitPattern: rawValue) }
}

private struct NativeXPCRequestCancellation: NativeCredentialCancellationChecking {
    let handle: NativeXPCRequestHandle

    func checkCancellation() throws {
        try Task.checkCancellation()
        guard !ss_native_xpc_request_is_cancelled(handle.rawValue) else {
            throw CancellationError()
        }
    }
}

private final class NativeCredentialXPCTaskRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var tasks: [UInt: Task<Void, Never>] = [:]

    func start(
        for handle: NativeXPCRequestHandle,
        operation: @escaping @Sendable () async -> Void
    ) -> Bool {
        // Create and publish the task while holding the same lock used by
        // cancellation and completion.  A very short request can otherwise
        // finish and remove itself before a later insert, leaving a completed
        // task retained forever and making peer cancellation ambiguous.
        lock.lock()
        guard tasks[handle.key] == nil else {
            lock.unlock()
            return false
        }
        let task = Task { await operation() }
        tasks[handle.key] = task
        lock.unlock()
        if ss_native_xpc_request_is_cancelled(handle.rawValue) {
            task.cancel()
        }
        return true
    }

    func cancel(_ handle: NativeXPCRequestHandle) {
        lock.withLock { tasks[handle.key] }?.cancel()
    }

    func remove(_ handle: NativeXPCRequestHandle) {
        _ = lock.withLock { tasks.removeValue(forKey: handle.key) }
    }
}

private final class NativeCredentialXPCServerContext: @unchecked Sendable {
    let service: NativeCredentialXPCServiceCore
    let proof: NativeCredentialXPCPeerRequirementProof
    let tasks = NativeCredentialXPCTaskRegistry()

    init(
        service: NativeCredentialXPCServiceCore,
        proof: NativeCredentialXPCPeerRequirementProof
    ) {
        self.service = service
        self.proof = proof
    }

    func receive(
        handle: NativeXPCRequestHandle,
        bytes: UnsafePointer<UInt8>?,
        length: Int,
        projectionFD: Int32
    ) {
        let requestData: Data
        if let bytes, length > 0, length <= NativeCredentialIPCRequest.maximumBytes {
            requestData = Data(bytes: bytes, count: length)
        } else {
            requestData = Data()
        }
        let started = tasks.start(for: handle) { [service, proof, tasks] in
            defer {
                if projectionFD >= 0 { Darwin.close(projectionFD) }
                tasks.remove(handle)
                ss_native_xpc_request_release(handle.rawValue)
            }
            let reply = await service.handleSystemXPC(
                requestData: requestData,
                proof: proof,
                projectionFD: projectionFD,
                cancellation: NativeXPCRequestCancellation(handle: handle)
            )
            guard !Task.isCancelled,
                  !ss_native_xpc_request_is_cancelled(handle.rawValue) else {
                return
            }
            reply.withUnsafeBytes { buffer in
                guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return }
                _ = ss_native_xpc_request_reply(handle.rawValue, base, buffer.count)
            }
        }
        if !started {
            if projectionFD >= 0 { Darwin.close(projectionFD) }
            ss_native_xpc_request_release(handle.rawValue)
        }
    }
}

private let nativeCredentialRequestHandler: SSNativeXPCRequestHandler = {
    request, bytes, length, projectionFD, context in
    guard let request, let context else { return }
    let server = Unmanaged<NativeCredentialXPCServerContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    server.receive(
        handle: NativeXPCRequestHandle(rawValue: request),
        bytes: bytes,
        length: length,
        projectionFD: projectionFD
    )
}

private let nativeCredentialCancellationHandler: SSNativeXPCCancellationHandler = {
    request, context in
    guard let request, let context else { return }
    let server = Unmanaged<NativeCredentialXPCServerContext>
        .fromOpaque(context)
        .takeUnretainedValue()
    server.tasks.cancel(NativeXPCRequestHandle(rawValue: request))
}

public enum SecureSandboxNativeCredentialXPCServiceMain {
    public static func run() -> Int32 {
        do {
            let signingPolicy = try NativeCredentialXPCSigningPolicy.resolveCurrentService()
            let proof = try NativeCredentialXPCPeerRequirementProof(
                requirementSHA256: signingPolicy.callerRequirementSHA256
            )
            let consumer: any CredentialConsumerLaunching =
                SystemExactCredentialConsumerLauncher(policyProvider: {
                    authority in
                    try RootOwnedNativeProjectionConsumerResolver.resolve(
                        authority: authority,
                        teamIdentifier: signingPolicy.teamIdentifier
                    )
                })
            let coordinator = NativeCredentialCoordinator(
                hostIdentity: SecureEnclaveHostIdentityStore(),
                callbackReceiver: { DarwinLoopbackAuthorizationReceiver() },
                browser: SystemVisibleBrowser(),
                transport: OpenAIFixedOriginHTTPClient(),
                validator: CoreOpenAITokenValidator(),
                vault: DataProtectionKeychainOpenAIVault(),
                consumer: consumer
            )
            let service = NativeCredentialXPCServiceCore(
                callerValidator: RejectAllAuditTokenCallers(),
                ticketReader: RootOwnedNativeAuthorizationTicketReader(),
                replayStore: DataProtectionKeychainTicketReplayStore(),
                coordinator: coordinator,
                custodyLedger: DataProtectionKeychainNativeCredentialCustodyLedger(),
                expectedXPCPeerRequirementSHA256: signingPolicy.callerRequirementSHA256
            )
            let server = NativeCredentialXPCServerContext(service: service, proof: proof)
            let context = Unmanaged.passRetained(server).toOpaque()
            let result = ss_native_xpc_server_run(
                NativeCredentialXPCSigningPolicy.serviceBundleIdentifier,
                signingPolicy.callerRequirement,
                nativeCredentialRequestHandler,
                nativeCredentialCancellationHandler,
                context
            )
            Unmanaged<NativeCredentialXPCServerContext>
                .fromOpaque(context)
                .release()
            return result
        } catch {
            // No listener is created unless the running service itself has the
            // exact Developer ID identity and hardened-runtime signature.
            return 78
        }
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
