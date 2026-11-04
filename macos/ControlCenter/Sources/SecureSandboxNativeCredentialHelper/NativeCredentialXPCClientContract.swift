import Darwin
import Foundation
import SecureSandboxNativeXPCTransport

public enum NativeCredentialXPCClientError: Error, Equatable, Sendable {
    case invalidRequest
    case invalidTeamIdentifier
    case transportUnavailable
    case replyRejected
}

public struct NativeCredentialXPCClientProjection: Equatable, Sendable {
    public let processIdentifier: Int32
    public let processStartTimeMicroseconds: UInt64
    public let executableSHA256: String
    public let sessionAuthoritySHA256: String
    public let startedAtMilliseconds: Int64
}

public struct NativeCredentialXPCClientReply: Equatable, Sendable {
    public let operationID: UUID?
    public let verified: Bool
    public let status: NativeCredentialStatus?
    public let projection: NativeCredentialXPCClientProjection?
    public let errorCode: String?
    public let responseSHA256: String
}

public struct NativeCredentialXPCClientReconciliationReply:
    Equatable, Sendable
{
    public let verified: Bool
    public let recoveryOperationID: UUID?
    public let originalOperationID: UUID?
    public let processIdentifier: Int32?
    public let processStartTimeMicroseconds: UInt64?
    public let consumerExecutableSHA256: String?
    public let sessionAuthoritySHA256: String?
    public let reconciliationEvidenceSHA256: String?
    public let errorCode: String?
    public let replySHA256: String
}

public struct NativeCredentialXPCClientProjectionIdentityReply:
    Equatable, Sendable
{
    public let verified: Bool
    public let recoveryOperationID: UUID?
    public let originalOperationID: UUID?
    public let processIdentifier: Int32?
    public let processStartTimeMicroseconds: UInt64?
    public let consumerExecutableSHA256: String?
    public let sessionAuthoritySHA256: String?
    public let identityEvidenceSHA256: String?
    public let errorCode: String?
    public let replySHA256: String
}

public enum NativeCredentialXPCClientContract {
    public static let serviceName = "org.zebeth.SecureSandbox.NativeCredentialHelper"
    public static let requiredCallerBundleIdentifier =
        "org.zebeth.SecureSandbox.NativeStackBackend"
    public static let maximumDataBytes = 32 * 1024

    public static func encodeRequest(
        operationID: UUID,
        operation: NativeCredentialOperation,
        authorizationTicketID: String? = nil,
        planSHA256: String? = nil,
        operatorRequestSHA256: String? = nil,
        stackSHA256: String? = nil,
        sessionAuthoritySHA256: String? = nil,
        authorizationReceiptSHA256: String? = nil,
        projectionAuthority: NativeCredentialProjectionAuthority? = nil
    ) throws -> Data {
        do {
            let command = try NativeCredentialCommand(
                operationID: operationID,
                operation: operation,
                provider: .openAIChatGPT,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                authorizationReceiptSHA256: authorizationReceiptSHA256
            )
            return try NativeCredentialIPCRequest(
                command: command,
                authorizationTicketID: authorizationTicketID,
                planSHA256: planSHA256,
                operatorRequestSHA256: operatorRequestSHA256,
                stackSHA256: stackSHA256,
                projectionAuthority: projectionAuthority
            ).encoded()
        } catch {
            throw NativeCredentialXPCClientError.invalidRequest
        }
    }

    public static func decodeReply(_ data: Data) throws -> NativeCredentialXPCClientReply {
        do {
            let reply = try NativeCredentialIPCReply.decodeExact(data)
            return NativeCredentialXPCClientReply(
                operationID: reply.operationID.flatMap(UUID.init(uuidString:)),
                verified: reply.outcome == .verified,
                status: reply.status,
                projection: reply.projection.map {
                    NativeCredentialXPCClientProjection(
                        processIdentifier: $0.processIdentifier,
                        processStartTimeMicroseconds: $0.processStartTimeMicroseconds,
                        executableSHA256: $0.executableSHA256,
                        sessionAuthoritySHA256: $0.sessionAuthoritySHA256,
                        startedAtMilliseconds: $0.startedAtMilliseconds
                    )
                },
                errorCode: reply.errorCode?.rawValue,
                responseSHA256: reply.responseSHA256
            )
        } catch {
            throw NativeCredentialXPCClientError.replyRejected
        }
    }

    public static func encodeProjectionReconciliationRequest(
        ticketID: UUID,
        recoveryOperationID: UUID,
        originalOperationID: UUID,
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        consumerExecutableSHA256: String,
        sessionAuthoritySHA256: String,
        stackSHA256: String,
        recoveryPlanSHA256: String,
        guestAbsenceEvidenceSHA256: String,
        egressClosedEvidenceSHA256: String,
        hostReleaseID: String,
        recoveryRequestSHA256: String,
        recoveryReceiptSHA256: String
    ) throws -> Data {
        do {
            return try NativeProjectionReconciliationIPCRequest(
                ticketID: ticketID,
                recoveryOperationID: recoveryOperationID,
                originalOperationID: originalOperationID,
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds,
                consumerExecutableSHA256: consumerExecutableSHA256,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                stackSHA256: stackSHA256,
                recoveryPlanSHA256: recoveryPlanSHA256,
                guestAbsenceEvidenceSHA256: guestAbsenceEvidenceSHA256,
                egressClosedEvidenceSHA256: egressClosedEvidenceSHA256,
                hostReleaseID: hostReleaseID,
                recoveryRequestSHA256: recoveryRequestSHA256,
                recoveryReceiptSHA256: recoveryReceiptSHA256
            ).encoded()
        } catch {
            throw NativeCredentialXPCClientError.invalidRequest
        }
    }

    public static func decodeProjectionReconciliationReply(
        _ data: Data
    ) throws -> NativeCredentialXPCClientReconciliationReply {
        if let reply = try? NativeProjectionReconciliationIPCReply
            .decodeExact(data) {
            return NativeCredentialXPCClientReconciliationReply(
                verified: true,
                recoveryOperationID: UUID(
                    uuidString: reply.recoveryOperationID
                ),
                originalOperationID: UUID(
                    uuidString: reply.originalOperationID
                ),
                processIdentifier: reply.processIdentifier,
                processStartTimeMicroseconds:
                    reply.processStartTimeMicroseconds,
                consumerExecutableSHA256: reply.consumerExecutableSHA256,
                sessionAuthoritySHA256: reply.sessionAuthoritySHA256,
                reconciliationEvidenceSHA256:
                    reply.reconciliationEvidenceSHA256,
                errorCode: nil,
                replySHA256: reply.replySHA256
            )
        }
        do {
            let failure = try NativeCredentialIPCReply.decodeExact(data)
            guard failure.outcome == .rejected else {
                throw NativeCredentialXPCClientError.replyRejected
            }
            return NativeCredentialXPCClientReconciliationReply(
                verified: false,
                recoveryOperationID: failure.operationID.flatMap(
                    UUID.init(uuidString:)
                ),
                originalOperationID: nil,
                processIdentifier: nil,
                processStartTimeMicroseconds: nil,
                consumerExecutableSHA256: nil,
                sessionAuthoritySHA256: nil,
                reconciliationEvidenceSHA256: nil,
                errorCode: failure.errorCode?.rawValue,
                replySHA256: failure.responseSHA256
            )
        } catch {
            throw NativeCredentialXPCClientError.replyRejected
        }
    }

    public static func encodeProjectionIdentityRecoveryRequest(
        ticketID: UUID,
        recoveryOperationID: UUID,
        originalOperationID: UUID,
        sessionAuthoritySHA256: String,
        stackSHA256: String,
        recoveryPlanSHA256: String,
        hostReleaseID: String,
        recoveryRequestSHA256: String,
        recoveryReceiptSHA256: String
    ) throws -> Data {
        do {
            return try NativeProjectionIdentityRecoveryIPCRequest(
                ticketID: ticketID,
                recoveryOperationID: recoveryOperationID,
                originalOperationID: originalOperationID,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                stackSHA256: stackSHA256,
                recoveryPlanSHA256: recoveryPlanSHA256,
                hostReleaseID: hostReleaseID,
                recoveryRequestSHA256: recoveryRequestSHA256,
                recoveryReceiptSHA256: recoveryReceiptSHA256
            ).encoded()
        } catch {
            throw NativeCredentialXPCClientError.invalidRequest
        }
    }

    public static func decodeProjectionIdentityRecoveryReply(
        _ data: Data
    ) throws -> NativeCredentialXPCClientProjectionIdentityReply {
        if let reply = try? NativeProjectionIdentityRecoveryIPCReply
            .decodeExact(data) {
            return NativeCredentialXPCClientProjectionIdentityReply(
                verified: true,
                recoveryOperationID: UUID(
                    uuidString: reply.recoveryOperationID
                ),
                originalOperationID: UUID(
                    uuidString: reply.originalOperationID
                ),
                processIdentifier: reply.processIdentifier,
                processStartTimeMicroseconds:
                    reply.processStartTimeMicroseconds,
                consumerExecutableSHA256: reply.consumerExecutableSHA256,
                sessionAuthoritySHA256: reply.sessionAuthoritySHA256,
                identityEvidenceSHA256: reply.identityEvidenceSHA256,
                errorCode: nil,
                replySHA256: reply.replySHA256
            )
        }
        do {
            let failure = try NativeCredentialIPCReply.decodeExact(data)
            guard failure.outcome == .rejected else {
                throw NativeCredentialXPCClientError.replyRejected
            }
            return NativeCredentialXPCClientProjectionIdentityReply(
                verified: false,
                recoveryOperationID: failure.operationID.flatMap(
                    UUID.init(uuidString:)
                ),
                originalOperationID: nil,
                processIdentifier: nil,
                processStartTimeMicroseconds: nil,
                consumerExecutableSHA256: nil,
                sessionAuthoritySHA256: nil,
                identityEvidenceSHA256: nil,
                errorCode: failure.errorCode?.rawValue,
                replySHA256: failure.responseSHA256
            )
        } catch {
            throw NativeCredentialXPCClientError.replyRejected
        }
    }

    public static func serviceDesignatedRequirement(
        teamIdentifier: String
    ) throws -> String {
        do {
            return try NativeCredentialXPCSigningPolicy.serviceRequirement(
                teamIdentifier: teamIdentifier
            )
        } catch {
            throw NativeCredentialXPCClientError.invalidTeamIdentifier
        }
    }

    public static func transact(
        request: Data,
        teamIdentifier: String,
        projectionFD: Int32? = nil
    ) throws -> NativeCredentialXPCClientReply {
        try decodeReply(transactBytes(
            request: request,
            teamIdentifier: teamIdentifier,
            projectionFD: projectionFD
        ))
    }

    public static func transactProjectionReconciliation(
        request: Data,
        teamIdentifier: String
    ) throws -> NativeCredentialXPCClientReconciliationReply {
        try decodeProjectionReconciliationReply(transactBytes(
            request: request,
            teamIdentifier: teamIdentifier,
            projectionFD: nil
        ))
    }

    public static func transactProjectionIdentityRecovery(
        request: Data,
        teamIdentifier: String
    ) throws -> NativeCredentialXPCClientProjectionIdentityReply {
        try decodeProjectionIdentityRecoveryReply(transactBytes(
            request: request,
            teamIdentifier: teamIdentifier,
            projectionFD: nil
        ))
    }

    private static func transactBytes(
        request: Data,
        teamIdentifier: String,
        projectionFD: Int32?
    ) throws -> Data {
        let serviceDesignatedRequirement = try serviceDesignatedRequirement(
            teamIdentifier: teamIdentifier
        )
        guard !request.isEmpty, request.count <= maximumDataBytes,
              serviceDesignatedRequirement.utf8.count <= 4_096 else {
            throw NativeCredentialXPCClientError.invalidRequest
        }
        var replyBytes: UnsafeMutablePointer<UInt8>?
        var replyLength = 0
        let result = request.withUnsafeBytes { requestBuffer in
            guard let requestBase = requestBuffer.bindMemory(to: UInt8.self).baseAddress else {
                return Int32(64)
            }
            if let projectionFD {
                return ss_native_xpc_client_request_with_fd(
                    serviceName, serviceDesignatedRequirement,
                    requestBase, requestBuffer.count, projectionFD,
                    &replyBytes, &replyLength
                )
            }
            return ss_native_xpc_client_request(
                serviceName, serviceDesignatedRequirement,
                requestBase, requestBuffer.count,
                &replyBytes, &replyLength
            )
        }
        guard result == 0, let replyBytes,
              (1...maximumDataBytes).contains(replyLength) else {
            if let replyBytes { ss_native_xpc_bytes_free(replyBytes) }
            throw NativeCredentialXPCClientError.transportUnavailable
        }
        defer { ss_native_xpc_bytes_free(replyBytes) }
        return Data(bytes: replyBytes, count: replyLength)
    }
}
