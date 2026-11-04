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
        authorizationReceiptSHA256: String? = nil
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
                stackSHA256: stackSHA256
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
        teamIdentifier: String
    ) throws -> NativeCredentialXPCClientReply {
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
            return ss_native_xpc_client_request(
                serviceName,
                serviceDesignatedRequirement,
                requestBase,
                requestBuffer.count,
                &replyBytes,
                &replyLength
            )
        }
        guard result == 0, let replyBytes,
              (1...maximumDataBytes).contains(replyLength) else {
            if let replyBytes { ss_native_xpc_bytes_free(replyBytes) }
            throw NativeCredentialXPCClientError.transportUnavailable
        }
        defer { ss_native_xpc_bytes_free(replyBytes) }
        return try decodeReply(Data(bytes: replyBytes, count: replyLength))
    }
}
