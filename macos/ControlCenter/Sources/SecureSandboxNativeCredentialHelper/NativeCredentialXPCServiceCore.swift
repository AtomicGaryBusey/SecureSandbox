import CryptoKit
import Foundation

enum NativeCredentialXPCError: Error, Equatable, Sendable {
    case invalidRequest
    case callerIdentityRejected
    case authorizationTicketRejected
    case authorizationTicketReplayed
    case ticketReplayStoreFailed
    case operationRejected
}

struct NativeCredentialIPCRequest: Codable, Equatable, Sendable {
    static let schemaName = "secure-sandbox-native-credential-ipc-request-v1"
    static let maximumBytes = 32 * 1024

    let schema: String
    let command: NativeCredentialCommand
    let authorizationTicketID: String?
    let planSHA256: String?
    let operatorRequestSHA256: String?
    let stackSHA256: String?
    let ipcRequestSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case command
        case authorizationTicketID = "authorization_ticket_id"
        case planSHA256 = "plan_sha256"
        case operatorRequestSHA256 = "operator_request_sha256"
        case stackSHA256 = "stack_sha256"
        case ipcRequestSHA256 = "ipc_request_sha256"
    }

    private struct DigestBody: Encodable {
        let command: NativeCredentialCommand
        let authorizationTicketID: String?
        let planSHA256: String?
        let operatorRequestSHA256: String?
        let stackSHA256: String?

        enum CodingKeys: String, CodingKey {
            case command
            case authorizationTicketID = "authorization_ticket_id"
            case planSHA256 = "plan_sha256"
            case operatorRequestSHA256 = "operator_request_sha256"
            case stackSHA256 = "stack_sha256"
        }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(command, forKey: .command)
            try values.encode(authorizationTicketID, forKey: .authorizationTicketID)
            try values.encode(planSHA256, forKey: .planSHA256)
            try values.encode(operatorRequestSHA256, forKey: .operatorRequestSHA256)
            try values.encode(stackSHA256, forKey: .stackSHA256)
        }
    }

    init(
        command: NativeCredentialCommand,
        authorizationTicketID: String? = nil,
        planSHA256: String? = nil,
        operatorRequestSHA256: String? = nil,
        stackSHA256: String? = nil
    ) throws {
        self.schema = Self.schemaName
        self.command = command
        self.authorizationTicketID = authorizationTicketID
        self.planSHA256 = planSHA256
        self.operatorRequestSHA256 = operatorRequestSHA256
        self.stackSHA256 = stackSHA256
        self.ipcRequestSHA256 = Self.sha256(try Self.canonicalData(DigestBody(
            command: command,
            authorizationTicketID: authorizationTicketID,
            planSHA256: planSHA256,
            operatorRequestSHA256: operatorRequestSHA256,
            stackSHA256: stackSHA256
        )))
        try validate()
    }

    static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= maximumBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "command", "authorization_ticket_id", "plan_sha256",
                  "operator_request_sha256", "stack_sha256", "ipc_request_sha256",
              ]),
              let request = try? Self.decoder.decode(Self.self, from: data),
              data == (try? request.encoded()) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        try request.validate()
        return request
    }

    func encoded() throws -> Data {
        try Self.canonicalData(self)
    }

    func validate() throws {
        try command.validate()
        guard schema == Self.schemaName,
              NativeAuthorizationTicket.isSHA256(ipcRequestSHA256),
              ipcRequestSHA256 == Self.sha256(try Self.canonicalData(DigestBody(
                  command: command,
                  authorizationTicketID: authorizationTicketID,
                  planSHA256: planSHA256,
                  operatorRequestSHA256: operatorRequestSHA256,
                  stackSHA256: stackSHA256
              ))) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        if command.operation == .status {
            guard authorizationTicketID == nil, planSHA256 == nil,
                  operatorRequestSHA256 == nil, stackSHA256 == nil else {
                throw NativeCredentialXPCError.invalidRequest
            }
        } else {
            guard let authorizationTicketID,
                  NativeAuthorizationTicket.isUUID4(authorizationTicketID),
                  let planSHA256,
                  NativeAuthorizationTicket.isSHA256(planSHA256),
                  let operatorRequestSHA256,
                  NativeAuthorizationTicket.isSHA256(operatorRequestSHA256),
                  let stackSHA256,
                  NativeAuthorizationTicket.isSHA256(stackSHA256) else {
                throw NativeCredentialXPCError.invalidRequest
            }
        }
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(command, forKey: .command)
        try values.encode(authorizationTicketID, forKey: .authorizationTicketID)
        try values.encode(planSHA256, forKey: .planSHA256)
        try values.encode(operatorRequestSHA256, forKey: .operatorRequestSHA256)
        try values.encode(stackSHA256, forKey: .stackSHA256)
        try values.encode(ipcRequestSHA256, forKey: .ipcRequestSHA256)
    }

    private static var decoder: JSONDecoder { JSONDecoder() }

    private static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct NativeCredentialProjectionStatus: Codable, Equatable, Sendable {
    let processIdentifier: Int32
    let executableSHA256: String
    let sessionAuthoritySHA256: String
    let startedAtMilliseconds: Int64

    enum CodingKeys: String, CodingKey {
        case processIdentifier = "process_identifier"
        case executableSHA256 = "executable_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case startedAtMilliseconds = "started_at_milliseconds"
    }

    init(_ launched: LaunchedCredentialConsumer) throws {
        guard launched.processIdentifier > 0,
              NativeAuthorizationTicket.isSHA256(launched.executableSHA256),
              NativeAuthorizationTicket.isSHA256(launched.sessionAuthoritySHA256) else {
            throw NativeCredentialXPCError.operationRejected
        }
        processIdentifier = launched.processIdentifier
        executableSHA256 = launched.executableSHA256
        sessionAuthoritySHA256 = launched.sessionAuthoritySHA256
        startedAtMilliseconds = Int64(launched.startedAt.timeIntervalSince1970 * 1_000)
    }

    func validate() throws {
        guard processIdentifier > 0,
              NativeAuthorizationTicket.isSHA256(executableSHA256),
              NativeAuthorizationTicket.isSHA256(sessionAuthoritySHA256),
              startedAtMilliseconds > 0 else {
            throw NativeCredentialXPCError.operationRejected
        }
    }
}

enum NativeCredentialIPCOutcome: String, Codable, Sendable {
    case verified
    case rejected
}

enum NativeCredentialIPCErrorCode: String, Codable, Sendable {
    case invalidRequest = "invalid-request"
    case callerRejected = "caller-rejected"
    case ticketRejected = "authorization-ticket-rejected"
    case ticketReplayed = "authorization-ticket-replayed"
    case credentialUnavailable = "credential-unavailable"
    case providerUnavailable = "provider-unavailable"
    case operationInProgress = "operation-in-progress"
    case operationRejected = "operation-rejected"
    case internalFailure = "internal-failure"
}

struct NativeCredentialIPCReply: Codable, Equatable, Sendable {
    static let schemaName = "secure-sandbox-native-credential-ipc-reply-v1"

    let schema: String
    let operationID: String?
    let outcome: NativeCredentialIPCOutcome
    let status: NativeCredentialStatus?
    let projection: NativeCredentialProjectionStatus?
    let errorCode: NativeCredentialIPCErrorCode?
    let responseSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case operationID = "operation_id"
        case outcome
        case status
        case projection
        case errorCode = "error_code"
        case responseSHA256 = "response_sha256"
    }

    private struct DigestBody: Encodable {
        let operationID: String?
        let outcome: NativeCredentialIPCOutcome
        let status: NativeCredentialStatus?
        let projection: NativeCredentialProjectionStatus?
        let errorCode: NativeCredentialIPCErrorCode?

        enum CodingKeys: String, CodingKey {
            case operationID = "operation_id"
            case outcome
            case status
            case projection
            case errorCode = "error_code"
        }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(operationID, forKey: .operationID)
            try values.encode(outcome, forKey: .outcome)
            try values.encode(status, forKey: .status)
            try values.encode(projection, forKey: .projection)
            try values.encode(errorCode, forKey: .errorCode)
        }
    }

    static func success(
        operationID: UUID,
        status: NativeCredentialStatus? = nil,
        projection: NativeCredentialProjectionStatus? = nil
    ) throws -> Self {
        try make(
            operationID: operationID.uuidString.lowercased(),
            outcome: .verified,
            status: status,
            projection: projection,
            errorCode: nil
        )
    }

    static func failure(operationID: UUID?, code: NativeCredentialIPCErrorCode) -> Self {
        // Every member is already bounded and encodable; construction failure
        // would indicate a programmer error, not provider-controlled input.
        try! make(
            operationID: operationID?.uuidString.lowercased(),
            outcome: .rejected,
            status: nil,
            projection: nil,
            errorCode: code
        )
    }

    private static func make(
        operationID: String?,
        outcome: NativeCredentialIPCOutcome,
        status: NativeCredentialStatus?,
        projection: NativeCredentialProjectionStatus?,
        errorCode: NativeCredentialIPCErrorCode?
    ) throws -> Self {
        guard (outcome == .verified) == (errorCode == nil),
              (outcome == .verified
                   ? ((status != nil) != (projection != nil)) && operationID != nil
                   : status == nil && projection == nil),
              operationID.map(NativeAuthorizationTicket.isUUID4) ?? true else {
            throw NativeCredentialXPCError.operationRejected
        }
        let body = DigestBody(
            operationID: operationID,
            outcome: outcome,
            status: status,
            projection: projection,
            errorCode: errorCode
        )
        return Self(
            schema: schemaName,
            operationID: operationID,
            outcome: outcome,
            status: status,
            projection: projection,
            errorCode: errorCode,
            responseSHA256: NativeAuthorizationTicket.sha256(try canonicalData(body))
        )
    }

    func encoded() throws -> Data { try Self.canonicalData(self) }

    static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 32 * 1024,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "operation_id", "outcome", "status", "projection",
                  "error_code", "response_sha256",
              ]),
              let reply = try? decoder.decode(Self.self, from: data),
              data == (try? reply.encoded()),
              reply.schema == schemaName,
              (reply.outcome == .verified) == (reply.errorCode == nil),
              (reply.outcome == .verified
                   ? ((reply.status != nil) != (reply.projection != nil))
                       && reply.operationID != nil
                   : reply.status == nil && reply.projection == nil),
              reply.operationID.map(NativeAuthorizationTicket.isUUID4) ?? true,
              NativeAuthorizationTicket.isSHA256(reply.responseSHA256),
              reply.responseSHA256 == NativeAuthorizationTicket.sha256(
                  try canonicalData(DigestBody(
                      operationID: reply.operationID,
                      outcome: reply.outcome,
                      status: reply.status,
                      projection: reply.projection,
                      errorCode: reply.errorCode
                  ))
              ) else {
            throw NativeCredentialXPCError.operationRejected
        }
        if let status = reply.status {
            _ = try NativeCredentialStatus(
                provider: status.provider,
                state: status.state,
                clientIDHash: status.clientIDHash,
                accountSubjectSHA256: status.accountSubjectSHA256,
                workspaceSHA256: status.workspaceSHA256,
                scopeSHA256: status.scopeSHA256,
                accessExpiresAt: status.accessExpiresAt,
                earliestRefreshAt: status.earliestRefreshAt,
                refreshExpiresAt: status.refreshExpiresAt
            )
        }
        try reply.projection?.validate()
        return reply
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(operationID, forKey: .operationID)
        try values.encode(outcome, forKey: .outcome)
        try values.encode(status, forKey: .status)
        try values.encode(projection, forKey: .projection)
        try values.encode(errorCode, forKey: .errorCode)
        try values.encode(responseSHA256, forKey: .responseSHA256)
    }

    private static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    private static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}

protocol NativeCredentialCoordinating: Sendable {
    func status(now: Date) async throws -> NativeCredentialStatus
    func login(now: Date) async throws -> NativeCredentialStatus
    func refresh(now: Date) async throws -> NativeCredentialStatus
    func logout() async throws -> NativeCredentialStatus
    func destroyLocalCredential() async throws -> NativeCredentialStatus
    func recoverLocalState() async throws -> NativeCredentialStatus
    func project(
        _ request: CredentialProjectionRequest,
        now: Date
    ) async throws -> LaunchedCredentialConsumer
}

extension NativeCredentialCoordinator: NativeCredentialCoordinating {}

protocol NativeCredentialCancellationChecking: Sendable {
    func checkCancellation() throws
}

struct NativeCredentialNeverCancelled: NativeCredentialCancellationChecking {
    func checkCancellation() throws { try Task.checkCancellation() }
}

struct NativeCredentialXPCPeerRequirementProof: Sendable {
    fileprivate let requirementSHA256: String

    init(requirementSHA256: String) throws {
        guard NativeAuthorizationTicket.isSHA256(requirementSHA256) else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        self.requirementSHA256 = requirementSHA256
    }
}

actor NativeCredentialXPCServiceCore {
    private let callerValidator: any NativeCredentialCallerIdentityValidating
    private let ticketReader: any NativeAuthorizationTicketReading
    private let replayStore: any NativeAuthorizationTicketReplayProtecting
    private let coordinator: any NativeCredentialCoordinating
    private let expectedXPCPeerRequirementSHA256: String?
    private var requestActive = false

    init(
        callerValidator: any NativeCredentialCallerIdentityValidating,
        ticketReader: any NativeAuthorizationTicketReading,
        replayStore: any NativeAuthorizationTicketReplayProtecting,
        coordinator: any NativeCredentialCoordinating,
        expectedXPCPeerRequirementSHA256: String? = nil
    ) {
        self.callerValidator = callerValidator
        self.ticketReader = ticketReader
        self.replayStore = replayStore
        self.coordinator = coordinator
        self.expectedXPCPeerRequirementSHA256 = expectedXPCPeerRequirementSHA256
    }

    func handle(requestData: Data, caller: CallerAuditEvidence, now: Date = Date()) async -> Data {
        do {
            try callerValidator.validate(caller)
        } catch {
            return Self.failureData(operationID: nil, error: error)
        }
        return await handleVerified(
            requestData: requestData,
            cancellation: NativeCredentialNeverCancelled(),
            now: now
        )
    }

    func handleSystemXPC(
        requestData: Data,
        proof: NativeCredentialXPCPeerRequirementProof,
        cancellation: any NativeCredentialCancellationChecking,
        now: Date = Date()
    ) async -> Data {
        guard let expectedXPCPeerRequirementSHA256,
              proof.requirementSHA256 == expectedXPCPeerRequirementSHA256 else {
            return Self.failureData(
                operationID: nil,
                error: NativeCredentialXPCError.callerIdentityRejected
            )
        }
        return await handleVerified(
            requestData: requestData,
            cancellation: cancellation,
            now: now
        )
    }

    private func handleVerified(
        requestData: Data,
        cancellation: any NativeCredentialCancellationChecking,
        now: Date
    ) async -> Data {
        guard !requestActive else {
            return Self.failureData(
                operationID: nil,
                error: NativeCredentialHelperError.operationInProgress
            )
        }
        requestActive = true
        defer { requestActive = false }
        var operationID: UUID?
        do {
            try cancellation.checkCancellation()
            let request = try NativeCredentialIPCRequest.decodeExact(requestData)
            operationID = request.command.operationID
            var authorizedTicket: NativeAuthorizationTicket?
            if request.command.operation != .status {
                guard let ticketID = request.authorizationTicketID else {
                    throw NativeCredentialXPCError.authorizationTicketRejected
                }
                let ticket = try ticketReader.read(ticketID: ticketID, now: now)
                try ticket.matches(request: request, now: now)
                try replayStore.claim(ticket, now: now)
                authorizedTicket = ticket
            }
            // A lost peer after durable ticket consumption must never start a
            // credential mutation. The consumed tombstone remains fail-closed.
            try cancellation.checkCancellation()
            let reply: NativeCredentialIPCReply
            switch request.command.operation {
            case .status:
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try await coordinator.status(now: now)
                )
            case .login:
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try await coordinator.login(now: now)
                )
            case .refresh:
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try await coordinator.refresh(now: now)
                )
            case .logout:
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try await coordinator.logout()
                )
            case .destroyLocalCredential:
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try await coordinator.destroyLocalCredential()
                )
            case .recoverLocalState:
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try await coordinator.recoverLocalState()
                )
            case .projectForSession:
                guard let session = request.command.sessionAuthoritySHA256,
                      let receipt = request.command.authorizationReceiptSHA256,
                      let expiration = authorizedTicket?.expiresAt else {
                    throw NativeCredentialXPCError.authorizationTicketRejected
                }
                let projectionRequest = try CredentialProjectionRequest(
                    operationID: request.command.operationID,
                    sessionAuthoritySHA256: session,
                    authorizationReceiptSHA256: receipt,
                    expiresAt: min(
                        Date(timeIntervalSince1970: TimeInterval(expiration)),
                        now.addingTimeInterval(120)
                    )
                )
                let launched = try await coordinator.project(projectionRequest, now: now)
                reply = try .success(
                    operationID: request.command.operationID,
                    projection: NativeCredentialProjectionStatus(launched)
                )
            }
            try cancellation.checkCancellation()
            return try reply.encoded()
        } catch {
            return Self.failureData(operationID: operationID, error: error)
        }
    }

    private static func failureData(operationID: UUID?, error: any Error) -> Data {
        // NativeCredentialIPCReply.failure is total for these bounded enum and
        // UUID inputs; no provider-controlled content reaches this path.
        try! NativeCredentialIPCReply.failure(
            operationID: operationID,
            code: errorCode(error)
        ).encoded()
    }

    private static func errorCode(_ error: any Error) -> NativeCredentialIPCErrorCode {
        switch error {
        case NativeCredentialXPCError.callerIdentityRejected:
            .callerRejected
        case NativeCredentialXPCError.invalidRequest:
            .invalidRequest
        case NativeCredentialXPCError.authorizationTicketReplayed:
            .ticketReplayed
        case NativeCredentialXPCError.authorizationTicketRejected,
             NativeCredentialXPCError.ticketReplayStoreFailed:
            .ticketRejected
        case NativeCredentialHelperError.credentialNotFound,
             NativeCredentialHelperError.credentialStoreFailed,
             NativeCredentialHelperError.secureEnclaveUnavailable,
             NativeCredentialHelperError.hostIdentityUnavailable:
            .credentialUnavailable
        case NativeCredentialHelperError.providerTransportFailed,
             NativeCredentialHelperError.revocationFailed,
             NativeCredentialHelperError.refreshValidationUnavailable:
            .providerUnavailable
        case NativeCredentialHelperError.operationInProgress:
            .operationInProgress
        default:
            .operationRejected
        }
    }
}

// The bundle-facing XPC target exports only this one bounded Data method.  Its
// connection adapter must obtain an audit token from the accepted Mach/XPC
// connection and construct CallerAuditEvidence before invoking the service
// core; PID-only identity is explicitly not an admissible substitute.
@objc protocol SecureSandboxNativeCredentialXPCProtocol {
    func perform(_ request: Data, withReply reply: @escaping (Data) -> Void)
}
