import CryptoKit
import Darwin
import Foundation

struct NativeProjectionReconciliationTicket: Codable, Equatable, Sendable {
    static let schemaName =
        "secure-sandbox-native-projection-reconciliation-ticket-v1"
    static let maximumBytes = 32 * 1024

    let schema: String
    let ticketID: String
    let recoveryOperationID: String
    let originalOperationID: String
    let provider: NativeCredentialProvider
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let consumerExecutableSHA256: String
    let sessionAuthoritySHA256: String
    let stackSHA256: String
    let recoveryPlanSHA256: String
    let guestAbsenceEvidenceSHA256: String
    let egressClosedEvidenceSHA256: String
    let hostReleaseID: String
    let recoveryRequestSHA256: String
    let recoveryReceiptSHA256: String
    let issuedAt: Int64
    let expiresAt: Int64
    let status: String
    let ticketSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case ticketID = "ticket_id"
        case recoveryOperationID = "recovery_operation_id"
        case originalOperationID = "original_operation_id"
        case provider
        case processIdentifier = "process_identifier"
        case processStartTimeMicroseconds = "process_start_time_us"
        case consumerExecutableSHA256 = "consumer_executable_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case stackSHA256 = "stack_sha256"
        case recoveryPlanSHA256 = "recovery_plan_sha256"
        case guestAbsenceEvidenceSHA256 = "guest_absence_evidence_sha256"
        case egressClosedEvidenceSHA256 = "egress_closed_evidence_sha256"
        case hostReleaseID = "host_release_id"
        case recoveryRequestSHA256 = "recovery_request_sha256"
        case recoveryReceiptSHA256 = "recovery_receipt_sha256"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case status
        case ticketSHA256 = "ticket_sha256"
    }

    private struct DigestBody: Encodable {
        let ticketID: String
        let recoveryOperationID: String
        let originalOperationID: String
        let provider: NativeCredentialProvider
        let processIdentifier: Int32
        let processStartTimeMicroseconds: UInt64
        let consumerExecutableSHA256: String
        let sessionAuthoritySHA256: String
        let stackSHA256: String
        let recoveryPlanSHA256: String
        let guestAbsenceEvidenceSHA256: String
        let egressClosedEvidenceSHA256: String
        let hostReleaseID: String
        let recoveryRequestSHA256: String
        let recoveryReceiptSHA256: String
        let issuedAt: Int64
        let expiresAt: Int64
        let status: String

        enum CodingKeys: String, CodingKey {
            case ticketID = "ticket_id"
            case recoveryOperationID = "recovery_operation_id"
            case originalOperationID = "original_operation_id"
            case provider
            case processIdentifier = "process_identifier"
            case processStartTimeMicroseconds = "process_start_time_us"
            case consumerExecutableSHA256 = "consumer_executable_sha256"
            case sessionAuthoritySHA256 = "session_authority_sha256"
            case stackSHA256 = "stack_sha256"
            case recoveryPlanSHA256 = "recovery_plan_sha256"
            case guestAbsenceEvidenceSHA256 = "guest_absence_evidence_sha256"
            case egressClosedEvidenceSHA256 = "egress_closed_evidence_sha256"
            case hostReleaseID = "host_release_id"
            case recoveryRequestSHA256 = "recovery_request_sha256"
            case recoveryReceiptSHA256 = "recovery_receipt_sha256"
            case issuedAt = "issued_at"
            case expiresAt = "expires_at"
            case status
        }
    }

    func validate(now: Date) throws {
        let digests = [
            consumerExecutableSHA256, sessionAuthoritySHA256, stackSHA256,
            recoveryPlanSHA256, guestAbsenceEvidenceSHA256,
            egressClosedEvidenceSHA256, hostReleaseID,
            recoveryRequestSHA256, recoveryReceiptSHA256,
        ]
        guard schema == Self.schemaName,
              provider == .openAIChatGPT,
              [ticketID, recoveryOperationID, originalOperationID]
                .allSatisfy(NativeAuthorizationTicket.isUUID4),
              processIdentifier > 0,
              processStartTimeMicroseconds > 0,
              digests.allSatisfy(NativeAuthorizationTicket.isSHA256),
              status == "authorized",
              issuedAt > 0,
              expiresAt > issuedAt,
              expiresAt <= issuedAt + 120,
              Int64(now.timeIntervalSince1970) >= issuedAt,
              Int64(now.timeIntervalSince1970) < expiresAt,
              ticketSHA256 == NativeAuthorizationTicket.sha256(
                  try NativeAuthorizationTicket.canonicalData(digestBody)
              ) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
    }

    func matches(
        request: NativeProjectionReconciliationIPCRequest,
        now: Date
    ) throws {
        try validate(now: now)
        guard ticketID == request.ticketID,
              recoveryOperationID == request.recoveryOperationID,
              originalOperationID == request.originalOperationID,
              provider == request.provider,
              processIdentifier == request.processIdentifier,
              processStartTimeMicroseconds
                == request.processStartTimeMicroseconds,
              consumerExecutableSHA256
                == request.consumerExecutableSHA256,
              sessionAuthoritySHA256 == request.sessionAuthoritySHA256,
              stackSHA256 == request.stackSHA256,
              recoveryPlanSHA256 == request.recoveryPlanSHA256,
              guestAbsenceEvidenceSHA256
                == request.guestAbsenceEvidenceSHA256,
              egressClosedEvidenceSHA256
                == request.egressClosedEvidenceSHA256,
              hostReleaseID == request.hostReleaseID,
              recoveryRequestSHA256 == request.recoveryRequestSHA256,
              recoveryReceiptSHA256 == request.recoveryReceiptSHA256 else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
    }

    private var digestBody: DigestBody {
        DigestBody(
            ticketID: ticketID,
            recoveryOperationID: recoveryOperationID,
            originalOperationID: originalOperationID,
            provider: provider,
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
            recoveryReceiptSHA256: recoveryReceiptSHA256,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            status: status
        )
    }
}

protocol NativeProjectionReconciliationTicketReading: Sendable {
    func read(
        ticketID: String,
        now: Date
    ) throws -> NativeProjectionReconciliationTicket
}

struct RootOwnedNativeProjectionReconciliationTicketReader:
    NativeProjectionReconciliationTicketReading, Sendable
{
    let root: URL
    let expectedOwner: uid_t

    init(
        root: URL = URL(
            fileURLWithPath:
                "/usr/local/var/lib/secure-sandbox/native-credential-tickets",
            isDirectory: true
        ),
        expectedOwner: uid_t = 0
    ) {
        self.root = root
        self.expectedOwner = expectedOwner
    }

    func read(
        ticketID: String,
        now: Date
    ) throws -> NativeProjectionReconciliationTicket {
        guard root.isFileURL, root.path.hasPrefix("/"),
              NativeAuthorizationTicket.isUUID4(ticketID) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        let path = root.appendingPathComponent(
            ticketID + ".json", isDirectory: false
        )
        var parentInfo = stat()
        var pathInfo = stat()
        guard lstat(root.path, &parentInfo) == 0,
              parentInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              parentInfo.st_uid == expectedOwner,
              parentInfo.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0,
              lstat(path.path, &pathInfo) == 0,
              pathInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              pathInfo.st_uid == expectedOwner,
              pathInfo.st_nlink == 1,
              pathInfo.st_mode & mode_t(0o777) == mode_t(0o644),
              pathInfo.st_size >= 2,
              pathInfo.st_size
                <= NativeProjectionReconciliationTicket.maximumBytes else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        let descriptor = Darwin.open(
            path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == pathInfo.st_dev,
              opened.st_ino == pathInfo.st_ino,
              opened.st_uid == expectedOwner,
              opened.st_nlink == 1,
              opened.st_mode & mode_t(0o777) == mode_t(0o644),
              opened.st_size == pathInfo.st_size else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        var data = Data(count: Int(opened.st_size))
        let count = data.withUnsafeMutableBytes { bytes in
            Darwin.read(descriptor, bytes.baseAddress, bytes.count)
        }
        let exactKeys: Set<String> = [
            "schema", "ticket_id", "recovery_operation_id",
            "original_operation_id", "provider", "process_identifier",
            "process_start_time_us", "consumer_executable_sha256",
            "session_authority_sha256", "stack_sha256",
            "recovery_plan_sha256", "guest_absence_evidence_sha256",
            "egress_closed_evidence_sha256", "host_release_id",
            "recovery_request_sha256", "recovery_receipt_sha256",
            "issued_at", "expires_at", "status", "ticket_sha256",
        ]
        guard count == data.count,
              let object = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == exactKeys,
              let ticket = try? JSONDecoder().decode(
                  NativeProjectionReconciliationTicket.self, from: data
              ),
              data == (try? NativeAuthorizationTicket.canonicalData(ticket)) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        try ticket.validate(now: now)
        return ticket
    }
}

struct NativeProjectionReconciliationIPCRequest: Codable, Equatable, Sendable {
    static let schemaName =
        "secure-sandbox-native-projection-reconciliation-request-v1"
    static let maximumBytes = 32 * 1024

    let schema: String
    let operation: NativeCredentialOperation
    let ticketID: String
    let recoveryOperationID: String
    let originalOperationID: String
    let provider: NativeCredentialProvider
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let consumerExecutableSHA256: String
    let sessionAuthoritySHA256: String
    let stackSHA256: String
    let recoveryPlanSHA256: String
    let guestAbsenceEvidenceSHA256: String
    let egressClosedEvidenceSHA256: String
    let hostReleaseID: String
    let recoveryRequestSHA256: String
    let recoveryReceiptSHA256: String
    let ipcRequestSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case operation
        case ticketID = "ticket_id"
        case recoveryOperationID = "recovery_operation_id"
        case originalOperationID = "original_operation_id"
        case provider
        case processIdentifier = "process_identifier"
        case processStartTimeMicroseconds = "process_start_time_us"
        case consumerExecutableSHA256 = "consumer_executable_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case stackSHA256 = "stack_sha256"
        case recoveryPlanSHA256 = "recovery_plan_sha256"
        case guestAbsenceEvidenceSHA256 = "guest_absence_evidence_sha256"
        case egressClosedEvidenceSHA256 = "egress_closed_evidence_sha256"
        case hostReleaseID = "host_release_id"
        case recoveryRequestSHA256 = "recovery_request_sha256"
        case recoveryReceiptSHA256 = "recovery_receipt_sha256"
        case ipcRequestSHA256 = "ipc_request_sha256"
    }

    private struct DigestBody: Encodable {
        let operation: NativeCredentialOperation
        let ticketID: String
        let recoveryOperationID: String
        let originalOperationID: String
        let provider: NativeCredentialProvider
        let processIdentifier: Int32
        let processStartTimeMicroseconds: UInt64
        let consumerExecutableSHA256: String
        let sessionAuthoritySHA256: String
        let stackSHA256: String
        let recoveryPlanSHA256: String
        let guestAbsenceEvidenceSHA256: String
        let egressClosedEvidenceSHA256: String
        let hostReleaseID: String
        let recoveryRequestSHA256: String
        let recoveryReceiptSHA256: String

        enum CodingKeys: String, CodingKey {
            case operation
            case ticketID = "ticket_id"
            case recoveryOperationID = "recovery_operation_id"
            case originalOperationID = "original_operation_id"
            case provider
            case processIdentifier = "process_identifier"
            case processStartTimeMicroseconds = "process_start_time_us"
            case consumerExecutableSHA256 = "consumer_executable_sha256"
            case sessionAuthoritySHA256 = "session_authority_sha256"
            case stackSHA256 = "stack_sha256"
            case recoveryPlanSHA256 = "recovery_plan_sha256"
            case guestAbsenceEvidenceSHA256 = "guest_absence_evidence_sha256"
            case egressClosedEvidenceSHA256 = "egress_closed_evidence_sha256"
            case hostReleaseID = "host_release_id"
            case recoveryRequestSHA256 = "recovery_request_sha256"
            case recoveryReceiptSHA256 = "recovery_receipt_sha256"
        }
    }

    init(
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
    ) throws {
        schema = Self.schemaName
        operation = .reconcileProjection
        self.ticketID = ticketID.uuidString.lowercased()
        self.recoveryOperationID = recoveryOperationID.uuidString.lowercased()
        self.originalOperationID = originalOperationID.uuidString.lowercased()
        provider = .openAIChatGPT
        self.processIdentifier = processIdentifier
        self.processStartTimeMicroseconds = processStartTimeMicroseconds
        self.consumerExecutableSHA256 = consumerExecutableSHA256
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
        self.stackSHA256 = stackSHA256
        self.recoveryPlanSHA256 = recoveryPlanSHA256
        self.guestAbsenceEvidenceSHA256 = guestAbsenceEvidenceSHA256
        self.egressClosedEvidenceSHA256 = egressClosedEvidenceSHA256
        self.hostReleaseID = hostReleaseID
        self.recoveryRequestSHA256 = recoveryRequestSHA256
        self.recoveryReceiptSHA256 = recoveryReceiptSHA256
        ipcRequestSHA256 = NativeAuthorizationTicket.sha256(
            try NativeAuthorizationTicket.canonicalData(Self.digestBody(
                operation: operation,
                ticketID: self.ticketID,
                recoveryOperationID: self.recoveryOperationID,
                originalOperationID: self.originalOperationID,
                provider: provider,
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
            ))
        )
        try validate()
    }

    static func decodeExact(_ data: Data) throws -> Self {
        let exactKeys: Set<String> = [
            "schema", "operation", "ticket_id", "recovery_operation_id",
            "original_operation_id", "provider", "process_identifier",
            "process_start_time_us", "consumer_executable_sha256",
            "session_authority_sha256", "stack_sha256",
            "recovery_plan_sha256", "guest_absence_evidence_sha256",
            "egress_closed_evidence_sha256", "host_release_id",
            "recovery_request_sha256", "recovery_receipt_sha256",
            "ipc_request_sha256",
        ]
        guard data.count <= maximumBytes,
              let object = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == exactKeys,
              let request = try? JSONDecoder().decode(Self.self, from: data),
              data == (try? request.encoded()) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        try request.validate()
        return request
    }

    func encoded() throws -> Data {
        try NativeAuthorizationTicket.canonicalData(self)
    }

    func validate() throws {
        let digests = [
            consumerExecutableSHA256, sessionAuthoritySHA256, stackSHA256,
            recoveryPlanSHA256, guestAbsenceEvidenceSHA256,
            egressClosedEvidenceSHA256, hostReleaseID,
            recoveryRequestSHA256, recoveryReceiptSHA256,
        ]
        guard schema == Self.schemaName,
              operation == .reconcileProjection,
              provider == .openAIChatGPT,
              [ticketID, recoveryOperationID, originalOperationID]
                .allSatisfy(NativeAuthorizationTicket.isUUID4),
              processIdentifier > 0,
              processStartTimeMicroseconds > 0,
              digests.allSatisfy(NativeAuthorizationTicket.isSHA256),
              ipcRequestSHA256 == NativeAuthorizationTicket.sha256(
                  try NativeAuthorizationTicket.canonicalData(digestBody)
              ) else {
            throw NativeCredentialXPCError.invalidRequest
        }
    }

    private var digestBody: DigestBody {
        Self.digestBody(
            operation: operation,
            ticketID: ticketID,
            recoveryOperationID: recoveryOperationID,
            originalOperationID: originalOperationID,
            provider: provider,
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
        )
    }

    private static func digestBody(
        operation: NativeCredentialOperation,
        ticketID: String,
        recoveryOperationID: String,
        originalOperationID: String,
        provider: NativeCredentialProvider,
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
    ) -> DigestBody {
        DigestBody(
            operation: operation,
            ticketID: ticketID,
            recoveryOperationID: recoveryOperationID,
            originalOperationID: originalOperationID,
            provider: provider,
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
        )
    }
}

struct NativeProjectionReconciliationCompletion: Equatable, Sendable {
    let evidenceSHA256: String
}

struct NativeProjectionReconciliationIPCReply: Codable, Equatable, Sendable {
    static let schemaName =
        "secure-sandbox-native-projection-reconciliation-reply-v1"

    let schema: String
    let outcome: String
    let recoveryOperationID: String
    let originalOperationID: String
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let consumerExecutableSHA256: String
    let sessionAuthoritySHA256: String
    let reconciliationEvidenceSHA256: String
    let replySHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case outcome
        case recoveryOperationID = "recovery_operation_id"
        case originalOperationID = "original_operation_id"
        case processIdentifier = "process_identifier"
        case processStartTimeMicroseconds = "process_start_time_us"
        case consumerExecutableSHA256 = "consumer_executable_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case reconciliationEvidenceSHA256 =
            "reconciliation_evidence_sha256"
        case replySHA256 = "reply_sha256"
    }

    private struct DigestBody: Encodable {
        let outcome: String
        let recoveryOperationID: String
        let originalOperationID: String
        let processIdentifier: Int32
        let processStartTimeMicroseconds: UInt64
        let consumerExecutableSHA256: String
        let sessionAuthoritySHA256: String
        let reconciliationEvidenceSHA256: String

        enum CodingKeys: String, CodingKey {
            case outcome
            case recoveryOperationID = "recovery_operation_id"
            case originalOperationID = "original_operation_id"
            case processIdentifier = "process_identifier"
            case processStartTimeMicroseconds = "process_start_time_us"
            case consumerExecutableSHA256 = "consumer_executable_sha256"
            case sessionAuthoritySHA256 = "session_authority_sha256"
            case reconciliationEvidenceSHA256 =
                "reconciliation_evidence_sha256"
        }
    }

    init(
        request: NativeProjectionReconciliationIPCRequest,
        completion: NativeProjectionReconciliationCompletion
    ) throws {
        schema = Self.schemaName
        outcome = "verified"
        recoveryOperationID = request.recoveryOperationID
        originalOperationID = request.originalOperationID
        processIdentifier = request.processIdentifier
        processStartTimeMicroseconds = request.processStartTimeMicroseconds
        consumerExecutableSHA256 = request.consumerExecutableSHA256
        sessionAuthoritySHA256 = request.sessionAuthoritySHA256
        reconciliationEvidenceSHA256 = completion.evidenceSHA256
        let body = DigestBody(
            outcome: "verified",
            recoveryOperationID: request.recoveryOperationID,
            originalOperationID: request.originalOperationID,
            processIdentifier: request.processIdentifier,
            processStartTimeMicroseconds:
                request.processStartTimeMicroseconds,
            consumerExecutableSHA256: request.consumerExecutableSHA256,
            sessionAuthoritySHA256: request.sessionAuthoritySHA256,
            reconciliationEvidenceSHA256: completion.evidenceSHA256
        )
        replySHA256 = NativeAuthorizationTicket.sha256(
            try NativeAuthorizationTicket.canonicalData(body)
        )
        try validate()
    }

    func encoded() throws -> Data {
        try NativeAuthorizationTicket.canonicalData(self)
    }

    static func decodeExact(_ data: Data) throws -> Self {
        let keys: Set<String> = [
            "schema", "outcome", "recovery_operation_id",
            "original_operation_id", "process_identifier",
            "process_start_time_us", "consumer_executable_sha256",
            "session_authority_sha256", "reconciliation_evidence_sha256",
            "reply_sha256",
        ]
        guard data.count <= 32 * 1024,
              let object = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == keys,
              let reply = try? JSONDecoder().decode(Self.self, from: data),
              data == (try? reply.encoded()) else {
            throw NativeCredentialXPCError.operationRejected
        }
        try reply.validate()
        return reply
    }

    private func validate() throws {
        guard schema == Self.schemaName,
              outcome == "verified",
              [recoveryOperationID, originalOperationID]
                .allSatisfy(NativeAuthorizationTicket.isUUID4),
              processIdentifier > 0,
              processStartTimeMicroseconds > 0,
              [consumerExecutableSHA256, sessionAuthoritySHA256,
               reconciliationEvidenceSHA256, replySHA256]
                .allSatisfy(NativeAuthorizationTicket.isSHA256),
              replySHA256 == NativeAuthorizationTicket.sha256(
                  try NativeAuthorizationTicket.canonicalData(digestBody)
              ) else {
            throw NativeCredentialXPCError.operationRejected
        }
    }

    private var digestBody: DigestBody {
        DigestBody(
            outcome: outcome,
            recoveryOperationID: recoveryOperationID,
            originalOperationID: originalOperationID,
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            consumerExecutableSHA256: consumerExecutableSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            reconciliationEvidenceSHA256: reconciliationEvidenceSHA256
        )
    }
}
