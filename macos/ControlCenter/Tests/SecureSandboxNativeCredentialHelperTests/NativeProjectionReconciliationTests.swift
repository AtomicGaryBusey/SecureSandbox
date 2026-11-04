import CryptoKit
import Foundation
import Testing
@testable import SecureSandboxNativeCredentialHelper

struct NativeProjectionReconciliationTests {
    private let now = Date(timeIntervalSince1970: 2_000_000_000)
    private let ticketID = UUID(
        uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )!
    private let recoveryOperationID = UUID(
        uuidString: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    )!
    private let originalOperationID = UUID(
        uuidString: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    )!
    private let processIdentifier: Int32 = 42
    private let processStartTimeMicroseconds: UInt64 = 123_456_789
    private let executableSHA256 = String(repeating: "1", count: 64)
    private let sessionAuthoritySHA256 = String(repeating: "2", count: 64)
    private let stackSHA256 = String(repeating: "3", count: 64)
    private let recoveryPlanSHA256 = String(repeating: "4", count: 64)
    private let guestAbsenceEvidenceSHA256 = String(repeating: "5", count: 64)
    private let egressClosedEvidenceSHA256 = String(repeating: "6", count: 64)
    private let hostReleaseID = String(repeating: "7", count: 64)
    private let recoveryRequestSHA256 = String(repeating: "8", count: 64)
    private let recoveryReceiptSHA256 = String(repeating: "9", count: 64)

    @Test func requestAndTicketAreCanonicalExactAndSelfDigested() throws {
        let request = try makeRequest()
        let encoded = try request.encoded()
        #expect(
            try NativeProjectionReconciliationIPCRequest.decodeExact(encoded)
                == request
        )
        let publicEncoded = try NativeCredentialXPCClientContract
            .encodeProjectionReconciliationRequest(
                ticketID: ticketID,
                recoveryOperationID: recoveryOperationID,
                originalOperationID: originalOperationID,
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds,
                consumerExecutableSHA256: executableSHA256,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                stackSHA256: stackSHA256,
                recoveryPlanSHA256: recoveryPlanSHA256,
                guestAbsenceEvidenceSHA256: guestAbsenceEvidenceSHA256,
                egressClosedEvidenceSHA256: egressClosedEvidenceSHA256,
                hostReleaseID: hostReleaseID,
                recoveryRequestSHA256: recoveryRequestSHA256,
                recoveryReceiptSHA256: recoveryReceiptSHA256
            )
        #expect(publicEncoded == encoded)
        let ticket = try makeTicket()
        try ticket.validate(now: now)
        try ticket.matches(request: request, now: now)

        var requestObject = try #require(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        requestObject["access_token"] = "forbidden"
        let hostile = try JSONSerialization.data(
            withJSONObject: requestObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) + Data([0x0a])
        #expect(throws: NativeCredentialXPCError.invalidRequest) {
            try NativeProjectionReconciliationIPCRequest.decodeExact(hostile)
        }

        let substituted = try makeRequest(
            guestAbsenceEvidenceSHA256: String(repeating: "a", count: 64)
        )
        #expect(
            throws: NativeCredentialXPCError.authorizationTicketRejected
        ) {
            try ticket.matches(request: substituted, now: now)
        }
    }

    @Test func rootOwnedReaderRejectsExtraFieldsAndSymlinks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "native-reconciliation-ticket-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: false
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: root.path
        )
        let path = root.appendingPathComponent(
            ticketID.uuidString.lowercased() + ".json"
        )
        let ticket = try makeTicket()
        try NativeAuthorizationTicket.canonicalData(ticket).write(to: path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: path.path
        )
        let reader = RootOwnedNativeProjectionReconciliationTicketReader(
            root: root,
            expectedOwner: geteuid()
        )
        #expect(
            try reader.read(
                ticketID: ticketID.uuidString.lowercased(), now: now
            ) == ticket
        )

        var object = try #require(
            JSONSerialization.jsonObject(
                with: NativeAuthorizationTicket.canonicalData(ticket)
            ) as? [String: Any]
        )
        object["fallback_authority"] = "forbidden"
        try (JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) + Data([0x0a])).write(to: path)
        #expect(
            throws: NativeCredentialXPCError.authorizationTicketRejected
        ) {
            try reader.read(
                ticketID: ticketID.uuidString.lowercased(), now: now
            )
        }

        try FileManager.default.removeItem(at: path)
        let target = root.appendingPathComponent("ticket-target.json")
        try NativeAuthorizationTicket.canonicalData(ticket).write(to: target)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: target.path
        )
        try FileManager.default.createSymbolicLink(
            at: path,
            withDestinationURL: target
        )
        #expect(
            throws: NativeCredentialXPCError.authorizationTicketRejected
        ) {
            try reader.read(
                ticketID: ticketID.uuidString.lowercased(), now: now
            )
        }
    }

    @Test func authorizedReconciliationIsOneShotAndContentFree() async throws {
        let ticket = try makeTicket()
        let request = try makeRequest()
        let ledger = ReconciliationLedger(
            record: custodyRecord(),
            processIdentity: .absent
        )
        let replay = ReconciliationReplayStore()
        let service = makeService(
            ticket: ticket,
            ledger: ledger,
            replay: replay
        )
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )

        let response = await service.handle(
            requestData: try request.encoded(),
            caller: caller,
            now: now
        )
        let reply = try NativeProjectionReconciliationIPCReply
            .decodeExact(response)
        #expect(reply.recoveryOperationID == request.recoveryOperationID)
        #expect(reply.originalOperationID == request.originalOperationID)
        #expect(ledger.projectionCount == 0)
        #expect(replay.claimedCount == 1)
        let publicReply = try NativeCredentialXPCClientContract
            .decodeProjectionReconciliationReply(response)
        #expect(publicReply.verified)
        #expect(publicReply.originalOperationID == originalOperationID)
        let responseText = String(decoding: response, as: UTF8.self)
        for forbidden in ["access_token", "refresh_token", "id_token"] {
            #expect(!responseText.contains(forbidden))
        }

        let replayed = await service.handle(
            requestData: try request.encoded(),
            caller: caller,
            now: now
        )
        let publicFailure = try NativeCredentialXPCClientContract
            .decodeProjectionReconciliationReply(replayed)
        #expect(!publicFailure.verified)
        #expect(publicFailure.errorCode == "authorization-ticket-replayed")
    }

    @Test func samePIDGenerationAndUnavailableReadbackFailClosed() throws {
        let ticket = try makeTicket()
        for identity in [
            NativeCredentialProcessIdentityObservation.unavailable,
            .exact(processStartTimeMicroseconds),
        ] {
            let record = custodyRecord()
            #expect(throws: NativeCredentialXPCError.ticketReplayStoreFailed) {
                try record.reconcilingProjection(
                    ticket: ticket,
                    now: now,
                    processIdentity: identity
                )
            }
        }
    }

    @Test func PIDReuseCanClearOnlyTheExactTicketedProjection() throws {
        let ticket = try makeTicket()
        let record = custodyRecord()
        let result = try record.reconcilingProjection(
            ticket: ticket,
            now: now,
            processIdentity: .exact(processStartTimeMicroseconds + 1)
        )
        #expect(result.record.projections.isEmpty)
        #expect(NativeAuthorizationTicket.isSHA256(
            result.completion.evidenceSHA256
        ))

        let wrongExecutable = try makeTicket(
            consumerExecutableSHA256: String(repeating: "a", count: 64)
        )
        #expect(throws: NativeCredentialXPCError.ticketReplayStoreFailed) {
            try record.reconcilingProjection(
                ticket: wrongExecutable,
                now: now,
                processIdentity: .absent
            )
        }
    }

    private func makeService(
        ticket: NativeProjectionReconciliationTicket,
        ledger: ReconciliationLedger,
        replay: ReconciliationReplayStore
    ) -> NativeCredentialXPCServiceCore {
        NativeCredentialXPCServiceCore(
            callerValidator: ReconciliationCaller(),
            ticketReader: RejectingAuthorizationTicketReader(),
            reconciliationTicketReader:
                FixedReconciliationTicketReader(ticket: ticket),
            replayStore: replay,
            coordinator: ReconciliationCoordinator(),
            custodyLedger: ledger
        )
    }

    private func makeRequest(
        guestAbsenceEvidenceSHA256: String? = nil
    ) throws -> NativeProjectionReconciliationIPCRequest {
        try NativeProjectionReconciliationIPCRequest(
            ticketID: ticketID,
            recoveryOperationID: recoveryOperationID,
            originalOperationID: originalOperationID,
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            consumerExecutableSHA256: executableSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            stackSHA256: stackSHA256,
            recoveryPlanSHA256: recoveryPlanSHA256,
            guestAbsenceEvidenceSHA256:
                guestAbsenceEvidenceSHA256
                    ?? self.guestAbsenceEvidenceSHA256,
            egressClosedEvidenceSHA256: egressClosedEvidenceSHA256,
            hostReleaseID: hostReleaseID,
            recoveryRequestSHA256: recoveryRequestSHA256,
            recoveryReceiptSHA256: recoveryReceiptSHA256
        )
    }

    private func makeTicket(
        consumerExecutableSHA256: String? = nil
    ) throws -> NativeProjectionReconciliationTicket {
        let executable = consumerExecutableSHA256 ?? executableSHA256
        let issuedAt = Int64(now.timeIntervalSince1970) - 1
        let expiresAt = issuedAt + 120
        let body: [String: Any] = [
            "ticket_id": ticketID.uuidString.lowercased(),
            "recovery_operation_id":
                recoveryOperationID.uuidString.lowercased(),
            "original_operation_id":
                originalOperationID.uuidString.lowercased(),
            "provider": "openAIChatGPT",
            "process_identifier": processIdentifier,
            "process_start_time_us": processStartTimeMicroseconds,
            "consumer_executable_sha256": executable,
            "session_authority_sha256": sessionAuthoritySHA256,
            "stack_sha256": stackSHA256,
            "recovery_plan_sha256": recoveryPlanSHA256,
            "guest_absence_evidence_sha256": guestAbsenceEvidenceSHA256,
            "egress_closed_evidence_sha256": egressClosedEvidenceSHA256,
            "host_release_id": hostReleaseID,
            "recovery_request_sha256": recoveryRequestSHA256,
            "recovery_receipt_sha256": recoveryReceiptSHA256,
            "issued_at": issuedAt,
            "expires_at": expiresAt,
            "status": "authorized",
        ]
        let ticketSHA256 = NativeAuthorizationTicket.sha256(
            try canonical(body)
        )
        return NativeProjectionReconciliationTicket(
            schema: NativeProjectionReconciliationTicket.schemaName,
            ticketID: ticketID.uuidString.lowercased(),
            recoveryOperationID: recoveryOperationID.uuidString.lowercased(),
            originalOperationID: originalOperationID.uuidString.lowercased(),
            provider: .openAIChatGPT,
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            consumerExecutableSHA256: executable,
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
            status: "authorized",
            ticketSHA256: ticketSHA256
        )
    }

    private func custodyRecord() -> NativeCredentialCustodyLedgerRecord {
        NativeCredentialCustodyLedgerRecord(
            schema: NativeCredentialCustodyLedgerRecord.schemaName,
            tombstoneSHA256: nil,
            projections: [NativeCredentialProjectionLedgerEntry(
                operationID: originalOperationID.uuidString.lowercased(),
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds,
                executableSHA256: executableSHA256,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                authorizationTicketSHA256: String(repeating: "1", count: 64),
                projectionPolicySHA256: String(repeating: "2", count: 64),
                qualificationSubjectSHA256: String(repeating: "3", count: 64),
                qualificationEvidenceSHA256: String(repeating: "4", count: 64),
                researchReleaseID: String(repeating: "5", count: 64),
                authorizationExpiresAtMilliseconds: 2_000_000_000_000
            )]
        )
    }

    private func canonical(_ object: [String: Any]) throws -> Data {
        var data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        data.append(0x0a)
        return data
    }
}

private struct FixedReconciliationTicketReader:
    NativeProjectionReconciliationTicketReading
{
    let ticket: NativeProjectionReconciliationTicket

    func read(
        ticketID: String,
        now: Date
    ) throws -> NativeProjectionReconciliationTicket {
        guard ticket.ticketID == ticketID else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        try ticket.validate(now: now)
        return ticket
    }
}

private struct RejectingAuthorizationTicketReader:
    NativeAuthorizationTicketReading
{
    func read(ticketID: String, now: Date) throws -> NativeAuthorizationTicket {
        throw NativeCredentialXPCError.authorizationTicketRejected
    }
}

private struct ReconciliationCaller: NativeCredentialCallerIdentityValidating {
    func validate(_ evidence: CallerAuditEvidence) throws {}
}

private final class ReconciliationReplayStore:
    NativeAuthorizationTicketReplayProtecting, @unchecked Sendable
{
    private let lock = NSLock()
    private var identifiers: Set<String> = []

    var claimedCount: Int { lock.withLock { identifiers.count } }

    func claim(
        ticketID: String,
        ticketSHA256: String,
        expiresAt: Int64,
        now: Date
    ) throws {
        try lock.withLock {
            guard identifiers.insert(ticketID).inserted else {
                throw NativeCredentialXPCError.authorizationTicketReplayed
            }
        }
    }
}

private final class ReconciliationLedger:
    NativeCredentialCustodyTracking, @unchecked Sendable
{
    private let lock = NSLock()
    private var record: NativeCredentialCustodyLedgerRecord
    private let processIdentity: NativeCredentialProcessIdentityObservation

    init(
        record: NativeCredentialCustodyLedgerRecord,
        processIdentity: NativeCredentialProcessIdentityObservation
    ) {
        self.record = record
        self.processIdentity = processIdentity
    }

    var projectionCount: Int { lock.withLock { record.projections.count } }

    func observe(
        hasCredential: Bool,
        now: Date
    ) throws -> NativeCredentialCustodyObservation {
        try lock.withLock {
            try record.observation(
                hasCredential: hasCredential,
                processIdentity: { _ in processIdentity }
            )
        }
    }
    func clear() throws {}
    func recordDestruction(ticketSHA256: String) throws {}
    func reserveProjection(operationID: UUID, expiresAt: Date, now: Date) throws {}
    func commitProjection(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        binding: NativeCredentialProjectionCustodyBinding,
        now: Date
    ) throws {}
    func cancelProjection(operationID: UUID) throws {}
    func completeTerminatedProjection(
        operationID: UUID,
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        sessionAuthoritySHA256: String
    ) throws {}
    func reconcileProjection(
        ticket: NativeProjectionReconciliationTicket,
        now: Date
    ) throws -> NativeProjectionReconciliationCompletion {
        try lock.withLock {
            let result = try record.reconcilingProjection(
                ticket: ticket,
                now: now,
                processIdentity: processIdentity
            )
            record = result.record
            return result.completion
        }
    }
}

private actor ReconciliationCoordinator: NativeCredentialCoordinating {
    func status(now: Date) throws -> NativeCredentialStatus { try loggedOut() }
    func login(now: Date) throws -> NativeCredentialStatus { try loggedOut() }
    func refresh(now: Date) throws -> NativeCredentialStatus { try loggedOut() }
    func logout() throws -> NativeCredentialStatus { try loggedOut() }
    func destroyLocalCredential() throws -> NativeCredentialStatus {
        try loggedOut()
    }
    func recoverLocalState() throws -> NativeCredentialStatus {
        try loggedOut()
    }
    func prepareProjection(
        _ request: CredentialProjectionRequest,
        now: Date
    ) throws -> PreparedCredentialConsumer {
        throw NativeCredentialHelperError.projectionRejected
    }
    private func loggedOut() throws -> NativeCredentialStatus {
        try NativeCredentialStatus(
            provider: .openAIChatGPT,
            state: .loggedOut
        )
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
