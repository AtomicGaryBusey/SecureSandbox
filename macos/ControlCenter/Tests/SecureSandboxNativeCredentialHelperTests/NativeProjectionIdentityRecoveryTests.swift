import Foundation
import Testing
@testable import SecureSandboxNativeCredentialHelper

struct NativeProjectionIdentityRecoveryTests {
    private let now = Date(timeIntervalSince1970:2000000000)
    private let ticketID = UUID(
        uuidString: "11111111-1111-4111-8111-111111111111"
    )!
    private let recoveryOperationID = UUID(
        uuidString: "22222222-2222-4222-8222-222222222222"
    )!
    private let originalOperationID = UUID(
        uuidString: "33333333-3333-4333-8333-333333333333"
    )!
    private let sessionAuthoritySHA256 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private let stackSHA256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    private let recoveryPlanSHA256 =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    private let hostReleaseID =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    private var recoveryRequestSHA256: String { hostReleaseID }
    private var recoveryReceiptSHA256: String { recoveryPlanSHA256 }

    @Test func requestAndPublicCodecAreCanonicalAndExact() throws {
        let request = try makeRequest()
        let encoded = try request.encoded()
        #expect(
            try NativeProjectionIdentityRecoveryIPCRequest.decodeExact(encoded)
                == request
        )
        let publicEncoded = try NativeCredentialXPCClientContract
            .encodeProjectionIdentityRecoveryRequest(
                ticketID: ticketID,
                recoveryOperationID: recoveryOperationID,
                originalOperationID: originalOperationID,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                stackSHA256: stackSHA256,
                recoveryPlanSHA256: recoveryPlanSHA256,
                hostReleaseID: hostReleaseID,
                recoveryRequestSHA256: recoveryRequestSHA256,
                recoveryReceiptSHA256: recoveryReceiptSHA256
            )
        #expect(publicEncoded == encoded)

        let ticket = try makeTicket()
        try ticket.validate(now: now)
        try ticket.matches(request: request, now: now)
        var hostile = try #require(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        hostile["credential_hint"] = "forbidden"
        #expect(throws: NativeCredentialXPCError.invalidRequest) {
            try NativeProjectionIdentityRecoveryIPCRequest.decodeExact(
                try canonical(hostile)
            )
        }

        hostile.removeValue(forKey: "credential_hint")
        hostile["operation"] =
            NativeCredentialOperation.reconcileProjection.rawValue
        #expect(throws: NativeCredentialXPCError.invalidRequest) {
            try NativeProjectionIdentityRecoveryIPCRequest.decodeExact(
                try canonical(hostile)
            )
        }
    }

    @Test func ledgerInspectionBindsStackAndPreservesCustody() throws {
        let entry = projectionEntry()
        let record = NativeCredentialCustodyLedgerRecord(
            schema: NativeCredentialCustodyLedgerRecord.schemaName,
            tombstoneSHA256: nil,
            projections: [entry]
        )
        let ticket = try makeTicket()
        let completion = try record.inspectingProjectionIdentity(
            ticket: ticket, now: now
        )
        #expect(completion.processIdentifier == entry.processIdentifier)
        #expect(completion.consumerExecutableSHA256 == entry.executableSHA256)
        #expect(completion.sessionAuthoritySHA256 == sessionAuthoritySHA256)
        #expect(NativeAuthorizationTicket.isSHA256(completion.evidenceSHA256))
        #expect(record.projections == [entry])

        let wrongStack = try makeTicket(stack: sessionAuthoritySHA256)
        #expect(throws: NativeCredentialXPCError.ticketReplayStoreFailed) {
            try record.inspectingProjectionIdentity(
                ticket: wrongStack, now: now
            )
        }
    }

    @Test func identityTicketIsOneShotReplayProtected() throws {
        let store = IdentityRecoveryReplayStore()
        let ticket = try makeTicket()
        try store.claim(ticket, now: now)
        #expect(
            throws: NativeCredentialXPCError.authorizationTicketReplayed
        ) {
            try store.claim(ticket, now: now)
        }
    }

    @Test func rootTicketReaderRejectsHostileExtensions() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: false
        )
        let path = root.appendingPathComponent(
            ticketID.uuidString.lowercased() + ".json"
        )
        let ticket = try makeTicket()
        try NativeAuthorizationTicket.canonicalData(ticket).write(to: path)
        try FileManager.default.setAttributes(
            [.posixPermissions:0o644], ofItemAtPath: path.path
        )
        let reader = RootOwnedNativeProjectionIdentityRecoveryTicketReader(
            root: root, expectedOwner: geteuid()
        )
        #expect(
            try reader.read(
                ticketID: ticketID.uuidString.lowercased(), now: now
            ) == ticket
        )

        var hostile = try #require(
            JSONSerialization.jsonObject(
                with: NativeAuthorizationTicket.canonicalData(ticket)
            ) as? [String: Any]
        )
        hostile["fallback_authority"] = "forbidden"
        try canonical(hostile).write(to: path)
        #expect(throws: NativeCredentialXPCError.authorizationTicketRejected) {
            try reader.read(
                ticketID: ticketID.uuidString.lowercased(), now: now
            )
        }
    }

    private func projectionEntry() -> NativeCredentialProjectionLedgerEntry {
        NativeCredentialProjectionLedgerEntry(
            operationID: originalOperationID.uuidString.lowercased(),
            provider: .openAIChatGPT,
            stackSHA256: stackSHA256,
            processIdentifier:42,
            processStartTimeMicroseconds:123456789,
            executableSHA256: sessionAuthoritySHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            authorizationTicketSHA256: stackSHA256,
            projectionPolicySHA256: recoveryPlanSHA256,
            qualificationSubjectSHA256: hostReleaseID,
            qualificationEvidenceSHA256: recoveryRequestSHA256,
            researchReleaseID: recoveryReceiptSHA256,
            authorizationExpiresAtMilliseconds:2000000100000
        )
    }

    private func makeRequest(
        stack: String? = nil
    ) throws -> NativeProjectionIdentityRecoveryIPCRequest {
        try NativeProjectionIdentityRecoveryIPCRequest(
            ticketID: ticketID,
            recoveryOperationID: recoveryOperationID,
            originalOperationID: originalOperationID,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            stackSHA256: stack ?? stackSHA256,
            recoveryPlanSHA256: recoveryPlanSHA256,
            hostReleaseID: hostReleaseID,
            recoveryRequestSHA256: recoveryRequestSHA256,
            recoveryReceiptSHA256: recoveryReceiptSHA256
        )
    }

    private func makeTicket(
        stack: String? = nil
    ) throws -> NativeProjectionIdentityRecoveryTicket {
        let selectedStack = stack ?? stackSHA256
        let body: [String: Any] = [
            "ticket_id": ticketID.uuidString.lowercased(),
            "recovery_operation_id":
                recoveryOperationID.uuidString.lowercased(),
            "original_operation_id":
                originalOperationID.uuidString.lowercased(),
            "provider": NativeCredentialProvider.openAIChatGPT.rawValue,
            "session_authority_sha256": sessionAuthoritySHA256,
            "stack_sha256": selectedStack,
            "recovery_plan_sha256": recoveryPlanSHA256,
            "host_release_id": hostReleaseID,
            "recovery_request_sha256": recoveryRequestSHA256,
            "recovery_receipt_sha256": recoveryReceiptSHA256,
            "issued_at":2000000000,
            "expires_at":2000000120,
            "status": "authorized",
        ]
        return NativeProjectionIdentityRecoveryTicket(
            schema: NativeProjectionIdentityRecoveryTicket.schemaName,
            ticketID: ticketID.uuidString.lowercased(),
            recoveryOperationID: recoveryOperationID.uuidString.lowercased(),
            originalOperationID: originalOperationID.uuidString.lowercased(),
            provider: .openAIChatGPT,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            stackSHA256: selectedStack,
            recoveryPlanSHA256: recoveryPlanSHA256,
            hostReleaseID: hostReleaseID,
            recoveryRequestSHA256: recoveryRequestSHA256,
            recoveryReceiptSHA256: recoveryReceiptSHA256,
            issuedAt:2000000000,
            expiresAt:2000000120,
            status: "authorized",
            ticketSHA256: NativeAuthorizationTicket.sha256(
                try canonical(body)
            )
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

private final class IdentityRecoveryReplayStore:
    NativeAuthorizationTicketReplayProtecting, @unchecked Sendable
{
    private let lock = NSLock()
    private var used = false

    func claim(
        ticketID: String,
        ticketSHA256: String,
        expiresAt: Swift.Int64,
        now: Date
    ) throws {
        _ = ticketID
        _ = ticketSHA256
        guard expiresAt > Int64(now.timeIntervalSince1970) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        lock.lock()
        defer { lock.unlock() }
        guard !used else {
            throw NativeCredentialXPCError.authorizationTicketReplayed
        }
        used = true
    }
}
