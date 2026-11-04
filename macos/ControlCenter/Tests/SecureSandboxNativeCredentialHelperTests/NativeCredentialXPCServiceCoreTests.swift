import CryptoKit
import Darwin
import Foundation
import Testing
@testable import SecureSandboxNativeCredentialHelper

struct NativeCredentialXPCServiceCoreTests {
    private let testTeam = "ABCDEFGHIJ"
    private let digest = String(repeating: "a", count: 64)
    private let stackDigest = String(repeating: "b", count: 64)
    private let now = Date(timeIntervalSince1970: 2_000_000_000)
    private let operationID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
    private let ticketID = "22222222-2222-4222-8222-222222222222"

    @Test func requestIsCanonicalSelfDigestedAndContentFree() throws {
        let command = try loginCommand()
        let request = try NativeCredentialIPCRequest(
            command: command,
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest
        )
        let encoded = try request.encoded()
        #expect(try NativeCredentialIPCRequest.decodeExact(encoded) == request)
        let text = String(decoding: encoded, as: UTF8.self)
        for forbidden in ["access_token", "refresh_token", "id_token", "authorization_code", "pkce"] {
            #expect(!text.contains(forbidden))
        }
        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["stack_sha256"] = String(repeating: "c", count: 64)
        #expect(throws: NativeCredentialXPCError.invalidRequest) {
            try NativeCredentialIPCRequest.decodeExact(
                JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) + Data([0x0a])
            )
        }
    }

    @Test func rootOwnedTicketReaderRequiresExactCanonicalFileAndMode() throws {
        let ticket = try makeTicket()
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent(ticketID + ".json")
        try NativeAuthorizationTicket.canonicalData(ticket).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        let reader = RootOwnedNativeAuthorizationTicketReader(
            root: root,
            expectedOwner: geteuid()
        )
        #expect(try reader.read(ticketID: ticketID, now: now) == ticket)

        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        #expect(throws: NativeCredentialXPCError.authorizationTicketRejected) {
            try reader.read(ticketID: ticketID, now: now)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        var object = try #require(
            JSONSerialization.jsonObject(with: try Data(contentsOf: path)) as? [String: Any]
        )
        object["provider_response"] = "forbidden"
        try (JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) + Data([0x0a]))
            .write(to: path)
        #expect(throws: NativeCredentialXPCError.authorizationTicketRejected) {
            try reader.read(ticketID: ticketID, now: now)
        }

        try FileManager.default.removeItem(at: path)
        let linked = root.appendingPathComponent("linked-ticket.json")
        try NativeAuthorizationTicket.canonicalData(ticket).write(to: linked)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: linked.path)
        try FileManager.default.createSymbolicLink(at: path, withDestinationURL: linked)
        #expect(throws: NativeCredentialXPCError.authorizationTicketRejected) {
            try reader.read(ticketID: ticketID, now: now)
        }
        let wrongOwner = RootOwnedNativeAuthorizationTicketReader(
            root: root,
            expectedOwner: geteuid() == uid_t.max ? geteuid() - 1 : geteuid() + 1
        )
        #expect(throws: NativeCredentialXPCError.authorizationTicketRejected) {
            try wrongOwner.read(ticketID: ticketID, now: now)
        }
    }

    @Test func serviceValidatesCallerTicketAndDurablyConsumesBeforeMutation() async throws {
        let ticket = try makeTicket()
        let replay = MemoryReplayStore()
        let coordinator = FakeCredentialCoordinator()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(ticket),
            replayStore: replay,
            coordinator: coordinator
        )
        let request = try NativeCredentialIPCRequest(
            command: loginCommand(),
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest
        )
        let caller = try CallerAuditEvidence(data: Data(repeating: 0, count: CallerAuditEvidence.byteCount))
        let first = await service.handle(requestData: try request.encoded(), caller: caller, now: now)
        let decodedFirst = try NativeCredentialIPCReply.decodeExact(first)
        #expect(decodedFirst.outcome == .verified)
        let firstObject = try #require(JSONSerialization.jsonObject(with: first) as? [String: Any])
        #expect(firstObject["outcome"] as? String == "verified")
        #expect(await coordinator.loginCount == 1)

        let replayed = await service.handle(requestData: try request.encoded(), caller: caller, now: now)
        let decodedReplay = try NativeCredentialIPCReply.decodeExact(replayed)
        #expect(decodedReplay.errorCode == .ticketReplayed)
        let replayObject = try #require(JSONSerialization.jsonObject(with: replayed) as? [String: Any])
        #expect(replayObject["error_code"] as? String == "authorization-ticket-replayed")
        #expect(await coordinator.loginCount == 1)
    }

    @Test func callerRejectionPrecedesRequestParsingAndOperation() async throws {
        let coordinator = FakeCredentialCoordinator()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: RejectCaller(),
            ticketReader: FixedTicketReader(try makeTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: coordinator
        )
        let caller = try CallerAuditEvidence(data: Data(repeating: 0, count: CallerAuditEvidence.byteCount))
        let reply = await service.handle(
            requestData: Data("raw-secret-shaped-garbage".utf8),
            caller: caller,
            now: now
        )
        let object = try #require(JSONSerialization.jsonObject(with: reply) as? [String: Any])
        #expect(object["error_code"] as? String == "caller-rejected")
        #expect(object["operation_id"] is NSNull)
        #expect(await coordinator.loginCount == 0)
    }

    @Test func productionCallerEvidenceRejectsWrongSizedAuditToken() {
        #expect(throws: NativeCredentialXPCError.callerIdentityRejected) {
            try CallerAuditEvidence(data: Data(repeating: 0, count: CallerAuditEvidence.byteCount - 1))
        }
    }

    @Test func xpcRequirementPolicyIsExactDeveloperIDAndRejectsWrongTeam() throws {
        let testTeam = "ABCDE" + "12345"
        let policy = try NativeCredentialXPCSigningPolicy.make(
            teamIdentifier: testTeam
        )
        #expect(policy.callerRequirement.contains(
            "identifier \"org.zebeth.SecureSandbox.NativeStackBackend\""
        ))
        #expect(policy.callerRequirement.contains("subject.OU] = \"ABCDE12345\""))
        #expect(policy.callerRequirement.contains("1.2.840.113635.100.6.1.13"))
        #expect(NativeAuthorizationTicket.isSHA256(policy.callerRequirementSHA256))
        #expect(throws: NativeCredentialXPCError.callerIdentityRejected) {
            try NativeCredentialXPCSigningPolicy.make(teamIdentifier: "WRONG")
        }
        // The unit-test host is not the exact hardened Developer ID XPC
        // service and must never be admitted as the production service self.
        #expect(throws: NativeCredentialXPCError.callerIdentityRejected) {
            try NativeCredentialXPCSigningPolicy.resolveCurrentService()
        }
    }

    @Test func wrongSystemPeerProofRejectsBeforeParsingTokenShapedInput() async throws {
        let coordinator = FakeCredentialCoordinator()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: RejectCaller(),
            ticketReader: FixedTicketReader(try makeTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: coordinator,
            expectedXPCPeerRequirementSHA256: digest
        )
        let wrongProof = try NativeCredentialXPCPeerRequirementProof(
            requirementSHA256: String(repeating: "f", count: 64)
        )
        let reply = await service.handleSystemXPC(
            requestData: Data("access_token=must-never-be-parsed".utf8),
            proof: wrongProof,
            cancellation: NativeCredentialNeverCancelled(),
            now: now
        )
        let decoded = try NativeCredentialIPCReply.decodeExact(reply)
        #expect(decoded.errorCode == .callerRejected)
        #expect(decoded.operationID == nil)
        #expect(await coordinator.loginCount == 0)
        #expect(!String(decoding: reply, as: UTF8.self).contains("access_token"))
    }

    @Test func connectionLossAfterTicketClaimConsumesTicketWithoutMutation() async throws {
        let ticket = try makeTicket()
        let replay = MemoryReplayStore()
        let coordinator = FakeCredentialCoordinator()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: RejectCaller(),
            ticketReader: FixedTicketReader(ticket),
            replayStore: replay,
            coordinator: coordinator,
            expectedXPCPeerRequirementSHA256: digest
        )
        let proof = try NativeCredentialXPCPeerRequirementProof(requirementSHA256: digest)
        let request = try NativeCredentialIPCRequest(
            command: loginCommand(),
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest
        )
        let cancelled = await service.handleSystemXPC(
            requestData: try request.encoded(),
            proof: proof,
            cancellation: CancelOnSecondCheck(),
            now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(cancelled).errorCode == .operationRejected)
        #expect(await coordinator.loginCount == 0)

        let replayed = await service.handleSystemXPC(
            requestData: try request.encoded(),
            proof: proof,
            cancellation: NativeCredentialNeverCancelled(),
            now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(replayed).errorCode == .ticketReplayed)
        #expect(await coordinator.loginCount == 0)
    }

    @Test func ticketBindsPlanAndOperatorRequestDigests() async throws {
        let coordinator = FakeCredentialCoordinator()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(try makeTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: coordinator
        )
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )
        let changedPlan = try NativeCredentialIPCRequest(
            command: loginCommand(),
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "e", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest
        )
        let planReply = await service.handle(
            requestData: try changedPlan.encoded(), caller: caller, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(planReply).errorCode == .ticketRejected)

        let changedRequest = try NativeCredentialIPCRequest(
            command: loginCommand(),
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "e", count: 64),
            stackSHA256: stackDigest
        )
        let requestReply = await service.handle(
            requestData: try changedRequest.encoded(), caller: caller, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(requestReply).errorCode == .ticketRejected)
        #expect(await coordinator.loginCount == 0)
    }

    @Test func qualificationForSubjectACannotAuthorizeSubjectB() throws {
        let ticket = try makeProjectionTicket()
        let authorityB = try testProjectionAuthority(
            operationID: operationID,
            requestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            runtimeAuthoritySHA256: String(repeating: "9", count: 64),
            observedAt: ticket.issuedAt - 1,
            expiresAt: ticket.expiresAt,
            subjectMarker: "e"
        )
        let requestB = try NativeCredentialIPCRequest(
            command: NativeCredentialCommand(
                operationID: operationID,
                operation: .projectForSession,
                provider: .openAIChatGPT,
                sessionAuthoritySHA256: String(repeating: "9", count: 64),
                authorizationReceiptSHA256: digest
            ),
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            projectionAuthority: authorityB
        )

        #expect(throws: NativeCredentialXPCError.authorizationTicketRejected) {
            try ticket.matches(request: requestB, now: now)
        }
    }

    @Test func publicBackendCodecOwnsCanonicalBytesAndExactReplyValidation() throws {
        let encoded = try NativeCredentialXPCClientContract.encodeRequest(
            operationID: operationID,
            operation: .login,
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            authorizationReceiptSHA256: digest
        )
        let decodedRequest = try NativeCredentialIPCRequest.decodeExact(encoded)
        #expect(decodedRequest.command.operation == .login)
        #expect(decodedRequest.planSHA256 == String(repeating: "c", count: 64))
        #expect(decodedRequest.operatorRequestSHA256 == String(repeating: "d", count: 64))

        let status = try NativeCredentialStatus(
            provider: .openAIChatGPT,
            state: .loggedOut
        )
        let replyData = try NativeCredentialIPCReply.success(
            operationID: operationID,
            status: status
        ).encoded()
        let publicReply = try NativeCredentialXPCClientContract.decodeReply(replyData)
        #expect(publicReply.verified)
        #expect(publicReply.operationID == operationID)
        #expect(publicReply.status?.state == .loggedOut)
        #expect(publicReply.errorCode == nil)

        var tampered = try #require(
            JSONSerialization.jsonObject(with: replyData) as? [String: Any]
        )
        tampered["response_sha256"] = String(repeating: "f", count: 64)
        let tamperedData = try JSONSerialization.data(
            withJSONObject: tampered,
            options: [.sortedKeys]
        ) + Data([0x0a])
        #expect(throws: NativeCredentialXPCClientError.replyRejected) {
            try NativeCredentialXPCClientContract.decodeReply(tamperedData)
        }

        let serviceRequirement = try NativeCredentialXPCClientContract
            .serviceDesignatedRequirement(teamIdentifier: testTeam)
        #expect(serviceRequirement.contains(
            "identifier \"org.zebeth.SecureSandbox.NativeCredentialHelper\""
        ))
        #expect(serviceRequirement.contains("subject.OU] = \"\(testTeam)\""))
    }

    @Test func projectionLedgerCommitFailureTerminatesExactConsumerBeforeRejecting() async throws {
        let ticket = try makeProjectionTicket()
        let ledger = CommitFailingCustodyLedger()
        let terminator = RecordingConsumerTermination()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(ticket),
            replayStore: MemoryReplayStore(),
            coordinator: FakeCredentialCoordinator(
                projectionTermination: terminator
            ),
            custodyLedger: ledger,
            projectionChannelValidator: AcceptProjectionChannel()
        )
        let command = try NativeCredentialCommand(
            operationID: operationID,
            operation: .projectForSession,
            provider: .openAIChatGPT,
            sessionAuthoritySHA256: String(repeating: "9", count: 64),
            authorizationReceiptSHA256: digest
        )
        let request = try NativeCredentialIPCRequest(
            command: command,
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            projectionAuthority: ticket.projectionAuthority
        )
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )
        let data = await service.handle(
            requestData: try request.encoded(), caller: caller,
            projectionFD: 3, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(data).outcome == .rejected)
        #expect(ledger.events == ["reserve", "commit", "cancel"])
        #expect(terminator.terminateCount == 1)
    }

    @Test func projectionIdentityCommitsBeforeCredentialRelease() async throws {
        let events = OrderedProjectionEvents()
        let ledger = OrderedCustodyLedger(events: events)
        let service = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(try makeProjectionTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: FakeCredentialCoordinator(
                projectionGate: RecordingCredentialReleaseGate(events: events)
            ),
            custodyLedger: ledger,
            projectionChannelValidator: AcceptProjectionChannel(),
            projectionClock: { self.now }
        )
        let request = try projectionRequest()
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )
        let data = await service.handle(
            requestData: try request.encoded(), caller: caller,
            projectionFD: 3, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(data).outcome == .verified)
        #expect(events.values.prefix(3) == ["reserve", "commit", "release"])
    }

    @Test func expiryAfterCommitPreventsReleaseAndRetainsCommittedIdentity() async throws {
        let events = OrderedProjectionEvents()
        let ledger = OrderedCustodyLedger(events: events)
        let terminator = RecordingConsumerTermination()
        let expiry = Date(timeIntervalSince1970: TimeInterval(
            try makeProjectionTicket().expiresAt
        ))
        let clock = SequenceProjectionClock([now, now, expiry])
        let service = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(try makeProjectionTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: FakeCredentialCoordinator(
                projectionTermination: terminator,
                projectionGate: RecordingCredentialReleaseGate(events: events)
            ),
            custodyLedger: ledger,
            projectionChannelValidator: AcceptProjectionChannel(),
            projectionClock: { clock.read() }
        )
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )
        let data = await service.handle(
            requestData: try projectionRequest().encoded(), caller: caller,
            projectionFD: 3, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(data).outcome == .rejected)
        #expect(events.values == ["reserve", "commit", "abort"])
        #expect(terminator.terminateCount == 1)
    }

    @Test func cancellationInsideReleaseGateOccursAfterCommitWithoutRelease() async throws {
        let events = OrderedProjectionEvents()
        let ledger = OrderedCustodyLedger(events: events)
        let terminator = RecordingConsumerTermination()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: RejectCaller(),
            ticketReader: FixedTicketReader(try makeProjectionTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: FakeCredentialCoordinator(
                projectionTermination: terminator,
                projectionGate: RecordingCredentialReleaseGate(events: events)
            ),
            custodyLedger: ledger,
            projectionChannelValidator: AcceptProjectionChannel(),
            expectedXPCPeerRequirementSHA256: digest,
            projectionClock: { self.now }
        )
        let proof = try NativeCredentialXPCPeerRequirementProof(
            requirementSHA256: digest
        )

        let data = await service.handleSystemXPC(
            requestData: try projectionRequest().encoded(),
            proof: proof,
            projectionFD: 3,
            cancellation: CancelOnNthCheck(4),
            now: now
        )

        #expect(try NativeCredentialIPCReply.decodeExact(data).outcome == .rejected)
        #expect(events.values == ["reserve", "commit", "abort"])
        #expect(terminator.terminateCount == 1)
    }

    @Test func unprovenConsumerTerminationRetainsDurableAmbiguity() async throws {
        let ledger = CommitFailingCustodyLedger()
        let service = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(try makeProjectionTicket()),
            replayStore: MemoryReplayStore(),
            coordinator: FakeCredentialCoordinator(
                projectionError: .consumerTerminationUnproven
            ),
            custodyLedger: ledger,
            projectionChannelValidator: AcceptProjectionChannel()
        )
        let command = try NativeCredentialCommand(
            operationID: operationID, operation: .projectForSession,
            provider: .openAIChatGPT,
            sessionAuthoritySHA256: String(repeating: "9", count: 64),
            authorizationReceiptSHA256: digest
        )
        let request = try NativeCredentialIPCRequest(
            command: command, authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            projectionAuthority: try makeProjectionTicket().projectionAuthority
        )
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )
        let data = await service.handle(
            requestData: try request.encoded(), caller: caller,
            projectionFD: 3, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(data).outcome == .rejected)
        #expect(ledger.events == ["reserve"])
    }

    @Test func projectionChannelPresenceIsOperationExactBeforeTicketClaim() async throws {
        let caller = try CallerAuditEvidence(
            data: Data(repeating: 0, count: CallerAuditEvidence.byteCount)
        )
        let projectionTicket = try makeProjectionTicket()
        let projectionReplay = MemoryReplayStore()
        let projectionService = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(projectionTicket),
            replayStore: projectionReplay,
            coordinator: FakeCredentialCoordinator(),
            projectionChannelValidator: AcceptProjectionChannel()
        )
        let projectionCommand = try NativeCredentialCommand(
            operationID: operationID, operation: .projectForSession,
            provider: .openAIChatGPT,
            sessionAuthoritySHA256: String(repeating: "9", count: 64),
            authorizationReceiptSHA256: digest
        )
        let projectionRequest = try NativeCredentialIPCRequest(
            command: projectionCommand, authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            projectionAuthority: projectionTicket.projectionAuthority
        )
        let missing = await projectionService.handle(
            requestData: try projectionRequest.encoded(), caller: caller, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(missing).errorCode == .invalidRequest)
        #expect(projectionReplay.claimedCount == 0)

        let loginReplay = MemoryReplayStore()
        let loginService = NativeCredentialXPCServiceCore(
            callerValidator: AcceptCaller(),
            ticketReader: FixedTicketReader(try makeTicket()),
            replayStore: loginReplay,
            coordinator: FakeCredentialCoordinator(),
            projectionChannelValidator: AcceptProjectionChannel()
        )
        let loginRequest = try NativeCredentialIPCRequest(
            command: loginCommand(), authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest
        )
        let unexpected = await loginService.handle(
            requestData: try loginRequest.encoded(), caller: caller,
            projectionFD: 3, now: now
        )
        #expect(try NativeCredentialIPCReply.decodeExact(unexpected).errorCode == .invalidRequest)
        #expect(loginReplay.claimedCount == 0)
    }

    @Test func authorizationExpiryOrProcessAmbiguityNeverClearsProjectionCustody() throws {
        let entry = NativeCredentialProjectionLedgerEntry(
            operationID: operationID.uuidString.lowercased(),
            provider: .openAIChatGPT,
            stackSHA256: String(repeating: "8", count: 64),
            processIdentifier: 42,
            processStartTimeMicroseconds: 123_456_789,
            executableSHA256: String(repeating: "e", count: 64),
            sessionAuthoritySHA256: String(repeating: "9", count: 64),
            authorizationTicketSHA256: String(repeating: "1", count: 64),
            projectionPolicySHA256: String(repeating: "2", count: 64),
            qualificationSubjectSHA256: String(repeating: "3", count: 64),
            qualificationEvidenceSHA256: String(repeating: "4", count: 64),
            researchReleaseID: String(repeating: "5", count: 64),
            authorizationExpiresAtMilliseconds: 1
        )
        let record = NativeCredentialCustodyLedgerRecord(
            schema: NativeCredentialCustodyLedgerRecord.schemaName,
            tombstoneSHA256: nil,
            projections: [entry]
        )
        try record.validate()
        let exact = try record.observation(
            hasCredential: true,
            processIdentity: { _ in .exact(123_456_789) }
        )
        #expect(exact.state == .sessionProjected)
        #expect(exact.projectionCount == 1)
        for observation in [
            NativeCredentialProcessIdentityObservation.absent,
            .unavailable,
            .exact(987_654_321),
        ] {
            let ambiguous = try record.observation(
                hasCredential: true,
                processIdentity: { _ in observation }
            )
            #expect(ambiguous.state == .ambiguous)
            #expect(ambiguous.projectionCount == nil)
        }
        let noCredential = try record.observation(
            hasCredential: false,
            processIdentity: { _ in .absent }
        )
        #expect(noCredential.state == .ambiguous)
        #expect(noCredential.tombstoneSHA256 == nil)
    }

    private func loginCommand() throws -> NativeCredentialCommand {
        try NativeCredentialCommand(
            operationID: operationID,
            operation: .login,
            provider: .openAIChatGPT,
            authorizationReceiptSHA256: digest
        )
    }

    private func makeTicket() throws -> NativeAuthorizationTicket {
        let issuedAt = Int64(now.timeIntervalSince1970) - 1
        let expiresAt = Int64(now.timeIntervalSince1970) + 60
        var body: [String: Any] = [
            "ticket_id": ticketID,
            "operation_id": operationID.uuidString.lowercased(),
            "request_id": "33333333-3333-4333-8333-333333333333",
            "operation": "login",
            "action": "signin-begin",
            "provider": "openAIChatGPT",
            "plan_sha256": String(repeating: "c", count: 64),
            "stack_sha256": stackDigest,
            "session_authority_sha256": NSNull(),
            "request_sha256": String(repeating: "d", count: 64),
            "authorization_receipt_sha256": digest,
            "issued_at": issuedAt,
            "expires_at": expiresAt,
            "status": "authorized",
        ]
        body.merge(testProjectionAuthorityJSON(nil)) { _, replacement in replacement }
        let canonical = try testCanonicalData(body)
        let ticket = NativeAuthorizationTicket(
            schema: NativeAuthorizationTicket.schemaName,
            ticketID: ticketID,
            operationID: operationID.uuidString.lowercased(),
            requestID: "33333333-3333-4333-8333-333333333333",
            operation: .login,
            action: .signinBegin,
            provider: .openAIChatGPT,
            planSHA256: String(repeating: "c", count: 64),
            stackSHA256: stackDigest,
            sessionAuthoritySHA256: nil,
            requestSHA256: String(repeating: "d", count: 64),
            authorizationReceiptSHA256: digest,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            status: "authorized",
            ticketSHA256: NativeAuthorizationTicket.sha256(canonical)
        )
        try ticket.validate(now: now)
        return ticket
    }

    private func makeProjectionTicket() throws -> NativeAuthorizationTicket {
        let issuedAt = Int64(now.timeIntervalSince1970) - 1
        let expiresAt = Int64(now.timeIntervalSince1970) + 60
        let session = String(repeating: "9", count: 64)
        let authority = try testProjectionAuthority(
            operationID: operationID,
            requestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            runtimeAuthoritySHA256: session,
            observedAt: issuedAt - 1,
            expiresAt: expiresAt
        )
        #expect(authority.launchDescriptorSHA256
            == (try authority.computedLaunchDescriptorSHA256))
        #expect(authority.qualificationSubjectSHA256
            == (try authority.computedQualificationSubjectSHA256))
        try authority.validate(
            operationID: operationID.uuidString.lowercased(),
            requestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            sessionAuthoritySHA256: session,
            ticketIssuedAt: issuedAt,
            ticketExpiresAt: expiresAt,
            now: now
        )
        var body: [String: Any] = [
            "ticket_id": ticketID,
            "operation_id": operationID.uuidString.lowercased(),
            "request_id": "33333333-3333-4333-8333-333333333333",
            "operation": "projectForSession",
            "action": "session-start",
            "provider": "openAIChatGPT",
            "plan_sha256": String(repeating: "c", count: 64),
            "stack_sha256": stackDigest,
            "session_authority_sha256": session,
            "request_sha256": String(repeating: "d", count: 64),
            "authorization_receipt_sha256": digest,
            "issued_at": issuedAt,
            "expires_at": expiresAt,
            "status": "authorized",
        ]
        body.merge(testProjectionAuthorityJSON(authority)) { _, replacement in replacement }
        let canonical = try testCanonicalData(body)
        let ticket = NativeAuthorizationTicket(
            schema: NativeAuthorizationTicket.schemaName,
            ticketID: ticketID,
            operationID: operationID.uuidString.lowercased(),
            requestID: "33333333-3333-4333-8333-333333333333",
            operation: .projectForSession,
            action: .sessionStart,
            provider: .openAIChatGPT,
            planSHA256: String(repeating: "c", count: 64),
            stackSHA256: stackDigest,
            sessionAuthoritySHA256: session,
            requestSHA256: String(repeating: "d", count: 64),
            authorizationReceiptSHA256: digest,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            status: "authorized",
            ticketSHA256: NativeAuthorizationTicket.sha256(canonical),
            projectionAuthority: authority
        )
        #expect(ticket.ticketSHA256 == (try ticket.computedTicketSHA256))
        try ticket.validate(now: now)
        return ticket
    }

    private func projectionRequest() throws -> NativeCredentialIPCRequest {
        let ticket = try makeProjectionTicket()
        return try NativeCredentialIPCRequest(
            command: NativeCredentialCommand(
                operationID: operationID,
                operation: .projectForSession,
                provider: .openAIChatGPT,
                sessionAuthoritySHA256: String(repeating: "9", count: 64),
                authorizationReceiptSHA256: digest
            ),
            authorizationTicketID: ticketID,
            planSHA256: String(repeating: "c", count: 64),
            operatorRequestSHA256: String(repeating: "d", count: 64),
            stackSHA256: stackDigest,
            projectionAuthority: ticket.projectionAuthority
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("native-xpc-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }
}

private struct AcceptProjectionChannel:
    NativeCredentialProjectionChannelValidating, Sendable
{
    func validate(_ descriptor: Int32) throws {
        guard descriptor == 3 else { throw NativeCredentialXPCError.invalidRequest }
    }
}

private struct AcceptCaller: NativeCredentialCallerIdentityValidating {
    func validate(_ evidence: CallerAuditEvidence) throws {}
}

private struct RejectCaller: NativeCredentialCallerIdentityValidating {
    func validate(_ evidence: CallerAuditEvidence) throws {
        throw NativeCredentialXPCError.callerIdentityRejected
    }
}

private struct FixedTicketReader: NativeAuthorizationTicketReading {
    let ticket: NativeAuthorizationTicket
    init(_ ticket: NativeAuthorizationTicket) { self.ticket = ticket }
    func read(ticketID: String, now: Date) throws -> NativeAuthorizationTicket {
        guard ticket.ticketID == ticketID else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        try ticket.validate(now: now)
        return ticket
    }
}

private final class MemoryReplayStore: NativeAuthorizationTicketReplayProtecting, @unchecked Sendable {
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

private final class CommitFailingCustodyLedger:
    NativeCredentialCustodyTracking, @unchecked Sendable
{
    private let lock = NSLock()
    private var recordedEvents: [String] = []
    var events: [String] { lock.withLock { recordedEvents } }

    func observe(hasCredential: Bool, now: Date) throws -> NativeCredentialCustodyObservation {
        NativeCredentialCustodyObservation(
            state: hasCredential ? .retained : .ambiguous,
            tombstoneSHA256: nil,
            projectionCount: hasCredential ? 0 : nil
        )
    }
    func clear() throws {}
    func recordDestruction(ticketSHA256: String) throws {}
    func reserveProjection(operationID: UUID, expiresAt: Date, now: Date) throws {
        lock.withLock { recordedEvents.append("reserve") }
    }
    func commitProjection(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        binding: NativeCredentialProjectionCustodyBinding,
        now: Date
    ) throws {
        lock.withLock { recordedEvents.append("commit") }
        throw NativeCredentialXPCError.ticketReplayStoreFailed
    }
    func cancelProjection(operationID: UUID) throws {
        lock.withLock { recordedEvents.append("cancel") }
    }
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
        throw NativeCredentialXPCError.ticketReplayStoreFailed
    }
}

private final class OrderedProjectionEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []
    var values: [String] { lock.withLock { storage } }
    func append(_ value: String) { lock.withLock { storage.append(value) } }
}

private final class OrderedCustodyLedger:
    NativeCredentialCustodyTracking, @unchecked Sendable
{
    private let events: OrderedProjectionEvents
    init(events: OrderedProjectionEvents) { self.events = events }
    func observe(hasCredential: Bool, now: Date) throws
        -> NativeCredentialCustodyObservation
    {
        NativeCredentialCustodyObservation(
            state: hasCredential ? .retained : .ambiguous,
            tombstoneSHA256: nil,
            projectionCount: hasCredential ? 0 : nil
        )
    }
    func clear() throws {}
    func recordDestruction(ticketSHA256: String) throws {}
    func reserveProjection(operationID: UUID, expiresAt: Date, now: Date) throws {
        events.append("reserve")
    }
    func commitProjection(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        binding: NativeCredentialProjectionCustodyBinding,
        now: Date
    ) throws {
        events.append("commit")
    }
    func cancelProjection(operationID: UUID) throws { events.append("cancel") }
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
        throw NativeCredentialXPCError.ticketReplayStoreFailed
    }
}

private final class RecordingCredentialReleaseGate:
    NativeCredentialReleaseGating, @unchecked Sendable
{
    private let events: OrderedProjectionEvents
    init(events: OrderedProjectionEvents) { self.events = events }
    func releaseCredential(
        before deadline: NativeCredentialReleaseDeadline,
        wallClock: @escaping @Sendable () -> Date,
        monotonicClock:
            @escaping @Sendable () -> ContinuousClock.Instant,
        continuationCheck: @escaping @Sendable () throws -> Void
    ) throws {
        try continuationCheck()
        try deadline.validate(
            wallNow: wallClock(),
            monotonicNow: monotonicClock()
        )
        events.append("release")
    }
    func abortWithoutRelease() { events.append("abort") }
}

private final class SequenceProjectionClock: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Date]
    init(_ values: [Date]) { self.values = values }
    func read() -> Date {
        lock.withLock {
            guard values.count > 1 else { return values[0] }
            return values.removeFirst()
        }
    }
}

private final class RecordingConsumerTermination:
    NativeCredentialConsumerTerminationAwaiting, @unchecked Sendable
{
    private let lock = NSLock()
    private var terminations = 0
    var terminateCount: Int {
        lock.withLock { terminations }
    }
    func waitForTermination() async throws
        -> NativeCredentialConsumerTerminationEvidence
    {
        throw NativeCredentialHelperError.consumerTerminationUnproven
    }
    func terminateAndReap() async throws {
        lock.withLock { terminations += 1 }
    }
}

private final class CancelOnSecondCheck: NativeCredentialCancellationChecking, @unchecked Sendable {
    private let lock = NSLock()
    private var checks = 0

    func checkCancellation() throws {
        let shouldCancel = lock.withLock {
            checks += 1
            return checks >= 2
        }
        if shouldCancel { throw CancellationError() }
    }
}

private final class CancelOnNthCheck:
    NativeCredentialCancellationChecking, @unchecked Sendable
{
    private let lock = NSLock()
    private let cancelOnCheck: Int
    private var checks = 0

    init(_ cancelOnCheck: Int) { self.cancelOnCheck = cancelOnCheck }

    func checkCancellation() throws {
        let shouldCancel = lock.withLock {
            checks += 1
            return checks >= cancelOnCheck
        }
        if shouldCancel { throw CancellationError() }
    }
}

private actor FakeCredentialCoordinator: NativeCredentialCoordinating {
    private(set) var loginCount = 0
    private let projectionError: NativeCredentialHelperError?
    private let projectionTermination:
        (any NativeCredentialConsumerTerminationAwaiting)?
    private let projectionGate: any NativeCredentialReleaseGating

    init(
        projectionError: NativeCredentialHelperError? = nil,
        projectionTermination:
            (any NativeCredentialConsumerTerminationAwaiting)? = nil,
        projectionGate: any NativeCredentialReleaseGating =
            ImmediateCredentialReleaseGate()
    ) {
        self.projectionError = projectionError
        self.projectionTermination = projectionTermination
        self.projectionGate = projectionGate
    }

    func status(now: Date) throws -> NativeCredentialStatus { try loggedOut() }
    func login(now: Date) throws -> NativeCredentialStatus {
        loginCount += 1
        return try loggedOut()
    }
    func refresh(now: Date) throws -> NativeCredentialStatus { try loggedOut() }
    func logout() throws -> NativeCredentialStatus { try loggedOut() }
    func destroyLocalCredential() throws -> NativeCredentialStatus { try loggedOut() }
    func recoverLocalState() throws -> NativeCredentialStatus { try loggedOut() }
    func prepareProjection(
        _ request: CredentialProjectionRequest,
        now: Date
    ) throws -> PreparedCredentialConsumer {
        if let projectionError { throw projectionError }
        let launched = LaunchedCredentialConsumer(
            processIdentifier: 42,
            processStartTimeMicroseconds: 123_456_789,
            executableSHA256: String(repeating: "e", count: 64),
            sessionAuthoritySHA256: request.sessionAuthoritySHA256,
            startedAt: now,
            termination: projectionTermination ?? ImmediateConsumerTermination(
                evidence: NativeCredentialConsumerTerminationEvidence(
                    operationID: request.operationID,
                    processIdentifier: 42,
                    processStartTimeMicroseconds: 123_456_789,
                    sessionAuthoritySHA256:
                        request.sessionAuthoritySHA256
                )
            )
        )
        return PreparedCredentialConsumer(
            consumer: launched,
            gate: projectionGate
        )
    }

    private func loggedOut() throws -> NativeCredentialStatus {
        try NativeCredentialStatus(provider: .openAIChatGPT, state: .loggedOut)
    }
}

private struct ImmediateCredentialReleaseGate: NativeCredentialReleaseGating {
    func releaseCredential(
        before deadline: NativeCredentialReleaseDeadline,
        wallClock: @escaping @Sendable () -> Date,
        monotonicClock:
            @escaping @Sendable () -> ContinuousClock.Instant,
        continuationCheck: @escaping @Sendable () throws -> Void
    ) throws { try continuationCheck() }
    func abortWithoutRelease() {}
}

private struct ImmediateConsumerTermination:
    NativeCredentialConsumerTerminationAwaiting
{
    let evidence: NativeCredentialConsumerTerminationEvidence

    func waitForTermination() async throws
        -> NativeCredentialConsumerTerminationEvidence
    {
        evidence
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
