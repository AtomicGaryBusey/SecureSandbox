import Darwin
import Foundation
import Testing
@testable import SecureSandboxNativeCredentialHelper

struct NativeCredentialProjectionCompletionTests {
    private let operationID = UUID(
        uuidString: "11111111-1111-4111-8111-111111111111"
    )!
    private let executableSHA256 = String(repeating: "e", count: 64)
    private let sessionAuthoritySHA256 = String(repeating: "9", count: 64)
    private let processIdentifier: Int32 = 42
    private let processStartTimeMicroseconds: UInt64 = 123_456_789

    @Test func exactSuccessfulChildReapCompletesOnlyItsProjection() async {
        let ledger = RecordingCompletionLedger()
        let consumer = launchedConsumer()
        let monitor = NativeCredentialProjectionCompletionMonitor(
            custodyLedger: ledger
        )
        let task = monitor.start(
            operationID: operationID,
            consumer: consumer,
            termination: FixedConsumerTermination(
                result: .success(terminationEvidence())
            )
        )

        await task.value

        #expect(ledger.completions == [CompletionCall(
            operationID: operationID,
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )])
    }

    @Test func crashOrMissingTerminalAckRetainsDurableAmbiguity() async {
        let ledger = RecordingCompletionLedger()
        let monitor = NativeCredentialProjectionCompletionMonitor(
            custodyLedger: ledger
        )
        let task = monitor.start(
            operationID: operationID,
            consumer: launchedConsumer(),
            termination: FixedConsumerTermination(
                result: .failure(.consumerTerminationUnproven)
            )
        )

        await task.value

        #expect(ledger.completions.isEmpty)
    }

    @Test func substitutedTerminationIdentityCannotCompleteProjection() async {
        let ledger = RecordingCompletionLedger()
        let monitor = NativeCredentialProjectionCompletionMonitor(
            custodyLedger: ledger
        )
        let substituted = NativeCredentialConsumerTerminationEvidence(
            operationID: UUID(),
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            sessionAuthoritySHA256: String(repeating: "8", count: 64)
        )
        let task = monitor.start(
            operationID: operationID,
            consumer: launchedConsumer(),
            termination: FixedConsumerTermination(result: .success(substituted))
        )

        await task.value

        #expect(ledger.completions.isEmpty)
    }

    @Test func directChildSuccessRequiresIndependentIdentityAbsence() async throws {
        let child = fixedChild(exitStatus: 0, identity: .absent)
        let waiter = SystemExactCredentialConsumerTermination(
            child: child,
            operationID: operationID,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )

        let evidence = try await waiter.waitForTermination()

        #expect(evidence == terminationEvidence(
            processIdentifier: processIdentifier
        ))
    }

    @Test func childFailureCannotProveTerminalCustody() async throws {
        let child = fixedChild(exitStatus: 1 << 8, identity: .absent)
        let waiter = SystemExactCredentialConsumerTermination(
            child: child,
            operationID: operationID,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )

        await #expect(
            throws: NativeCredentialHelperError.consumerTerminationUnproven
        ) {
            try await waiter.waitForTermination()
        }
    }

    @Test func sameProcessIdentityAfterWaitCannotCompleteProjection() async throws {
        let child = fixedChild(
            exitStatus: 0,
            identity: .exact(processStartTimeMicroseconds)
        )
        let waiter = SystemExactCredentialConsumerTermination(
            child: child,
            operationID: operationID,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )

        await #expect(
            throws: NativeCredentialHelperError.consumerTerminationUnproven
        ) {
            try await waiter.waitForTermination()
        }
    }

    @Test func exactCompletionRejectsCrashAmbiguityAndPermitsCapacityReuse() throws {
        let entries = try (1...64).map { index in
            try projectionEntry(index: index)
        }
        let record = NativeCredentialCustodyLedgerRecord(
            schema: NativeCredentialCustodyLedgerRecord.schemaName,
            tombstoneSHA256: nil,
            projections: entries
        )
        try record.validate()
        let firstID = try #require(UUID(uuidString: entries[0].operationID))

        for processIdentity in [
            NativeCredentialProcessIdentityObservation.unavailable,
            .exact(entries[0].processStartTimeMicroseconds!),
        ] {
            #expect(throws: NativeCredentialXPCError.ticketReplayStoreFailed) {
                try record.completingTerminatedProjection(
                    operationID: firstID,
                    processIdentifier: entries[0].processIdentifier,
                    processStartTimeMicroseconds:
                        entries[0].processStartTimeMicroseconds!,
                    sessionAuthoritySHA256: sessionAuthoritySHA256,
                    processIdentity: processIdentity
                )
            }
        }

        let completed = try record.completingTerminatedProjection(
            operationID: firstID,
            processIdentifier: entries[0].processIdentifier,
            processStartTimeMicroseconds:
                entries[0].processStartTimeMicroseconds!,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            processIdentity: .absent
        )
        #expect(completed.projections.count == 63)

        let replacement = NativeCredentialCustodyLedgerRecord(
            schema: NativeCredentialCustodyLedgerRecord.schemaName,
            tombstoneSHA256: nil,
            projections: (completed.projections + [try projectionEntry(index: 65)])
                .sorted { $0.operationID < $1.operationID }
        )
        try replacement.validate()
        #expect(replacement.projections.count == 64)
    }

    @Test func exactPIDReuseIsIndependentAbsenceEvidence() throws {
        let entry = try projectionEntry(index: 1)
        let record = NativeCredentialCustodyLedgerRecord(
            schema: NativeCredentialCustodyLedgerRecord.schemaName,
            tombstoneSHA256: nil,
            projections: [entry]
        )
        let completed = try record.completingTerminatedProjection(
            operationID: try #require(UUID(uuidString: entry.operationID)),
            processIdentifier: entry.processIdentifier,
            processStartTimeMicroseconds:
                entry.processStartTimeMicroseconds!,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            processIdentity: .exact(
                entry.processStartTimeMicroseconds! + 1
            )
        )

        #expect(completed.projections.isEmpty)
    }

    @Test func cleanupNeverSignalsMismatchedOrUnavailablePIDGeneration() {
        for identity in [
            NativeCredentialProcessIdentityObservation.unavailable,
            .exact(processStartTimeMicroseconds + 1),
        ] {
            let signals = SignalCounter()
            let child = SystemOwnedCredentialConsumerProcess(
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds:
                    processStartTimeMicroseconds,
                processIdentity: { _ in identity },
                signalProcess: { identifier, signal in
                    signals.record(identifier: identifier, signal: signal)
                    return (0, 0)
                },
                pollForProcess: { _ in (0, 0, 0) },
                waitForProcess: { ($0, 0) }
            )

            #expect(
                throws: NativeCredentialHelperError
                    .consumerTerminationUnproven
            ) {
                try child.terminateAndReap()
            }
            #expect(signals.count == 0)
        }
    }

    @Test func cleanupRequiresIndependentPostReapAbsenceOrReuse() throws {
        let successfulIdentity = ProcessIdentitySequence([
            .exact(processStartTimeMicroseconds),
            .exact(processStartTimeMicroseconds + 1),
        ])
        let signals = SignalCounter()
        let child = SystemOwnedCredentialConsumerProcess(
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            processIdentity: { _ in successfulIdentity.next() },
            signalProcess: { identifier, signal in
                signals.record(identifier: identifier, signal: signal)
                return (0, 0)
            },
            pollForProcess: { _ in (0, 0, 0) },
            waitForProcess: { ($0, 0) }
        )

        try child.terminateAndReap()
        #expect(signals.count == 1)

        let unresolvedIdentity = ProcessIdentitySequence([
            .exact(processStartTimeMicroseconds),
            .exact(processStartTimeMicroseconds),
        ])
        let unresolved = SystemOwnedCredentialConsumerProcess(
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            processIdentity: { _ in unresolvedIdentity.next() },
            signalProcess: { _, _ in (0, 0) },
            pollForProcess: { _ in (0, 0, 0) },
            waitForProcess: { ($0, 0) }
        )
        #expect(
            throws: NativeCredentialHelperError.consumerTerminationUnproven
        ) {
            try unresolved.terminateAndReap()
        }
    }

    @Test func alreadyExitedOwnedZombieIsReapedWithoutRawPIDSignal() throws {
        let signals = SignalCounter()
        let child = SystemOwnedCredentialConsumerProcess(
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            processIdentity: { _ in .absent },
            signalProcess: { identifier, signal in
                signals.record(identifier: identifier, signal: signal)
                return (0, 0)
            },
            pollForProcess: { identifier in (identifier, 1 << 8, 0) },
            waitForProcess: { ($0, 1 << 8) }
        )

        try child.terminateAndReap()

        #expect(signals.count == 0)
    }

    @Test func posixSpawnedChildIsOwnedUntilItsOnlyWaitPID() async throws {
        let null = open("/dev/null", O_RDWR | O_CLOEXEC)
        #expect(null >= 0)
        defer { if null >= 0 { close(null) } }
        let identifier = try SystemCredentialConsumerSpawner.spawn(
            executableURL: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["0.02"],
            environment: ["PATH": "/usr/bin:/bin"],
            standardInput: null,
            standardOutput: null
        )
        guard case .exact(let start) =
                nativeCredentialProcessIdentity(identifier) else {
            try SystemCredentialConsumerSpawner
                .terminateUnidentifiedDirectChild(identifier)
            Issue.record("spawned direct-child identity unavailable")
            return
        }
        let child = SystemOwnedCredentialConsumerProcess(
            processIdentifier: identifier,
            processStartTimeMicroseconds: start
        )
        let waiter = SystemExactCredentialConsumerTermination(
            child: child,
            operationID: operationID,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )
        _ = try await waiter.waitForTermination()
    }

    private func launchedConsumer() -> LaunchedCredentialConsumer {
        LaunchedCredentialConsumer(
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            executableSHA256: executableSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            startedAt: Date(timeIntervalSince1970: 2_000_000_000)
        )
    }

    private func fixedChild(
        exitStatus: Int32,
        identity: NativeCredentialProcessIdentityObservation
    ) -> SystemOwnedCredentialConsumerProcess {
        SystemOwnedCredentialConsumerProcess(
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            processIdentity: { _ in identity },
            signalProcess: { _, _ in (0, 0) },
            waitForProcess: { ($0, exitStatus) }
        )
    }

    private func terminationEvidence(
        processIdentifier: Int32? = nil
    ) -> NativeCredentialConsumerTerminationEvidence {
        NativeCredentialConsumerTerminationEvidence(
            operationID: operationID,
            processIdentifier: processIdentifier ?? self.processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            sessionAuthoritySHA256: sessionAuthoritySHA256
        )
    }

    private func projectionEntry(
        index: Int
    ) throws -> NativeCredentialProjectionLedgerEntry {
        let operationID = try #require(UUID(uuidString: String(
            format: "00000000-0000-4000-8000-%012x", index
        )))
        return NativeCredentialProjectionLedgerEntry(
            operationID: operationID.uuidString.lowercased(),
            provider: .openAIChatGPT,
            stackSHA256: String(repeating: "8", count: 64),
            processIdentifier: Int32(100 + index),
            processStartTimeMicroseconds: UInt64(1_000 + index),
            executableSHA256: executableSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            authorizationTicketSHA256: String(repeating: "1", count: 64),
            projectionPolicySHA256: String(repeating: "2", count: 64),
            qualificationSubjectSHA256: String(repeating: "3", count: 64),
            qualificationEvidenceSHA256: String(repeating: "4", count: 64),
            researchReleaseID: String(repeating: "5", count: 64),
            authorizationExpiresAtMilliseconds: 2_000_000_000_000
        )
    }
}

private struct FixedConsumerTermination:
    NativeCredentialConsumerTerminationAwaiting
{
    let result: Result<
        NativeCredentialConsumerTerminationEvidence,
        NativeCredentialHelperError
    >

    func waitForTermination() async throws
        -> NativeCredentialConsumerTerminationEvidence
    {
        try result.get()
    }
}

private struct CompletionCall: Equatable {
    let operationID: UUID
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let sessionAuthoritySHA256: String
}

private final class RecordingCompletionLedger:
    NativeCredentialCustodyTracking, @unchecked Sendable
{
    private let lock = NSLock()
    private var recordedCompletions: [CompletionCall] = []

    var completions: [CompletionCall] {
        lock.withLock { recordedCompletions }
    }

    func observe(
        hasCredential: Bool,
        now: Date
    ) throws -> NativeCredentialCustodyObservation {
        NativeCredentialCustodyObservation(
            state: .ambiguous,
            tombstoneSHA256: nil,
            projectionCount: nil
        )
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
    ) throws {
        lock.withLock {
            recordedCompletions.append(CompletionCall(
                operationID: operationID,
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds,
                sessionAuthoritySHA256: sessionAuthoritySHA256
            ))
        }
    }
    func reconcileProjection(
        ticket: NativeProjectionReconciliationTicket,
        now: Date
    ) throws -> NativeProjectionReconciliationCompletion {
        throw NativeCredentialXPCError.ticketReplayStoreFailed
    }
}

private final class SignalCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    var count: Int { lock.withLock { value } }

    func record(identifier: Int32, signal: Int32) {
        lock.withLock { value += 1 }
    }
}

private final class ProcessIdentitySequence: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [NativeCredentialProcessIdentityObservation]

    init(_ values: [NativeCredentialProcessIdentityObservation]) {
        self.values = values
    }

    func next() -> NativeCredentialProcessIdentityObservation {
        lock.withLock {
            values.isEmpty ? .unavailable : values.removeFirst()
        }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
