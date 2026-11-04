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
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try process.run()
        let waiter = SystemExactCredentialConsumerTermination(
            process: process,
            operationID: operationID,
            processIdentifier: process.processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            processIdentity: { _ in .absent }
        )

        let evidence = try await waiter.waitForTermination()

        #expect(evidence == terminationEvidence(
            processIdentifier: process.processIdentifier
        ))
    }

    @Test func childFailureCannotProveTerminalCustody() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/false")
        try process.run()
        let waiter = SystemExactCredentialConsumerTermination(
            process: process,
            operationID: operationID,
            processIdentifier: process.processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            processIdentity: { _ in .absent }
        )

        await #expect(
            throws: NativeCredentialHelperError.consumerTerminationUnproven
        ) {
            try await waiter.waitForTermination()
        }
    }

    @Test func sameProcessIdentityAfterWaitCannotCompleteProjection() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try process.run()
        let waiter = SystemExactCredentialConsumerTermination(
            process: process,
            operationID: operationID,
            processIdentifier: process.processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            processIdentity: { _ in .exact(123_456_789) }
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
            let terminator = SystemNativeCredentialProjectionTerminator(
                processIdentity: { _ in identity },
                signalProcess: { identifier, signal in
                    signals.record(identifier: identifier, signal: signal)
                    return (0, 0)
                },
                reapProcess: { $0 }
            )

            #expect(throws: NativeCredentialXPCError.operationRejected) {
                try terminator.terminateAndReap(
                    processIdentifier: processIdentifier,
                    processStartTimeMicroseconds:
                        processStartTimeMicroseconds
                )
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
        let terminator = SystemNativeCredentialProjectionTerminator(
            processIdentity: { _ in successfulIdentity.next() },
            signalProcess: { identifier, signal in
                signals.record(identifier: identifier, signal: signal)
                return (0, 0)
            },
            reapProcess: { $0 }
        )

        try terminator.terminateAndReap(
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds
        )
        #expect(signals.count == 1)

        let unresolvedIdentity = ProcessIdentitySequence([
            .exact(processStartTimeMicroseconds),
            .exact(processStartTimeMicroseconds),
        ])
        let unresolved = SystemNativeCredentialProjectionTerminator(
            processIdentity: { _ in unresolvedIdentity.next() },
            signalProcess: { _, _ in (0, 0) },
            reapProcess: { $0 }
        )
        #expect(throws: NativeCredentialXPCError.operationRejected) {
            try unresolved.terminateAndReap(
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds
            )
        }
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
            processIdentifier: Int32(100 + index),
            processStartTimeMicroseconds: UInt64(1_000 + index),
            executableSHA256: executableSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
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
