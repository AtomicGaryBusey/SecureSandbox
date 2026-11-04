import Foundation

struct NativeCredentialProjectionCompletionMonitor: Sendable {
    let custodyLedger: any NativeCredentialCustodyTracking

    @discardableResult
    func start(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        termination: any NativeCredentialConsumerTerminationAwaiting
    ) -> Task<Void, Never> {
        Task.detached(priority: .utility) {
            do {
                let evidence = try await termination.waitForTermination()
                guard evidence.operationID == operationID,
                      evidence.processIdentifier
                        == consumer.processIdentifier,
                      evidence.processStartTimeMicroseconds
                        == consumer.processStartTimeMicroseconds,
                      evidence.sessionAuthoritySHA256
                        == consumer.sessionAuthoritySHA256 else {
                    throw NativeCredentialHelperError
                        .consumerTerminationUnproven
                }
                try custodyLedger.completeTerminatedProjection(
                    operationID: operationID,
                    processIdentifier: evidence.processIdentifier,
                    processStartTimeMicroseconds:
                        evidence.processStartTimeMicroseconds,
                    sessionAuthoritySHA256:
                        evidence.sessionAuthoritySHA256
                )
            } catch {
                // Crash, nonzero exit, identity ambiguity, and persistence
                // failure deliberately leave the durable projection in place.
            }
        }
    }
}
