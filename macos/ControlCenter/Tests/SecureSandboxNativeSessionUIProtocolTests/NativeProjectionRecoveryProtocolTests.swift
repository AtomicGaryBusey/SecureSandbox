import Foundation
import Testing
@testable import SecureSandboxNativeSessionUIProtocol

private let recoveryID = "11111111-1111-4111-8111-111111111111"
private let originalID = "22222222-2222-4222-8222-222222222222"
private let sessionID = "33333333-3333-4333-8333-333333333333"
private let digestA = String(repeating: "a", count: 64)
private let digestB = String(repeating: "b", count: 64)
private let digestC = String(repeating: "c", count: 64)
private let digestD = String(repeating: "d", count: 64)
private let digestE = String(repeating: "e", count: 64)
private let digestF = String(repeating: "f", count: 64)

private func recoveryRequest(
    _ kind: NativeProjectionRecoveryKind
) throws -> NativeProjectionRecoveryPlanRequest {
    try NativeProjectionRecoveryPlanRequest(
        kind: kind,
        recoveryOperationID: recoveryID,
        originalOperationID: originalID
    )
}

private func identityPlanObject(extra: [String: Any] = [:]) throws
    -> [String: Any]
{
    var body: [String: Any] = [
        "created_at": 1_000,
        "expires_at": 1_120,
        "host_release_id": digestA,
        "original_operation_id": originalID,
        "recovery_operation_id": recoveryID,
        "session_authority_sha256": digestB,
        "session_id": sessionID,
        "stack_id": "openai-codex-daybreak",
        "stack_sha256": digestC,
    ]
    body.merge(extra) { _, new in new }
    var plan = body
    plan["schema"] =
        "secure-sandbox-native-projection-identity-recovery-plan-v1"
    plan["plan_sha256"] = try CanonicalNativeJSON.digest(body)
    return plan
}

private func reconciliationPlanObject(extra: [String: Any] = [:]) throws
    -> [String: Any]
{
    var body: [String: Any] = [
        "consumer_executable_sha256": digestD,
        "created_at": 1_000,
        "egress_closed_evidence_sha256": digestE,
        "expires_at": 1_120,
        "guest_absence_evidence_sha256": digestF,
        "host_release_id": digestA,
        "original_operation_id": originalID,
        "process_identifier": 42,
        "process_start_time_us": 987_654_321,
        "recovery_operation_id": recoveryID,
        "session_authority_sha256": digestB,
        "session_id": sessionID,
        "stack_id": "openai-codex-daybreak",
        "stack_sha256": digestC,
    ]
    body.merge(extra) { _, new in new }
    var plan = body
    plan["schema"] =
        "secure-sandbox-native-projection-reconciliation-plan-v1"
    plan["plan_sha256"] = try CanonicalNativeJSON.digest(body)
    return plan
}

private func planReply(
    request: NativeProjectionRecoveryPlanRequest,
    plan: [String: Any],
    schema: String
) throws -> Data {
    let body: [String: Any] = [
        "plan": plan,
        "recovery_operation_id": request.recoveryOperationID,
        "request_sha256": request.requestSHA256,
    ]
    var reply = body
    reply["schema"] = schema
    reply["reply_sha256"] = try CanonicalNativeJSON.digest(body)
    return try CanonicalNativeJSON.encodeLine(reply)
}

@Suite(.serialized) struct NativeProjectionRecoveryProtocolTests {
    @Test func exactIdentityPlanIsCanonicalAndBoundToOneRequest() throws {
        let request = try recoveryRequest(.identityImport)
        let requestObject = try CanonicalNativeJSON.parseLine(
            request.canonicalData, maximumBytes: 32 * 1_024
        )
        #expect(Set(requestObject.keys) == [
            "schema", "recovery_operation_id", "original_operation_id",
            "request_sha256",
        ])
        let plan = try NativeProjectionRecoveryProtocol.decodeIdentityPlanReply(
            planReply(
                request: request,
                plan: identityPlanObject(),
                schema:
                    "secure-sandbox-native-projection-identity-recovery-plan-query-reply-v1"
            ),
            request: request,
            now: 1_060
        )
        #expect(plan.stackID == "openai-codex-daybreak")
        #expect(plan.sessionAuthoritySHA256 == digestB)

        let replayedRequest = try NativeProjectionRecoveryPlanRequest(
            kind: .identityImport,
            recoveryOperationID: "44444444-4444-4444-8444-444444444444",
            originalOperationID: originalID
        )
        #expect(throws: (any Error).self) {
            try NativeProjectionRecoveryProtocol.decodeIdentityPlanReply(
                planReply(
                    request: request,
                    plan: identityPlanObject(),
                    schema:
                        "secure-sandbox-native-projection-identity-recovery-plan-query-reply-v1"
                ),
                request: replayedRequest,
                now: 1_060
            )
        }
    }

    @Test func wrongKindExtraFieldAndDigestSubstitutionFailClosed() throws {
        let identity = try recoveryRequest(.identityImport)
        #expect(throws: (any Error).self) {
            try NativeProjectionRecoveryProtocol.decodeIdentityPlanReply(
                planReply(
                    request: identity,
                    plan: identityPlanObject(extra: ["token": "forbidden"]),
                    schema:
                        "secure-sandbox-native-projection-identity-recovery-plan-query-reply-v1"
                ),
                request: identity,
                now: 1_060
            )
        }
        let reconciliation = try recoveryRequest(.reconciliation)
        #expect(throws: (any Error).self) {
            try NativeProjectionRecoveryProtocol.decodeIdentityPlanReply(
                planReply(
                    request: reconciliation,
                    plan: reconciliationPlanObject(),
                    schema:
                        "secure-sandbox-native-projection-reconciliation-plan-query-reply-v1"
                ),
                request: reconciliation,
                now: 1_060
            )
        }
        var substituted = try reconciliationPlanObject()
        substituted["stack_sha256"] = digestA
        #expect(throws: (any Error).self) {
            try NativeProjectionRecoveryProtocol.decodeReconciliationPlanReply(
                planReply(
                    request: reconciliation,
                    plan: substituted,
                    schema:
                        "secure-sandbox-native-projection-reconciliation-plan-query-reply-v1"
                ),
                request: reconciliation,
                now: 1_060
            )
        }
    }

    @Test func reconciliationPlanPinsConsumerAndBothClosureProofs() throws {
        let request = try recoveryRequest(.reconciliation)
        let plan = try NativeProjectionRecoveryProtocol
            .decodeReconciliationPlanReply(
                planReply(
                    request: request,
                    plan: reconciliationPlanObject(),
                    schema:
                        "secure-sandbox-native-projection-reconciliation-plan-query-reply-v1"
                ),
                request: request,
                now: 1_060
            )
        #expect(plan.processIdentifier == 42)
        #expect(plan.processStartTimeMicroseconds == 987_654_321)
        #expect(plan.guestAbsenceEvidenceSHA256 == digestF)
        #expect(plan.egressClosedEvidenceSHA256 == digestE)
    }

    @Test func authorizationResultsRejectExtraFieldsAndPlanSubstitution() throws {
        let identityRequest = try recoveryRequest(.identityImport)
        let identityPlan = try NativeProjectionRecoveryProtocol
            .decodeIdentityPlanReply(
                planReply(
                    request: identityRequest,
                    plan: identityPlanObject(),
                    schema:
                        "secure-sandbox-native-projection-identity-recovery-plan-query-reply-v1"
                ),
                request: identityRequest,
                now: 1_060
            )
        let body: [String: Any] = [
            "consumer_executable_sha256": digestD,
            "identity_evidence_sha256": digestE,
            "original_operation_id": originalID,
            "outcome": "verified",
            "process_identifier": 42,
            "process_start_time_us": 987_654_321,
            "recovery_operation_id": recoveryID,
            "session_authority_sha256": digestB,
        ]
        var result = body
        result["schema"] =
            "secure-sandbox-native-projection-identity-recovery-reply-v1"
        result["reply_sha256"] = try CanonicalNativeJSON.digest(body)
        let decoded = try JSONDecoder().decode(
            NativeProjectionIdentityRecoveryResult.self,
            from: CanonicalNativeJSON.encodeLine(result)
        )
        try decoded.validate(plan: identityPlan)

        result["raw_provider_identifier"] = "forbidden"
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(
                NativeProjectionIdentityRecoveryResult.self,
                from: CanonicalNativeJSON.encodeLine(result)
            )
        }
    }
}
