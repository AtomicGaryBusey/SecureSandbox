import Foundation
import Testing
@testable import SecureSandboxNativeSessionUIProtocol

private let deploymentQueryID = "11111111-1111-4111-8111-111111111111"
private let deploymentID = "22222222-2222-4222-8222-222222222222"
private let promotionID = "33333333-3333-4333-8333-333333333333"
private let deploymentA = String(repeating: "a", count: 64)
private let deploymentB = String(repeating: "b", count: 64)
private let deploymentC = String(repeating: "c", count: 64)
private let deploymentD = String(repeating: "d", count: 64)
private let deploymentE = String(repeating: "e", count: 64)
private let deploymentF = String(repeating: "f", count: 64)

private func absentGuestStatus(
    role: String, observedAt: Int = 900
) throws -> [String: Any] {
    let body: [String: Any] = [
        "catalog_sha256": NSNull(),
        "closed_evidence_sha256": NSNull(),
        "generation_kind": "absent",
        "observed_at": observedAt,
        "package_sha256": NSNull(),
        "pending": false,
        "release_id": NSNull(),
        "role": role,
        "state": "absent",
    ]
    var value = body
    value["schema"] = "secure-sandbox-native-deployment-status-v1"
    value["evidence_sha256"] = try CanonicalNativeJSON.digest(body)
    return value
}

private func stableStatusDigest(_ value: [String: Any]) throws -> String {
    try CanonicalNativeJSON.digest([
        "catalog_sha256": value["catalog_sha256"]!,
        "closed_evidence_sha256": value["closed_evidence_sha256"]!,
        "generation_kind": value["generation_kind"]!,
        "package_sha256": value["package_sha256"]!,
        "release_id": value["release_id"]!,
        "role": value["role"]!,
        "state": value["state"]!,
    ])
}

private func deploymentPlan(
    hostReleaseID: String = deploymentA,
    createdAt: Int = 1_000,
    expiresAt: Int = 2_000,
    extra: [String: Any] = [:],
    omitting: String? = nil
) throws -> [String: Any] {
    let gateway = try absentGuestStatus(role: "gateway")
    let research = try absentGuestStatus(role: "research")
    var body: [String: Any] = [
        "catalog_sha256": deploymentB,
        "created_at": createdAt,
        "deployment_id": deploymentID,
        "expires_at": expiresAt,
        "gateway_package_sha256": deploymentC,
        "host_release_id": hostReleaseID,
        "previous_gateway_package_sha256": NSNull(),
        "previous_gateway_status_sha256": try stableStatusDigest(gateway),
        "previous_research_package_sha256": NSNull(),
        "previous_research_status_sha256": try stableStatusDigest(research),
        "research_package_sha256": deploymentD,
    ]
    body.merge(extra) { _, new in new }
    if let omitting { body.removeValue(forKey: omitting) }
    var value = body
    value["schema"] = "secure-sandbox-native-deployment-plan-v1"
    value["plan_sha256"] = try CanonicalNativeJSON.digest(body)
    return value
}

private func deploymentPlanResponse(
    hostReleaseID: String = deploymentA,
    createdAt: Int = 1_000,
    expiresAt: Int = 2_000,
    planExtra: [String: Any] = [:],
    planOmitting: String? = nil
) throws -> [String: Any] {
    let plan = try deploymentPlan(
        hostReleaseID: hostReleaseID,
        createdAt: createdAt,
        expiresAt: expiresAt,
        extra: planExtra,
        omitting: planOmitting
    )
    let gateway = try absentGuestStatus(role: "gateway")
    let research = try absentGuestStatus(role: "research")
    let body: [String: Any] = [
        "payload_container_sha256": deploymentE,
        "plan": plan,
        "prior_gateway": gateway,
        "prior_research": research,
    ]
    var value = body
    value["schema"] = "secure-sandbox-native-deployment-plan-response-v1"
    value["response_sha256"] = try CanonicalNativeJSON.digest(body)
    return value
}

private func deploymentReply(
    request: NativeDeploymentQueryRequest,
    result: [String: Any],
    hostReleaseID: String = deploymentA,
    schema: String? = nil,
    command: String? = nil,
    extra: [String: Any] = [:]
) throws -> Data {
    let replySchema: String
    switch request.command {
    case .plan: replySchema = "secure-sandbox-native-deployment-plan-reply-v1"
    case .status:
        replySchema = "secure-sandbox-native-deployment-status-reply-v1"
    case .recoveryPlan:
        replySchema =
            "secure-sandbox-native-deployment-recovery-plan-reply-v1"
    }
    let body: [String: Any] = [
        "command": command ?? request.command.rawValue,
        "host_release_id": hostReleaseID,
        "query_id": request.queryID,
        "request_sha256": request.requestSHA256,
        "result": result,
    ]
    var reply = body
    reply["schema"] = schema ?? replySchema
    reply["reply_sha256"] = try CanonicalNativeJSON.digest(body)
    reply.merge(extra) { _, new in new }
    return try CanonicalNativeJSON.encodeLine(reply)
}

private func recoveryPlan(
    actions: [String] = ["rollback", "resume"]
) throws -> [String: Any] {
    let response = try deploymentPlanResponse()
    let body: [String: Any] = [
        "active_journal_sha256": deploymentF,
        "allowed_actions": actions,
        "deployment_id": deploymentID,
        "gateway_status_sha256": NSNull(),
        "host_release_id": deploymentA,
        "observed_pair": "candidate-prior",
        "phase": "research-installed",
        "plan_response": response,
        "research_status_sha256": NSNull(),
    ]
    var value = body
    value["schema"] = "secure-sandbox-native-deployment-recovery-plan-v1"
    value["recovery_plan_sha256"] = try CanonicalNativeJSON.digest(body)
    return value
}

private func catalogGate(
    state: String = "active",
    activePromotionID: Any = promotionID,
    activeStateSHA256: Any = deploymentB
) throws -> [String: Any] {
    let body: [String: Any] = [
        "active_promotion_id": activePromotionID,
        "active_state_sha256": activeStateSHA256,
        "state": state,
    ]
    var value = body
    value["schema"] =
        "secure-sandbox-native-stack-catalog-promotion-gate-state-v1"
    value["gate_sha256"] = try CanonicalNativeJSON.digest(body)
    return value
}

private func catalogGateReply(
    request: NativeCatalogPromotionGateRequest,
    gate: [String: Any],
    hostReleaseID: String = deploymentA
) throws -> Data {
    let body: [String: Any] = [
        "command": NativeCatalogPromotionGateRequest.command,
        "gate": gate,
        "host_release_id": hostReleaseID,
        "query_id": request.queryID,
        "request_sha256": request.requestSHA256,
    ]
    var reply = body
    reply["schema"] =
        "secure-sandbox-native-stack-catalog-promotion-gate-reply-v1"
    reply["reply_sha256"] = try CanonicalNativeJSON.digest(body)
    return try CanonicalNativeJSON.encodeLine(reply)
}

private func catalogTerminal(
    expectedGateSHA256: String,
    historicalHostReleaseID: String = deploymentA
) throws -> [String: Any] {
    let body: [String: Any] = [
        "catalog_sha256": deploymentC,
        "expected_gate_sha256": expectedGateSHA256,
        "host_release_id": historicalHostReleaseID,
        "promotion_id": promotionID,
        "promotion_receipt_sha256": deploymentD,
        "recovery_intent_sha256": deploymentE,
        "replay_authority_sha256": deploymentF,
        "state": "finalized",
    ]
    var value = body
    value["schema"] =
        "secure-sandbox-native-stack-catalog-recovery-terminal-v1"
    value["terminal_sha256"] = try CanonicalNativeJSON.digest(body)
    return value
}

private func catalogRecoveryReply(
    request: NativeCatalogPromotionRecoveryRequest,
    terminal: [String: Any],
    currentHostReleaseID: String = deploymentA
) throws -> Data {
    let body: [String: Any] = [
        "command": NativeCatalogPromotionRecoveryRequest.command,
        "host_release_id": currentHostReleaseID,
        "recovery_id": request.recoveryID,
        "request_sha256": request.requestSHA256,
        "terminal": terminal,
    ]
    var reply = body
    reply["schema"] =
        "secure-sandbox-native-stack-catalog-recovery-reply-v1"
    reply["reply_sha256"] = try CanonicalNativeJSON.digest(body)
    return try CanonicalNativeJSON.encodeLine(reply)
}

@Suite(.serialized) struct NativeDeploymentProtocolTests {
    @Test func exactPlanPreservesCanonicalAuthorizationEvidence() throws {
        let request = try NativeDeploymentQueryRequest(
            command: .plan, queryID: deploymentQueryID
        )
        let raw = try deploymentReply(
            request: request, result: deploymentPlanResponse()
        )
        let result = try NativeDeploymentProtocol.decodePlanReply(
            raw, request: request, now: 1_500
        )
        #expect(result.currentHostReleaseID == deploymentA)
        #expect(result.response.plan.deploymentID == deploymentID)
        let expectedResponse = try CanonicalNativeJSON.encodeLine(
            deploymentPlanResponse()
        )
        #expect(result.response.canonicalData == expectedResponse)
        #expect(result.canonicalReplyData == raw)
    }

    @Test func crossCommandReplayAndEnvelopeFieldChangesFailClosed() throws {
        let planRequest = try NativeDeploymentQueryRequest(
            command: .plan, queryID: deploymentQueryID
        )
        let statusRequest = try NativeDeploymentQueryRequest(
            command: .status, queryID: deploymentQueryID
        )
        let raw = try deploymentReply(
            request: planRequest, result: deploymentPlanResponse()
        )
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodeStatusReply(
                raw, request: statusRequest
            )
        }
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodePlanReply(
                deploymentReply(
                    request: planRequest,
                    result: deploymentPlanResponse(),
                    extra: ["unexpected": true]
                ),
                request: planRequest,
                now: 1_500
            )
        }
    }

    @Test func nestedExtraAndMissingPlanFieldsFailClosed() throws {
        let request = try NativeDeploymentQueryRequest(
            command: .plan, queryID: deploymentQueryID
        )
        for response in [
            try deploymentPlanResponse(planExtra: ["unexpected": "field"]),
            try deploymentPlanResponse(planOmitting: "catalog_sha256"),
        ] {
            #expect(throws: (any Error).self) {
                try NativeDeploymentProtocol.decodePlanReply(
                    deploymentReply(request: request, result: response),
                    request: request,
                    now: 1_500
                )
            }
        }
    }

    @Test func digestAndCanonicalMutationsFailClosed() throws {
        let request = try NativeDeploymentQueryRequest(
            command: .plan, queryID: deploymentQueryID
        )
        var response = try deploymentPlanResponse()
        var plan = response["plan"] as! [String: Any]
        plan["catalog_sha256"] = deploymentF
        response["plan"] = plan
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodePlanReply(
                deploymentReply(request: request, result: response),
                request: request,
                now: 1_500
            )
        }

        let canonical = try deploymentReply(
            request: request, result: deploymentPlanResponse()
        )
        let noncanonical = String(decoding: canonical, as: UTF8.self)
            .replacingOccurrences(of: ",\"host_release_id\"", with: ", \"host_release_id\"")
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodePlanReply(
                Data(noncanonical.utf8), request: request, now: 1_500
            )
        }
    }

    @Test func stalePlanAndHostReleaseMismatchFailClosed() throws {
        let request = try NativeDeploymentQueryRequest(
            command: .plan, queryID: deploymentQueryID
        )
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodePlanReply(
                deploymentReply(
                    request: request,
                    result: deploymentPlanResponse(
                        createdAt: 1_000, expiresAt: 2_000
                    )
                ),
                request: request,
                now: 2_000
            )
        }
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodePlanReply(
                deploymentReply(
                    request: request,
                    result: deploymentPlanResponse(hostReleaseID: deploymentB),
                    hostReleaseID: deploymentA
                ),
                request: request,
                now: 1_500
            )
        }
    }

    @Test func recoveryActionOrderIsFrozenAndExpiredPlanIsAdmitted() throws {
        let request = try NativeDeploymentQueryRequest(
            command: .recoveryPlan, queryID: deploymentQueryID
        )
        let admitted = try NativeDeploymentProtocol.decodeRecoveryPlanReply(
            deploymentReply(request: request, result: recoveryPlan()),
            request: request
        )
        #expect(admitted.recoveryPlan.allowedActions == ["rollback", "resume"])
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodeRecoveryPlanReply(
                deploymentReply(
                    request: request,
                    result: recoveryPlan(actions: ["resume", "rollback"])
                ),
                request: request
            )
        }
    }

    @Test func catalogGateBindsStableActiveIdentityAndDigest() throws {
        let request = try NativeCatalogPromotionGateRequest(
            queryID: deploymentQueryID
        )
        let first = try NativeCatalogRecoveryProtocol.decodeGateReply(
            catalogGateReply(request: request, gate: catalogGate()),
            request: request
        )
        let second = try NativeCatalogRecoveryProtocol.decodeGateReply(
            catalogGateReply(request: request, gate: catalogGate()),
            request: request
        )
        #expect(first.gate.state == "active")
        #expect(first.gate.activePromotionID == promotionID)
        #expect(first.gate.gateSHA256 == second.gate.gateSHA256)

        var mutated = try catalogGate()
        mutated["active_state_sha256"] = deploymentC
        #expect(throws: (any Error).self) {
            try NativeCatalogRecoveryProtocol.decodeGateReply(
                catalogGateReply(request: request, gate: mutated),
                request: request
            )
        }
    }

    @Test func catalogExpectedGateMismatchFailsClosed() throws {
        let gate = try catalogGate()
        let gateDigest = gate["gate_sha256"] as! String
        let request = try NativeCatalogPromotionRecoveryRequest(
            expectedGateSHA256: gateDigest,
            recoveryID: deploymentQueryID
        )
        #expect(throws: (any Error).self) {
            try NativeCatalogRecoveryProtocol.decodeRecoveryReply(
                catalogRecoveryReply(
                    request: request,
                    terminal: catalogTerminal(
                        expectedGateSHA256: deploymentF
                    )
                ),
                request: request
            )
        }
    }

    @Test func lostReplyReplayAllowsHistoricalTerminalProvenance() throws {
        let gate = try catalogGate()
        let gateDigest = gate["gate_sha256"] as! String
        let request = try NativeCatalogPromotionRecoveryRequest(
            expectedGateSHA256: gateDigest,
            recoveryID: deploymentQueryID
        )
        let raw = try catalogRecoveryReply(
            request: request,
            terminal: catalogTerminal(
                expectedGateSHA256: gateDigest,
                historicalHostReleaseID: deploymentB
            ),
            currentHostReleaseID: deploymentA
        )
        let result = try NativeCatalogRecoveryProtocol.decodeRecoveryReply(
            raw, request: request
        )
        #expect(result.currentHostReleaseID == deploymentA)
        #expect(result.terminal.historicalHostReleaseID == deploymentB)
        #expect(result.terminal.recoveryIntentSHA256 == deploymentE)
        #expect(result.canonicalReplyData == raw)
    }

    @Test func exactErrorRepliesRejectWithoutTrustingPayload() throws {
        let deploymentRequest = try NativeDeploymentQueryRequest(
            command: .status, queryID: deploymentQueryID
        )
        let deploymentError = try CanonicalNativeJSON.encodeLine([
            "command": "status",
            "error": "native_deployment_query_invalid",
            "schema": "secure-sandbox-native-deployment-query-error-v1",
            "status": "rejected",
        ])
        #expect(throws: (any Error).self) {
            try NativeDeploymentProtocol.decodeStatusReply(
                deploymentError, request: deploymentRequest
            )
        }

        let gateRequest = try NativeCatalogPromotionGateRequest(
            queryID: deploymentQueryID
        )
        let catalogError = try CanonicalNativeJSON.encodeLine([
            "command": NativeCatalogPromotionGateRequest.command,
            "error": "native_catalog_promotion_gate_invalid",
            "schema":
                "secure-sandbox-native-stack-catalog-promotion-gate-error-v1",
            "status": "rejected",
        ])
        #expect(throws: (any Error).self) {
            try NativeCatalogRecoveryProtocol.decodeGateReply(
                catalogError, request: gateRequest
            )
        }

        let malformed = try CanonicalNativeJSON.encodeLine([
            "command": NativeCatalogPromotionGateRequest.command,
            "error": "native_catalog_promotion_gate_invalid",
            "schema":
                "secure-sandbox-native-stack-catalog-promotion-gate-error-v1",
            "status": "rejected",
            "unexpected": true,
        ])
        #expect(throws: (any Error).self) {
            try NativeCatalogRecoveryProtocol.decodeGateReply(
                malformed, request: gateRequest
            )
        }
    }
}
