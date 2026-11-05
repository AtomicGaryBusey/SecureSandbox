import Foundation

public enum NativeDeploymentQueryCommand: String, Sendable {
    case plan
    case status
    case recoveryPlan = "recovery-plan"

    fileprivate var requestSchema: String {
        switch self {
        case .plan: "secure-sandbox-native-deployment-plan-request-v1"
        case .status: "secure-sandbox-native-deployment-status-request-v1"
        case .recoveryPlan:
            "secure-sandbox-native-deployment-recovery-plan-request-v1"
        }
    }

    fileprivate var replySchema: String {
        switch self {
        case .plan: "secure-sandbox-native-deployment-plan-reply-v1"
        case .status: "secure-sandbox-native-deployment-status-reply-v1"
        case .recoveryPlan:
            "secure-sandbox-native-deployment-recovery-plan-reply-v1"
        }
    }
}

public struct NativeDeploymentQueryRequest: Sendable {
    public let command: NativeDeploymentQueryCommand
    public let queryID: String
    public let requestSHA256: String
    public let canonicalData: Data

    public init(
        command: NativeDeploymentQueryCommand,
        queryID: String = UUID().uuidString.lowercased()
    ) throws {
        guard CanonicalNativeJSON.isUUID4(queryID) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_request_invalid"
            )
        }
        let body: [String: Any] = [
            "command": command.rawValue,
            "query_id": queryID,
        ]
        let digest = try CanonicalNativeJSON.digest(body)
        self.command = command
        self.queryID = queryID
        requestSHA256 = digest
        canonicalData = try CanonicalNativeJSON.encodeLine([
            "query_id": queryID,
            "request_sha256": digest,
            "schema": command.requestSchema,
        ])
    }
}

public enum NativeDeploymentGuestRole: String, Sendable {
    case gateway
    case research
}

public struct NativeDeploymentGuestStatus: Hashable, Sendable {
    public let role: NativeDeploymentGuestRole
    public let state: String
    public let generationKind: String
    public let packageSHA256: String?
    public let releaseID: String?
    public let catalogSHA256: String?
    public let closedEvidenceSHA256: String?
    public let observedAt: Int
    public let evidenceSHA256: String
    public let stableStatusSHA256: String
    public let canonicalData: Data
}

public struct NativeDeploymentPlan: Hashable, Sendable, Identifiable {
    public let deploymentID: String
    public let hostReleaseID: String
    public let catalogSHA256: String
    public let gatewayPackageSHA256: String
    public let researchPackageSHA256: String
    public let previousGatewayPackageSHA256: String?
    public let previousResearchPackageSHA256: String?
    public let previousGatewayStatusSHA256: String
    public let previousResearchStatusSHA256: String
    public let createdAt: Int
    public let expiresAt: Int
    public let planSHA256: String
    public let canonicalData: Data

    public var id: String { deploymentID }
}

public struct NativeDeploymentPlanResponse: Hashable, Sendable {
    public let plan: NativeDeploymentPlan
    public let priorGateway: NativeDeploymentGuestStatus
    public let priorResearch: NativeDeploymentGuestStatus
    public let payloadContainerSHA256: String
    public let responseSHA256: String
    public let canonicalData: Data
}

public struct NativeDeploymentPublicStatus: Hashable, Sendable {
    public let state: String
    public let phase: String?
    public let deploymentID: String?
    public let hostReleaseID: String?
    public let activeJournalSHA256: String?
    public let errorSHA256: String?
    public let statusSHA256: String
    public let canonicalData: Data
}

public struct NativeDeploymentRecoveryPlan: Hashable, Sendable {
    public let activeJournalSHA256: String
    public let deploymentID: String
    public let hostReleaseID: String
    public let phase: String
    public let observedPair: String
    public let allowedActions: [String]
    public let planResponse: NativeDeploymentPlanResponse
    public let gatewayStatusSHA256: String?
    public let researchStatusSHA256: String?
    public let recoveryPlanSHA256: String
    public let canonicalData: Data
}

public struct NativeDeploymentPlanQueryResult: Sendable {
    public let request: NativeDeploymentQueryRequest
    public let currentHostReleaseID: String
    public let response: NativeDeploymentPlanResponse
    public let canonicalReplyData: Data
}

public struct NativeDeploymentStatusQueryResult: Sendable {
    public let request: NativeDeploymentQueryRequest
    public let currentHostReleaseID: String
    public let status: NativeDeploymentPublicStatus
    public let canonicalReplyData: Data
}

public struct NativeDeploymentRecoveryPlanQueryResult: Sendable {
    public let request: NativeDeploymentQueryRequest
    public let currentHostReleaseID: String
    public let recoveryPlan: NativeDeploymentRecoveryPlan
    public let canonicalReplyData: Data
}

public enum NativeDeploymentProtocol {
    private static let queryErrorSchema =
        "secure-sandbox-native-deployment-query-error-v1"
    private static let planResponseSchema =
        "secure-sandbox-native-deployment-plan-response-v1"
    private static let planSchema =
        "secure-sandbox-native-deployment-plan-v1"
    private static let guestStatusSchema =
        "secure-sandbox-native-deployment-status-v1"
    private static let publicStatusSchema =
        "secure-sandbox-native-deployment-public-status-v1"
    private static let recoveryPlanSchema =
        "secure-sandbox-native-deployment-recovery-plan-v1"

    public static func decodePlanReply(
        _ data: Data,
        request: NativeDeploymentQueryRequest,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeDeploymentPlanQueryResult {
        guard request.command == .plan else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_command_mismatch"
            )
        }
        let envelope = try decodeEnvelope(data, request: request)
        let response = try validatePlanResponse(
            envelope.result,
            expectedHostReleaseID: envelope.hostReleaseID,
            now: now,
            requireFresh: true
        )
        return NativeDeploymentPlanQueryResult(
            request: request,
            currentHostReleaseID: envelope.hostReleaseID,
            response: response,
            canonicalReplyData: data
        )
    }

    public static func decodeStatusReply(
        _ data: Data,
        request: NativeDeploymentQueryRequest
    ) throws -> NativeDeploymentStatusQueryResult {
        guard request.command == .status else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_command_mismatch"
            )
        }
        let envelope = try decodeEnvelope(data, request: request)
        let status = try validatePublicStatus(
            envelope.result, expectedHostReleaseID: envelope.hostReleaseID
        )
        return NativeDeploymentStatusQueryResult(
            request: request,
            currentHostReleaseID: envelope.hostReleaseID,
            status: status,
            canonicalReplyData: data
        )
    }

    public static func decodeRecoveryPlanReply(
        _ data: Data,
        request: NativeDeploymentQueryRequest
    ) throws -> NativeDeploymentRecoveryPlanQueryResult {
        guard request.command == .recoveryPlan else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_command_mismatch"
            )
        }
        let envelope = try decodeEnvelope(data, request: request)
        let recovery = try validateRecoveryPlan(
            envelope.result, expectedHostReleaseID: envelope.hostReleaseID
        )
        return NativeDeploymentRecoveryPlanQueryResult(
            request: request,
            currentHostReleaseID: envelope.hostReleaseID,
            recoveryPlan: recovery,
            canonicalReplyData: data
        )
    }

    private struct Envelope {
        let hostReleaseID: String
        let result: [String: Any]
    }

    private static func decodeEnvelope(
        _ data: Data, request: NativeDeploymentQueryRequest
    ) throws -> Envelope {
        let reply = try CanonicalNativeJSON.parseLine(
            data, maximumBytes: 4 * 1_024 * 1_024
        )
        if reply["schema"] as? String == queryErrorSchema {
            try validateErrorReply(reply, command: request.command.rawValue)
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_rejected"
            )
        }
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "query_id", "command", "request_sha256",
            "host_release_id", "result", "reply_sha256",
        ], "native_deployment_query_reply_fields_invalid")
        guard reply["schema"] as? String == request.command.replySchema,
              reply["query_id"] as? String == request.queryID,
              reply["command"] as? String == request.command.rawValue,
              reply["request_sha256"] as? String == request.requestSHA256,
              let hostReleaseID = reply["host_release_id"] as? String,
              CanonicalNativeJSON.isSHA256(hostReleaseID),
              let result = reply["result"] as? [String: Any],
              let supplied = reply["reply_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(supplied) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_reply_identity_invalid"
            )
        }
        let body: [String: Any] = [
            "command": request.command.rawValue,
            "host_release_id": hostReleaseID,
            "query_id": request.queryID,
            "request_sha256": request.requestSHA256,
            "result": result,
        ]
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_reply_digest_mismatch"
            )
        }
        return Envelope(hostReleaseID: hostReleaseID, result: result)
    }

    private static func validateErrorReply(
        _ reply: [String: Any], command: String
    ) throws {
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "command", "status", "error",
        ], "native_deployment_query_error_fields_invalid")
        guard reply["schema"] as? String == queryErrorSchema,
              reply["command"] as? String == command,
              reply["status"] as? String == "rejected",
              nativeDeploymentSafeDiagnostic(reply["error"]) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_query_error_invalid"
            )
        }
    }

    private static func validatePlanResponse(
        _ value: [String: Any],
        expectedHostReleaseID: String,
        now: Int,
        requireFresh: Bool
    ) throws -> NativeDeploymentPlanResponse {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "plan", "prior_gateway", "prior_research",
            "payload_container_sha256", "response_sha256",
        ], "native_deployment_plan_response_fields_invalid")
        guard value["schema"] as? String == planResponseSchema,
              let rawPlan = value["plan"] as? [String: Any],
              let rawGateway = value["prior_gateway"] as? [String: Any],
              let rawResearch = value["prior_research"] as? [String: Any],
              let payload = nativeDeploymentRequiredSHA(
                value["payload_container_sha256"]
              ),
              let supplied = nativeDeploymentRequiredSHA(
                value["response_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_plan_response_invalid"
            )
        }
        let plan = try validatePlan(
            rawPlan,
            expectedHostReleaseID: expectedHostReleaseID,
            now: now,
            requireFresh: requireFresh
        )
        let gateway = try validateGuestStatus(rawGateway, role: .gateway)
        let research = try validateGuestStatus(rawResearch, role: .research)
        guard gateway.packageSHA256 == plan.previousGatewayPackageSHA256,
              research.packageSHA256 == plan.previousResearchPackageSHA256,
              gateway.stableStatusSHA256
                == plan.previousGatewayStatusSHA256,
              research.stableStatusSHA256
                == plan.previousResearchStatusSHA256 else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_predecessor_status_mismatch"
            )
        }
        let body: [String: Any] = [
            "payload_container_sha256": payload,
            "plan": rawPlan,
            "prior_gateway": rawGateway,
            "prior_research": rawResearch,
        ]
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_plan_response_digest_mismatch"
            )
        }
        return NativeDeploymentPlanResponse(
            plan: plan,
            priorGateway: gateway,
            priorResearch: research,
            payloadContainerSHA256: payload,
            responseSHA256: supplied,
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }

    private static func validatePlan(
        _ value: [String: Any],
        expectedHostReleaseID: String,
        now: Int,
        requireFresh: Bool
    ) throws -> NativeDeploymentPlan {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "deployment_id", "host_release_id", "catalog_sha256",
            "gateway_package_sha256", "research_package_sha256",
            "previous_gateway_package_sha256",
            "previous_research_package_sha256",
            "previous_gateway_status_sha256",
            "previous_research_status_sha256", "created_at", "expires_at",
            "plan_sha256",
        ], "native_deployment_plan_fields_invalid")
        guard value["schema"] as? String == planSchema,
              let deploymentID = value["deployment_id"] as? String,
              CanonicalNativeJSON.isUUID4(deploymentID),
              let hostReleaseID = value["host_release_id"] as? String,
              hostReleaseID == expectedHostReleaseID,
              CanonicalNativeJSON.isSHA256(hostReleaseID),
              let catalog = nativeDeploymentRequiredSHA(
                value["catalog_sha256"]
              ),
              let gateway = nativeDeploymentRequiredSHA(
                value["gateway_package_sha256"]
              ),
              let research = nativeDeploymentRequiredSHA(
                value["research_package_sha256"]
              ),
              let previousGatewayBox = nativeDeploymentOptionalSHA(
                value["previous_gateway_package_sha256"]
              ),
              let previousResearchBox = nativeDeploymentOptionalSHA(
                value["previous_research_package_sha256"]
              ),
              let previousGatewayStatus = nativeDeploymentRequiredSHA(
                value["previous_gateway_status_sha256"]
              ),
              let previousResearchStatus = nativeDeploymentRequiredSHA(
                value["previous_research_status_sha256"]
              ),
              let created = CanonicalNativeJSON.exactInteger(
                value["created_at"]
              ),
              let expires = CanonicalNativeJSON.exactInteger(
                value["expires_at"]
              ),
              1 <= created, created < expires, expires - created <= 3_600,
              !requireFresh || (created <= now && now < expires),
              let supplied = nativeDeploymentRequiredSHA(
                value["plan_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_plan_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "plan_sha256")
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_plan_digest_mismatch"
            )
        }
        return NativeDeploymentPlan(
            deploymentID: deploymentID,
            hostReleaseID: hostReleaseID,
            catalogSHA256: catalog,
            gatewayPackageSHA256: gateway,
            researchPackageSHA256: research,
            previousGatewayPackageSHA256: previousGatewayBox.value,
            previousResearchPackageSHA256: previousResearchBox.value,
            previousGatewayStatusSHA256: previousGatewayStatus,
            previousResearchStatusSHA256: previousResearchStatus,
            createdAt: created,
            expiresAt: expires,
            planSHA256: supplied,
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }

    private static func validateGuestStatus(
        _ value: [String: Any], role expectedRole: NativeDeploymentGuestRole
    ) throws -> NativeDeploymentGuestStatus {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "role", "state", "generation_kind", "package_sha256",
            "release_id", "catalog_sha256", "closed_evidence_sha256",
            "pending", "observed_at", "evidence_sha256",
        ], "native_deployment_guest_status_fields_invalid")
        guard value["schema"] as? String == guestStatusSchema,
              value["role"] as? String == expectedRole.rawValue,
              let state = value["state"] as? String,
              let generation = value["generation_kind"] as? String,
              value["pending"] as? Bool == false,
              let observed = CanonicalNativeJSON.exactInteger(
                value["observed_at"]
              ), observed >= 1,
              let evidence = nativeDeploymentRequiredSHA(
                value["evidence_sha256"]
              ),
              let packageBox = nativeDeploymentOptionalSHA(
                value["package_sha256"]
              ),
              let releaseBox = nativeDeploymentOptionalSHA(
                value["release_id"]
              ),
              let catalogBox = nativeDeploymentOptionalSHA(
                value["catalog_sha256"]
              ),
              let closedBox = nativeDeploymentOptionalSHA(
                value["closed_evidence_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_guest_status_invalid"
            )
        }
        let package = packageBox.value
        let release = releaseBox.value
        let catalog = catalogBox.value
        let closed = closedBox.value
        let identityValid: Bool
        if state == "absent" {
            identityValid = generation == "absent"
                && package == nil && release == nil && catalog == nil
                && closed == nil
        } else if state == "verified" {
            identityValid = ["legacy", "protected"].contains(generation)
                && package != nil && release != nil && closed != nil
                && (expectedRole == .research ? catalog != nil : catalog == nil)
        } else {
            identityValid = false
        }
        guard identityValid else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_guest_status_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "evidence_sha256")
        guard evidence == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_guest_status_digest_mismatch"
            )
        }
        let projection: [String: Any] = [
            "catalog_sha256": nativeDeploymentNullable(catalog),
            "closed_evidence_sha256": nativeDeploymentNullable(closed),
            "generation_kind": generation,
            "package_sha256": nativeDeploymentNullable(package),
            "release_id": nativeDeploymentNullable(release),
            "role": expectedRole.rawValue,
            "state": state,
        ]
        return NativeDeploymentGuestStatus(
            role: expectedRole,
            state: state,
            generationKind: generation,
            packageSHA256: package,
            releaseID: release,
            catalogSHA256: catalog,
            closedEvidenceSHA256: closed,
            observedAt: observed,
            evidenceSHA256: evidence,
            stableStatusSHA256: try CanonicalNativeJSON.digest(projection),
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }

    private static func validatePublicStatus(
        _ value: [String: Any], expectedHostReleaseID: String
    ) throws -> NativeDeploymentPublicStatus {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "state", "phase", "deployment_id", "host_release_id",
            "active_journal_sha256", "error_sha256", "status_sha256",
        ], "native_deployment_public_status_fields_invalid")
        guard value["schema"] as? String == publicStatusSchema,
              let state = value["state"] as? String,
              let supplied = nativeDeploymentRequiredSHA(
                value["status_sha256"]
              ),
              let phaseBox = nativeDeploymentOptionalString(value["phase"]),
              let deploymentBox = nativeDeploymentOptionalString(
                value["deployment_id"]
              ),
              let hostBox = nativeDeploymentOptionalString(
                value["host_release_id"]
              ),
              let activeBox = nativeDeploymentOptionalSHA(
                value["active_journal_sha256"]
              ),
              let errorBox = nativeDeploymentOptionalSHA(
                value["error_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_public_status_invalid"
            )
        }
        let phase = phaseBox.value
        let deploymentID = deploymentBox.value
        let hostReleaseID = hostBox.value
        let active = activeBox.value
        let error = errorBox.value
        let valid: Bool
        if state == "ready" {
            valid = phase == nil && deploymentID == nil
                && hostReleaseID == nil && active == nil && error == nil
        } else if state == "recovery-required" && phase == "state-invalid" {
            valid = deploymentID == nil && hostReleaseID == nil
                && active == nil && error != nil
        } else if state == "recovery-required" {
            valid = phase.map(nativeDeploymentSafePhase) == true
                && deploymentID.map(CanonicalNativeJSON.isUUID4) == true
                && hostReleaseID == expectedHostReleaseID
                && hostReleaseID.map(CanonicalNativeJSON.isSHA256) == true
                && active != nil && error == nil
        } else {
            valid = false
        }
        guard valid else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_public_status_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "status_sha256")
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_public_status_digest_mismatch"
            )
        }
        return NativeDeploymentPublicStatus(
            state: state,
            phase: phase,
            deploymentID: deploymentID,
            hostReleaseID: hostReleaseID,
            activeJournalSHA256: active,
            errorSHA256: error,
            statusSHA256: supplied,
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }

    private static func validateRecoveryPlan(
        _ value: [String: Any], expectedHostReleaseID: String
    ) throws -> NativeDeploymentRecoveryPlan {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "active_journal_sha256", "deployment_id",
            "host_release_id", "phase", "observed_pair", "allowed_actions",
            "plan_response", "gateway_status_sha256",
            "research_status_sha256", "recovery_plan_sha256",
        ], "native_deployment_recovery_plan_fields_invalid")
        guard value["schema"] as? String == recoveryPlanSchema,
              let active = nativeDeploymentRequiredSHA(
                value["active_journal_sha256"]
              ),
              let deploymentID = value["deployment_id"] as? String,
              CanonicalNativeJSON.isUUID4(deploymentID),
              let hostReleaseID = value["host_release_id"] as? String,
              hostReleaseID == expectedHostReleaseID,
              let phase = value["phase"] as? String,
              nativeDeploymentSafePhase(phase),
              let observed = value["observed_pair"] as? String,
              ["prior-prior", "candidate-prior", "candidate-candidate",
               "unavailable"].contains(observed),
              let actions = value["allowed_actions"] as? [String],
              nativeDeploymentAllowedRecoveryActions(actions),
              let rawResponse = value["plan_response"] as? [String: Any],
              let gatewayBox = nativeDeploymentOptionalSHA(
                value["gateway_status_sha256"]
              ),
              let researchBox = nativeDeploymentOptionalSHA(
                value["research_status_sha256"]
              ),
              (gatewayBox.value == nil) == (researchBox.value == nil),
              let supplied = nativeDeploymentRequiredSHA(
                value["recovery_plan_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_recovery_plan_invalid"
            )
        }
        let planResponse = try validatePlanResponse(
            rawResponse,
            expectedHostReleaseID: expectedHostReleaseID,
            now: 0,
            requireFresh: false
        )
        guard deploymentID == planResponse.plan.deploymentID,
              hostReleaseID == planResponse.plan.hostReleaseID else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_recovery_plan_identity_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "recovery_plan_sha256")
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_deployment_recovery_plan_digest_mismatch"
            )
        }
        return NativeDeploymentRecoveryPlan(
            activeJournalSHA256: active,
            deploymentID: deploymentID,
            hostReleaseID: hostReleaseID,
            phase: phase,
            observedPair: observed,
            allowedActions: actions,
            planResponse: planResponse,
            gatewayStatusSHA256: gatewayBox.value,
            researchStatusSHA256: researchBox.value,
            recoveryPlanSHA256: supplied,
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }
}

private struct NativeDeploymentOptional<Value> {
    let value: Value?
}

private func nativeDeploymentRequiredSHA(_ value: Any?) -> String? {
    guard let string = value as? String,
          CanonicalNativeJSON.isSHA256(string) else { return nil }
    return string
}

private func nativeDeploymentOptionalSHA(
    _ value: Any?
) -> NativeDeploymentOptional<String>? {
    if value is NSNull { return NativeDeploymentOptional(value: nil) }
    guard let string = nativeDeploymentRequiredSHA(value) else { return nil }
    return NativeDeploymentOptional(value: string)
}

private func nativeDeploymentOptionalString(
    _ value: Any?
) -> NativeDeploymentOptional<String>? {
    if value is NSNull { return NativeDeploymentOptional(value: nil) }
    guard let string = value as? String else { return nil }
    return NativeDeploymentOptional(value: string)
}

private func nativeDeploymentNullable(_ value: String?) -> Any {
    value ?? NSNull()
}

private func nativeDeploymentAllowedRecoveryActions(_ value: [String]) -> Bool {
    value.isEmpty || value == ["resume"] || value == ["rollback"]
        || value == ["rollback", "resume"]
}

private func nativeDeploymentSafePhase(_ value: String) -> Bool {
    value.range(
        of: #"^[a-z][a-z-]{0,63}$"#, options: .regularExpression
    ) != nil
}

private func nativeDeploymentSafeDiagnostic(_ value: Any?) -> Bool {
    guard let value = value as? String else { return false }
    return value.range(
        of: #"^[a-z][a-z0-9_]{0,127}$"#, options: .regularExpression
    ) != nil
}

public struct NativeCatalogPromotionGateRequest: Sendable {
    public static let command = "catalog-promotion-gate"
    public static let schema =
        "secure-sandbox-native-stack-catalog-promotion-gate-request-v1"

    public let queryID: String
    public let requestSHA256: String
    public let canonicalData: Data

    public init(queryID: String = UUID().uuidString.lowercased()) throws {
        guard CanonicalNativeJSON.isUUID4(queryID) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_promotion_gate_request_invalid"
            )
        }
        let body: [String: Any] = [
            "command": Self.command,
            "query_id": queryID,
        ]
        let digest = try CanonicalNativeJSON.digest(body)
        self.queryID = queryID
        requestSHA256 = digest
        canonicalData = try CanonicalNativeJSON.encodeLine([
            "query_id": queryID,
            "request_sha256": digest,
            "schema": Self.schema,
        ])
    }
}

public struct NativeCatalogPromotionGate: Hashable, Sendable {
    public let state: String
    public let activePromotionID: String?
    public let activeStateSHA256: String?
    public let gateSHA256: String
    public let canonicalData: Data
}

public struct NativeCatalogPromotionGateQueryResult: Sendable {
    public let request: NativeCatalogPromotionGateRequest
    public let currentHostReleaseID: String
    public let gate: NativeCatalogPromotionGate
    public let canonicalReplyData: Data
}

public struct NativeCatalogPromotionRecoveryRequest: Sendable {
    public static let command = "catalog-promotion-recover-active"
    public static let schema =
        "secure-sandbox-native-stack-catalog-recovery-request-v1"

    public let recoveryID: String
    public let expectedGateSHA256: String
    public let requestSHA256: String
    public let canonicalData: Data

    public init(
        expectedGateSHA256: String,
        recoveryID: String = UUID().uuidString.lowercased()
    ) throws {
        guard CanonicalNativeJSON.isUUID4(recoveryID),
              CanonicalNativeJSON.isSHA256(expectedGateSHA256) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_recovery_request_invalid"
            )
        }
        let body: [String: Any] = [
            "command": Self.command,
            "expected_gate_sha256": expectedGateSHA256,
            "recovery_id": recoveryID,
        ]
        let digest = try CanonicalNativeJSON.digest(body)
        self.recoveryID = recoveryID
        self.expectedGateSHA256 = expectedGateSHA256
        requestSHA256 = digest
        canonicalData = try CanonicalNativeJSON.encodeLine([
            "expected_gate_sha256": expectedGateSHA256,
            "recovery_id": recoveryID,
            "request_sha256": digest,
            "schema": Self.schema,
        ])
    }
}

public struct NativeCatalogPromotionRecoveryTerminal: Hashable, Sendable {
    public let promotionID: String
    public let catalogSHA256: String
    public let historicalHostReleaseID: String
    public let promotionReceiptSHA256: String
    public let replayAuthoritySHA256: String
    public let expectedGateSHA256: String
    public let recoveryIntentSHA256: String
    public let terminalSHA256: String
    public let canonicalData: Data
}

public struct NativeCatalogPromotionRecoveryResult: Sendable {
    public let request: NativeCatalogPromotionRecoveryRequest
    public let currentHostReleaseID: String
    public let terminal: NativeCatalogPromotionRecoveryTerminal
    public let canonicalReplyData: Data
}

public enum NativeCatalogRecoveryProtocol {
    private static let gateReplySchema =
        "secure-sandbox-native-stack-catalog-promotion-gate-reply-v1"
    private static let gateErrorSchema =
        "secure-sandbox-native-stack-catalog-promotion-gate-error-v1"
    private static let gateSchema =
        "secure-sandbox-native-stack-catalog-promotion-gate-state-v1"
    private static let recoveryReplySchema =
        "secure-sandbox-native-stack-catalog-recovery-reply-v1"
    private static let recoveryErrorSchema =
        "secure-sandbox-native-stack-catalog-recovery-error-v1"
    private static let terminalSchema =
        "secure-sandbox-native-stack-catalog-recovery-terminal-v1"

    public static func decodeGateReply(
        _ data: Data, request: NativeCatalogPromotionGateRequest
    ) throws -> NativeCatalogPromotionGateQueryResult {
        let reply = try CanonicalNativeJSON.parseLine(
            data, maximumBytes: 1_048_576
        )
        if reply["schema"] as? String == gateErrorSchema {
            try validateCatalogError(
                reply,
                schema: gateErrorSchema,
                command: NativeCatalogPromotionGateRequest.command
            )
            throw NativeSessionProtocolError.rejected(
                "native_catalog_promotion_gate_rejected"
            )
        }
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "query_id", "command", "request_sha256",
            "host_release_id", "gate", "reply_sha256",
        ], "native_catalog_promotion_gate_reply_fields_invalid")
        guard reply["schema"] as? String == gateReplySchema,
              reply["query_id"] as? String == request.queryID,
              reply["command"] as? String
                == NativeCatalogPromotionGateRequest.command,
              reply["request_sha256"] as? String == request.requestSHA256,
              let hostReleaseID = nativeDeploymentRequiredSHA(
                reply["host_release_id"]
              ),
              let rawGate = reply["gate"] as? [String: Any],
              let supplied = nativeDeploymentRequiredSHA(
                reply["reply_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_promotion_gate_reply_invalid"
            )
        }
        let gate = try validateGate(rawGate)
        let body: [String: Any] = [
            "command": NativeCatalogPromotionGateRequest.command,
            "gate": rawGate,
            "host_release_id": hostReleaseID,
            "query_id": request.queryID,
            "request_sha256": request.requestSHA256,
        ]
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_promotion_gate_reply_digest_mismatch"
            )
        }
        return NativeCatalogPromotionGateQueryResult(
            request: request,
            currentHostReleaseID: hostReleaseID,
            gate: gate,
            canonicalReplyData: data
        )
    }

    public static func decodeRecoveryReply(
        _ data: Data, request: NativeCatalogPromotionRecoveryRequest
    ) throws -> NativeCatalogPromotionRecoveryResult {
        let reply = try CanonicalNativeJSON.parseLine(
            data, maximumBytes: 1_048_576
        )
        if reply["schema"] as? String == recoveryErrorSchema {
            try validateCatalogError(
                reply,
                schema: recoveryErrorSchema,
                command: NativeCatalogPromotionRecoveryRequest.command
            )
            throw NativeSessionProtocolError.rejected(
                "native_catalog_recovery_rejected"
            )
        }
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "recovery_id", "command", "request_sha256",
            "host_release_id", "terminal", "reply_sha256",
        ], "native_catalog_recovery_reply_fields_invalid")
        guard reply["schema"] as? String == recoveryReplySchema,
              reply["recovery_id"] as? String == request.recoveryID,
              reply["command"] as? String
                == NativeCatalogPromotionRecoveryRequest.command,
              reply["request_sha256"] as? String == request.requestSHA256,
              let currentHostReleaseID = nativeDeploymentRequiredSHA(
                reply["host_release_id"]
              ),
              let rawTerminal = reply["terminal"] as? [String: Any],
              let supplied = nativeDeploymentRequiredSHA(
                reply["reply_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_recovery_reply_invalid"
            )
        }
        let terminal = try validateTerminal(
            rawTerminal, expectedGateSHA256: request.expectedGateSHA256
        )
        let body: [String: Any] = [
            "command": NativeCatalogPromotionRecoveryRequest.command,
            "host_release_id": currentHostReleaseID,
            "recovery_id": request.recoveryID,
            "request_sha256": request.requestSHA256,
            "terminal": rawTerminal,
        ]
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_recovery_reply_digest_mismatch"
            )
        }
        // The wrapper names the currently executing Host release. A retained
        // terminal intentionally keeps the historical promotion provenance.
        return NativeCatalogPromotionRecoveryResult(
            request: request,
            currentHostReleaseID: currentHostReleaseID,
            terminal: terminal,
            canonicalReplyData: data
        )
    }

    private static func validateGate(
        _ value: [String: Any]
    ) throws -> NativeCatalogPromotionGate {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "state", "active_promotion_id",
            "active_state_sha256", "gate_sha256",
        ], "native_catalog_promotion_gate_fields_invalid")
        guard value["schema"] as? String == gateSchema,
              let state = value["state"] as? String,
              let promotionBox = nativeDeploymentOptionalString(
                value["active_promotion_id"]
              ),
              let stateDigestBox = nativeDeploymentOptionalSHA(
                value["active_state_sha256"]
              ),
              let gateDigest = nativeDeploymentRequiredSHA(
                value["gate_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_promotion_gate_invalid"
            )
        }
        let promotionID = promotionBox.value
        let stateDigest = stateDigestBox.value
        let identityValid: Bool
        if state == "active" {
            identityValid = promotionID.map(CanonicalNativeJSON.isUUID4) == true
                && stateDigest != nil
        } else if state == "ready" || state == "invalid" {
            identityValid = promotionID == nil && stateDigest == nil
        } else {
            identityValid = false
        }
        let body: [String: Any] = [
            "active_promotion_id": nativeDeploymentNullable(promotionID),
            "active_state_sha256": nativeDeploymentNullable(stateDigest),
            "state": state,
        ]
        guard identityValid,
              gateDigest == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_promotion_gate_invalid"
            )
        }
        return NativeCatalogPromotionGate(
            state: state,
            activePromotionID: promotionID,
            activeStateSHA256: stateDigest,
            gateSHA256: gateDigest,
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }

    private static func validateTerminal(
        _ value: [String: Any], expectedGateSHA256: String
    ) throws -> NativeCatalogPromotionRecoveryTerminal {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "state", "promotion_id", "catalog_sha256",
            "host_release_id", "promotion_receipt_sha256",
            "replay_authority_sha256", "expected_gate_sha256",
            "recovery_intent_sha256", "terminal_sha256",
        ], "native_catalog_recovery_terminal_fields_invalid")
        guard value["schema"] as? String == terminalSchema,
              value["state"] as? String == "finalized",
              let promotionID = value["promotion_id"] as? String,
              CanonicalNativeJSON.isUUID4(promotionID),
              let catalog = nativeDeploymentRequiredSHA(
                value["catalog_sha256"]
              ),
              let historicalHost = nativeDeploymentRequiredSHA(
                value["host_release_id"]
              ),
              let receipt = nativeDeploymentRequiredSHA(
                value["promotion_receipt_sha256"]
              ),
              let replay = nativeDeploymentRequiredSHA(
                value["replay_authority_sha256"]
              ),
              let gate = nativeDeploymentRequiredSHA(
                value["expected_gate_sha256"]
              ),
              gate == expectedGateSHA256,
              let intent = nativeDeploymentRequiredSHA(
                value["recovery_intent_sha256"]
              ),
              let terminal = nativeDeploymentRequiredSHA(
                value["terminal_sha256"]
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_recovery_terminal_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "terminal_sha256")
        guard terminal == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_recovery_terminal_digest_mismatch"
            )
        }
        return NativeCatalogPromotionRecoveryTerminal(
            promotionID: promotionID,
            catalogSHA256: catalog,
            historicalHostReleaseID: historicalHost,
            promotionReceiptSHA256: receipt,
            replayAuthoritySHA256: replay,
            expectedGateSHA256: gate,
            recoveryIntentSHA256: intent,
            terminalSHA256: terminal,
            canonicalData: try CanonicalNativeJSON.encodeLine(value)
        )
    }

    private static func validateCatalogError(
        _ reply: [String: Any], schema: String, command: String
    ) throws {
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "command", "status", "error",
        ], "native_catalog_error_fields_invalid")
        guard reply["schema"] as? String == schema,
              reply["command"] as? String == command,
              reply["status"] as? String == "rejected",
              nativeDeploymentSafeDiagnostic(reply["error"]) else {
            throw NativeSessionProtocolError.rejected(
                "native_catalog_error_invalid"
            )
        }
    }
}
