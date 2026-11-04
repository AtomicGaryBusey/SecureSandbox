import Foundation

public enum NativeProjectionRecoveryKind: Equatable, Sendable {
    case identityImport
    case reconciliation

    fileprivate var requestSchema: String {
        switch self {
        case .identityImport:
            "secure-sandbox-native-projection-identity-recovery-plan-request-v1"
        case .reconciliation:
            "secure-sandbox-native-projection-reconciliation-plan-request-v1"
        }
    }

    fileprivate var replySchema: String {
        switch self {
        case .identityImport:
            "secure-sandbox-native-projection-identity-recovery-plan-query-reply-v1"
        case .reconciliation:
            "secure-sandbox-native-projection-reconciliation-plan-query-reply-v1"
        }
    }
}

public struct NativeProjectionRecoveryPlanRequest: Sendable {
    public let kind: NativeProjectionRecoveryKind
    public let recoveryOperationID: String
    public let originalOperationID: String
    public let requestSHA256: String
    public let canonicalData: Data

    public init(
        kind: NativeProjectionRecoveryKind,
        recoveryOperationID: String = UUID().uuidString.lowercased(),
        originalOperationID: String
    ) throws {
        guard CanonicalNativeJSON.isUUID4(recoveryOperationID),
              CanonicalNativeJSON.isUUID4(originalOperationID),
              recoveryOperationID != originalOperationID else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_recovery_request_identity_invalid"
            )
        }
        let body: [String: Any] = [
            "original_operation_id": originalOperationID,
            "recovery_operation_id": recoveryOperationID,
        ]
        let digest = try CanonicalNativeJSON.digest(body)
        var request = body
        request["schema"] = kind.requestSchema
        request["request_sha256"] = digest
        self.kind = kind
        self.recoveryOperationID = recoveryOperationID
        self.originalOperationID = originalOperationID
        requestSHA256 = digest
        canonicalData = try CanonicalNativeJSON.encodeLine(request)
    }
}

public struct NativeProjectionIdentityRecoveryPlan: Hashable, Sendable, Identifiable {
    public let recoveryOperationID: String
    public let originalOperationID: String
    public let sessionID: String
    public let stackID: String
    public let stackSHA256: String
    public let sessionAuthoritySHA256: String
    public let hostReleaseID: String
    public let createdAt: Int
    public let expiresAt: Int
    public let planSHA256: String
    public let canonicalData: Data

    public var id: String { recoveryOperationID }
}

public struct NativeProjectionReconciliationPlan: Hashable, Sendable, Identifiable {
    public let recoveryOperationID: String
    public let originalOperationID: String
    public let sessionID: String
    public let stackID: String
    public let stackSHA256: String
    public let sessionAuthoritySHA256: String
    public let processIdentifier: Int
    public let processStartTimeMicroseconds: Int
    public let consumerExecutableSHA256: String
    public let guestAbsenceEvidenceSHA256: String
    public let egressClosedEvidenceSHA256: String
    public let hostReleaseID: String
    public let createdAt: Int
    public let expiresAt: Int
    public let planSHA256: String
    public let canonicalData: Data

    public var id: String { recoveryOperationID }
}

public enum NativeProjectionRecoveryProtocol {
    public static func decodeIdentityPlanReply(
        _ data: Data,
        request: NativeProjectionRecoveryPlanRequest,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeProjectionIdentityRecoveryPlan {
        guard request.kind == .identityImport else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_identity_request_kind_invalid"
            )
        }
        let plan = try decodePlanEnvelope(data, request: request)
        let fields: Set<String> = [
            "schema", "recovery_operation_id", "original_operation_id",
            "session_id", "stack_id", "stack_sha256",
            "session_authority_sha256", "host_release_id", "created_at",
            "expires_at", "plan_sha256",
        ]
        try CanonicalNativeJSON.requireKeys(
            plan, fields, "native_projection_identity_plan_fields_invalid"
        )
        let common = try validateCommonPlan(
            plan, request: request,
            expectedSchema:
                "secure-sandbox-native-projection-identity-recovery-plan-v1",
            now: now
        )
        return NativeProjectionIdentityRecoveryPlan(
            recoveryOperationID: request.recoveryOperationID,
            originalOperationID: request.originalOperationID,
            sessionID: common.sessionID,
            stackID: common.stackID,
            stackSHA256: common.stackSHA256,
            sessionAuthoritySHA256: common.sessionAuthoritySHA256,
            hostReleaseID: common.hostReleaseID,
            createdAt: common.createdAt,
            expiresAt: common.expiresAt,
            planSHA256: common.planSHA256,
            canonicalData: try CanonicalNativeJSON.encodeLine(plan)
        )
    }

    public static func decodeReconciliationPlanReply(
        _ data: Data,
        request: NativeProjectionRecoveryPlanRequest,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeProjectionReconciliationPlan {
        guard request.kind == .reconciliation else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_reconciliation_request_kind_invalid"
            )
        }
        let plan = try decodePlanEnvelope(data, request: request)
        let fields: Set<String> = [
            "schema", "recovery_operation_id", "original_operation_id",
            "session_id", "stack_id", "stack_sha256",
            "session_authority_sha256", "process_identifier",
            "process_start_time_us", "consumer_executable_sha256",
            "guest_absence_evidence_sha256",
            "egress_closed_evidence_sha256", "host_release_id",
            "created_at", "expires_at", "plan_sha256",
        ]
        try CanonicalNativeJSON.requireKeys(
            plan, fields, "native_projection_reconciliation_plan_fields_invalid"
        )
        let common = try validateCommonPlan(
            plan, request: request,
            expectedSchema:
                "secure-sandbox-native-projection-reconciliation-plan-v1",
            now: now
        )
        guard let processIdentifier = CanonicalNativeJSON.exactInteger(
                    plan["process_identifier"]
              ), processIdentifier > 0,
              let processStart = CanonicalNativeJSON.exactInteger(
                    plan["process_start_time_us"]
              ), processStart > 0,
              let executable = plan["consumer_executable_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(executable),
              let guest = plan["guest_absence_evidence_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(guest),
              let egress = plan["egress_closed_evidence_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(egress) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_reconciliation_plan_identity_invalid"
            )
        }
        return NativeProjectionReconciliationPlan(
            recoveryOperationID: request.recoveryOperationID,
            originalOperationID: request.originalOperationID,
            sessionID: common.sessionID,
            stackID: common.stackID,
            stackSHA256: common.stackSHA256,
            sessionAuthoritySHA256: common.sessionAuthoritySHA256,
            processIdentifier: processIdentifier,
            processStartTimeMicroseconds: processStart,
            consumerExecutableSHA256: executable,
            guestAbsenceEvidenceSHA256: guest,
            egressClosedEvidenceSHA256: egress,
            hostReleaseID: common.hostReleaseID,
            createdAt: common.createdAt,
            expiresAt: common.expiresAt,
            planSHA256: common.planSHA256,
            canonicalData: try CanonicalNativeJSON.encodeLine(plan)
        )
    }

    private struct CommonPlan {
        let sessionID: String
        let stackID: String
        let stackSHA256: String
        let sessionAuthoritySHA256: String
        let hostReleaseID: String
        let createdAt: Int
        let expiresAt: Int
        let planSHA256: String
    }

    private static func decodePlanEnvelope(
        _ data: Data, request: NativeProjectionRecoveryPlanRequest
    ) throws -> [String: Any] {
        let reply = try CanonicalNativeJSON.parseLine(
            data, maximumBytes: 1_048_576
        )
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "recovery_operation_id", "request_sha256", "plan",
            "reply_sha256",
        ], "native_projection_recovery_reply_fields_invalid")
        guard reply["schema"] as? String == request.kind.replySchema,
              reply["recovery_operation_id"] as? String
                == request.recoveryOperationID,
              reply["request_sha256"] as? String == request.requestSHA256,
              let plan = reply["plan"] as? [String: Any],
              let supplied = reply["reply_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(supplied) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_recovery_reply_identity_invalid"
            )
        }
        let body: [String: Any] = [
            "plan": plan,
            "recovery_operation_id": request.recoveryOperationID,
            "request_sha256": request.requestSHA256,
        ]
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_recovery_reply_digest_mismatch"
            )
        }
        return plan
    }

    private static func validateCommonPlan(
        _ plan: [String: Any],
        request: NativeProjectionRecoveryPlanRequest,
        expectedSchema: String,
        now: Int
    ) throws -> CommonPlan {
        guard plan["schema"] as? String == expectedSchema,
              plan["recovery_operation_id"] as? String
                == request.recoveryOperationID,
              plan["original_operation_id"] as? String
                == request.originalOperationID,
              let sessionID = plan["session_id"] as? String,
              CanonicalNativeJSON.isUUID4(sessionID),
              let stackID = plan["stack_id"] as? String,
              stackID.range(
                of: #"^[a-z][a-z0-9-]{0,62}$"#,
                options: .regularExpression
              ) != nil,
              let stackSHA256 = plan["stack_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(stackSHA256),
              let authority = plan["session_authority_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(authority),
              let release = plan["host_release_id"] as? String,
              CanonicalNativeJSON.isSHA256(release),
              let created = CanonicalNativeJSON.exactInteger(
                plan["created_at"]
              ),
              let expires = CanonicalNativeJSON.exactInteger(
                plan["expires_at"]
              ),
              created <= now, now < expires, expires <= created + 120,
              let digest = plan["plan_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(digest) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_recovery_plan_invalid"
            )
        }
        var body = plan
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "plan_sha256")
        guard digest == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_recovery_plan_digest_mismatch"
            )
        }
        return CommonPlan(
            sessionID: sessionID, stackID: stackID,
            stackSHA256: stackSHA256,
            sessionAuthoritySHA256: authority, hostReleaseID: release,
            createdAt: created, expiresAt: expires, planSHA256: digest
        )
    }
}

public struct NativeProjectionIdentityRecoveryResult: Decodable, Sendable {
    public let schema: String
    public let outcome: String
    public let recoveryOperationID: String
    public let originalOperationID: String
    public let processIdentifier: Int
    public let processStartTimeMicroseconds: Int
    public let consumerExecutableSHA256: String
    public let sessionAuthoritySHA256: String
    public let identityEvidenceSHA256: String
    public let replySHA256: String

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: ProjectionRecoveryCodingKey.self)
        try requireResultKeys(values, expected: Self.fieldNames)
        schema = try values.decode(String.self, forKey: .init("schema"))
        outcome = try values.decode(String.self, forKey: .init("outcome"))
        recoveryOperationID = try values.decode(
            String.self, forKey: .init("recovery_operation_id")
        )
        originalOperationID = try values.decode(
            String.self, forKey: .init("original_operation_id")
        )
        processIdentifier = try values.decode(
            Int.self, forKey: .init("process_identifier")
        )
        processStartTimeMicroseconds = try values.decode(
            Int.self, forKey: .init("process_start_time_us")
        )
        consumerExecutableSHA256 = try values.decode(
            String.self, forKey: .init("consumer_executable_sha256")
        )
        sessionAuthoritySHA256 = try values.decode(
            String.self, forKey: .init("session_authority_sha256")
        )
        identityEvidenceSHA256 = try values.decode(
            String.self, forKey: .init("identity_evidence_sha256")
        )
        replySHA256 = try values.decode(
            String.self, forKey: .init("reply_sha256")
        )
    }

    public func validate(plan: NativeProjectionIdentityRecoveryPlan) throws {
        guard schema
                == "secure-sandbox-native-projection-identity-recovery-reply-v1",
              outcome == "verified",
              recoveryOperationID == plan.recoveryOperationID,
              originalOperationID == plan.originalOperationID,
              processIdentifier > 0, processStartTimeMicroseconds > 0,
              CanonicalNativeJSON.isSHA256(consumerExecutableSHA256),
              sessionAuthoritySHA256 == plan.sessionAuthoritySHA256,
              CanonicalNativeJSON.isSHA256(identityEvidenceSHA256),
              CanonicalNativeJSON.isSHA256(replySHA256) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_identity_result_invalid"
            )
        }
        let body: [String: Any] = [
            "consumer_executable_sha256": consumerExecutableSHA256,
            "identity_evidence_sha256": identityEvidenceSHA256,
            "original_operation_id": originalOperationID,
            "outcome": outcome,
            "process_identifier": processIdentifier,
            "process_start_time_us": processStartTimeMicroseconds,
            "recovery_operation_id": recoveryOperationID,
            "session_authority_sha256": sessionAuthoritySHA256,
        ]
        guard replySHA256 == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_identity_result_digest_mismatch"
            )
        }
    }

    private static let fieldNames: Set<String> = [
        "schema", "outcome", "recovery_operation_id",
        "original_operation_id", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "identity_evidence_sha256",
        "reply_sha256",
    ]
}

public struct NativeProjectionReconciliationResult: Decodable, Sendable {
    public let schema: String
    public let outcome: String
    public let recoveryOperationID: String
    public let originalOperationID: String
    public let processIdentifier: Int
    public let processStartTimeMicroseconds: Int
    public let consumerExecutableSHA256: String
    public let sessionAuthoritySHA256: String
    public let reconciliationEvidenceSHA256: String
    public let replySHA256: String

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: ProjectionRecoveryCodingKey.self)
        try requireResultKeys(values, expected: Self.fieldNames)
        schema = try values.decode(String.self, forKey: .init("schema"))
        outcome = try values.decode(String.self, forKey: .init("outcome"))
        recoveryOperationID = try values.decode(
            String.self, forKey: .init("recovery_operation_id")
        )
        originalOperationID = try values.decode(
            String.self, forKey: .init("original_operation_id")
        )
        processIdentifier = try values.decode(
            Int.self, forKey: .init("process_identifier")
        )
        processStartTimeMicroseconds = try values.decode(
            Int.self, forKey: .init("process_start_time_us")
        )
        consumerExecutableSHA256 = try values.decode(
            String.self, forKey: .init("consumer_executable_sha256")
        )
        sessionAuthoritySHA256 = try values.decode(
            String.self, forKey: .init("session_authority_sha256")
        )
        reconciliationEvidenceSHA256 = try values.decode(
            String.self, forKey: .init("reconciliation_evidence_sha256")
        )
        replySHA256 = try values.decode(
            String.self, forKey: .init("reply_sha256")
        )
    }

    public func validate(plan: NativeProjectionReconciliationPlan) throws {
        guard schema
                == "secure-sandbox-native-projection-reconciliation-reply-v1",
              outcome == "verified",
              recoveryOperationID == plan.recoveryOperationID,
              originalOperationID == plan.originalOperationID,
              processIdentifier == plan.processIdentifier,
              processStartTimeMicroseconds
                == plan.processStartTimeMicroseconds,
              consumerExecutableSHA256 == plan.consumerExecutableSHA256,
              sessionAuthoritySHA256 == plan.sessionAuthoritySHA256,
              CanonicalNativeJSON.isSHA256(reconciliationEvidenceSHA256),
              CanonicalNativeJSON.isSHA256(replySHA256) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_reconciliation_result_invalid"
            )
        }
        let body: [String: Any] = [
            "consumer_executable_sha256": consumerExecutableSHA256,
            "original_operation_id": originalOperationID,
            "outcome": outcome,
            "process_identifier": processIdentifier,
            "process_start_time_us": processStartTimeMicroseconds,
            "reconciliation_evidence_sha256":
                reconciliationEvidenceSHA256,
            "recovery_operation_id": recoveryOperationID,
            "session_authority_sha256": sessionAuthoritySHA256,
        ]
        guard replySHA256 == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_projection_reconciliation_result_digest_mismatch"
            )
        }
    }

    private static let fieldNames: Set<String> = [
        "schema", "outcome", "recovery_operation_id",
        "original_operation_id", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "reconciliation_evidence_sha256",
        "reply_sha256",
    ]
}

private struct ProjectionRecoveryCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int? = nil

    init(_ value: String) { stringValue = value }
    init?(stringValue: String) { self.init(stringValue) }
    init?(intValue: Int) { return nil }
}

private func requireResultKeys(
    _ container: KeyedDecodingContainer<ProjectionRecoveryCodingKey>,
    expected: Set<String>
) throws {
    guard Set(container.allKeys.map(\.stringValue)) == expected else {
        throw NativeSessionProtocolError.rejected(
            "native_projection_recovery_result_fields_invalid"
        )
    }
}
