import CryptoKit
import Foundation

public enum NativeSessionAction: String, Sendable {
    case start = "session-start"
    case stop = "session-stop"
}

public struct NativeSessionPlanRequest: Sendable {
    public static let schema = "secure-sandbox-native-stack-session-plan-request-v1"

    public let action: NativeSessionAction
    public let actionID: String
    public let sessionID: String
    public let stackID: String
    public let stackSHA256: String
    public let catalogSHA256: String
    public let sourceID: String?
    public let resumeSessionID: String?
    public let leaseProfileID: String?
    public let requestSHA256: String
    public let canonicalData: Data

    public init(
        action: NativeSessionAction,
        actionID: String = UUID().uuidString.lowercased(),
        sessionID: String,
        stackID: String,
        stackSHA256: String,
        catalogSHA256: String,
        sourceID: String?,
        resumeSessionID: String?,
        leaseProfileID: String?
    ) throws {
        guard CanonicalNativeJSON.isUUID4(actionID),
              CanonicalNativeJSON.isUUID4(sessionID),
              nativeSessionIdentifier(stackID),
              CanonicalNativeJSON.isSHA256(stackSHA256),
              CanonicalNativeJSON.isSHA256(catalogSHA256),
              sourceID.map({ CanonicalNativeJSON.isUUID4($0) }) ?? true,
              resumeSessionID.map({ CanonicalNativeJSON.isUUID4($0) }) ?? true,
              resumeSessionID != sessionID else {
            throw NativeSessionProtocolError.rejected("native_session_plan_request_invalid")
        }
        switch action {
        case .start:
            guard ["interactive", "extended"].contains(leaseProfileID) else {
                throw NativeSessionProtocolError.rejected(
                    "native_session_plan_start_request_invalid"
                )
            }
        case .stop:
            guard resumeSessionID == nil, leaseProfileID == nil else {
                throw NativeSessionProtocolError.rejected(
                    "native_session_plan_stop_request_invalid"
                )
            }
        }
        let body: [String: Any] = [
            "action": action.rawValue,
            "action_id": actionID,
            "catalog_sha256": catalogSHA256,
            "lease_profile_id": nativeNullable(leaseProfileID),
            "resume_session_id": nativeNullable(resumeSessionID),
            "session_id": sessionID,
            "source_id": nativeNullable(sourceID),
            "stack_id": stackID,
            "stack_sha256": stackSHA256,
        ]
        let digest = try CanonicalNativeJSON.digest(body)
        var request = body
        request["schema"] = Self.schema
        request["request_sha256"] = digest

        self.action = action
        self.actionID = actionID
        self.sessionID = sessionID
        self.stackID = stackID
        self.stackSHA256 = stackSHA256
        self.catalogSHA256 = catalogSHA256
        self.sourceID = sourceID
        self.resumeSessionID = resumeSessionID
        self.leaseProfileID = leaseProfileID
        requestSHA256 = digest
        canonicalData = try CanonicalNativeJSON.encodeLine(request)
    }
}

public struct NativeSessionAuthoritySummary: Hashable, Sendable {
    public let vendorID: String
    public let harnessID: String
    public let harnessGenerationID: String
    public let harnessExecutableSHA256: String
    public let harnessAdapterID: String
    public let modelID: String
    public let modelSettingsSHA256: String
    public let programID: String
    public let programTier: String
    public let programRequirementsVersion: String
    public let networkPolicyID: String
    public let sourceManifestSHA256: String?
    public let personaSHA256: String
    public let toolCatalogSHA256: String
    public let extensionSetSHA256: String
}

public struct NativeSessionPlan: Hashable, Sendable, Identifiable {
    public let action: NativeSessionAction
    public let actionID: String
    public let sessionID: String
    public let stackID: String
    public let stackSHA256: String
    public let catalogSHA256: String
    public let statusSHA256: String
    public let runtimeAuthoritySHA256: String
    public let sourceID: String?
    public let resumeSessionID: String?
    public let leaseProfileID: String?
    public let createdAt: Int
    public let expiresAt: Int
    public let planSHA256: String
    public let authority: NativeSessionAuthoritySummary
    public let canonicalData: Data

    public var id: String { actionID }

    public var expectedSessionIDSHA256: String {
        SHA256.hash(data: Data(sessionID.utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
}

public enum NativeSessionPlanProtocol {
    public static let planSchema = "secure-sandbox-native-stack-session-plan-v1"
    public static let replySchema =
        "secure-sandbox-native-stack-session-plan-query-reply-v1"

    public static func decodeReply(
        _ data: Data,
        request: NativeSessionPlanRequest,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeSessionPlan {
        let reply = try CanonicalNativeJSON.parseLine(data, maximumBytes: 1_048_576)
        try CanonicalNativeJSON.requireKeys(reply, [
            "schema", "action_id", "request_sha256", "plan", "reply_sha256",
        ], "native_session_plan_reply_fields_invalid")
        guard reply["schema"] as? String == replySchema,
              reply["action_id"] as? String == request.actionID,
              reply["request_sha256"] as? String == request.requestSHA256,
              let plan = reply["plan"] as? [String: Any],
              let replyDigest = reply["reply_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(replyDigest) else {
            throw NativeSessionProtocolError.rejected(
                "native_session_plan_reply_identity_invalid"
            )
        }
        let replyBody: [String: Any] = [
            "action_id": request.actionID,
            "plan": plan,
            "request_sha256": request.requestSHA256,
        ]
        guard replyDigest == (try CanonicalNativeJSON.digest(replyBody)) else {
            throw NativeSessionProtocolError.rejected(
                "native_session_plan_reply_digest_mismatch"
            )
        }
        return try validatePlan(plan, request: request, now: now)
    }

    private static func validatePlan(
        _ plan: [String: Any], request: NativeSessionPlanRequest, now: Int
    ) throws -> NativeSessionPlan {
        try CanonicalNativeJSON.requireKeys(plan, [
            "schema", "action", "action_id", "session_id", "stack_id",
            "stack_sha256", "catalog_sha256", "status_sha256",
            "runtime_authority", "runtime_authority_sha256", "source_id",
            "source_manifest_sha256", "resume_session_id", "lease_profile_id",
            "created_at", "expires_at", "plan_sha256",
        ], "native_session_plan_fields_invalid")
        guard plan["schema"] as? String == planSchema,
              plan["action"] as? String == request.action.rawValue,
              plan["action_id"] as? String == request.actionID,
              plan["session_id"] as? String == request.sessionID,
              plan["stack_id"] as? String == request.stackID,
              plan["stack_sha256"] as? String == request.stackSHA256,
              plan["catalog_sha256"] as? String == request.catalogSHA256,
              CanonicalNativeJSON.isSHA256(plan["status_sha256"]),
              plan["source_id"] as? String == request.sourceID,
              plan["resume_session_id"] as? String == request.resumeSessionID,
              plan["lease_profile_id"] as? String == request.leaseProfileID,
              let runtime = plan["runtime_authority"] as? [String: Any],
              let runtimeDigest = plan["runtime_authority_sha256"] as? String,
              let created = CanonicalNativeJSON.exactInteger(plan["created_at"]),
              let expires = CanonicalNativeJSON.exactInteger(plan["expires_at"]),
              created <= now, now < expires, expires <= created + 180,
              let planDigest = plan["plan_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(planDigest) else {
            throw NativeSessionProtocolError.rejected("native_session_plan_invalid")
        }
        if request.sourceID == nil {
            guard plan["source_manifest_sha256"] is NSNull else {
                throw NativeSessionProtocolError.rejected(
                    "native_session_plan_source_invalid"
                )
            }
        } else {
            guard CanonicalNativeJSON.isSHA256(plan["source_manifest_sha256"]) else {
                throw NativeSessionProtocolError.rejected(
                    "native_session_plan_source_invalid"
                )
            }
        }
        var body = plan
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "plan_sha256")
        guard planDigest == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_session_plan_digest_mismatch"
            )
        }
        let authority = try validateRuntimeAuthority(
            runtime,
            expectedDigest: runtimeDigest,
            sessionID: request.sessionID,
            stackID: request.stackID,
            stackSHA256: request.stackSHA256,
            sourceID: request.sourceID,
            sourceManifestSHA256: plan["source_manifest_sha256"] as? String
        )
        return NativeSessionPlan(
            action: request.action,
            actionID: request.actionID,
            sessionID: request.sessionID,
            stackID: request.stackID,
            stackSHA256: request.stackSHA256,
            catalogSHA256: request.catalogSHA256,
            statusSHA256: plan["status_sha256"] as! String,
            runtimeAuthoritySHA256: runtimeDigest,
            sourceID: request.sourceID,
            resumeSessionID: request.resumeSessionID,
            leaseProfileID: request.leaseProfileID,
            createdAt: created,
            expiresAt: expires,
            planSHA256: planDigest,
            authority: authority,
            canonicalData: try CanonicalNativeJSON.encodeLine(plan)
        )
    }

    private static func validateRuntimeAuthority(
        _ runtime: [String: Any],
        expectedDigest: String,
        sessionID: String,
        stackID: String,
        stackSHA256: String,
        sourceID: String?,
        sourceManifestSHA256: String?
    ) throws -> NativeSessionAuthoritySummary {
        try CanonicalNativeJSON.requireKeys(runtime, [
            "schema", "model_stack_binding", "session_context_binding",
            "harness_binding", "binding_sha256",
        ], "native_runtime_authority_fields_invalid")
        guard runtime["schema"] as? String == "secure-sandbox-runtime-authority-v1",
              runtime["binding_sha256"] as? String == expectedDigest,
              let modelStack = runtime["model_stack_binding"] as? [String: Any],
              let context = runtime["session_context_binding"] as? [String: Any],
              let harness = runtime["harness_binding"] as? [String: Any] else {
            throw NativeSessionProtocolError.rejected(
                "native_runtime_authority_identity_invalid"
            )
        }
        let runtimeBody: [String: Any] = [
            "harness_binding": harness,
            "model_stack_binding": modelStack,
            "session_context_binding": context,
        ]
        guard expectedDigest == (try CanonicalNativeJSON.digest(runtimeBody)) else {
            throw NativeSessionProtocolError.rejected(
                "native_runtime_authority_digest_mismatch"
            )
        }
        let native = try validateModelStack(
            modelStack, stackID: stackID, stackSHA256: stackSHA256
        )
        let harnessValues = try validateHarness(harness)
        guard native["harness_id"] == harnessValues["harness_id"],
              native["harness_generation_id"]
                == harnessValues["harness_generation_id"],
              native["harness_adapter_id"] == harnessValues["harness_adapter_id"] else {
            throw NativeSessionProtocolError.rejected(
                "native_runtime_harness_mismatch"
            )
        }
        let contextValues = try validateContext(
            context, sessionID: sessionID, sourceID: sourceID,
            sourceManifestSHA256: sourceManifestSHA256
        )
        return NativeSessionAuthoritySummary(
            vendorID: native["vendor_id"]!,
            harnessID: native["harness_id"]!,
            harnessGenerationID: native["harness_generation_id"]!,
            harnessExecutableSHA256: harnessValues["harness_executable_sha256"]!,
            harnessAdapterID: native["harness_adapter_id"]!,
            modelID: native["model_id"]!,
            modelSettingsSHA256: native["model_settings_sha256"]!,
            programID: native["program_id"]!,
            programTier: native["program_tier"]!,
            programRequirementsVersion: native["program_requirements_version"]!,
            networkPolicyID: native["network_policy_id"]!,
            sourceManifestSHA256: sourceManifestSHA256,
            personaSHA256: contextValues["persona_sha256"]!,
            toolCatalogSHA256: contextValues["tool_catalog_sha256"]!,
            extensionSetSHA256: contextValues["extension_set_sha256"]!
        )
    }

    private static func validateModelStack(
        _ value: [String: Any], stackID: String, stackSHA256: String
    ) throws -> [String: String] {
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "authority", "binding_sha256", "mode",
        ], "native_model_stack_fields_invalid")
        guard value["schema"] as? String
                == "secure-sandbox-model-stack-runtime-binding-v1",
              value["mode"] as? String == "native-vendor-harness-model-stack",
              let authority = value["authority"] as? [String: Any],
              let supplied = value["binding_sha256"] as? String,
              supplied == (try CanonicalNativeJSON.digest([
                "authority": authority,
                "mode": "native-vendor-harness-model-stack",
              ])) else {
            throw NativeSessionProtocolError.rejected("native_model_stack_invalid")
        }
        let fields: Set<String> = [
            "schema", "mode", "stack_id", "stack_sha256", "vendor_id",
            "harness_id", "harness_generation_id", "harness_adapter_id",
            "authentication_mode", "credential_custody",
            "account_subject_sha256", "workspace_sha256", "program_id",
            "program_requirements_version", "program_tier", "model_id",
            "model_settings_sha256", "network_policy_id", "binding_sha256",
        ]
        try CanonicalNativeJSON.requireKeys(
            authority, fields, "native_stack_authority_fields_invalid"
        )
        guard authority["schema"] as? String
                == "secure-sandbox-native-stack-runtime-binding-v1",
              authority["mode"] as? String
                == "native-vendor-harness-model-stack",
              authority["stack_id"] as? String == stackID,
              authority["stack_sha256"] as? String == stackSHA256 else {
            throw NativeSessionProtocolError.rejected(
                "native_stack_authority_identity_invalid"
            )
        }
        var body = authority
        body.removeValue(forKey: "schema")
        let digest = body.removeValue(forKey: "binding_sha256") as? String
        guard CanonicalNativeJSON.isSHA256(digest),
              digest == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_stack_authority_digest_mismatch"
            )
        }
        let stringFields = fields.subtracting(["schema", "binding_sha256"])
        var result: [String: String] = [:]
        for field in stringFields {
            guard let item = authority[field] as? String, !item.isEmpty else {
                throw NativeSessionProtocolError.rejected(
                    "native_stack_authority_value_invalid"
                )
            }
            result[field] = item
        }
        for field in [
            "stack_sha256", "harness_generation_id", "account_subject_sha256",
            "workspace_sha256", "model_settings_sha256",
        ] where !CanonicalNativeJSON.isSHA256(result[field]) {
            throw NativeSessionProtocolError.rejected(
                "native_stack_authority_digest_value_invalid"
            )
        }
        return result
    }

    private static func validateHarness(_ value: [String: Any]) throws -> [String: String] {
        let fields: Set<String> = [
            "schema", "harness_id", "harness_generation_id",
            "harness_manifest_sha256", "harness_executable_sha256",
            "harness_inventory_sha256", "harness_adapter_id",
            "harness_adapter_sha256", "binding_sha256",
        ]
        try CanonicalNativeJSON.requireKeys(
            value, fields, "native_harness_binding_fields_invalid"
        )
        guard value["schema"] as? String
                == "secure-sandbox-harness-runtime-binding-v1" else {
            throw NativeSessionProtocolError.rejected(
                "native_harness_binding_schema_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        let supplied = body.removeValue(forKey: "binding_sha256") as? String
        guard CanonicalNativeJSON.isSHA256(supplied),
              supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_harness_binding_digest_mismatch"
            )
        }
        var result: [String: String] = [:]
        for field in fields.subtracting(["schema", "binding_sha256"]) {
            guard let item = value[field] as? String, !item.isEmpty else {
                throw NativeSessionProtocolError.rejected(
                    "native_harness_binding_value_invalid"
                )
            }
            result[field] = item
        }
        for field in [
            "harness_generation_id", "harness_manifest_sha256",
            "harness_executable_sha256", "harness_inventory_sha256",
            "harness_adapter_sha256",
        ] where !CanonicalNativeJSON.isSHA256(result[field]) {
            throw NativeSessionProtocolError.rejected(
                "native_harness_binding_digest_value_invalid"
            )
        }
        return result
    }

    private static func validateContext(
        _ value: [String: Any], sessionID: String, sourceID: String?,
        sourceManifestSHA256: String?
    ) throws -> [String: String] {
        let fields: Set<String> = [
            "schema", "session_id", "source_id", "source_manifest_sha256",
            "persona_sha256", "tool_catalog_sha256", "extension_set_sha256",
            "binding_sha256",
        ]
        try CanonicalNativeJSON.requireKeys(
            value, fields, "native_session_context_fields_invalid"
        )
        guard value["schema"] as? String
                == "secure-sandbox-session-context-binding-v1",
              value["session_id"] as? String == sessionID,
              value["source_id"] as? String == sourceID,
              value["source_manifest_sha256"] as? String == sourceManifestSHA256 else {
            throw NativeSessionProtocolError.rejected(
                "native_session_context_identity_invalid"
            )
        }
        var body = value
        body.removeValue(forKey: "schema")
        let supplied = body.removeValue(forKey: "binding_sha256") as? String
        guard CanonicalNativeJSON.isSHA256(supplied),
              supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_session_context_digest_mismatch"
            )
        }
        var result: [String: String] = [:]
        for field in ["persona_sha256", "tool_catalog_sha256", "extension_set_sha256"] {
            guard let item = value[field] as? String,
                  CanonicalNativeJSON.isSHA256(item) else {
                throw NativeSessionProtocolError.rejected(
                    "native_session_context_digest_value_invalid"
                )
            }
            result[field] = item
        }
        return result
    }
}

private func nativeSessionIdentifier(_ value: String) -> Bool {
    value.range(of: #"^[a-z0-9][a-z0-9._-]{0,63}$"#, options: .regularExpression)
        != nil
}

private func nativeNullable(_ value: String?) -> Any {
    if let value { return value }
    return NSNull()
}
