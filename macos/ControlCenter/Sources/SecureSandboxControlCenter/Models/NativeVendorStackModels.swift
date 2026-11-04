import Foundation
import SecureSandboxNativeSessionUIProtocol

struct NativeVendorStackCatalogStatus: Decodable, Sendable {
    let catalog: NativeVendorStackCatalog
    let catalogSHA256: String
    let schema: String
    let source: String
    let stacks: [NativeVendorStackRevision]
    let status: String

    enum CodingKeys: String, CodingKey {
        case catalog
        case catalogSHA256 = "catalog_sha256"
        case schema, source, stacks, status
    }
}

struct NativeVendorStackRevision: Decodable, Sendable {
    let readiness: NativeVendorStackReadiness
    let revisionSHA256: String
    let stack: NativeVendorStack

    enum CodingKeys: String, CodingKey {
        case readiness
        case revisionSHA256 = "revision_sha256"
        case stack
    }
}

struct NativeVendorStackReadiness: Codable, Hashable, Sendable {
    let missing: [String]
    let schema: String
    let stackID: String
    let stackSHA256: String
    let status: String

    enum CodingKeys: String, CodingKey {
        case missing, schema, status
        case stackID = "stack_id"
        case stackSHA256 = "stack_sha256"
    }
}

struct NativeVendorStackCatalog: Codable, Hashable, Sendable {
    var schema = "secure-sandbox-native-vendor-stack-catalog-v1"
    var stacks: [NativeVendorStack]
}

struct NativeVendorStack: Codable, Identifiable, Hashable, Sendable {
    var accountBinding: NativeVendorAccountBinding
    var authentication: NativeVendorAuthentication
    var displayName: String
    var harness: NativeVendorHarness
    var mode: String
    var model: NativeVendorModel
    var networkPolicyID: String
    var stackID: String
    var vendorID: String

    var id: String { stackID }

    enum CodingKeys: String, CodingKey {
        case accountBinding = "account_binding"
        case authentication
        case displayName = "display_name"
        case harness, mode, model
        case networkPolicyID = "network_policy_id"
        case stackID = "stack_id"
        case vendorID = "vendor_id"
    }
}

struct NativeVendorAccountBinding: Codable, Hashable, Sendable {
    var accountSubjectSHA256: String?
    var programID: String
    var programRequirementsVersion: String
    var programTier: String
    var workspaceSHA256: String?

    enum CodingKeys: String, CodingKey {
        case accountSubjectSHA256 = "account_subject_sha256"
        case programID = "program_id"
        case programRequirementsVersion = "program_requirements_version"
        case programTier = "program_tier"
        case workspaceSHA256 = "workspace_sha256"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if let accountSubjectSHA256 {
            try container.encode(accountSubjectSHA256, forKey: .accountSubjectSHA256)
        } else {
            try container.encodeNil(forKey: .accountSubjectSHA256)
        }
        try container.encode(programID, forKey: .programID)
        try container.encode(programRequirementsVersion, forKey: .programRequirementsVersion)
        try container.encode(programTier, forKey: .programTier)
        if let workspaceSHA256 {
            try container.encode(workspaceSHA256, forKey: .workspaceSHA256)
        } else {
            try container.encodeNil(forKey: .workspaceSHA256)
        }
    }
}

struct NativeVendorAuthentication: Codable, Hashable, Sendable {
    var credentialCustody: String
    var mode: String

    enum CodingKeys: String, CodingKey {
        case credentialCustody = "credential_custody"
        case mode
    }
}

struct NativeVendorHarness: Codable, Hashable, Sendable {
    var adapterID: String
    var generationID: String?
    var harnessID: String

    enum CodingKeys: String, CodingKey {
        case adapterID = "adapter_id"
        case generationID = "generation_id"
        case harnessID = "harness_id"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(adapterID, forKey: .adapterID)
        if let generationID {
            try container.encode(generationID, forKey: .generationID)
        } else {
            try container.encodeNil(forKey: .generationID)
        }
        try container.encode(harnessID, forKey: .harnessID)
    }
}

struct NativeVendorModel: Codable, Hashable, Sendable {
    var modelID: String
    var modelName: String
    var settings: NativeVendorModelSettings

    enum CodingKeys: String, CodingKey {
        case modelID = "model_id"
        case modelName = "model_name"
        case settings
    }
}

struct NativeVendorModelSettings: Codable, Hashable, Sendable {
    var cyberAccess: String?
    var effort: String?
    var reasoningEffort: String?

    enum CodingKeys: String, CodingKey {
        case cyberAccess = "cyber_access"
        case effort
        case reasoningEffort = "reasoning_effort"
    }
}

struct NativeStackPublicCatalogStatus: Decodable, Hashable, Sendable {
    let schema: String
    let catalogSHA256: String
    let hostReleaseID: String
    let promotionID: String
    let promotionReceiptSHA256: String
    let publishedAt: Int
    let stacks: [NativeStackPublicRevision]
    let statusSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, stacks
        case catalogSHA256 = "catalog_sha256"
        case hostReleaseID = "host_release_id"
        case promotionID = "promotion_id"
        case promotionReceiptSHA256 = "promotion_receipt_sha256"
        case publishedAt = "published_at"
        case statusSHA256 = "status_sha256"
    }

    func validate() throws {
        guard schema == "secure-sandbox-native-stack-catalog-public-status-v1",
              NativeStackModelValidation.isSHA256(catalogSHA256),
              NativeStackModelValidation.isSHA256(hostReleaseID),
              NativeStackModelValidation.isUUID4(promotionID),
              NativeStackModelValidation.isSHA256(promotionReceiptSHA256),
              NativeStackModelValidation.isSHA256(statusSHA256),
              publishedAt > 0, (1...8).contains(stacks.count),
              stacks == stacks.sorted(by: { $0.stackID < $1.stackID }),
              Set(stacks.map(\.stackID)).count == stacks.count,
              stacks.allSatisfy({
                  NativeStackModelValidation.isIdentifier($0.stackID)
                      && NativeStackModelValidation.isSHA256($0.stackSHA256)
              })
        else { throw NativeStackControlError.rejected("native_stack_public_status_invalid") }
    }
}

struct NativeStackPublicRevision: Decodable, Hashable, Sendable {
    let stackID: String
    let stackSHA256: String

    enum CodingKeys: String, CodingKey {
        case stackID = "stack_id"
        case stackSHA256 = "stack_sha256"
    }
}

struct NativeStackOperationalStatus: Decodable, Hashable, Sendable {
    let schema: String
    let stackID: String
    let stackSHA256: String
    let harness: NativeStackHarnessStatus
    let authentication: NativeStackObservation
    let credentialCustody: NativeStackCredentialCustodyStatus
    let accountBinding: NativeStackAccountBindingStatus
    let programEntitlement: NativeStackEntitlementStatus
    let modelEntitlement: NativeStackEntitlementStatus
    let network: NativeStackNetworkStatus
    let activation: NativeStackActivationStatus
    let liveRunCount: Int
    let fenceReason: String?
    let statusSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, harness, authentication, network, activation
        case stackID = "stack_id"
        case stackSHA256 = "stack_sha256"
        case credentialCustody = "credential_custody"
        case accountBinding = "account_binding"
        case programEntitlement = "program_entitlement"
        case modelEntitlement = "model_entitlement"
        case liveRunCount = "live_run_count"
        case fenceReason = "fence_reason"
        case statusSHA256 = "status_sha256"
    }

    func validate() throws {
        guard schema == "secure-sandbox-native-stack-operational-status-v2",
              NativeStackModelValidation.isIdentifier(stackID),
              NativeStackModelValidation.isSHA256(stackSHA256),
              NativeStackModelValidation.isSHA256(statusSHA256),
              liveRunCount >= 0
        else { throw NativeStackControlError.rejected("native_stack_operational_status_invalid") }
        try harness.validate()
        try authentication.validate(states: [
            "signed-out", "signed-in", "expired", "revoked", "ambiguous", "fenced",
        ])
        try credentialCustody.validate()
        try accountBinding.validate()
        try programEntitlement.validate()
        try modelEntitlement.validate()
        try network.validate()
        try activation.validate()
        if ["fenced", "recovery-required"].contains(activation.state) {
            guard let fenceReason,
                  NativeStackModelValidation.isIdentifier(fenceReason) else {
                throw NativeStackControlError.rejected("native_stack_fence_reason_missing")
            }
        } else if fenceReason != nil {
            throw NativeStackControlError.rejected("native_stack_fence_reason_unexpected")
        }
    }
}

struct NativeStackObservation: Decodable, Hashable, Sendable {
    let state: String
    let observedAt: Int?
    let evidenceSHA256: String?

    enum CodingKeys: String, CodingKey {
        case state
        case observedAt = "observed_at"
        case evidenceSHA256 = "evidence_sha256"
    }

    func validate(states: Set<String>) throws {
        guard states.contains(state), (observedAt == nil) == (evidenceSHA256 == nil),
              observedAt.map({ $0 > 0 }) ?? true,
              evidenceSHA256.map(NativeStackModelValidation.isSHA256) ?? true
        else { throw NativeStackControlError.rejected("native_stack_observation_invalid") }
    }
}

struct NativeStackEntitlementStatus: Decodable, Hashable, Sendable {
    let state: String
    let observedAt: Int?
    let evidenceSHA256: String?
    let assurance: String

    enum CodingKeys: String, CodingKey {
        case state, assurance
        case observedAt = "observed_at"
        case evidenceSHA256 = "evidence_sha256"
    }

    func validate() throws {
        try NativeStackObservation(
            state: state, observedAt: observedAt, evidenceSHA256: evidenceSHA256
        ).validate(states: ["unknown", "verified", "denied", "stale", "ambiguous"])
        guard ["unknown", "operator-external", "provider-enforced"].contains(assurance),
              (state == "verified" && assurance != "unknown")
                || (state != "verified" && assurance == "unknown")
        else {
            throw NativeStackControlError.rejected(
                "native_stack_entitlement_assurance_invalid"
            )
        }
    }
}

struct NativeStackHarnessStatus: Decodable, Hashable, Sendable {
    let state: String
    let observedAt: Int?
    let evidenceSHA256: String?
    let generationID: String?
    let bindingSHA256: String?

    enum CodingKeys: String, CodingKey {
        case state
        case observedAt = "observed_at"
        case evidenceSHA256 = "evidence_sha256"
        case generationID = "generation_id"
        case bindingSHA256 = "binding_sha256"
    }

    func validate() throws {
        try NativeStackObservation(
            state: state, observedAt: observedAt, evidenceSHA256: evidenceSHA256
        ).validate(states: ["missing", "admitted", "mismatch", "revoked", "ambiguous"])
        guard generationID.map(NativeStackModelValidation.isSHA256) ?? true,
              bindingSHA256.map(NativeStackModelValidation.isSHA256) ?? true,
              state != "admitted" || (generationID != nil && bindingSHA256 != nil)
        else { throw NativeStackControlError.rejected("native_stack_harness_status_invalid") }
    }
}

struct NativeStackCredentialCustodyStatus: Decodable, Hashable, Sendable {
    let state: String
    let observedAt: Int
    let evidenceSHA256: String
    let tombstoneSHA256: String?
    let projectionCount: Int?

    enum CodingKeys: String, CodingKey {
        case state
        case observedAt = "observed_at"
        case evidenceSHA256 = "evidence_sha256"
        case tombstoneSHA256 = "tombstone_sha256"
        case projectionCount = "projection_count"
    }

    func validate() throws {
        guard ["absent", "retained", "session-projected", "ambiguous"].contains(state),
              observedAt > 0, NativeStackModelValidation.isSHA256(evidenceSHA256),
              tombstoneSHA256.map(NativeStackModelValidation.isSHA256) ?? true
        else { throw NativeStackControlError.rejected("native_stack_custody_status_invalid") }
        switch state {
        case "ambiguous":
            guard (projectionCount == nil || projectionCount == 0),
                  tombstoneSHA256 == nil else {
                throw NativeStackControlError.rejected("native_stack_custody_status_invalid")
            }
        case "session-projected":
            guard let projectionCount, projectionCount > 0, tombstoneSHA256 == nil else {
                throw NativeStackControlError.rejected("native_stack_custody_status_invalid")
            }
        case "retained":
            guard projectionCount == 0, tombstoneSHA256 == nil else {
                throw NativeStackControlError.rejected("native_stack_custody_status_invalid")
            }
        default:
            guard projectionCount == 0 else {
                throw NativeStackControlError.rejected("native_stack_custody_status_invalid")
            }
        }
    }
}

struct NativeStackAccountBindingStatus: Decodable, Hashable, Sendable {
    let state: String
    let observedAt: Int?
    let evidenceSHA256: String?
    let accountSubjectSHA256: String?
    let workspaceSHA256: String?

    enum CodingKeys: String, CodingKey {
        case state
        case observedAt = "observed_at"
        case evidenceSHA256 = "evidence_sha256"
        case accountSubjectSHA256 = "account_subject_sha256"
        case workspaceSHA256 = "workspace_sha256"
    }

    func validate() throws {
        try NativeStackObservation(
            state: state, observedAt: observedAt, evidenceSHA256: evidenceSHA256
        ).validate(states: ["unbound", "observed", "bound", "mismatch", "ambiguous"])
        guard accountSubjectSHA256.map(NativeStackModelValidation.isSHA256) ?? true,
              workspaceSHA256.map(NativeStackModelValidation.isSHA256) ?? true,
              !["observed", "bound", "mismatch"].contains(state)
                || (accountSubjectSHA256 != nil && workspaceSHA256 != nil)
        else { throw NativeStackControlError.rejected("native_stack_binding_status_invalid") }
    }
}

struct NativeStackNetworkStatus: Decodable, Hashable, Sendable {
    let phase: String
    let grantSHA256: String?
    let expiresAt: Int?
    let observedAt: Int

    enum CodingKeys: String, CodingKey {
        case phase
        case grantSHA256 = "grant_sha256"
        case expiresAt = "expires_at"
        case observedAt = "observed_at"
    }

    func validate() throws {
        guard ["closed", "login", "inference", "status-logout", "ambiguous"].contains(phase),
              observedAt > 0, grantSHA256.map(NativeStackModelValidation.isSHA256) ?? true,
              expiresAt.map({ $0 > 0 }) ?? true
        else { throw NativeStackControlError.rejected("native_stack_network_status_invalid") }
        if phase == "closed" {
            guard grantSHA256 == nil, expiresAt == nil else {
                throw NativeStackControlError.rejected("native_stack_network_status_invalid")
            }
        } else if phase != "ambiguous" {
            guard grantSHA256 != nil, expiresAt != nil else {
                throw NativeStackControlError.rejected("native_stack_network_status_invalid")
            }
        }
    }
}

struct NativeStackActivationStatus: Decodable, Hashable, Sendable {
    let state: String
    let observedAt: Int?
    let evidenceSHA256: String?
    let receiptSHA256: String?

    enum CodingKeys: String, CodingKey {
        case state
        case observedAt = "observed_at"
        case evidenceSHA256 = "evidence_sha256"
        case receiptSHA256 = "receipt_sha256"
    }

    func validate() throws {
        try NativeStackObservation(
            state: state, observedAt: observedAt, evidenceSHA256: evidenceSHA256
        ).validate(states: [
            "inactive", "active", "fenced", "rollback-pending", "recovery-required",
        ])
        guard receiptSHA256.map(NativeStackModelValidation.isSHA256) ?? true,
              state != "active" || receiptSHA256 != nil
        else { throw NativeStackControlError.rejected("native_stack_activation_status_invalid") }
    }
}

struct NativeStackActionPlan: Decodable, Hashable, Sendable {
    let schema: String
    let actionID: String
    let action: String
    let createdAt: Int
    let expiresAt: Int
    let identity: NativeStackActionIdentity
    let currentStatusSHA256: String
    let observedAccountSubjectSHA256: String?
    let observedWorkspaceSHA256: String?
    let requestedNetworkPhase: String
    let impact: NativeStackActionImpact
    let planSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, action, identity, impact
        case actionID = "action_id"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case currentStatusSHA256 = "current_status_sha256"
        case observedAccountSubjectSHA256 = "observed_account_subject_sha256"
        case observedWorkspaceSHA256 = "observed_workspace_sha256"
        case requestedNetworkPhase = "requested_network_phase"
        case planSHA256 = "plan_sha256"
    }
}

struct NativeStackActionIdentity: Decodable, Hashable, Sendable {
    let stackID: String
    let stackSHA256: String
    let vendorID: String
    let harnessID: String
    let harnessGenerationID: String?
    let harnessAdapterID: String
    let authenticationMode: String
    let credentialCustody: String
    let accountSubjectSHA256: String?
    let workspaceSHA256: String?
    let programID: String
    let programTier: String
    let programRequirementsVersion: String
    let modelID: String
    let modelSettingsSHA256: String
    let networkPolicyID: String

    enum CodingKeys: String, CodingKey {
        case stackID = "stack_id"
        case stackSHA256 = "stack_sha256"
        case vendorID = "vendor_id"
        case harnessID = "harness_id"
        case harnessGenerationID = "harness_generation_id"
        case harnessAdapterID = "harness_adapter_id"
        case authenticationMode = "authentication_mode"
        case credentialCustody = "credential_custody"
        case accountSubjectSHA256 = "account_subject_sha256"
        case workspaceSHA256 = "workspace_sha256"
        case programID = "program_id"
        case programTier = "program_tier"
        case programRequirementsVersion = "program_requirements_version"
        case modelID = "model_id"
        case modelSettingsSHA256 = "model_settings_sha256"
        case networkPolicyID = "network_policy_id"
    }
}

struct NativeStackActionImpact: Decodable, Hashable, Sendable {
    let stopsBoundRuns: Bool
    let destroysCredentials: Bool
    let changesLiveAuthority: Bool

    enum CodingKeys: String, CodingKey {
        case stopsBoundRuns = "stops_bound_runs"
        case destroysCredentials = "destroys_credentials"
        case changesLiveAuthority = "changes_live_authority"
    }
}

struct NativeStackActionReceipt: Decodable, Hashable, Sendable {
    let schema: String
    let actionID: String
    let action: String
    let planSHA256: String
    let completedAt: Int
    let result: String
    let statusSHA256: String
    let evidenceSHA256: String
    let receiptSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, action, result
        case actionID = "action_id"
        case planSHA256 = "plan_sha256"
        case completedAt = "completed_at"
        case statusSHA256 = "status_sha256"
        case evidenceSHA256 = "evidence_sha256"
        case receiptSHA256 = "receipt_sha256"
    }
}

struct NativeStackCatalogPromotionPlan: Decodable, Hashable, Sendable {
    let schema: String
    let promotionID: String
    let sourceUID: Int
    let sourceSHA256: String
    let previousCatalogSHA256: String?
    let catalogSHA256: String
    let createdAt: Int
    let expiresAt: Int
    let hostReleaseID: String
    let planSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case promotionID = "promotion_id"
        case sourceUID = "source_uid"
        case sourceSHA256 = "source_sha256"
        case previousCatalogSHA256 = "previous_catalog_sha256"
        case catalogSHA256 = "catalog_sha256"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case hostReleaseID = "host_release_id"
        case planSHA256 = "plan_sha256"
    }
}

struct NativeStackCatalogPromotionReceipt: Decodable, Hashable, Sendable {
    let schema: String
    let promotionID: String
    let planSHA256: String
    let authorizationSHA256: String
    let authorizationReceiptSHA256: String
    let sourceSHA256: String
    let previousCatalogSHA256: String?
    let catalogSHA256: String
    let hostReleaseID: String
    let promotedAt: Int
    let status: String
    let receiptSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, status
        case promotionID = "promotion_id"
        case planSHA256 = "plan_sha256"
        case authorizationSHA256 = "authorization_sha256"
        case authorizationReceiptSHA256 = "authorization_receipt_sha256"
        case sourceSHA256 = "source_sha256"
        case previousCatalogSHA256 = "previous_catalog_sha256"
        case catalogSHA256 = "catalog_sha256"
        case hostReleaseID = "host_release_id"
        case promotedAt = "promoted_at"
        case receiptSHA256 = "receipt_sha256"
    }
}

struct NativeProgramAttestationPlan: Decodable, Hashable, Sendable, Identifiable {
    let schema: String
    let attestationID: String
    let stackID: String
    let stackSHA256: String
    let catalogSHA256: String
    let statusSHA256: String
    let harnessGenerationID: String
    let accountSubjectSHA256: String
    let workspaceSHA256: String
    let programID: String
    let programTier: String
    let programRequirementsVersion: String
    let assurance: String
    let createdAt: Int
    let expiresAt: Int
    let planSHA256: String

    var id: String { attestationID }

    enum CodingKeys: String, CodingKey {
        case schema, assurance
        case attestationID = "attestation_id"
        case stackID = "stack_id"
        case stackSHA256 = "stack_sha256"
        case catalogSHA256 = "catalog_sha256"
        case statusSHA256 = "status_sha256"
        case harnessGenerationID = "harness_generation_id"
        case accountSubjectSHA256 = "account_subject_sha256"
        case workspaceSHA256 = "workspace_sha256"
        case programID = "program_id"
        case programTier = "program_tier"
        case programRequirementsVersion = "program_requirements_version"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case planSHA256 = "plan_sha256"
    }

    func validateDigest() throws {
        let body: [String: Any] = [
            "account_subject_sha256": accountSubjectSHA256,
            "assurance": assurance,
            "attestation_id": attestationID,
            "catalog_sha256": catalogSHA256,
            "created_at": createdAt,
            "expires_at": expiresAt,
            "harness_generation_id": harnessGenerationID,
            "program_id": programID,
            "program_requirements_version": programRequirementsVersion,
            "program_tier": programTier,
            "stack_id": stackID,
            "stack_sha256": stackSHA256,
            "status_sha256": statusSHA256,
            "workspace_sha256": workspaceSHA256,
        ]
        guard planSHA256 == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_program_attestation_plan_digest_mismatch"
            )
        }
    }
}

struct NativeProgramAttestationResult: Decodable, Hashable, Sendable {
    let schema: String
    let actionID: String
    let action: String
    let planSHA256: String
    let authorizationSHA256: String
    let status: String
    let evidenceSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, action, status
        case actionID = "action_id"
        case planSHA256 = "plan_sha256"
        case authorizationSHA256 = "authorization_sha256"
        case evidenceSHA256 = "evidence_sha256"
    }
}

struct NativeSessionStopReply: Decodable, Hashable, Sendable {
    let schema: String
    let operationID: String
    let sessionID: String
    let state: String
    let finalSummarySHA256: String
    let evidenceSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, state
        case operationID = "operation_id"
        case sessionID = "session_id"
        case finalSummarySHA256 = "final_summary_sha256"
        case evidenceSHA256 = "evidence_sha256"
    }
}

private enum NativeStackModelValidation {
    static func isSHA256(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    static func isUUID4(_ value: String) -> Bool {
        value.range(
            of: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            options: .regularExpression
        ) != nil
    }

    static func isIdentifier(_ value: String) -> Bool {
        value.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }
}
