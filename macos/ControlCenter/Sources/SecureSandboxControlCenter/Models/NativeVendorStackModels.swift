import Foundation

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
    var programTier: String
    var workspaceSHA256: String?

    enum CodingKeys: String, CodingKey {
        case accountSubjectSHA256 = "account_subject_sha256"
        case programID = "program_id"
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
