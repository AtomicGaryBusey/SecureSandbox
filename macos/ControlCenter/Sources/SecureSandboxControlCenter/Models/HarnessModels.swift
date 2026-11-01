import Foundation

struct HarnessControlCenterStatus: Codable, Sendable {
    let schema: String
    let lifecycle: HarnessLifecycleStatus
    let protected: HarnessProtectedAvailability
    let protectedActions: HarnessProtectedActions

    enum CodingKeys: String, CodingKey {
        case schema, lifecycle, protected
        case protectedActions = "protected_actions"
    }
}

struct HarnessLifecycleStatus: Codable, Sendable {
    let schema: String
    let authority: String
    let automaticDownload: Bool
    let automaticInstall: Bool
    let policyConfigured: Bool
    let policySHA256: String?
    let floor: HarnessMetadataFloor?
    let generations: [HarnessQuarantineGeneration]

    enum CodingKeys: String, CodingKey {
        case schema, authority, floor, generations
        case automaticDownload = "automatic_download"
        case automaticInstall = "automatic_install"
        case policyConfigured = "policy_configured"
        case policySHA256 = "policy_sha256"
    }
}

struct HarnessMetadataFloor: Codable, Sendable {
    let schema: String
    let sequence: Int
    let envelopeSHA256: String
    let policySHA256: String

    enum CodingKeys: String, CodingKey {
        case schema, sequence
        case envelopeSHA256 = "envelope_sha256"
        case policySHA256 = "policy_sha256"
    }
}

struct HarnessQuarantineGeneration: Codable, Identifiable, Sendable {
    var id: String { generationID }
    let generationID: String
    let state: String
    let artifactPresent: Bool
    let manifestPresent: Bool

    enum CodingKeys: String, CodingKey {
        case state
        case generationID = "generation_id"
        case artifactPresent = "artifact_present"
        case manifestPresent = "manifest_present"
    }
}

struct HarnessProtectedAvailability: Codable, Sendable {
    let availability: String
    let reason: String?
    let status: HarnessProtectedStatus?
}

struct HarnessProtectedActions: Codable, Sendable {
    let activate: Bool
    let rollback: Bool
    let retire: Bool
    let revoke: Bool
    let requiresTouchID: Bool
    let passwordFallback: Bool

    enum CodingKeys: String, CodingKey {
        case activate, rollback, retire, revoke
        case requiresTouchID = "requires_touch_id"
        case passwordFallback = "password_fallback"
    }
}

struct HarnessProtectedStatus: Codable, Sendable {
    let schema: String
    let status: String
    let admission: String
    let recoveryPending: Bool
    let activeGenerationID: String?
    let predecessorGenerationID: String?
    let selectorEpoch: Int
    let highestReleaseSequence: Int
    let revokedGenerationIDs: [String]
    let generations: [HarnessProtectedGeneration]

    enum CodingKeys: String, CodingKey {
        case schema, status, admission, generations
        case recoveryPending = "recovery_pending"
        case activeGenerationID = "active_generation_id"
        case predecessorGenerationID = "predecessor_generation_id"
        case selectorEpoch = "selector_epoch"
        case highestReleaseSequence = "highest_release_sequence"
        case revokedGenerationIDs = "revoked_generation_ids"
    }
}

struct HarnessProtectedGeneration: Codable, Identifiable, Sendable {
    var id: String { generationID }
    let generationID: String
    let harnessID: String
    let vendorID: String
    let version: String
    let platform: String
    let releaseSequence: Int
    let artifactSHA256: String
    let artifactSize: Int
    let manifestSHA256: String
    let policySHA256: String
    let adapterID: String
    let adapterSHA256: String
    let suiteSHA256: String
    let qualificationSHA256: String
    let inventorySHA256: String
    let publishedAt: Int
    let status: String
    let reasonSHA256: String?

    enum CodingKeys: String, CodingKey {
        case version, platform, status
        case generationID = "generation_id"
        case harnessID = "harness_id"
        case vendorID = "vendor_id"
        case releaseSequence = "release_sequence"
        case artifactSHA256 = "artifact_sha256"
        case artifactSize = "artifact_size"
        case manifestSHA256 = "manifest_sha256"
        case policySHA256 = "policy_sha256"
        case adapterID = "adapter_id"
        case adapterSHA256 = "adapter_sha256"
        case suiteSHA256 = "suite_sha256"
        case qualificationSHA256 = "qualification_sha256"
        case inventorySHA256 = "inventory_sha256"
        case publishedAt = "published_at"
        case reasonSHA256 = "reason_sha256"
    }
}

struct HarnessLifecycleReceipt: Codable, Sendable {
    let schema: String
    let receiptID: String
    let action: String
    let status: String
    let observedAt: Int
    let generationID: String?
    let sequence: Int?
    let releaseCount: Int?
    let envelopeSHA256: String?
    let policySHA256: String?
    let artifactSHA256: String?
    let manifestSHA256: String?
    let evidenceSHA256: [String]?
    let note: String?

    enum CodingKeys: String, CodingKey {
        case schema, action, status, sequence, note
        case receiptID = "receipt_id"
        case observedAt = "observed_at"
        case generationID = "generation_id"
        case releaseCount = "release_count"
        case envelopeSHA256 = "envelope_sha256"
        case policySHA256 = "policy_sha256"
        case artifactSHA256 = "artifact_sha256"
        case manifestSHA256 = "manifest_sha256"
        case evidenceSHA256 = "evidence_sha256"
    }
}

struct HarnessQualificationReport: Codable, Sendable {
    let schema: String
    let qualificationID: String
    let status: String
    let authority: String
    let note: String
    let adapterID: String
    let generationID: String
    let reportSHA256: String
    let observationSetSHA256: String
    let caseResults: [HarnessQualificationCase]

    enum CodingKeys: String, CodingKey {
        case schema, status, authority, note
        case qualificationID = "qualification_id"
        case adapterID = "adapter_id"
        case generationID = "generation_id"
        case reportSHA256 = "report_sha256"
        case observationSetSHA256 = "observation_set_sha256"
        case caseResults = "case_results"
    }
}

struct HarnessQualificationCase: Codable, Identifiable, Sendable {
    var id: String { caseID }
    let caseID: String
    let status: String
    let failures: [String]
    let observationSHA256: String

    enum CodingKeys: String, CodingKey {
        case status, failures
        case caseID = "case_id"
        case observationSHA256 = "observation_sha256"
    }
}

struct HarnessReleaseCatalog: Codable, Sendable {
    let schema: String
    let sequence: Int
    let publishedAt: Int
    let expiresAt: Int
    let envelopeSHA256: String
    let policySHA256: String
    let authority: String
    let releases: [HarnessRelease]

    enum CodingKeys: String, CodingKey {
        case schema, sequence, authority, releases
        case publishedAt = "published_at"
        case expiresAt = "expires_at"
        case envelopeSHA256 = "envelope_sha256"
        case policySHA256 = "policy_sha256"
    }
}

struct HarnessRelease: Codable, Identifiable, Sendable {
    var id: String { generationID }
    let schema: String
    let generationID: String
    let harnessID: String
    let vendorID: String
    let version: String
    let platform: String
    let releaseSequence: Int
    let adapterID: String
    let artifact: HarnessReleaseArtifact
    let evidence: [HarnessReleaseEvidence]
    let compatibility: HarnessReleaseCompatibility

    enum CodingKeys: String, CodingKey {
        case schema, version, platform, artifact, evidence, compatibility
        case generationID = "generation_id"
        case harnessID = "harness_id"
        case vendorID = "vendor_id"
        case releaseSequence = "release_sequence"
        case adapterID = "adapter_id"
    }
}

struct HarnessReleaseArtifact: Codable, Sendable {
    let filename: String
    let mediaType: String
    let sha256: String
    let size: Int
    let url: String

    enum CodingKeys: String, CodingKey {
        case filename, sha256, size, url
        case mediaType = "media_type"
    }
}

struct HarnessReleaseEvidence: Codable, Identifiable, Sendable {
    var id: String { kind }
    let kind: String
    let mediaType: String
    let required: Bool
    let sha256: String
    let subjectSHA256: String

    enum CodingKeys: String, CodingKey {
        case kind, required, sha256
        case mediaType = "media_type"
        case subjectSHA256 = "subject_sha256"
    }
}

struct HarnessReleaseCompatibility: Codable, Sendable {
    let adapterSHA256: String
    let controllerSchema: String

    enum CodingKeys: String, CodingKey {
        case adapterSHA256 = "adapter_sha256"
        case controllerSchema = "controller_schema"
    }
}
