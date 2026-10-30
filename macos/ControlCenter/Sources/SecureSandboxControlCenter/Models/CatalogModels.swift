import Foundation

enum ControlSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case sessions = "Sessions"
    case sources = "Sources"
    case findings = "Findings"
    case evidence = "Evidence"
    case recovery = "Recovery"
    case activity = "Activity"
    case maintenance = "Maintenance"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .sessions: "terminal"
        case .sources: "square.stack"
        case .findings: "checkmark.shield"
        case .evidence: "doc.text.magnifyingglass"
        case .recovery: "externaldrive"
        case .activity: "clock.arrow.circlepath"
        case .maintenance: "wrench.adjustable"
        }
    }
}

struct Envelope<T: Decodable>: Decodable {
    let schema: String
    let catalog: String
    let data: T
}

struct HostStatus: Decodable, Sendable {
    let schema: String
    let status: String
    let observed: Observed
    let reachability: Reachability?

    struct Observed: Decodable, Sendable {
        let gateway: String
        let research: String
        let target: String
        let gatewayNet0: String

        enum CodingKeys: String, CodingKey {
            case gateway, research, target
            case gatewayNet0 = "gateway_net0"
        }
    }

    struct Reachability: Decodable, Sendable {
        let gateway: String
        let research: String
        let target: String
    }
}

struct SessionRecord: Decodable, Identifiable, Sendable {
    let id: String
    let createdAt: String
    let lastAt: String
    let turns: String
    let compacts: String
    let runs: String
    let label: String

    enum CodingKeys: String, CodingKey {
        case id, turns, compacts, runs, label
        case createdAt = "created_at"
        case lastAt = "last_at"
    }

    static func displayNames(in catalog: [SessionRecord]) -> [String: String] {
        var names: [String: String] = [:]
        var unlabelledByTitle: [String: [String]] = [:]
        for session in catalog {
            if session.label == "-" {
                let title = "Session from \(OperatorDate.display(session.createdAt))"
                unlabelledByTitle[title, default: []].append(session.id)
            } else {
                names[session.id] = session.label
            }
        }
        for (title, ids) in unlabelledByTitle {
            for (offset, id) in ids.sorted().enumerated() {
                names[id] = ids.count == 1 ? title : "\(title) · \(offset + 1) of \(ids.count)"
            }
        }
        return names
    }
}

struct SourceRecord: Decodable, Identifiable, Sendable {
    let id: String
    let importedAt: String
    let repository: String
    let commit: String
    let worktree: String

    enum CodingKeys: String, CodingKey {
        case id, repository, commit, worktree
        case importedAt = "imported_at"
    }
}

struct SourcePlan: Decodable, Sendable {
    let planID: String
    let repository: String
    let requestedRef: String
    let resolvedCommit: String
    let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case repository
        case planID = "plan_id"
        case requestedRef = "requested_ref"
        case resolvedCommit = "resolved_commit"
        case expiresAt = "expires_at"
    }
}

struct SourcePlanStatus: Decodable, Sendable {
    let schema: String
    let planID: String
    let repository: String
    let requestedRef: String
    let resolvedCommit: String
    let expiresAt: String
    let state: String
    let sourceID: String?

    enum CodingKeys: String, CodingKey {
        case schema, repository, state
        case planID = "plan_id"
        case requestedRef = "requested_ref"
        case resolvedCommit = "resolved_commit"
        case expiresAt = "expires_at"
        case sourceID = "source_id"
    }
}

struct SourceImportResult: Decodable, Sendable {
    let planID: String
    let sourceID: String
    let repository: String

    enum CodingKeys: String, CodingKey {
        case repository
        case planID = "plan_id"
        case sourceID = "source_id"
    }
}

struct SessionLabelResult: Decodable, Sendable {
    let sessionID: String
    let label: String

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case label
    }
}

struct FindingRecord: Decodable, Identifiable, Sendable {
    let findingID: String
    let proposedSeverity: String
    let state: String
    let disposition: String
    let submittedAt: String

    var id: String { findingID }

    static func displayNames(in catalog: [FindingRecord]) -> [String: String] {
        var byDate: [String: [FindingRecord]] = [:]
        for finding in catalog {
            let date = OperatorDate.display(finding.submittedAt)
            byDate[date, default: []].append(finding)
        }
        var names: [String: String] = [:]
        for (date, findings) in byDate {
            let ordered = findings.sorted {
                $0.submittedAt == $1.submittedAt ? $0.id < $1.id : $0.submittedAt > $1.submittedAt
            }
            for (offset, finding) in ordered.enumerated() {
                names[finding.id] = ordered.count == 1 ? date : "\(date) · \(offset + 1) of \(ordered.count)"
            }
        }
        return names
    }

    enum CodingKeys: String, CodingKey {
        case findingID = "finding_id"
        case proposedSeverity = "proposed_severity"
        case state, disposition
        case submittedAt = "submitted_at"
    }
}

struct FindingDetail: Codable, Sendable {
    let findingID: String
    let currentState: String
    let claim: String
    let counterargument: String
    let limitations: String
    let claimEvidenceSupport: String
    let proposedSeverity: String
    let submittedAt: String
    let evidenceCount: Int
    let amendmentCount: Int
    let eventCount: Int
    let contentSHA256: String
    let claimRequiresExecution: Bool
    let evidence: [FindingEvidence]
    let history: [FindingHistory]

    enum CodingKeys: String, CodingKey {
        case claim, counterargument, limitations, evidence, history
        case findingID = "finding_id"
        case currentState = "current_state"
        case claimEvidenceSupport = "claim_evidence_support"
        case proposedSeverity = "proposed_severity"
        case submittedAt = "submitted_at"
        case evidenceCount = "evidence_count"
        case amendmentCount = "amendment_count"
        case eventCount = "event_count"
        case contentSHA256 = "content_sha256"
        case claimRequiresExecution = "claim_requires_execution"
    }
}

struct FindingEvidence: Codable, Identifiable, Sendable {
    let kind: String
    let sha256: String
    let sourceID: String?
    let receiptID: String?
    let path: String?
    let line: Int?
    var id: String { sha256 }

    enum CodingKeys: String, CodingKey {
        case sha256, path, line
        case kind = "class"
        case sourceID = "source_id"
        case receiptID = "receipt_id"
    }
}

struct FindingHistory: Codable, Sendable {
    let event: String
    let recordedAt: String
    let actor: String?
    let toState: String?
    let verificationMethod: String?
    let rationale: String?

    enum CodingKeys: String, CodingKey {
        case event, actor, rationale
        case recordedAt = "recorded_at"
        case toState = "to_state"
        case verificationMethod = "verification_method"
    }
}

struct FindingTransitionRequest: Encodable, Sendable {
    let schema = "secure-sandbox-control-center-finding-transition-v1"
    let findingID: String
    let expectedContentSHA256: String
    let expectedState: String
    let toState: String
    let verificationMethod: String
    let consultedEvidence: [String]
    let actorID: String
    let actorRole: String
    let rationale: String
    let conflictNote: String

    enum CodingKeys: String, CodingKey {
        case schema, rationale
        case findingID = "finding_id"
        case expectedContentSHA256 = "expected_content_sha256"
        case expectedState = "expected_state"
        case toState = "to_state"
        case verificationMethod = "verification_method"
        case consultedEvidence = "consulted_evidence"
        case actorID = "actor_id"
        case actorRole = "actor_role"
        case conflictNote = "conflict_note"
    }
}

struct FindingTransitionResult: Decodable, Sendable {
    let status: String
    let findingID: String
    let state: String
    let eventID: String
    let entrySHA256: String

    enum CodingKeys: String, CodingKey {
        case status, state
        case findingID = "finding_id"
        case eventID = "event_id"
        case entrySHA256 = "entry_sha256"
    }
}

struct FindingRelationRequest: Encodable, Sendable {
    let schema = "secure-sandbox-control-center-finding-relation-v1"
    let findingID: String
    let expectedContentSHA256: String
    let expectedState: String
    let relation: String
    let targetFindingID: String
    let actorID: String
    let actorRole: String
    let rationale: String
    let conflictNote: String

    enum CodingKeys: String, CodingKey {
        case schema, relation, rationale
        case findingID = "finding_id"
        case expectedContentSHA256 = "expected_content_sha256"
        case expectedState = "expected_state"
        case targetFindingID = "target_finding_id"
        case actorID = "actor_id"
        case actorRole = "actor_role"
        case conflictNote = "conflict_note"
    }
}

struct FindingRelationResult: Decodable, Sendable {
    let status: String
    let findingID: String
    let relation: String
    let targetFindingID: String
    let eventID: String
    let entrySHA256: String

    enum CodingKeys: String, CodingKey {
        case status, relation
        case findingID = "finding_id"
        case targetFindingID = "target_finding_id"
        case eventID = "event_id"
        case entrySHA256 = "entry_sha256"
    }
}

struct FindingReopenOptions: Decodable, Sendable {
    let findingID: String
    let contentSHA256: String
    let currentState: String
    let options: [FindingEvidence]

    enum CodingKeys: String, CodingKey {
        case options
        case findingID = "finding_id"
        case contentSHA256 = "content_sha256"
        case currentState = "current_state"
    }
}

struct FindingReopenRequest: Encodable, Sendable {
    let schema = "secure-sandbox-control-center-finding-reopen-v1"
    let findingID: String
    let expectedContentSHA256: String
    let expectedState: String
    let newEvidenceSHA256: String
    let actorID: String
    let actorRole: String
    let rationale: String
    let conflictNote: String

    enum CodingKeys: String, CodingKey {
        case schema, rationale
        case findingID = "finding_id"
        case expectedContentSHA256 = "expected_content_sha256"
        case expectedState = "expected_state"
        case newEvidenceSHA256 = "new_evidence_sha256"
        case actorID = "actor_id"
        case actorRole = "actor_role"
        case conflictNote = "conflict_note"
    }
}

struct FindingDispositionRequest: Encodable, Sendable {
    let schema = "secure-sandbox-control-center-finding-disposition-v1"
    let findingID: String
    let expectedContentSHA256: String
    let expectedState: String
    let actorID: String
    let actorRole: String
    let rationale: String
    let conflictNote: String

    enum CodingKeys: String, CodingKey {
        case schema, rationale
        case findingID = "finding_id"
        case expectedContentSHA256 = "expected_content_sha256"
        case expectedState = "expected_state"
        case actorID = "actor_id"
        case actorRole = "actor_role"
        case conflictNote = "conflict_note"
    }
}

struct FindingDispositionResult: Decodable, Sendable {
    let status: String
    let findingID: String
    let state: String
    let archiveSHA256: String

    enum CodingKeys: String, CodingKey {
        case status, state
        case findingID = "finding_id"
        case archiveSHA256 = "archive_sha256"
    }
}

struct ArtifactRecord: Decodable, Identifiable, Sendable {
    let id: String
    let capturedAt: String
    let version: String
    let fileName: String
    let runID: String
    let sha256: String

    static func displayNames(in catalog: [ArtifactRecord]) -> [String: String] {
        var byTitle: [String: [ArtifactRecord]] = [:]
        for artifact in catalog {
            let title = "\(OperatorDate.display(artifact.capturedAt)) · \(artifact.version)"
            byTitle[artifact.fileName + "\u{0}" + title, default: []].append(artifact)
        }
        var names: [String: String] = [:]
        for artifacts in byTitle.values {
            let ordered = artifacts.sorted {
                $0.capturedAt == $1.capturedAt ? $0.id < $1.id : $0.capturedAt > $1.capturedAt
            }
            for (offset, artifact) in ordered.enumerated() {
                let title = "\(OperatorDate.display(artifact.capturedAt)) · \(artifact.version)"
                names[artifact.id] = ordered.count == 1 ? title : "\(title) · \(offset + 1) of \(ordered.count)"
            }
        }
        return names
    }

    enum CodingKeys: String, CodingKey {
        case id, version, sha256
        case capturedAt = "captured_at"
        case fileName = "file_name"
        case runID = "run_id"
    }
}

struct ArtifactDetail: Decodable, Sendable {
    let id: String
    let capturedAt: String
    let fileName: String
    let version: String
    let runID: String
    let sha256: String
    let content: String

    enum CodingKeys: String, CodingKey {
        case id, version, sha256, content
        case capturedAt = "captured_at"
        case fileName = "file_name"
        case runID = "run_id"
    }
}

struct ActivityRecord: Decodable, Identifiable, Sendable {
    let sequence: Int
    let timeGenerated: String
    let eventType: String
    let severity: String
    let decision: String?
    let status: Int?
    let vmID: String?
    let message: String?

    var id: Int { sequence }

    enum CodingKeys: String, CodingKey {
        case sequence
        case timeGenerated = "TimeGenerated"
        case eventType = "EventType"
        case severity = "Severity"
        case decision = "Decision"
        case status = "Status"
        case vmID = "VmId"
        case message = "Message"
    }
}

struct MaintenanceStatus: Decodable, Sendable {
    let timeSync: String
    let snapshotPolicy: String

    enum CodingKeys: String, CodingKey {
        case timeSync = "time_sync"
        case snapshotPolicy = "snapshot_policy"
    }
}

struct BoundaryVerificationResult: Decodable, Sendable {
    let status: String
    let passedChecks: Int
    let gateNotices: Int
    let failedChecks: Int
    let failureLabels: [String]

    enum CodingKeys: String, CodingKey {
        case status
        case passedChecks = "passed_checks"
        case gateNotices = "gate_notices"
        case failedChecks = "failed_checks"
        case failureLabels = "failure_labels"
    }
}

struct LifecycleResult: Decodable, Sendable {
    let operation: String
    let status: String
    let gateway: String
    let research: String
    let target: String
    let gatewayNet0: String?
    let guestReachability: String?
    let clockSync: String?
    let boundaryVerification: String?

    enum CodingKeys: String, CodingKey {
        case operation, status, gateway, research, target
        case gatewayNet0 = "gateway_net0"
        case guestReachability = "guest_reachability"
        case clockSync = "clock_sync"
        case boundaryVerification = "boundary_verification"
    }
}

struct LifecycleProgress: Decodable, Sendable {
    let state: String
    let operation: String?
    let phase: String?
    let target: String?
    let transitionID: String?
    let observedAt: String?

    enum CodingKeys: String, CodingKey {
        case state, operation, phase, target
        case transitionID = "transition_id"
        case observedAt = "observed_at"
    }
}

struct PanicResult: Decodable, Sendable {
    let status: String
    let research: String
    let target: String
    let gatewayNet0: String

    enum CodingKeys: String, CodingKey {
        case status, research, target
        case gatewayNet0 = "gateway_net0"
    }
}

struct IdentityReloadResult: Decodable, Sendable {
    let status: String
    let provisioning: String
    let control: String
}

struct DependencyRecord: Decodable, Identifiable, Sendable {
    let state: String
    let package: String
    let version: String
    let sourceID: String
    var id: String { "\(package)@\(version)" }

    enum CodingKeys: String, CodingKey {
        case state, package, version
        case sourceID = "source_id"
    }
}

struct DependencyPlan: Decodable, Sendable {
    let planID: String
    let root: String
    let dependencySetSHA256: String
    let expiresAt: String
    let dependencies: [DependencyRecord]

    enum CodingKeys: String, CodingKey {
        case root, dependencies
        case planID = "plan_id"
        case dependencySetSHA256 = "dependency_set_sha256"
        case expiresAt = "expires_at"
    }
}

struct DependencyStatus: Decodable, Sendable {
    let planID: String
    let dependencies: [DependencyRecord]
    enum CodingKeys: String, CodingKey {
        case dependencies
        case planID = "plan_id"
    }
}

struct DependencyBundle: Decodable, Sendable {
    let bundleID: String
    let root: String
    let dependencySetSHA256: String
    let dependencyCount: String
    enum CodingKeys: String, CodingKey {
        case root
        case bundleID = "bundle_id"
        case dependencySetSHA256 = "dependency_set_sha256"
        case dependencyCount = "dependency_count"
    }
}

struct DependencyBundleRecord: Decodable, Identifiable, Sendable {
    let id: String
    let root: String
    let createdAt: String
    let dependencyCount: String
    let dependencySetSHA256: String

    enum CodingKeys: String, CodingKey {
        case id, root
        case createdAt = "created_at"
        case dependencyCount = "dependency_count"
        case dependencySetSHA256 = "dependency_set_sha256"
    }
}

struct SourceIndexResult: Decodable, Sendable {
    let kind: String
    let sourceID: String
    let status: String
    let digest: String
    let itemCount: Int

    enum CodingKeys: String, CodingKey {
        case kind, status, digest
        case sourceID = "source_id"
        case itemCount = "item_count"
    }
}

struct BackupPreflight: Decodable, Sendable {
    let destination: String
    let volumeUUID: String
    let encrypted: Bool
    let freeBytes: Int64
    let logicalBytes: Int64
    let reserveBytes: Int64
    let stackStopped: Bool
    let ready: Bool
    let vmBytes: VMBytes
    let hostConfigBytes: Int64

    struct VMBytes: Decodable, Sendable {
        let gateway: Int64
        let research: Int64
        let target: Int64
    }

    enum CodingKeys: String, CodingKey {
        case destination, encrypted, ready
        case volumeUUID = "volume_uuid"
        case freeBytes = "free_bytes"
        case logicalBytes = "logical_bytes"
        case reserveBytes = "reserve_bytes"
        case stackStopped = "stack_stopped"
        case vmBytes = "vm_bytes"
        case hostConfigBytes = "host_config_bytes"
    }
}

struct BackupPlan: Decodable, Sendable {
    let planID: String
    let destination: String
    let volumeUUID: String
    let expiresUnix: Int64
    let logicalBytes: Int64

    enum CodingKeys: String, CodingKey {
        case destination
        case planID = "plan_id"
        case volumeUUID = "volume_uuid"
        case expiresUnix = "expires_unix"
        case logicalBytes = "logical_bytes"
    }
}

struct BackupSubmission: Decodable, Sendable {
    let planID: String
    let state: String
    enum CodingKeys: String, CodingKey {
        case state
        case planID = "plan_id"
    }
}

struct BackupOperationStatus: Decodable, Sendable {
    let planID: String
    let state: String
    let phase: String
    let error: String?
    let fileCount: Int?
    let logicalBytes: Int64?

    enum CodingKeys: String, CodingKey {
        case state, phase, error
        case planID = "plan_id"
        case fileCount = "file_count"
        case logicalBytes = "logical_bytes"
    }
}

struct BackupInventory: Decodable, Sendable {
    let destination: String
    let volumeUUID: String
    let encrypted: Bool
    let entries: [BackupEntry]

    enum CodingKeys: String, CodingKey {
        case destination, encrypted, entries
        case volumeUUID = "volume_uuid"
    }
}

struct BackupEntry: Decodable, Identifiable, Sendable {
    let generationID: String
    let state: String
    let name: String
    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case state, name
        case generationID = "generation_id"
    }
}

struct RestorePreview: Decodable, Sendable {
    let generationID: String
    let destination: String
    let volumeUUID: String
    let fileCount: Int
    let logicalBytes: Int64
    let hostFreeBytes: Int64
    let reserveBytes: Int64
    let stackStopped: Bool
    let hostConfigMatches: Bool
    let differingHostConfig: [String]
    let ready: Bool

    enum CodingKeys: String, CodingKey {
        case destination, ready
        case generationID = "generation_id"
        case volumeUUID = "volume_uuid"
        case fileCount = "file_count"
        case logicalBytes = "logical_bytes"
        case hostFreeBytes = "host_free_bytes"
        case reserveBytes = "reserve_bytes"
        case stackStopped = "stack_stopped"
        case hostConfigMatches = "host_config_matches"
        case differingHostConfig = "differing_host_config"
    }
}

struct RestorePlan: Decodable, Sendable {
    let restoreID: String
    let source: String
    let generationID: String
    let volumeUUID: String
    let fileCount: Int
    let logicalBytes: Int64
    let expiresUnix: Int64

    enum CodingKeys: String, CodingKey {
        case source
        case restoreID = "restore_id"
        case generationID = "generation_id"
        case volumeUUID = "volume_uuid"
        case fileCount = "file_count"
        case logicalBytes = "logical_bytes"
        case expiresUnix = "expires_unix"
    }
}

struct RestoreSubmission: Decodable, Sendable {
    let restoreID: String
    let state: String
    enum CodingKeys: String, CodingKey {
        case state
        case restoreID = "restore_id"
    }
}

struct RestoreOperationStatus: Decodable, Sendable {
    let restoreID: String
    let state: String
    let phase: String
    let error: String?
    let recoverable: Bool
    enum CodingKeys: String, CodingKey {
        case state, phase, error, recoverable
        case restoreID = "restore_id"
    }
}

struct RestoreRetirement: Decodable, Sendable {
    let restoreID: String
    let state: String
    let kind: String
    let entryCount: Int
    let reclaimableBytes: Int64
    let ready: Bool
    let error: String?

    enum CodingKeys: String, CodingKey {
        case state, kind, ready, error
        case restoreID = "restore_id"
        case entryCount = "entry_count"
        case reclaimableBytes = "reclaimable_bytes"
    }
}

struct MemoryProposal: Decodable, Identifiable, Sendable {
    let proposalID: String
    let runID: String
    let createdAt: String
    let category: String
    let title: String
    let contentSHA256: String
    let status: String
    let authority: String
    var id: String { proposalID }

    enum CodingKeys: String, CodingKey {
        case category, title, status, authority
        case proposalID = "proposal_id"
        case runID = "run_id"
        case createdAt = "created_at"
        case contentSHA256 = "content_sha256"
    }
}

struct TranscriptDetail: Decodable, Sendable {
    let runID: String
    let recordCount: Int
    let content: String

    enum CodingKeys: String, CodingKey {
        case content
        case runID = "run_id"
        case recordCount = "record_count"
    }
}

struct TranscriptExport: Decodable, Sendable {
    let runID: String
    let recordCount: Int
    let byteCount: Int
    let sha256: String
    let status: String

    enum CodingKeys: String, CodingKey {
        case sha256, status
        case runID = "run_id"
        case recordCount = "record_count"
        case byteCount = "byte_count"
    }
}

struct ToolResultCatalog: Decodable, Sendable {
    let runID: String
    let results: [ToolResultRecord]

    enum CodingKeys: String, CodingKey {
        case results
        case runID = "run_id"
    }
}

struct ToolResultRecord: Decodable, Identifiable, Sendable {
    let toolUseID: String
    let name: String
    let ordinal: Int
    let bytes: Int
    let sha256: String
    let isError: Bool
    var id: String { toolUseID }

    enum CodingKeys: String, CodingKey {
        case name, ordinal, bytes, sha256
        case toolUseID = "tool_use_id"
        case isError = "is_error"
    }
}

struct ToolResultDetail: Decodable, Sendable {
    let runID: String
    let toolUseID: String
    let name: String
    let ordinal: Int
    let bytes: Int
    let sha256: String
    let isError: Bool
    let content: String

    enum CodingKeys: String, CodingKey {
        case name, ordinal, bytes, sha256, content
        case runID = "run_id"
        case toolUseID = "tool_use_id"
        case isError = "is_error"
    }
}

struct SessionRuns: Decodable, Sendable {
    let sessionID: String
    let totalRuns: Int
    let runIDs: [String]

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case totalRuns = "total_runs"
        case runIDs = "run_ids"
    }
}

struct LeaseStatus: Decodable, Sendable {
    let runID: String
    let leaseID: String
    let state: String
    let expiresAt: Int64
    let maximumExpiresAt: Int64
    let renewals: Int
    let requests: Int
    let inputTokens: Int
    let outputTokens: Int

    enum CodingKeys: String, CodingKey {
        case state, renewals, requests
        case runID = "run_id"
        case leaseID = "lease_id"
        case expiresAt = "expires_at"
        case maximumExpiresAt = "maximum_expires_at"
        case inputTokens = "input_tokens"
        case outputTokens = "output_tokens"
    }
}

struct LeaseReconcilePlan: Decodable, Sendable {
    let schema: String
    let runID: String
    let leaseID: String
    let gatewaySummarySHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case runID = "run_id"
        case leaseID = "lease_id"
        case gatewaySummarySHA256 = "gateway_summary_sha256"
    }
}

struct LeaseCompleted: Decodable, Sendable {
    let runID: String
    let leaseID: String
    let phase: String
    let gatewaySummarySHA256: String

    enum CodingKeys: String, CodingKey {
        case phase
        case runID = "run_id"
        case leaseID = "lease_id"
        case gatewaySummarySHA256 = "gateway_summary_sha256"
    }
}

struct TimeSyncResult: Decodable, Sendable {
    let status: String
    let operation: String
}

struct SafetyAuditResult: Decodable, Sendable {
    let verified: Bool
    let hostDirectTier: Int
    let detail: String

    enum CodingKeys: String, CodingKey {
        case verified, detail
        case hostDirectTier = "host_direct_tier"
    }
}

struct SnapshotPolicyResult: Decodable, Sendable {
    let verified: Bool
    let detail: String
}

struct SnapshotPreview: Decodable, Sendable {
    let policyVerified: Bool
    let rows: [SnapshotRow]
    let freeBytes: Int64
    let minimumBytes: Int64
    let stackStopped: Bool
    let guiClosed: Bool
    let ready: Bool

    enum CodingKeys: String, CodingKey {
        case rows, ready
        case policyVerified = "policy_verified"
        case freeBytes = "free_bytes"
        case minimumBytes = "minimum_bytes"
        case stackStopped = "stack_stopped"
        case guiClosed = "gui_closed"
    }
}

struct SnapshotRow: Decodable, Identifiable, Sendable {
    let vm: String
    let count: Int
    let retain: Int
    let remove: Int
    var id: String { vm }
}

struct SnapshotApplyResult: Decodable, Sendable {
    let status: String
    let commandStatus: Int
    let rows: [SnapshotRow]

    enum CodingKeys: String, CodingKey {
        case status, rows
        case commandStatus = "command_status"
    }
}
