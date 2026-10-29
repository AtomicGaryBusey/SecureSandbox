import Foundation

enum Section: String, CaseIterable, Identifiable {
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

    var displayName: String { label == "-" ? "Session \(id.prefix(8))" : label }
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

    enum CodingKeys: String, CodingKey {
        case findingID = "finding_id"
        case proposedSeverity = "proposed_severity"
        case state, disposition
        case submittedAt = "submitted_at"
    }
}
