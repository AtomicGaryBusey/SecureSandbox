import Foundation
import Observation

@MainActor @Observable
final class CatalogStore {
    var status: HostStatus?
    var sessions: [SessionRecord] = [] {
        didSet { sessionDisplayNames = SessionRecord.displayNames(in: sessions) }
    }
    var sessionDisplayNames: [String: String] = [:]
    var sources: [SourceRecord] = []
    var findings: [FindingRecord] = [] {
        didSet { findingDisplayNames = FindingRecord.displayNames(in: findings) }
    }
    var findingDisplayNames: [String: String] = [:]
    var artifacts: [ArtifactRecord] = [] {
        didSet { artifactDisplayNames = ArtifactRecord.displayNames(in: artifacts) }
    }
    var artifactDisplayNames: [String: String] = [:]
    var artifactsLoaded = false
    var artifactsLoading = false
    var activity: [ActivityRecord] = []
    var maintenance: MaintenanceStatus?
    var errors: [String: String] = [:]
    var refreshedAt: Date?
    var isRefreshing = false

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false; refreshedAt = Date() }
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        let overviewTask = Task.detached { try client.load("overview", as: HostStatus.self) }
        let sessionsTask = Task.detached { try client.load("sessions", as: [SessionRecord].self) }
        let sourcesTask = Task.detached { try client.load("sources", as: [SourceRecord].self) }
        let findingsTask = Task.detached { try client.load("findings", as: [FindingRecord].self) }
        let activityTask = Task.detached { try client.load("activity", as: [ActivityRecord].self) }
        let maintenanceTask = Task.detached { try client.load("maintenance", as: MaintenanceStatus.self) }
        switch await overviewTask.result {
        case .success(let value):
            status = value
            errors.removeValue(forKey: "overview")
        case .failure(let error):
            status = nil
            errors["overview"] = error.localizedDescription
        }
        switch await sessionsTask.result {
        case .success(let value):
            sessions = value
            errors.removeValue(forKey: "sessions")
        case .failure(let error):
            sessions = []
            errors["sessions"] = error.localizedDescription
        }
        switch await sourcesTask.result {
        case .success(let value):
            sources = value
            errors.removeValue(forKey: "sources")
        case .failure(let error):
            sources = []
            errors["sources"] = error.localizedDescription
        }
        switch await findingsTask.result {
        case .success(let value):
            findings = value
            errors.removeValue(forKey: "findings")
        case .failure(let error):
            findings = []
            errors["findings"] = error.localizedDescription
        }
        switch await activityTask.result {
        case .success(let value):
            activity = value
            errors.removeValue(forKey: "activity")
        case .failure(let error):
            activity = []
            errors["activity"] = error.localizedDescription
        }
        switch await maintenanceTask.result {
        case .success(let value):
            maintenance = value
            errors.removeValue(forKey: "maintenance")
        case .failure(let error):
            maintenance = nil
            errors["maintenance"] = error.localizedDescription
        }
    }

    func refreshArtifacts() async {
        guard !artifactsLoading else { return }
        artifactsLoading = true
        defer { artifactsLoading = false; artifactsLoaded = true }
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        do {
            artifacts = try await Task.detached { try client.load("artifacts", as: [ArtifactRecord].self) }.value
            errors.removeValue(forKey: "artifacts")
        } catch {
            artifacts = []
            errors["artifacts"] = error.localizedDescription
        }
    }

    func setLabel(id: String, label: String) async throws {
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        _ = try await Task.detached {
            try client.labelSession(id: id, label: label)
        }.value
        sessions = try await Task.detached {
            try client.load("sessions", as: [SessionRecord].self)
        }.value
    }

    func removeLabel(id: String) async throws {
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        _ = try await Task.detached {
            try client.unlabelSession(id: id)
        }.value
        sessions = try await Task.detached {
            try client.load("sessions", as: [SessionRecord].self)
        }.value
    }
}
