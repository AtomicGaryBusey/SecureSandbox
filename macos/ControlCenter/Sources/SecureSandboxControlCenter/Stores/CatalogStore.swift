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
    var findings: [FindingRecord] = []
    var artifacts: [ArtifactRecord] = []
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
        do {
            status = try await Task.detached { try client.load("overview", as: HostStatus.self) }.value
            errors.removeValue(forKey: "overview")
        } catch {
            status = nil
            errors["overview"] = error.localizedDescription
        }
        do {
            sessions = try await Task.detached { try client.load("sessions", as: [SessionRecord].self) }.value
            errors.removeValue(forKey: "sessions")
        } catch {
            sessions = []
            errors["sessions"] = error.localizedDescription
        }
        do {
            sources = try await Task.detached { try client.load("sources", as: [SourceRecord].self) }.value
            errors.removeValue(forKey: "sources")
        } catch {
            sources = []
            errors["sources"] = error.localizedDescription
        }
        do {
            findings = try await Task.detached { try client.load("findings", as: [FindingRecord].self) }.value
            errors.removeValue(forKey: "findings")
        } catch {
            findings = []
            errors["findings"] = error.localizedDescription
        }
        do {
            activity = try await Task.detached { try client.load("activity", as: [ActivityRecord].self) }.value
            errors.removeValue(forKey: "activity")
        } catch {
            activity = []
            errors["activity"] = error.localizedDescription
        }
        do {
            maintenance = try await Task.detached { try client.load("maintenance", as: MaintenanceStatus.self) }.value
            errors.removeValue(forKey: "maintenance")
        } catch {
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
