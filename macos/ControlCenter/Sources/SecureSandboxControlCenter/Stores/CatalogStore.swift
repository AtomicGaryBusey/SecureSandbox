import Foundation
import Observation

@MainActor @Observable
final class CatalogStore {
    var status: HostStatus?
    var sessions: [SessionRecord] = []
    var sources: [SourceRecord] = []
    var findings: [FindingRecord] = []
    var errors: [String: String] = [:]
    var refreshedAt: Date?
    var isRefreshing = false

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false; refreshedAt = Date() }
        let path = UserDefaults.standard.string(forKey: "repositoryPath")
            ?? (NSHomeDirectory() + "/SecureSandbox")
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
    }
}
