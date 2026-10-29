import SwiftUI

struct MaintenanceView: View {
    let store: CatalogStore
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var checkingBoundaries = false
    @State private var boundaryResult: BoundaryVerificationResult?
    @State private var boundaryError: String?
    @State private var showingTimeSync = false
    @State private var checkingSafety = false
    @State private var safetyResult: SafetyAuditResult?
    @State private var safetyError: String?

    var body: some View {
        Form {
            Section("Read-only checks") {
                if let status = store.maintenance {
                    statusRow("Guest clocks", value: status.timeSync)
                    statusRow("Snapshot retention", value: status.snapshotPolicy)
                } else if let error = store.errors["maintenance"] {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } else {
                    ProgressView("Checking maintenance state…")
                }
                Button("Synchronize Guest Clocks…") { showingTimeSync = true }
                Button("Run Boundary Verification") { Task { await verify() } }
                    .disabled(checkingBoundaries)
                if checkingBoundaries { ProgressView("Checking all lab boundaries…") }
                if let boundaryResult {
                    Label("\(boundaryResult.passedChecks) checks passed · \(boundaryResult.gateNotices) gate notices", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                }
                if let boundaryError {
                    Label(boundaryError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                Button("Run Safety Audit") { Task { await auditSafety() } }
                    .disabled(checkingSafety)
                if checkingSafety { ProgressView("Checking host, controller, boundaries, and off-host evidence…") }
                if let safetyResult {
                    Label(safetyResult.detail,
                          systemImage: safetyResult.verified ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .foregroundStyle(safetyResult.verified ? .green : .orange)
                    LabeledContent("Host-direct posture tier", value: String(safetyResult.hostDirectTier))
                }
                if let safetyError {
                    Label(safetyError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
            Section("Additional controls") {
                Text("Dependency bundles, lease controls, memory proposals, boundary checks, and break-glass tools are being added to this surface.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Maintenance")
        .sheet(isPresented: $showingTimeSync) {
            TimeSyncSheet(store: store)
        }
    }

    private func statusRow(_ title: String, value: String) -> some View {
        LabeledContent(title) {
            Label(value.capitalized, systemImage: value == "verified" ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(value == "verified" ? .green : .orange)
        }
    }

    private func verify() async {
        checkingBoundaries = true
        boundaryResult = nil
        boundaryError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            boundaryResult = try await Task.detached {
                try client.verifyBoundaries()
            }.value
        } catch {
            boundaryError = error.localizedDescription
        }
        checkingBoundaries = false
    }

    private func auditSafety() async {
        checkingSafety = true
        safetyResult = nil
        safetyError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            safetyResult = try await Task.detached { try client.safetyAudit() }.value
        } catch {
            safetyError = error.localizedDescription
        }
        checkingSafety = false
    }
}

private struct TimeSyncSheet: View {
    let store: CatalogStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var status: HostStatus?
    @State private var error: String?
    @State private var result: TimeSyncResult?
    @State private var busy = false

    private var ready: Bool {
        guard let status else { return false }
        return status.status == "verified" && [status.observed.gateway, status.observed.research,
                                                status.observed.target].allSatisfy { $0 == "running" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Synchronize guest clocks").font(.title2.bold())
            Text("This changes the clocks of Gateway, Research, and Target. The host refuses the operation while a Claude run is active and checks all three clocks afterward.")
                .foregroundStyle(.secondary)
            if status == nil && error == nil { ProgressView("Checking VM state…") }
            if let status {
                LabeledContent("Gateway", value: status.observed.gateway)
                LabeledContent("Research", value: status.observed.research)
                LabeledContent("Target", value: status.observed.target)
            }
            if !ready && status != nil {
                Label("All three VMs must be running.", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            if busy { ProgressView("Synchronizing and independently checking clocks…") }
            if result != nil {
                Label("Guest clocks are within five seconds of the Mac.", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button(result == nil ? "Cancel" : "Done") { dismiss() }.disabled(busy)
                if result == nil {
                    Button("Synchronize Clocks") { Task { await apply() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(!ready || busy || error != nil)
                }
            }
        }
        .padding(24)
        .frame(width: 540)
        .task { await check() }
    }

    private func check() async {
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            status = try await Task.detached { try client.load("overview", as: HostStatus.self) }.value
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func apply() async {
        busy = true
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let checked = try await Task.detached { try client.applyTimeSync() }.value
            guard checked.status == "verified", checked.operation == "time-sync" else {
                throw CatalogError.invalidSchema
            }
            result = checked
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
        await store.refresh()
    }
}
