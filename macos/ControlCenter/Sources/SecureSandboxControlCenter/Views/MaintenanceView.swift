import SwiftUI

struct MaintenanceView: View {
    let store: CatalogStore
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var checkingBoundaries = false
    @State private var boundaryResult: BoundaryVerificationResult?
    @State private var boundaryError: String?

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
            }
            Section("Additional controls") {
                Text("Dependency bundles, lease controls, memory proposals, boundary checks, and break-glass tools are being added to this surface.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Maintenance")
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
}
