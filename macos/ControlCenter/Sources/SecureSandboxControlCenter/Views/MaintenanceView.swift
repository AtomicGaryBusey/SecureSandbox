import SwiftUI

struct MaintenanceView: View {
    let store: CatalogStore

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
}
