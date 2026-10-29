import SwiftUI

struct RecoveryView: View {
    let store: CatalogStore

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Recovery").font(.largeTitle.bold())
            GroupBox("Snapshot retention") {
                HStack {
                    Text("Policy check")
                    Spacer()
                    if let status = store.maintenance?.snapshotPolicy {
                        Label(status.capitalized, systemImage: status == "verified" ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(status == "verified" ? .green : .orange)
                    } else {
                        Text("Unavailable").foregroundStyle(.secondary)
                    }
                }
                .padding(8)
            }
            Text("Coordinated VM backup, manifest verification, restore preview, and rollback are in development.")
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(28)
        .navigationTitle("Recovery")
    }
}
