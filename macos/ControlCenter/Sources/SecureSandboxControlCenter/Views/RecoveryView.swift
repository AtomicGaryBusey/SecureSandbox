import SwiftUI
import UniformTypeIdentifiers

struct RecoveryView: View {
    let store: CatalogStore
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var choosingDestination = false
    @State private var preflight: BackupPreflight?
    @State private var preflightError: String?
    @State private var checking = false

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
            GroupBox("Coordinated VM backup") {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Choose a mounted, encrypted APFS destination. Preflight checks all three VM bundles, available space, and stopped VM state.")
                        .foregroundStyle(.secondary)
                    Button("Choose Destination…") { choosingDestination = true }
                    if checking { ProgressView("Checking backup destination…") }
                    if let preflight {
                        LabeledContent("Destination", value: preflight.destination)
                            .textSelection(.enabled)
                        LabeledContent("VM data", value: ByteCountFormatter.string(fromByteCount: preflight.logicalBytes, countStyle: .file))
                        LabeledContent("Free space", value: ByteCountFormatter.string(fromByteCount: preflight.freeBytes, countStyle: .file))
                        LabeledContent("Required reserve", value: ByteCountFormatter.string(fromByteCount: preflight.reserveBytes, countStyle: .file))
                        LabeledContent("Encrypted APFS", value: preflight.encrypted ? "Verified" : "Required")
                        LabeledContent("Stack stopped", value: preflight.stackStopped ? "Verified" : "Required")
                        Label(preflight.ready ? "Destination preflight passed" : "Destination preflight needs attention",
                              systemImage: preflight.ready ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(preflight.ready ? .green : .orange)
                    }
                    if let preflightError {
                        Label(preflightError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Text("Backup execution, manifest verification, restore preview, and rollback are still being built.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(8)
            }
            Spacer()
        }
        .padding(28)
        .navigationTitle("Recovery")
        .fileImporter(isPresented: $choosingDestination, allowedContentTypes: [.folder]) { result in
            switch result {
            case .success(let url): Task { await checkDestination(url.path) }
            case .failure(let error): preflightError = error.localizedDescription
            }
        }
    }

    private func checkDestination(_ destination: String) async {
        checking = true
        preflight = nil
        preflightError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            preflight = try await Task.detached {
                try client.backupPreflight(destination: destination)
            }.value
        } catch {
            preflightError = error.localizedDescription
        }
        checking = false
    }
}
