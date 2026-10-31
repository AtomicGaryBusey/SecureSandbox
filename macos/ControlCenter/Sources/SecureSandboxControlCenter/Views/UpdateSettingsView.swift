import SwiftUI

struct UpdateSettingsView: View {
    let store: UpdateStore
    @AppStorage("automaticUpdateChecks") private var automaticChecks = false

    var body: some View {
        Form {
            Section("Installed Control Center") {
                LabeledContent("Version", value: store.installedVersion)
                statusRow
                if let checked = store.lastCheckedAt {
                    LabeledContent("Last checked", value: checked.formatted(date: .abbreviated, time: .shortened))
                }
            }

            Section("Checking") {
                Toggle("Automatically check for signed update metadata", isOn: $automaticChecks)
                    .onChange(of: automaticChecks) { _, enabled in
                        if enabled { Task { await store.requestNotificationPermission() } }
                    }
                Text("Automatic checks may fetch only bounded signed metadata and may notify you. They never download an app or install anything.")
                    .foregroundStyle(.secondary)
                Button("Check Now") { Task { await store.check() } }
                    .disabled(store.state == .checking || store.state == .downloading || store.state == .installing)
            }

            if let update = store.verifiedUpdate {
                Section("Reviewed Release") {
                    LabeledContent("Version", value: "\(update.manifest.version) (\(update.manifest.build))")
                    LabeledContent("Release sequence", value: String(update.manifest.sequence))
                    LabeledContent("Channel", value: update.manifest.channel)
                    LabeledContent("Published", value: update.manifest.publishedAt)
                    LabeledContent("Release commit", value: update.manifest.releaseCommit)
                        .textSelection(.enabled)
                    LabeledContent("Artifact bytes", value: update.manifest.artifact.size.formatted())
                    LabeledContent("Artifact SHA-256", value: grouped(update.manifest.artifact.sha256))
                        .textSelection(.enabled)
                    LabeledContent("Manifest envelope SHA-256", value: grouped(update.envelopeDigest))
                        .textSelection(.enabled)
                }

                Section("Security and Compatibility") {
                    LabeledContent("Classification", value: update.manifest.security.classification)
                    Text(update.manifest.security.summary)
                    LabeledContent("Control Center", value: update.manifest.compatibility.controlCenter)
                    LabeledContent("Protected environment", value: update.manifest.compatibility.protectedEnvironment)
                    Text("Control Center replacement cannot advance Host, Gateway, Research, Target, a harness, or a model profile. Those remain separate reviewed and authorized operations.")
                        .foregroundStyle(.secondary)
                }

                Section("Manual Update") {
                    if store.state == .available {
                        Button("Download Reviewed Artifact") { Task { await store.download() } }
                    }
                    if store.state == .downloaded {
                        Button("Install with Touch ID…") { Task { await store.install() } }
                            .buttonStyle(.borderedProminent)
                    }
                    Text("Download is available only after manual review. Installation is a second action and requires Touch ID after all cryptographic, Developer ID, hardened-runtime, and Gatekeeper checks pass. A failed check has no bypass.")
                        .foregroundStyle(.secondary)
                }
            }

            Section("Recovery") {
                Button("Roll Back to Retained Accepted Version…") { Task { await store.rollback() } }
                    .disabled(!store.hasRetainedRollback || store.state == .checking
                              || store.state == .downloading || store.state == .installing)
                Text("Rollback requires Touch ID and can select only the single predecessor retained by a previously accepted update. It does not lower the monotonic release floor.")
                    .foregroundStyle(.secondary)
            }

            Section("Non-negotiable policy") {
                Label(store.automaticInstallInvariant, systemImage: "hand.raised.fill")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder
    private var statusRow: some View {
        switch store.state {
        case .idle:
            LabeledContent("Update status", value: "Not checked")
        case .checking:
            LabeledContent("Update status") { ProgressView().controlSize(.small) }
        case .unavailable(let reason):
            LabeledContent("Update status", value: "Not provisioned")
            Label(reason, systemImage: "lock.fill").foregroundStyle(.secondary)
        case .current:
            LabeledContent("Update status", value: "Current")
        case .available:
            LabeledContent("Update status", value: "Signed update available")
        case .downloading:
            LabeledContent("Update status") { ProgressView("Downloading manually…") }
        case .downloaded:
            LabeledContent("Update status", value: "Artifact verified; Touch ID required")
        case .installing:
            LabeledContent("Update status") { ProgressView("Preparing replacement…") }
        case .rejected(let reason):
            LabeledContent("Update status", value: "Rejected")
            Label(reason, systemImage: "exclamationmark.shield.fill")
                .foregroundStyle(.red)
                .textSelection(.enabled)
        }
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.count - offset))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }
}
