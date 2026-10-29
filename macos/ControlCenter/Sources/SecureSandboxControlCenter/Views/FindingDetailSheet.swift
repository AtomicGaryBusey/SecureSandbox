import SwiftUI

struct FindingDetailSheet: View {
    let findingID: String
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @Environment(\.dismiss) private var dismiss
    @State private var detail: FindingDetail?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Finding detail").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }
            }
            Label("Agent-authored finding text is untrusted source material.", systemImage: "exclamationmark.shield")
                .foregroundStyle(.secondary)
            if let error {
                ContentUnavailableView("Finding unavailable", systemImage: "wifi.slash", description: Text(error))
            } else if let detail {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        LabeledContent("State", value: detail.currentState.capitalized)
                        LabeledContent("Proposed severity", value: detail.proposedSeverity.capitalized)
                        LabeledContent("Evidence support", value: detail.claimEvidenceSupport.capitalized)
                        LabeledContent("Submitted", value: detail.submittedAt)
                        LabeledContent("Evidence items", value: String(detail.evidenceCount))
                        LabeledContent("Amendments", value: String(detail.amendmentCount))
                        LabeledContent("History events", value: String(detail.eventCount))
                        Divider()
                        textSection("Claim", detail.claim)
                        textSection("Counterargument", detail.counterargument)
                        textSection("Limitations", detail.limitations)
                        LabeledContent("Finding ID", value: detail.findingID)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                ProgressView("Verifying finding…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(24)
        .frame(width: 720, height: 650)
        .task { await load() }
    }

    private func textSection(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Text(body).textSelection(.enabled)
        }
    }

    private func load() async {
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            detail = try await Task.detached {
                try client.findingDetail(id: findingID)
            }.value
        } catch {
            self.error = error.localizedDescription
        }
    }
}
