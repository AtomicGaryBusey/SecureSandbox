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
                        Divider()
                        Text("Evidence").font(.headline)
                        if detail.evidence.isEmpty {
                            Text("No evidence recorded").foregroundStyle(.secondary)
                        }
                        ForEach(Array(detail.evidence.enumerated()), id: \.offset) { index, item in
                            VStack(alignment: .leading, spacing: 4) {
                                Text("\(index + 1). \(item.kind.replacingOccurrences(of: "_", with: " ").capitalized)")
                                    .font(.subheadline.bold())
                                if let path = item.path {
                                    Text(item.line.map { "\(path):\($0)" } ?? path)
                                        .font(.caption).textSelection(.enabled)
                                }
                                if let sourceID = item.sourceID {
                                    LabeledContent("Source", value: sourceID).font(.caption).textSelection(.enabled)
                                }
                                if let receiptID = item.receiptID {
                                    LabeledContent("Receipt", value: receiptID).font(.caption).textSelection(.enabled)
                                }
                                LabeledContent("Evidence SHA-256", value: grouped(item.sha256))
                                    .font(.caption.monospaced()).textSelection(.enabled)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                        }
                        Divider()
                        Text("Adjudication history").font(.headline)
                        if detail.history.isEmpty {
                            Text("No adjudication events").foregroundStyle(.secondary)
                        }
                        ForEach(Array(detail.history.enumerated()), id: \.offset) { _, event in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(event.event.replacingOccurrences(of: "_", with: " ").capitalized)
                                    .font(.subheadline.bold())
                                Text("\(event.recordedAt) · \(event.actor ?? "operator")")
                                    .font(.caption).foregroundStyle(.secondary)
                                if let toState = event.toState { LabeledContent("State", value: toState.capitalized) }
                                if let method = event.verificationMethod { LabeledContent("Method", value: method.replacingOccurrences(of: "_", with: " ")) }
                                if let rationale = event.rationale { Text(rationale).textSelection(.enabled) }
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                        }
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

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.distance(from: start, to: digest.endIndex)))
            return String(digest[start..<end])
        }.joined(separator: " ")
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
