import SwiftUI
import UniformTypeIdentifiers

struct FindingDetailSheet: View {
    let findingID: String
    let disposition: String
    let otherFindings: [FindingRecord]
    let onChanged: () -> Void
    private let repositoryPath = ControlCenterPaths.repository
    @Environment(\.dismiss) private var dismiss
    @State private var detail: FindingDetail?
    @State private var error: String?
    @State private var showingTransition = false
    @State private var showingRelation = false
    @State private var showingReopen = false
    @State private var showingDisposition = false
    @State private var preparingExport = false
    @State private var exporting = false
    @State private var exportDocument: ArtifactTextDocument?
    @State private var exportError: String?
    @State private var exportMessage: String?
    @State private var includeProvenance = false
    @State private var pendingProvenance: [String: String]?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Finding detail").font(.title2.bold())
                Spacer()
                Button("Export Finding…") { Task { await prepareExport() } }
                    .disabled(detail == nil || error != nil || preparingExport)
                Button("Close") { dismiss() }
            }
            if preparingExport { ProgressView("Refreshing finding for export…") }
            if let exportError {
                Text(exportError).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
            if let exportMessage {
                Text(exportMessage).font(.caption).textSelection(.enabled)
            }
            Toggle("Include provenance sidecar", isOn: $includeProvenance)
                .toggleStyle(.checkbox)
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
                        LabeledContent("Submitted", value: OperatorDate.display(detail.submittedAt))
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
                                Text("\(OperatorDate.display(event.recordedAt)) · \(event.actor ?? "operator")")
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
                        if ["candidate", "needs_evidence", "disputed"].contains(detail.currentState) {
                            Button("Adjudicate Finding…") { showingTransition = true }
                        }
                        if !otherFindings.isEmpty {
                            Button("Relate to Another Finding…") { showingRelation = true }
                        }
                        if ["validated", "rejected", "withdrawn"].contains(detail.currentState) {
                            Button("Review New Evidence to Reopen…") { showingReopen = true }
                            if disposition == "active" {
                                Button("Archive Terminal Finding…", role: .destructive) {
                                    showingDisposition = true
                                }
                            }
                        }
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
        .fileExporter(isPresented: $exporting, document: exportDocument,
                      contentType: .json, defaultFilename: "finding-\(findingID).json") { result in
            switch result {
            case .success(let destination):
                do {
                    try ExportProvenance.protectExport(destination)
                    if let pendingProvenance {
                        try ExportProvenance.writeBeside(destination, fields: pendingProvenance)
                    }
                    exportMessage = "Exported finding as \(destination.lastPathComponent)."
                } catch {
                    exportMessage = "Finding exported; file protection or provenance needs attention: \(error.localizedDescription)"
                }
            case .failure(let failure):
                exportError = failure.localizedDescription
            }
            exportDocument = nil
            pendingProvenance = nil
        }
        .sheet(isPresented: $showingTransition) {
            if let detail {
                FindingTransitionSheet(detail: detail) { Task { await load() }; onChanged() }
            }
        }
        .sheet(isPresented: $showingRelation) {
            if let detail {
                FindingRelationSheet(detail: detail, targets: otherFindings) { Task { await load() }; onChanged() }
            }
        }
        .sheet(isPresented: $showingReopen) {
            if let detail {
                FindingReopenSheet(detail: detail) { Task { await load() }; onChanged() }
            }
        }
        .sheet(isPresented: $showingDisposition) {
            if let detail {
                FindingDispositionSheet(detail: detail) { Task { await load() }; onChanged() }
            }
        }
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

    private func prepareExport() async {
        guard let displayed = detail else { return }
        preparingExport = true
        exportError = nil
        exportMessage = nil
        defer { preparingExport = false }
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let fresh = try await Task.detached {
                try client.findingDetail(id: findingID)
            }.value
            guard fresh.contentSHA256 == displayed.contentSHA256,
                  fresh.currentState == displayed.currentState,
                  fresh.amendmentCount == displayed.amendmentCount,
                  fresh.eventCount == displayed.eventCount else {
                exportError = "The finding changed since it was opened. Close and reopen it before exporting."
                return
            }
            let payload = FindingExportPayload(
                schema: "secure-sandbox-control-center-finding-export-v1",
                exportedAt: ISO8601DateFormatter().string(from: Date()), finding: fresh)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let rendered = try encoder.encode(payload)
            let text = String(decoding: rendered, as: UTF8.self) + "\n"
            pendingProvenance = includeProvenance ? [
                "schema": "secure-sandbox-finding-export-provenance-v1",
                "finding_id": fresh.findingID,
                "finding_content_sha256": fresh.contentSHA256,
                "finding_state": fresh.currentState,
                "export_file_sha256": ExportProvenance.digest(text),
            ] : nil
            exportDocument = ArtifactTextDocument(text: text)
            exporting = true
        } catch {
            exportError = error.localizedDescription
        }
    }
}

private struct FindingExportPayload: Encodable {
    let schema: String
    let exportedAt: String
    let finding: FindingDetail

    enum CodingKeys: String, CodingKey {
        case schema, finding
        case exportedAt = "exported_at"
    }
}
