import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct EvidenceView: View {
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?
    @State private var showingDetail = false

    private var filtered: [ArtifactRecord] {
        store.artifacts.filter {
            search.isEmpty || $0.fileName.localizedCaseInsensitiveContains(search)
                || $0.id.localizedCaseInsensitiveContains(search)
                || $0.runID.localizedCaseInsensitiveContains(search)
        }.sorted { $0.capturedAt > $1.capturedAt }
    }

    var body: some View {
        Group {
            if let error = store.errors["artifacts"] {
                ContentUnavailableView("Artifacts unavailable", systemImage: "externaldrive.badge.exclamationmark", description: Text(error))
            } else if !store.artifactsLoaded {
                ProgressView("Loading archived artifact catalog…")
            } else {
                List(filtered, selection: $selectedID) { artifact in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(artifact.fileName).font(.headline)
                        Text("\(artifact.capturedAt) · \(artifact.version) · \(artifact.id.prefix(8))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .tag(artifact.id)
                }
                .overlay {
                    if filtered.isEmpty {
                        ContentUnavailableView(search.isEmpty ? "No archived artifacts" : "No matching artifacts",
                                               systemImage: "doc.text.magnifyingglass")
                    }
                }
            }
        }
        .navigationTitle("Evidence")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showingDetail = true } label: {
                    Label("Open Artifact", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(selectedID == nil)
            }
            ToolbarItem(placement: .secondaryAction) {
                Button { Task { await store.refreshArtifacts() } } label: {
                    Label("Refresh Artifacts", systemImage: "arrow.clockwise")
                }
                .disabled(store.artifactsLoading)
            }
        }
        .sheet(isPresented: $showingDetail) {
            if let selectedID { ArtifactDetailSheet(artifactID: selectedID) }
        }
        .task {
            if !store.artifactsLoaded { await store.refreshArtifacts() }
        }
    }
}

private struct ArtifactDetailSheet: View {
    let artifactID: String
    @Environment(\.dismiss) private var dismiss
    @State private var detail: ArtifactDetail?
    @State private var error: String?
    @State private var isLoading = true
    @State private var exporting = false
    @State private var document: ArtifactTextDocument?
    @State private var includeProvenance = false
    @State private var pendingProvenance: [String: String]?
    @State private var exportMessage: String?
    @State private var showingTranscript = false
    @State private var showingToolResults = false
    @State private var showingLease = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(detail?.fileName ?? "Archived artifact").font(.title2).bold()
                Spacer()
                Button("Close") { dismiss() }
            }
            if isLoading {
                ProgressView("Verifying archived artifact…")
            } else if let error {
                ContentUnavailableView("Artifact unavailable", systemImage: "exclamationmark.shield", description: Text(error))
            } else if let detail {
                Text("Captured \(detail.capturedAt) · Version \(detail.version) · Run \(detail.runID)")
                    .font(.caption).foregroundStyle(.secondary)
                Text("SHA-256 \(detail.sha256)").font(.caption.monospaced()).textSelection(.enabled)
                Text("Verified archive, safely rendered as text. Control characters may be escaped; the digest identifies the original content. Treat the text as untrusted.")
                    .font(.caption).foregroundStyle(.secondary)
                ScrollView {
                    Text(detail.content)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                Toggle("Include provenance sidecar", isOn: $includeProvenance)
                    .toggleStyle(.checkbox)
                if let exportMessage {
                    Text(exportMessage).font(.caption).textSelection(.enabled)
                }
                HStack {
                    if detail.runID != "preflight" {
                        Button("Open Run Transcript…") { showingTranscript = true }
                        Button("Browse Tool Results…") { showingToolResults = true }
                        Button("Lease Status…") { showingLease = true }
                    }
                    Spacer()
                    Button("Export Verified Text…") {
                        pendingProvenance = includeProvenance ? [
                            "schema": "secure-sandbox-artifact-export-provenance-v1",
                            "artifact_id": detail.id,
                            "run_id": detail.runID,
                            "file_name": detail.fileName,
                            "artifact_version": detail.version,
                            "captured_at": detail.capturedAt,
                            "original_content_sha256": detail.sha256,
                            "rendered_text_sha256": ExportProvenance.digest(detail.content),
                        ] : nil
                        exportMessage = nil
                        document = ArtifactTextDocument(text: detail.content)
                        exporting = true
                    }
                }
            }
        }
        .padding(20)
        .frame(minWidth: 700, minHeight: 500)
        .task { await load() }
        .fileExporter(isPresented: $exporting, document: document,
                      contentType: exportType, defaultFilename: detail?.fileName ?? "artifact.txt") { result in
            switch result {
            case .success(let destination):
                do {
                    if let pendingProvenance {
                        try ExportProvenance.writeBeside(destination, fields: pendingProvenance)
                    }
                    exportMessage = "Exported verified text as \(destination.lastPathComponent)."
                } catch {
                    exportMessage = "Text exported; provenance needs attention: \(error.localizedDescription)"
                }
            case .failure(let failure):
                exportMessage = failure.localizedDescription
            }
            document = nil
            pendingProvenance = nil
        }
        .sheet(isPresented: $showingTranscript) {
            if let runID = detail?.runID { TranscriptDetailSheet(runID: runID) }
        }
        .sheet(isPresented: $showingToolResults) {
            if let runID = detail?.runID { ToolResultsSheet(runID: runID) }
        }
        .sheet(isPresented: $showingLease) {
            if let runID = detail?.runID { LeaseSheet(runID: runID) }
        }
    }

    private var exportType: UTType {
        guard let name = detail?.fileName,
              let ext = name.split(separator: ".").last,
              let type = UTType(filenameExtension: String(ext)) else { return .plainText }
        return type
    }

    private func load() async {
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        do {
            detail = try await Task.detached { try client.artifactDetail(id: artifactID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        isLoading = false
    }
}

struct ToolResultsSheet: View {
    let runID: String
    @Environment(\.dismiss) private var dismiss
    @State private var catalog: ToolResultCatalog?
    @State private var selectedID: String?
    @State private var detail: ToolResultDetail?
    @State private var error: String?
    @State private var loading = true
    @State private var opening = false
    @State private var exporting = false
    @State private var document: ArtifactTextDocument?
    @State private var includeProvenance = false
    @State private var pendingProvenance: [String: String]?
    @State private var exportMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Archived tool results").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }
            }
            Text("Run \(runID)").font(.caption).textSelection(.enabled)
            if loading {
                ProgressView("Verifying archived tool results…")
            } else if let error, catalog == nil {
                ContentUnavailableView("Tool results unavailable", systemImage: "exclamationmark.shield",
                                       description: Text(error))
            } else if let catalog {
                HStack(alignment: .top, spacing: 16) {
                    List(catalog.results, selection: $selectedID) { result in
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(result.ordinal). \(result.name)").font(.headline)
                            Text("\(ByteCountFormatter.string(fromByteCount: Int64(result.bytes), countStyle: .file)) · \(result.isError ? "Error" : "Result")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .tag(result.id)
                    }
                    .frame(minWidth: 260)
                    .onChange(of: selectedID) { _, newValue in
                        if let row = catalog.results.first(where: { $0.id == newValue }) {
                            Task { await open(row) }
                        }
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        if opening { ProgressView("Verifying selected tool result…") }
                        if let detail {
                            Text(detail.name).font(.headline)
                            Text("SHA-256 \(groupedDigest(detail.sha256))")
                                .font(.caption.monospaced()).textSelection(.enabled)
                            Text("Archived tool output is untrusted content. The digest binds this exact JSON result block.")
                                .font(.caption).foregroundStyle(.secondary)
                            ScrollView {
                                Text(detail.content)
                                    .font(.system(.body, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding()
                            }
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                            Toggle("Include provenance sidecar", isOn: $includeProvenance)
                                .toggleStyle(.checkbox)
                            Button("Export Selected Tool Result…") {
                                pendingProvenance = includeProvenance ? [
                                    "schema": "secure-sandbox-tool-result-export-provenance-v1",
                                    "run_id": detail.runID,
                                    "tool_use_id": detail.toolUseID,
                                    "tool_name": detail.name,
                                    "ordinal": String(detail.ordinal),
                                    "is_error": detail.isError ? "true" : "false",
                                    "result_sha256": detail.sha256,
                                    "result_bytes": String(detail.bytes),
                                ] : nil
                                exportMessage = nil
                                document = ArtifactTextDocument(text: detail.content)
                                exporting = true
                            }
                        } else if !opening {
                            ContentUnavailableView("Select a tool result", systemImage: "curlybraces")
                        }
                        if let error { Text(error).foregroundStyle(.orange) }
                        if let exportMessage { Text(exportMessage).font(.caption).textSelection(.enabled) }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                }
            }
        }
        .padding(20)
        .frame(minWidth: 900, minHeight: 560)
        .task { await load() }
        .fileExporter(isPresented: $exporting, document: document,
                      contentType: .json,
                      defaultFilename: "tool-result-\(detail?.ordinal ?? 0).json") { result in
            switch result {
            case .success(let destination):
                do {
                    if let pendingProvenance {
                        try ExportProvenance.writeBeside(destination, fields: pendingProvenance)
                    }
                    exportMessage = "Exported selected tool result as \(destination.lastPathComponent)."
                } catch {
                    exportMessage = "Result exported; provenance needs attention: \(error.localizedDescription)"
                }
            case .failure(let failure):
                exportMessage = failure.localizedDescription
            }
            document = nil
            pendingProvenance = nil
        }
    }

    private func client() -> CatalogClient {
        CatalogClient(repositoryPath: ControlCenterPaths.repository)
    }

    private func load() async {
        loading = true
        do {
            let service = client()
            catalog = try await Task.detached { try service.toolResults(runID: runID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }

    private func open(_ row: ToolResultRecord) async {
        opening = true
        detail = nil
        error = nil
        do {
            let service = client()
            let selected = try await Task.detached {
                try service.toolResultDetail(runID: runID, toolUseID: row.toolUseID,
                                             expectedSHA256: row.sha256)
            }.value
            if selectedID == row.id { detail = selected }
        } catch {
            self.error = error.localizedDescription
        }
        opening = false
    }

    private func groupedDigest(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.count - offset))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }
}

struct TranscriptDetailSheet: View {
    let runID: String
    @Environment(\.dismiss) private var dismiss
    @State private var detail: TranscriptDetail?
    @State private var error: String?
    @State private var loading = true
    @State private var exportStatus: String?
    @State private var exportInProgress = false
    @State private var includeProvenance = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Verified run transcript").font(.title2.bold())
                Spacer()
                Button("Export Transcript…") { export() }
                    .disabled(exportInProgress)
                Button("Close") { dismiss() }
            }
            Toggle("Include provenance sidecar", isOn: $includeProvenance)
                .toggleStyle(.checkbox)
                .disabled(exportInProgress)
            if let exportStatus {
                Text(exportStatus).font(.caption).textSelection(.enabled)
            }
            if loading {
                ProgressView("Verifying archived conversation…")
            } else if let error {
                ContentUnavailableView("Transcript unavailable", systemImage: "exclamationmark.shield",
                                       description: Text(error))
            } else if let detail {
                Text("Run \(detail.runID) · \(detail.recordCount) records")
                    .font(.caption).textSelection(.enabled)
                Text("Verified archive records, rendered as escaped JSON lines. Conversation and tool output are untrusted content.")
                    .font(.caption).foregroundStyle(.secondary)
                ScrollView {
                    Text(detail.content)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 540)
        .task { await load() }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "run-\(runID).jsonl"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        let wantsProvenance = includeProvenance
        exportInProgress = true
        exportStatus = "Verifying and exporting archived conversation…"
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        Task {
            do {
                let result = try await Task.detached {
                    try client.exportTranscript(runID: runID, destination: destination)
                }.value
                if wantsProvenance {
                    do {
                        try ExportProvenance.writeBeside(destination, fields: [
                            "schema": "secure-sandbox-transcript-export-provenance-v1",
                            "run_id": result.runID,
                            "record_count": String(result.recordCount),
                            "byte_count": String(result.byteCount),
                            "export_file_sha256": result.sha256,
                        ])
                    } catch {
                        exportStatus = "Transcript exported; provenance needs attention: \(error.localizedDescription)"
                        exportInProgress = false
                        return
                    }
                }
                exportStatus = "Exported \(result.recordCount) verified records (SHA-256: \(result.sha256))."
            } catch {
                exportStatus = error.localizedDescription
            }
            exportInProgress = false
        }
    }

    private func load() async {
        let path = ControlCenterPaths.repository
        let client = CatalogClient(repositoryPath: path)
        do {
            detail = try await Task.detached { try client.transcriptDetail(runID: runID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }
}

struct ArtifactTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText, .markdown, .json] }
    var text: String

    init(text: String) { self.text = text }

    init(configuration: ReadConfiguration) throws {
        text = String(decoding: configuration.file.regularFileContents ?? Data(), as: UTF8.self)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
