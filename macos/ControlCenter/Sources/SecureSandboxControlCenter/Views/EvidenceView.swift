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
    @State private var showingTranscript = false

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
                HStack {
                    Button("Open Run Transcript…") { showingTranscript = true }
                    Spacer()
                    Button("Export Verified Text…") {
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
                      contentType: exportType, defaultFilename: detail?.fileName ?? "artifact.txt") { _ in
            document = nil
        }
        .sheet(isPresented: $showingTranscript) {
            if let runID = detail?.runID { TranscriptDetailSheet(runID: runID) }
        }
    }

    private var exportType: UTType {
        guard let name = detail?.fileName,
              let ext = name.split(separator: ".").last,
              let type = UTType(filenameExtension: String(ext)) else { return .plainText }
        return type
    }

    private func load() async {
        let path = UserDefaults.standard.string(forKey: "repositoryPath")
            ?? (NSHomeDirectory() + "/SecureSandbox")
        let client = CatalogClient(repositoryPath: path)
        do {
            detail = try await Task.detached { try client.artifactDetail(id: artifactID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        isLoading = false
    }
}

private struct TranscriptDetailSheet: View {
    let runID: String
    @Environment(\.dismiss) private var dismiss
    @State private var detail: TranscriptDetail?
    @State private var error: String?
    @State private var loading = true
    @State private var exporting = false
    @State private var document: ArtifactTextDocument?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Verified run transcript").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }
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
                HStack {
                    Spacer()
                    Button("Export Transcript…") {
                        document = ArtifactTextDocument(text: detail.content)
                        exporting = true
                    }
                }
            }
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 540)
        .task { await load() }
        .fileExporter(isPresented: $exporting, document: document,
                      contentType: .plainText, defaultFilename: "run-\(runID).jsonl") { _ in
            document = nil
        }
    }

    private func load() async {
        let path = UserDefaults.standard.string(forKey: "repositoryPath")
            ?? (NSHomeDirectory() + "/SecureSandbox")
        let client = CatalogClient(repositoryPath: path)
        do {
            detail = try await Task.detached { try client.transcriptDetail(runID: runID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }
}

private struct ArtifactTextDocument: FileDocument {
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
