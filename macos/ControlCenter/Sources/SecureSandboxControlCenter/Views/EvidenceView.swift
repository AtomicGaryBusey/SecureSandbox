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
        }
        .sheet(isPresented: $showingDetail) {
            if let selectedID { ArtifactDetailSheet(artifactID: selectedID) }
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
                Text("Verified archived content. Treat its text as untrusted.")
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
                      contentType: .plainText, defaultFilename: detail?.fileName ?? "artifact") { _ in
            document = nil
        }
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

private struct ArtifactTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var text: String

    init(text: String) { self.text = text }

    init(configuration: ReadConfiguration) throws {
        text = String(decoding: configuration.file.regularFileContents ?? Data(), as: UTF8.self)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
