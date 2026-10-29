import SwiftUI

struct SourceIndexSheet: View {
    let source: SourceRecord
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var busyKind: String?
    @State private var attempted: Set<String> = []
    @State private var results: [String: SourceIndexResult] = [:]
    @State private var errors: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("Analysis indexes").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.disabled(busyKind != nil)
            }
            Text(source.repository).font(.headline)
            Text("The Research VM builds sealed indexes from this imported snapshot. Indexing requires an idle lab run and can take several minutes.")
                .foregroundStyle(.secondary)
            indexRow("corpus", title: "Corpus search", countLabel: "documents")
            indexRow("codegraph", title: "CodeGraph", countLabel: "nodes")
            Text("If an outcome is unclear, inspect the existing index before trying again. This window will not automatically repeat an attempted build.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(width: 580)
    }

    @ViewBuilder
    private func indexRow(_ kind: String, title: String, countLabel: String) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 10) {
                if busyKind == kind { ProgressView("Building and sealing index…") }
                if let result = results[kind] {
                    Label("Indexed \(result.itemCount) \(countLabel)", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    LabeledContent("Index SHA-256", value: result.digest).textSelection(.enabled)
                }
                if let error = errors[kind] {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
                Button("Build \(title) Index") { Task { await build(kind) } }
                    .disabled(busyKind != nil || attempted.contains(kind))
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func build(_ kind: String) async {
        guard busyKind == nil, !attempted.contains(kind) else { return }
        attempted.insert(kind)
        busyKind = kind
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let result = try await Task.detached {
                try client.indexSource(kind: kind, sourceID: source.id)
            }.value
            guard result.kind == kind, result.sourceID == source.id, result.status == "indexed" else {
                throw CatalogError.invalidSchema
            }
            results[kind] = result
        } catch {
            errors[kind] = error.localizedDescription
        }
        busyKind = nil
    }
}
