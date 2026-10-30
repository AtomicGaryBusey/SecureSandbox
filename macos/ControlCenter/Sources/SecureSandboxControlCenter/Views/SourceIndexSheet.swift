import SwiftUI

struct SourceIndexSheet: View {
    let source: SourceRecord
    @Environment(\.dismiss) private var dismiss
    private let repositoryPath = ControlCenterPaths.repository
    @State private var busyKind: String?
    @State private var attempted: Set<String> = []
    @State private var results: [String: SourceIndexResult] = [:]
    @State private var errors: [String: String] = [:]
    @State private var checkingExisting = false

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
        .task {
            await checkExisting("corpus", reportMissing: false)
            await checkExisting("codegraph", reportMissing: false)
        }
    }

    @ViewBuilder
    private func indexRow(_ kind: String, title: String, countLabel: String) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 10) {
                if busyKind == kind {
                    ProgressView(checkingExisting ? "Checking sealed index…" : "Building and sealing index…")
                }
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
                if results[kind] == nil {
                    Button("Check Existing Index") {
                        Task { await checkExisting(kind, reportMissing: true) }
                    }
                    .disabled(busyKind != nil)
                }
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
            errors[kind] = nil
        } catch {
            let submissionError = error.localizedDescription
            do {
                let status = try await Task.detached {
                    try client.indexSourceStatus(kind: kind, sourceID: source.id)
                }.value
                if status.status == "indexed" {
                    results[kind] = status
                    errors[kind] = nil
                } else {
                    attempted.remove(kind)
                    errors[kind] = "Build outcome was unclear (\(submissionError)). No sealed index was found; you may retry deliberately."
                }
            } catch {
                errors[kind] = "Build outcome was unclear (\(submissionError)). Readback also failed: \(error.localizedDescription)"
            }
        }
        busyKind = nil
    }

    private func checkExisting(_ kind: String, reportMissing: Bool) async {
        guard busyKind == nil else { return }
        busyKind = kind
        checkingExisting = true
        defer {
            checkingExisting = false
            busyKind = nil
        }
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let status = try await Task.detached {
                try client.indexSourceStatus(kind: kind, sourceID: source.id)
            }.value
            guard status.kind == kind, status.sourceID == source.id else {
                throw CatalogError.invalidSchema
            }
            if status.status == "indexed" {
                results[kind] = status
                attempted.insert(kind)
                errors[kind] = nil
            } else if status.status == "not_indexed" {
                attempted.remove(kind)
                if reportMissing { errors[kind] = "No sealed index exists yet." }
            } else {
                throw CatalogError.invalidSchema
            }
        } catch {
            errors[kind] = "Index readback failed: \(error.localizedDescription)"
        }
    }
}
