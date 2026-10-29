import SwiftUI

struct DependencyBundlesSheet: View {
    @Environment(\.dismiss) private var dismiss
    private let repositoryPath = ControlCenterPaths.repository
    @State private var bundles: [DependencyBundleRecord] = []
    @State private var selectedID: String?
    @State private var loading = true
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Sealed dependency bundles").font(.title2.bold())
                Spacer()
                Button("Refresh") { Task { await load() } }.disabled(loading)
                Button("Close") { dismiss() }
            }
            Text("Bundles contain exact direct runtime dependencies. Package lifecycle scripts remain disabled.")
                .font(.caption).foregroundStyle(.secondary)
            if loading {
                ProgressView("Reading sealed bundle catalog…")
            } else if let error {
                ContentUnavailableView("Bundle catalog unavailable", systemImage: "exclamationmark.shield",
                                       description: Text(error))
            } else if bundles.isEmpty {
                ContentUnavailableView("No sealed bundles", systemImage: "shippingbox",
                                       description: Text("Assemble a reviewed dependency plan to create one."))
            } else {
                List(bundles, selection: $selectedID) { bundle in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(bundle.root).font(.headline)
                        Text("\(bundle.dependencyCount) packages · \(bundle.createdAt)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(bundle.id)
                }
                if let selected = bundles.first(where: { $0.id == selectedID }) {
                    GroupBox("Selected bundle") {
                        VStack(alignment: .leading, spacing: 6) {
                            LabeledContent("Root", value: selected.root)
                            LabeledContent("Direct packages", value: selected.dependencyCount)
                            LabeledContent("Created", value: selected.createdAt)
                            LabeledContent("Bundle ID", value: selected.id)
                            LabeledContent("Set SHA-256", value: grouped(selected.dependencySetSHA256))
                        }
                        .textSelection(.enabled)
                        .padding(8)
                    }
                }
            }
        }
        .padding(20)
        .frame(minWidth: 650, minHeight: 420)
        .task { await load() }
    }

    private func load() async {
        loading = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            bundles = try await Task.detached { try client.dependencyBundles() }.value
            if !bundles.contains(where: { $0.id == selectedID }) { selectedID = nil }
        } catch {
            bundles = []
            self.error = error.localizedDescription
        }
        loading = false
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.count - offset))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }
}
