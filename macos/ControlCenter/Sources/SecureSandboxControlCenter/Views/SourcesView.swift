import SwiftUI

struct SourcesView: View {
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?

    private var filtered: [SourceRecord] {
        store.sources.filter { search.isEmpty || $0.repository.localizedCaseInsensitiveContains(search) || $0.id.localizedCaseInsensitiveContains(search) }
            .sorted { $0.importedAt > $1.importedAt }
    }

    var body: some View {
        VStack(spacing: 0) {
            if let error = store.errors["sources"] {
                ContentUnavailableView("Sources unavailable", systemImage: "wifi.slash", description: Text(error))
            } else {
                List(filtered, selection: $selectedID) { source in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(source.repository).font(.headline)
                        Text("Imported \(source.importedAt)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(source.id)
                }
                .overlay {
                    if filtered.isEmpty { ContentUnavailableView.search(text: search) }
                }
                if let source = store.sources.first(where: { $0.id == selectedID }) {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Text(source.repository).font(.title3.bold())
                        LabeledContent("Imported", value: source.importedAt)
                        LabeledContent("Commit", value: source.commit).textSelection(.enabled)
                        LabeledContent("Source ID", value: source.id).textSelection(.enabled)
                    }
                    .padding()
                }
            }
        }
        .navigationTitle("Sources")
    }
}
