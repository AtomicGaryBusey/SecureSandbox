import SwiftUI

struct SourcesView: View {
    @Environment(\.openWindow) private var openWindow
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?
    @State private var planKind: SourcePlanKind?
    @State private var showingDependencies = false
    @State private var showingIndexes = false
    @State private var showingBundles = false

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
                        Text("Imported \(OperatorDate.display(source.importedAt))")
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
                        LabeledContent("Imported", value: OperatorDate.display(source.importedAt))
                        LabeledContent("Commit", value: source.commit).textSelection(.enabled)
                        LabeledContent("Source ID", value: source.id).textSelection(.enabled)
                        Button("Analyze Source…") {
                            openWindow(id: "terminal", value: "source:\(source.id)")
                        }
                        Button("Build Analysis Indexes…") { showingIndexes = true }
                        if source.repository.hasPrefix("npm/") {
                            Button("Plan Direct Dependencies…") { showingDependencies = true }
                        }
                    }
                    .padding()
                }
            }
        }
        .navigationTitle("Sources")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Sealed Bundles…") { showingBundles = true }
                    .help("Browse assembled direct dependency bundles")
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("GitHub Repository…") { planKind = .github }
                    Button("Exact npm Package…") { planKind = .npm }
                } label: {
                    Label("Import Source", systemImage: "plus")
                }
                .help("Resolve a public GitHub revision or exact npm package")
            }
        }
        .sheet(item: $planKind) { kind in
            SourcePlanSheet(store: store, kind: kind)
        }
        .sheet(isPresented: $showingDependencies) {
            if let source = store.sources.first(where: { $0.id == selectedID }) {
                DependencyPlanSheet(source: source)
            }
        }
        .sheet(isPresented: $showingIndexes) {
            if let source = store.sources.first(where: { $0.id == selectedID }) {
                SourceIndexSheet(source: source)
            }
        }
        .sheet(isPresented: $showingBundles) {
            DependencyBundlesSheet()
        }
    }
}
