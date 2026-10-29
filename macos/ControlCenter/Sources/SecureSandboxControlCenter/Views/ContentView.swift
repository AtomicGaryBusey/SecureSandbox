import SwiftUI

struct ContentView: View {
    let store: CatalogStore
    @State private var navigation = NavigationState()
    @State private var search = ""
    @FocusState private var searchFocused: Bool

    var body: some View {
        NavigationSplitView {
            List(ControlSection.allCases, selection: $navigation.section) { section in
                Label(section.rawValue, systemImage: section.symbol)
                    .tag(section)
            }
            .listStyle(.sidebar)
            .navigationTitle("SecureSandbox")
        } detail: {
            Group {
                switch navigation.section ?? .overview {
                case .overview: OverviewView(store: store)
                case .sessions: SessionsView(store: store, navigation: navigation, search: search)
                case .sources: SourcesView(store: store, search: search)
                case .findings: FindingsView(store: store, search: search)
                case .evidence: EvidenceView(store: store, search: search)
                case .recovery: RecoveryView(store: store)
                case .activity: ActivityView(store: store, search: search)
                case .maintenance: MaintenanceView(store: store)
                }
            }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        Task { await store.refresh() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(store.isRefreshing)
                    .help("Refresh live catalogs")
                }
            }
        }
        .searchable(text: $search, prompt: "Search sessions, sources, findings, and artifacts")
        .focusedSceneValue(navigation)
        .searchFocused($searchFocused)
        .onChange(of: navigation.searchRequest) { _, _ in searchFocused = true }
        .onChange(of: search) { _, term in
            if let selected = navigation.selectedSessionID,
               !store.sessions.contains(where: {
                   $0.id == selected && (term.isEmpty
                       || (store.sessionDisplayNames[$0.id] ?? "").localizedCaseInsensitiveContains(term)
                       || $0.id.localizedCaseInsensitiveContains(term))
               }) {
                navigation.selectedSessionID = nil
            }
        }
        .task { await store.refresh() }
    }
}

private struct PendingView: View {
    let title: String
    let detail: String

    var body: some View {
        ContentUnavailableView(title, systemImage: "hammer", description: Text(detail))
    }
}
