import SwiftUI

struct ContentView: View {
    let store: CatalogStore
    @State private var selection: Section? = .overview
    @State private var search = ""

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $selection) { section in
                Label(section.rawValue, systemImage: section.symbol)
                    .tag(section)
            }
            .listStyle(.sidebar)
            .navigationTitle("SecureSandbox")
        } detail: {
            Group {
                switch selection ?? .overview {
                case .overview: OverviewView(store: store)
                case .sessions: SessionsView(store: store, search: search)
                case .sources: SourcesView(store: store, search: search)
                case .findings: FindingsView(store: store, search: search)
                case .evidence: PendingView(title: "Evidence", detail: "Verified report and tool export is being built.")
                case .recovery: PendingView(title: "Recovery", detail: "Coordinated VM backup and restore is being built.")
                case .activity: PendingView(title: "Activity", detail: "Operation history and receipts are being built.")
                case .maintenance: PendingView(title: "Maintenance", detail: "Maintenance controls and boundary checks are being built.")
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
        .searchable(text: $search, prompt: "Search sessions, sources, and findings")
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
