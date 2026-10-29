import SwiftUI

struct SessionsView: View {
    @Environment(\.openWindow) private var openWindow
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?
    @State private var showingLabel = false

    private var filtered: [SessionRecord] {
        store.sessions.filter { search.isEmpty || $0.displayName.localizedCaseInsensitiveContains(search) || $0.id.localizedCaseInsensitiveContains(search) }
            .sorted { $0.lastAt > $1.lastAt }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let error = store.errors["sessions"] {
                ContentUnavailableView("Sessions unavailable", systemImage: "wifi.slash", description: Text(error))
            } else {
                List(filtered, selection: $selectedID) { session in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(session.displayName).font(.headline)
                        Text("Last active \(session.lastAt) · \(session.turns) turns")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(session.id)
                }
                .overlay {
                    if filtered.isEmpty { ContentUnavailableView.search(text: search) }
                }
                if let session = store.sessions.first(where: { $0.id == selectedID }) {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Text(session.displayName).font(.title3.bold())
                        LabeledContent("Created", value: session.createdAt)
                        LabeledContent("Last active", value: session.lastAt)
                        LabeledContent("Runs", value: session.runs)
                        LabeledContent("Session ID", value: session.id).textSelection(.enabled)
                    }
                    .padding()
                }
            }
        }
        .navigationTitle("Sessions")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    openWindow(id: "terminal", value: "new")
                } label: {
                    Label("New Analysis", systemImage: "plus")
                }
                .help("Start a new approved Claude session")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingLabel = true
                } label: {
                    Label("Label Session", systemImage: "tag")
                }
                .disabled(selectedID == nil)
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    if let selectedID { openWindow(id: "terminal", value: selectedID) }
                } label: {
                    Label("Open Session Terminal", systemImage: "terminal")
                }
                .disabled(selectedID == nil)
                .help("Resume the selected registered session")
            }
        }
        .sheet(isPresented: $showingLabel) {
            if let session = store.sessions.first(where: { $0.id == selectedID }) {
                SessionLabelSheet(store: store, session: session)
            }
        }
    }
}
