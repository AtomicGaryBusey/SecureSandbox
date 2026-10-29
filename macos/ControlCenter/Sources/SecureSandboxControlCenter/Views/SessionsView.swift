import SwiftUI

struct SessionsView: View {
    @Environment(\.openWindow) private var openWindow
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?
    @State private var showingLabel = false
    @State private var showingRuns = false

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
                Button { showingRuns = true } label: {
                    Label("Browse Session Runs", systemImage: "clock.arrow.circlepath")
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
        .sheet(isPresented: $showingRuns) {
            if let selectedID { SessionRunsSheet(sessionID: selectedID) }
        }
    }
}

private struct SessionRunsSheet: View {
    let sessionID: String
    @Environment(\.dismiss) private var dismiss
    @State private var runs: SessionRuns?
    @State private var error: String?
    @State private var loading = true
    @State private var transcriptRun: RunSelection?
    @State private var toolsRun: RunSelection?
    @State private var leaseRun: RunSelection?

    private struct RunSelection: Identifiable {
        let id: String
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Session runs").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }
            }
            if loading { ProgressView("Reading session run history…") }
            if let error {
                ContentUnavailableView("Run history unavailable", systemImage: "exclamationmark.shield",
                                       description: Text(error))
            } else if let runs {
                Text("\(runs.totalRuns) recorded runs · \(runs.runIDs.count) linked")
                    .foregroundStyle(.secondary)
                if runs.runIDs.isEmpty {
                    ContentUnavailableView("No linked runs", systemImage: "clock",
                                           description: Text("Older runs retain their count but predate run linkage."))
                } else {
                    List {
                        ForEach(0..<runs.runIDs.count, id: \.self) { offset in
                            let runID = runs.runIDs[runs.runIDs.count - 1 - offset]
                            HStack {
                                VStack(alignment: .leading) {
                                    Text("Run \(runs.totalRuns - offset)").font(.headline)
                                    Text(runID).font(.caption.monospaced()).foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                }
                                Spacer()
                                Button("Transcript") { transcriptRun = RunSelection(id: runID) }
                                Button("Tool Results") { toolsRun = RunSelection(id: runID) }
                                Button("Lease") { leaseRun = RunSelection(id: runID) }
                            }
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(minWidth: 680, minHeight: 400)
        .task { await load() }
        .sheet(item: $transcriptRun) { selection in
            TranscriptDetailSheet(runID: selection.id)
        }
        .sheet(item: $toolsRun) { selection in
            ToolResultsSheet(runID: selection.id)
        }
        .sheet(item: $leaseRun) { selection in
            LeaseSheet(runID: selection.id)
        }
    }

    private func load() async {
        let path = UserDefaults.standard.string(forKey: "repositoryPath")
            ?? (NSHomeDirectory() + "/SecureSandbox")
        let client = CatalogClient(repositoryPath: path)
        do {
            runs = try await Task.detached { try client.sessionRuns(sessionID: sessionID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }
}
