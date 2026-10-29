import SwiftUI

struct FindingReopenSheet: View {
    let detail: FindingDetail
    let onRecorded: () -> Void
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var options: FindingReopenOptions?
    @State private var selectedDigest = ""
    @State private var actorID = ""
    @State private var actorRole = "research_lead"
    @State private var rationale = ""
    @State private var conflictNote = ""
    @State private var loading = true
    @State private var busy = false
    @State private var attempted = false
    @State private var confirming = false
    @State private var result: FindingTransitionResult?
    @State private var error: String?

    private var ready: Bool {
        options?.options.contains(where: { $0.sha256 == selectedDigest }) == true
            && !actorID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !rationale.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !conflictNote.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Reopen finding").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.disabled(busy)
            }
            Text("Choose evidence added after the terminal decision. Reopening returns the finding to Needs Evidence.")
                .foregroundStyle(.secondary)
            LabeledContent("Current state", value: detail.currentState.capitalized)
            if loading { ProgressView("Checking fresh evidence against the terminal inventory…") }
            if let options, options.options.isEmpty {
                ContentUnavailableView("No new evidence", systemImage: "doc.badge.clock",
                                       description: Text("Add a new evidence amendment before reopening this finding."))
            }
            if let options, !options.options.isEmpty {
                Form {
                    Picker("New evidence", selection: $selectedDigest) {
                        Text("Choose new evidence").tag("")
                        ForEach(Array(options.options.enumerated()), id: \.offset) { index, item in
                            Text("\(index + 1). \(item.kind.replacingOccurrences(of: "_", with: " ").capitalized) · \(item.path ?? grouped(item.sha256))")
                                .tag(item.sha256)
                        }
                    }
                    TextField("Adjudicator ID", text: $actorID)
                    Picker("Role", selection: $actorRole) {
                        Text("Research lead").tag("research_lead")
                        Text("Architect").tag("architect")
                        Text("Independent reviewer").tag("independent_reviewer")
                    }
                    Section("Rationale") { TextEditor(text: $rationale).frame(height: 95) }
                    Section("Conflict note") { TextEditor(text: $conflictNote).frame(height: 65) }
                }
                .formStyle(.grouped)
            }
            if busy { ProgressView("Reopening and checking the journal receipt…") }
            if let result {
                Label("Finding reopened and verified", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                Text("Event \(result.eventID)").font(.caption.monospaced()).textSelection(.enabled)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button(result == nil ? "Cancel" : "Done") { dismiss() }.disabled(busy)
                if result == nil {
                    Button("Review & Reopen…") { confirming = true }
                        .buttonStyle(.borderedProminent).disabled(!ready || busy || attempted)
                }
            }
        }
        .padding(24)
        .frame(width: 720, height: 640)
        .task { await load() }
        .confirmationDialog("Reopen this finding?", isPresented: $confirming) {
            Button("Reopen with Selected Evidence") { Task { await reopen() } }
        } message: {
            Text("Finding \(detail.findingID) will return to Needs Evidence using the selected new evidence. The actor, rationale, and conflict note are recorded in the journal.")
        }
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.distance(from: start, to: digest.endIndex)))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }

    private func load() async {
        loading = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            options = try await Task.detached { try client.findingReopenOptions(id: detail.findingID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }

    private func reopen() async {
        guard ready, !attempted, let options else { return }
        attempted = true
        busy = true
        error = nil
        let request = FindingReopenRequest(
            findingID: detail.findingID, expectedContentSHA256: options.contentSHA256,
            expectedState: options.currentState, newEvidenceSHA256: selectedDigest,
            actorID: actorID, actorRole: actorRole, rationale: rationale, conflictNote: conflictNote)
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            result = try await Task.detached { try client.reopenFinding(request) }.value
            onRecorded()
        } catch {
            self.error = "Outcome is unclear or rejected: \(error.localizedDescription). Close and refresh before another action."
        }
        busy = false
    }
}
