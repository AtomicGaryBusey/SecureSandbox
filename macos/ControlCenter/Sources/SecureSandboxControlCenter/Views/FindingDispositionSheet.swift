import SwiftUI

struct FindingDispositionSheet: View {
    let detail: FindingDetail
    let onRecorded: () -> Void
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var actorID = ""
    @State private var actorRole = "research_lead"
    @State private var rationale = ""
    @State private var conflictNote = ""
    @State private var confirming = false
    @State private var busy = false
    @State private var attempted = false
    @State private var result: FindingDispositionResult?
    @State private var error: String?

    private var ready: Bool {
        ["validated", "rejected", "withdrawn"].contains(detail.currentState)
            && !actorID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !rationale.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !conflictNote.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Archive terminal finding").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.disabled(busy)
            }
            Label("This removes the candidate from active capacity and preserves it in the root-owned archive.",
                  systemImage: "archivebox.fill")
                .foregroundStyle(.orange)
            LabeledContent("Terminal state", value: detail.currentState.capitalized)
            LabeledContent("Finding", value: detail.findingID).textSelection(.enabled)
            Form {
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
            if busy { ProgressView("Archiving and verifying the archive marker…") }
            if let result {
                Label("Terminal finding archived and verified", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                Text("Archive SHA-256: \(grouped(result.archiveSHA256))")
                    .font(.caption.monospaced()).textSelection(.enabled)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button(result == nil ? "Cancel" : "Done") { dismiss() }.disabled(busy)
                if result == nil {
                    Button("Review & Archive…", role: .destructive) { confirming = true }
                        .disabled(!ready || busy || attempted)
                }
            }
        }
        .padding(24)
        .frame(width: 680, height: 560)
        .confirmationDialog("Archive this terminal finding?", isPresented: $confirming) {
            Button("Archive Finding", role: .destructive) { Task { await archive() } }
        } message: {
            Text("Finding \(detail.findingID) in \(detail.currentState) state will be moved to the root-owned archive. The archive marker and candidate digest will be read back.")
        }
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.distance(from: start, to: digest.endIndex)))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }

    private func archive() async {
        guard ready, !attempted else { return }
        attempted = true
        busy = true
        error = nil
        let request = FindingDispositionRequest(
            findingID: detail.findingID, expectedContentSHA256: detail.contentSHA256,
            expectedState: detail.currentState, actorID: actorID, actorRole: actorRole,
            rationale: rationale, conflictNote: conflictNote)
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            result = try await Task.detached { try client.disposeFinding(request) }.value
            onRecorded()
        } catch {
            self.error = "Outcome is unclear or rejected: \(error.localizedDescription). Close and refresh before another action."
        }
        busy = false
    }
}
