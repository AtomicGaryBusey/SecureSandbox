import SwiftUI

struct FindingRelationSheet: View {
    let detail: FindingDetail
    let targets: [FindingRecord]
    let onRecorded: () -> Void
    @Environment(\.dismiss) private var dismiss
    private let repositoryPath = ControlCenterPaths.repository
    @State private var targetID = ""
    @State private var relation = "duplicate_of"
    @State private var actorID = ""
    @State private var actorRole = "research_lead"
    @State private var rationale = ""
    @State private var conflictNote = ""
    @State private var confirming = false
    @State private var busy = false
    @State private var attempted = false
    @State private var result: FindingRelationResult?
    @State private var error: String?

    private var ready: Bool {
        targets.contains { $0.findingID == targetID }
            && !actorID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !rationale.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !conflictNote.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Relate findings").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.disabled(busy)
            }
            Text("Record a directional relation in the append-only adjudication journal.")
                .foregroundStyle(.secondary)
            Form {
                Picker("Relation", selection: $relation) {
                    Text("Duplicate of").tag("duplicate_of")
                    Text("Supersedes").tag("supersedes")
                    Text("Disputes").tag("disputes")
                }
                Picker("Target finding", selection: $targetID) {
                    Text("Choose a finding").tag("")
                    ForEach(targets) { target in
                        Text("\(target.proposedSeverity.capitalized) · \(target.state.capitalized) · \(target.submittedAt) · \(target.findingID.prefix(8))")
                            .tag(target.findingID)
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
            if busy { ProgressView("Recording relation and checking its journal receipt…") }
            if let result {
                Label("Relation recorded and verified", systemImage: "checkmark.shield.fill")
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
                    Button("Review & Record…") { confirming = true }
                        .buttonStyle(.borderedProminent).disabled(!ready || busy || attempted)
                }
            }
        }
        .padding(24)
        .frame(width: 720, height: 620)
        .confirmationDialog("Record this finding relation?", isPresented: $confirming) {
            Button("Record \(relation.replacingOccurrences(of: "_", with: " ").capitalized)") {
                Task { await record() }
            }
        } message: {
            Text("Finding \(detail.findingID) will be linked to \(targetID). The direction, actor, rationale, and conflict note are recorded together.")
        }
    }

    private func record() async {
        guard ready, !attempted else { return }
        attempted = true
        busy = true
        error = nil
        let request = FindingRelationRequest(
            findingID: detail.findingID, expectedContentSHA256: detail.contentSHA256,
            expectedState: detail.currentState, relation: relation, targetFindingID: targetID,
            actorID: actorID, actorRole: actorRole, rationale: rationale, conflictNote: conflictNote)
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            result = try await Task.detached { try client.applyFindingRelation(request) }.value
            onRecorded()
        } catch {
            self.error = "Outcome is unclear or rejected: \(error.localizedDescription). Close and refresh before another action."
        }
        busy = false
    }
}
