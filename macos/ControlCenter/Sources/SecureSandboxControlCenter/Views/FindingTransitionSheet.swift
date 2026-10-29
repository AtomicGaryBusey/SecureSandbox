import SwiftUI

struct FindingTransitionSheet: View {
    let detail: FindingDetail
    let onRecorded: () -> Void
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var toState = ""
    @State private var method = "inspected_evidence"
    @State private var selectedEvidence: Set<String> = []
    @State private var actorID = ""
    @State private var actorRole = "research_lead"
    @State private var rationale = ""
    @State private var conflictNote = ""
    @State private var confirming = false
    @State private var busy = false
    @State private var attempted = false
    @State private var result: FindingTransitionResult?
    @State private var error: String?

    private var targets: [String] {
        switch detail.currentState {
        case "candidate": ["needs_evidence", "disputed", "validated", "rejected", "withdrawn"]
        case "needs_evidence": ["disputed", "validated", "rejected", "withdrawn"]
        case "disputed": ["needs_evidence", "validated", "rejected", "withdrawn"]
        default: []
        }
    }

    private var ready: Bool {
        targets.contains(toState) && !actorID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !rationale.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !conflictNote.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && (toState != "validated" || (!selectedEvidence.isEmpty && method != "reasoning_only"
                && (!detail.claimRequiresExecution || method == "re_executed")))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Adjudicate finding").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.disabled(busy)
            }
            Text("Review the evidence and record your decision as an append-only root-authorized event.")
                .foregroundStyle(.secondary)
            LabeledContent("Current state", value: detail.currentState.capitalized)
            Form {
                Picker("New state", selection: $toState) {
                    Text("Choose a state").tag("")
                    ForEach(targets, id: \.self) { value in
                        Text(value.replacingOccurrences(of: "_", with: " ").capitalized).tag(value)
                    }
                }
                Picker("Verification method", selection: $method) {
                    Text("Inspected evidence").tag("inspected_evidence")
                    Text("Re-executed").tag("re_executed")
                    Text("Reasoning only").tag("reasoning_only")
                }
                Section("Consulted evidence") {
                    if detail.evidence.isEmpty { Text("No evidence is available").foregroundStyle(.secondary) }
                    ForEach(Array(detail.evidence.enumerated()), id: \.offset) { index, item in
                        Toggle(isOn: Binding(
                            get: { selectedEvidence.contains(item.sha256) },
                            set: { selected in
                                if selected { selectedEvidence.insert(item.sha256) }
                                else { selectedEvidence.remove(item.sha256) }
                            }
                        )) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(index + 1). \(item.kind.replacingOccurrences(of: "_", with: " ").capitalized)")
                                if let path = item.path { Text(path).font(.caption).foregroundStyle(.secondary) }
                                Text(grouped(item.sha256)).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                TextField("Adjudicator ID", text: $actorID)
                Picker("Role", selection: $actorRole) {
                    Text("Research lead").tag("research_lead")
                    Text("Architect").tag("architect")
                    Text("Independent reviewer").tag("independent_reviewer")
                }
                Section("Rationale") { TextEditor(text: $rationale).frame(height: 90) }
                Section("Conflict note") { TextEditor(text: $conflictNote).frame(height: 65) }
            }
            .formStyle(.grouped)
            if detail.claimRequiresExecution && toState == "validated" && method != "re_executed" {
                Label("This claim requires re-execution before validation.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            if busy { ProgressView("Submitting adjudication and checking its journal receipt…") }
            if let result {
                Label("\(result.state.capitalized) recorded and verified", systemImage: "checkmark.shield.fill")
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
                        .buttonStyle(.borderedProminent)
                        .disabled(!ready || busy || attempted)
                }
            }
        }
        .padding(24)
        .frame(width: 760, height: 780)
        .confirmationDialog("Record this finding transition?", isPresented: $confirming) {
            Button("Record \(toState.replacingOccurrences(of: "_", with: " ").capitalized)") {
                Task { await record() }
            }
        } message: {
            Text("Finding \(detail.findingID) will move from \(detail.currentState) to \(toState). The selected evidence, rationale, actor, and conflict note are bound to this exact request.")
        }
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.distance(from: start, to: digest.endIndex)))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }

    private func record() async {
        guard ready, !attempted else { return }
        attempted = true
        busy = true
        error = nil
        let request = FindingTransitionRequest(
            findingID: detail.findingID, expectedContentSHA256: detail.contentSHA256,
            expectedState: detail.currentState, toState: toState, verificationMethod: method,
            consultedEvidence: selectedEvidence.sorted(),
            actorID: actorID, actorRole: actorRole, rationale: rationale,
            conflictNote: conflictNote)
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            result = try await Task.detached { try client.applyFindingTransition(request) }.value
            onRecorded()
        } catch {
            self.error = "Outcome is unclear or rejected: \(error.localizedDescription). Close and refresh the finding before another action."
        }
        busy = false
    }
}
