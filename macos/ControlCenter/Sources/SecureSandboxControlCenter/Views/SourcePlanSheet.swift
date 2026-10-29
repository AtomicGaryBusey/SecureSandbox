import SwiftUI

struct SourcePlanSheet: View {
    let store: CatalogStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var url = ""
    @State private var ref = "main"
    @State private var plan: SourcePlan?
    @State private var planStatus: SourcePlanStatus?
    @State private var imported: SourceImportResult?
    @State private var importAttempted = false
    @State private var isImporting = false
    @State private var error: String?
    @State private var isPlanning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Import a repository").font(.title2.bold())
            Text("Paste a public GitHub repository URL. The gateway resolves the ref to an immutable commit before import.")
                .foregroundStyle(.secondary)
            Form {
                TextField("Repository URL", text: $url, prompt: Text("https://github.com/owner/repository"))
                TextField("Ref", text: $ref)
            }
            .formStyle(.grouped)
            if isPlanning { ProgressView("Resolving source…") }
            if isImporting { ProgressView("Importing and verifying source…") }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
            if let plan {
                GroupBox("Resolved source") {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("Repository", value: plan.repository)
                        LabeledContent("Requested ref", value: plan.requestedRef)
                        LabeledContent("Immutable commit", value: plan.resolvedCommit)
                            .textSelection(.enabled)
                        LabeledContent("Plan expires", value: plan.expiresAt)
                        LabeledContent("Plan ID", value: plan.planID)
                            .textSelection(.enabled)
                    }
                    .padding(8)
                }
                if let planStatus {
                    LabeledContent("Plan state", value: planStatus.state.capitalized)
                    if let sourceID = planStatus.sourceID {
                        LabeledContent("Imported source", value: sourceID)
                            .textSelection(.enabled)
                    }
                }
                if imported != nil {
                    Label("The source is published with archived evidence.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }
            }
            HStack {
                Spacer()
                Button("Close") { dismiss() }
                if let plan {
                    Button("Check Status") { Task { await checkStatus(planID: plan.planID) } }
                        .disabled(isPlanning || isImporting)
                    Button("Import") { Task { await importSource(planID: plan.planID) } }
                        .disabled(planStatus?.state != "planned" || importAttempted || isPlanning || isImporting)
                }
                Button("Resolve") { Task { await resolve() } }
                    .disabled(url.isEmpty || ref.isEmpty || isPlanning || isImporting)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 580)
    }

    private func resolve() async {
        isPlanning = true
        error = nil
        plan = nil
        planStatus = nil
        imported = nil
        importAttempted = false
        let client = CatalogClient(repositoryPath: repositoryPath)
        let requestedURL = url
        let requestedRef = ref
        do {
            plan = try await Task.detached {
                try client.planSource(url: requestedURL, ref: requestedRef)
            }.value
            if let plan { await checkStatus(planID: plan.planID) }
        } catch {
            self.error = error.localizedDescription
        }
        isPlanning = false
    }

    private func checkStatus(planID: String, clearError: Bool = true) async {
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            planStatus = try await Task.detached {
                try client.sourceStatus(planID: planID)
            }.value
            if clearError { error = nil }
        } catch {
            if clearError || self.error == nil { self.error = error.localizedDescription }
        }
    }

    private func importSource(planID: String) async {
        guard !importAttempted else { return }
        importAttempted = true
        isImporting = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            imported = try await Task.detached {
                try client.applySource(planID: planID)
            }.value
            await store.refresh()
        } catch {
            self.error = error.localizedDescription
        }
        await checkStatus(planID: planID, clearError: false)
        isImporting = false
    }
}
