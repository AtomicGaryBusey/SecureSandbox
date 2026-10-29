import SwiftUI

struct SourcePlanSheet: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var url = ""
    @State private var ref = "main"
    @State private var plan: SourcePlan?
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
                Text("Import execution will be available after the operation receipt and reattachment contract is installed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Close") { dismiss() }
                Button("Resolve") { Task { await resolve() } }
                    .disabled(url.isEmpty || ref.isEmpty || isPlanning)
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
        let client = CatalogClient(repositoryPath: repositoryPath)
        let requestedURL = url
        let requestedRef = ref
        do {
            plan = try await Task.detached {
                try client.planSource(url: requestedURL, ref: requestedRef)
            }.value
        } catch {
            self.error = error.localizedDescription
        }
        isPlanning = false
    }
}
