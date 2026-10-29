import SwiftUI

struct DependencyPlanSheet: View {
    let source: SourceRecord
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var plan: DependencyPlan?
    @State private var status: DependencyStatus?
    @State private var bundle: DependencyBundle?
    @State private var error: String?
    @State private var busy = false
    @State private var attempted = false

    private var allReady: Bool {
        guard let plan, let status else { return false }
        let expected = plan.dependencies.map { $0.id }.sorted()
        let observed = status.dependencies.map { $0.id }.sorted()
        return expected == observed && status.dependencies.allSatisfy { $0.state == "READY" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Direct runtime dependencies").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.disabled(busy)
            }
            Text("Source: \(source.repository)").foregroundStyle(.secondary)
            Text("This bundle contains exact direct runtime dependencies. Lifecycle scripts remain disabled; transitive completeness is not claimed.")
                .font(.caption).foregroundStyle(.secondary)
            if busy { ProgressView(bundle == nil ? "Checking dependency plan…" : "Reading bundle…") }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .textSelection(.enabled)
            }
            if let plan {
                GroupBox("Immutable plan") {
                    VStack(alignment: .leading, spacing: 6) {
                        LabeledContent("Root", value: plan.root)
                        LabeledContent("Expires", value: plan.expiresAt)
                        LabeledContent("Set SHA-256", value: plan.dependencySetSHA256)
                            .textSelection(.enabled)
                        LabeledContent("Plan ID", value: plan.planID).textSelection(.enabled)
                    }
                    .padding(8)
                }
                List(status?.dependencies ?? plan.dependencies) { item in
                    HStack {
                        Label("\(item.package)@\(item.version)",
                              systemImage: item.state == "READY" ? "checkmark.circle.fill" : "arrow.down.circle")
                        Spacer()
                        Text(item.state.capitalized).foregroundStyle(item.state == "READY" ? .green : .orange)
                    }
                }
                .frame(minHeight: 170)
                HStack {
                    Button("Check Imported Packages") { Task { await refreshStatus() } }
                        .disabled(busy || attempted)
                    Spacer()
                    Button("Assemble Sealed Bundle") { Task { await apply() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(!allReady || busy || attempted)
                }
            }
            if let bundle {
                Label("Sealed bundle \(bundle.bundleID) contains \(bundle.dependencyCount) direct dependencies.",
                      systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                    .textSelection(.enabled)
            }
        }
        .padding(24)
        .frame(width: 650, height: 600)
        .task { await createPlan() }
    }

    private func createPlan() async {
        busy = true
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            plan = try await Task.detached { try client.dependencyPlan(sourceID: source.id) }.value
            await refreshStatus()
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    private func refreshStatus() async {
        guard let plan else { return }
        busy = true
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let fresh = try await Task.detached { try client.dependencyStatus(planID: plan.planID) }.value
            guard fresh.planID == plan.planID else { throw CatalogError.invalidSchema }
            status = fresh
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    private func apply() async {
        guard let plan, allReady, !attempted else { return }
        attempted = true
        busy = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            bundle = try await Task.detached {
                try client.dependencyApply(planID: plan.planID, expectedDigest: plan.dependencySetSHA256)
            }.value
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }
}
