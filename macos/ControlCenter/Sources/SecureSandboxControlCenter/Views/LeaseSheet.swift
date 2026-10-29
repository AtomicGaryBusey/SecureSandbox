import SwiftUI

struct LeaseSheet: View {
    let runID: String
    @Environment(\.dismiss) private var dismiss
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var status: LeaseStatus?
    @State private var error: String?
    @State private var loading = true
    @State private var renewing = false
    @State private var confirmSeconds = 0
    @State private var confirming = false
    @State private var reconcilePlan: LeaseReconcilePlan?
    @State private var completed: LeaseCompleted?
    @State private var reconciling = false
    @State private var confirmingReconcile = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Run lease").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }
            }
            Text("Run \(runID)").font(.caption.monospaced()).textSelection(.enabled)
            if loading { ProgressView("Reading Gateway lease…") }
            if let status {
                Label(status.state.capitalized,
                      systemImage: status.state == "active" ? "clock.badge.checkmark" : "checkmark.circle")
                LabeledContent("Expires", value: date(status.expiresAt))
                LabeledContent("Maximum", value: date(status.maximumExpiresAt))
                LabeledContent("Renewals", value: String(status.renewals))
                LabeledContent("Requests", value: String(status.requests))
                LabeledContent("Input tokens", value: String(status.inputTokens))
                LabeledContent("Output tokens", value: String(status.outputTokens))
                if status.state == "active" {
                    HStack {
                        Button("Extend 5 Minutes…") { request(300) }
                            .disabled(loading || renewing || error != nil || status.expiresAt + 300 > status.maximumExpiresAt)
                        Button("Extend 15 Minutes…") { request(900) }
                            .disabled(loading || renewing || error != nil || status.expiresAt + 900 > status.maximumExpiresAt)
                    }
                } else {
                    HStack {
                        Button("Prepare Reconciliation") { Task { await prepareReconciliation() } }
                            .disabled(reconciling || loading)
                        Button("Check Completed Record") { Task { await checkCompleted() } }
                            .disabled(reconciling || loading)
                    }
                }
            }
            if renewing { ProgressView("Renewing and reading back lease…") }
            if reconciling { ProgressView("Checking Research and Gateway…") }
            if let reconcilePlan {
                Divider()
                Text("Reconciliation review").font(.headline)
                Text("Research is locally closed and Gateway has a final summary for this lease.")
                    .foregroundStyle(.secondary)
                LabeledContent("Lease", value: reconcilePlan.leaseID).textSelection(.enabled)
                LabeledContent("Gateway summary SHA-256", value: grouped(reconcilePlan.gatewaySummarySHA256))
                    .font(.caption.monospaced()).textSelection(.enabled)
                Button("Commit Reconciliation…") { confirmingReconcile = true }
                    .disabled(reconciling || completed != nil)
            }
            if let completed {
                Label("Research completion verified for this run", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                LabeledContent("Recorded Gateway digest", value: grouped(completed.gatewaySummarySHA256))
                    .font(.caption.monospaced()).textSelection(.enabled)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("Refresh") { Task { await load() } }.disabled(loading || renewing)
            }
        }
        .padding(20)
        .frame(minWidth: 520)
        .task { await load() }
        .confirmationDialog("Extend this run lease?", isPresented: $confirming) {
            Button("Extend \(confirmSeconds / 60) Minutes") { Task { await renew() } }
        } message: {
            Text("Gateway and Research will both receive the renewal. The result is read back before it is shown. Do not repeat an unclear outcome without refreshing.")
        }
        .confirmationDialog("Commit this closed run?", isPresented: $confirmingReconcile) {
            Button("Commit Exact Gateway Summary") { Task { await reconcile() } }
        } message: {
            Text("Research will bind its completed record to the reviewed Gateway summary digest. The saved record is read back before success is shown.")
        }
    }

    private func date(_ seconds: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).formatted()
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.distance(from: start, to: digest.endIndex)))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }

    private func request(_ seconds: Int) {
        confirmSeconds = seconds
        confirming = true
    }

    private func load() async {
        loading = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            status = try await Task.detached { try client.leaseStatus(runID: runID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }

    private func renew() async {
        guard [300, 900].contains(confirmSeconds), status?.state == "active" else { return }
        renewing = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        let seconds = confirmSeconds
        do {
            status = try await Task.detached {
                try client.renewLease(runID: runID, seconds: seconds)
            }.value
        } catch {
            self.error = error.localizedDescription
        }
        renewing = false
    }

    private func prepareReconciliation() async {
        guard status?.state == "closed" else { return }
        reconciling = true
        reconcilePlan = nil
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            reconcilePlan = try await Task.detached { try client.leaseReconcilePlan(runID: runID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        reconciling = false
    }

    private func checkCompleted() async {
        reconciling = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            completed = try await Task.detached { try client.completedLease(runID: runID) }.value
        } catch {
            self.error = error.localizedDescription
        }
        reconciling = false
    }

    private func reconcile() async {
        guard let plan = reconcilePlan, plan.runID == runID, completed == nil else { return }
        reconciling = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            completed = try await Task.detached {
                try client.reconcileLease(runID: runID, expectedDigest: plan.gatewaySummarySHA256)
            }.value
            reconcilePlan = nil
        } catch {
            self.error = error.localizedDescription
        }
        reconciling = false
    }
}
