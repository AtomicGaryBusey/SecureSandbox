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
                }
            }
            if renewing { ProgressView("Renewing and reading back lease…") }
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
    }

    private func date(_ seconds: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).formatted()
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
}
