import SwiftUI

struct OverviewView: View {
    let store: CatalogStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack {
                    VStack(alignment: .leading) {
                        Text("Lab overview").font(.largeTitle.bold())
                        Text("Live VM state and reachability").foregroundStyle(.secondary)
                    }
                    Spacer()
                    if store.isRefreshing { ProgressView().controlSize(.small) }
                }
                if let error = store.errors["overview"] {
                    ContentUnavailableView("Status unavailable", systemImage: "wifi.slash", description: Text(error))
                } else if let status = store.status {
                    if let reachability = status.reachability,
                       [reachability.gateway, reachability.research, reachability.target].contains(where: { $0 != "reachable" }) {
                        Label("Guest reachability is incomplete. Check the control identity and refresh before operating the lab.", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    HStack(spacing: 12) {
                        VMCard(name: "Gateway", symbol: "network", state: status.observed.gateway, reachability: status.reachability?.gateway)
                        VMCard(name: "Research", symbol: "desktopcomputer", state: status.observed.research, reachability: status.reachability?.research)
                        VMCard(name: "Target", symbol: "shippingbox", state: status.observed.target, reachability: status.reachability?.target)
                    }
                    LabeledContent("VM state readback", value: status.status.capitalized)
                    LabeledContent("Gateway uplink", value: status.observed.gatewayNet0.capitalized)
                } else {
                    ProgressView("Reading host state…")
                }
                if let refreshed = store.refreshedAt {
                    Text("Checked \(refreshed.formatted(date: .abbreviated, time: .standard))")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(28)
            .frame(maxWidth: 960, alignment: .leading)
        }
        .navigationTitle("Overview")
    }
}

private struct VMCard: View {
    let name: String
    let symbol: String
    let state: String
    let reachability: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(name, systemImage: symbol).font(.headline)
            Label(state.capitalized, systemImage: state == "running" ? "checkmark.circle.fill" : "pause.circle")
                .foregroundStyle(state == "running" ? .green : .secondary)
            Text(reachability?.capitalized ?? "Reachability unknown")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
    }
}
