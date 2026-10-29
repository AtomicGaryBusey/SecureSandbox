import SwiftUI

struct OverviewView: View {
    let store: CatalogStore
    @State private var lifecycleOperation: LifecycleOperation?

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
                       [(status.observed.gateway, reachability.gateway),
                        (status.observed.research, reachability.research),
                        (status.observed.target, reachability.target)]
                        .contains(where: { $0.0 == "running" && $0.1 != "reachable" }) {
                        Label("A running guest is unreachable. Check the control identity and refresh before operating the lab.", systemImage: "exclamationmark.triangle.fill")
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
                HStack {
                    Button("Start Stack…") { lifecycleOperation = .start }
                    Button("Stop Stack…") { lifecycleOperation = .stop }
                }
                .disabled(store.status == nil)
            }
            .padding(28)
            .frame(maxWidth: 960, alignment: .leading)
        }
        .navigationTitle("Overview")
        .sheet(item: $lifecycleOperation) { operation in
            LifecycleSheet(operation: operation, store: store)
        }
    }
}

private enum LifecycleOperation: String, Identifiable {
    case start, stop
    var id: String { rawValue }
    var title: String { self == .start ? "Start SecureSandbox" : "Stop SecureSandbox" }
}

private struct LifecycleSheet: View {
    let operation: LifecycleOperation
    let store: CatalogStore
    @Environment(\.dismiss) private var dismiss
    private let repositoryPath = ControlCenterPaths.repository
    @State private var preflight: HostStatus?
    @State private var result: LifecycleResult?
    @State private var error: String?
    @State private var busy = false
    @State private var liveObservation: HostStatus?
    @State private var observedAt: Date?
    @State private var phaseObservation: LifecycleProgress?
    @State private var finalObservation: HostStatus?
    @State private var finalObservedAt: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(operation.title).font(.title2.bold())
            Text("Quit Parallels Desktop before this operation. The host will check its GUI state, acquire the lifecycle lock, and independently verify Gateway, Research, and Target.")
                .foregroundStyle(.secondary)
            if let preflight {
                LabeledContent("Gateway", value: preflight.observed.gateway)
                LabeledContent("Research", value: preflight.observed.research)
                LabeledContent("Target", value: preflight.observed.target)
                if operation == .stop {
                    Label("Stopping ends any active work in these VMs. Save and quit the agent session first.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            } else if error == nil {
                ProgressView("Checking live VM state…")
            }
            if busy {
                ProgressView("Changing VM state and verifying boundaries…")
                if let phaseObservation, phaseObservation.state == "active",
                   phaseObservation.operation == operation.rawValue {
                    GroupBox("Host phase") {
                        VStack(alignment: .leading, spacing: 5) {
                            Label(phaseTitle(phaseObservation), systemImage: "clock.arrow.circlepath")
                            if let observedAt = phaseObservation.observedAt {
                                Text("Reported \(observedAt). This is progress, not completion.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                if let liveObservation, let observedAt {
                    GroupBox("Observed during transition") {
                        VStack(alignment: .leading, spacing: 6) {
                            LabeledContent("Gateway", value: liveObservation.observed.gateway.capitalized)
                            LabeledContent("Research", value: liveObservation.observed.research.capitalized)
                            LabeledContent("Target", value: liveObservation.observed.target.capitalized)
                            LabeledContent("Gateway uplink", value: liveObservation.observed.gatewayNet0.capitalized)
                            Text("Read back \(observedAt.formatted(date: .omitted, time: .standard)). Completion still requires the final host record and independent verification.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(8)
                    }
                }
            }
            if let result {
                Label("Verified: Gateway, Research, and Target are \(result.gateway).", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                if operation == .start {
                    LabeledContent("Gateway uplink", value: result.gatewayNet0 ?? "unknown")
                    LabeledContent("Guest reachability", value: result.guestReachability ?? "unknown")
                    LabeledContent("Guest clocks", value: result.clockSync ?? "unknown")
                    LabeledContent("Boundary verification", value: result.boundaryVerification ?? "unknown")
                }
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .textSelection(.enabled)
            }
            if let finalObservation, let finalObservedAt {
                GroupBox("Independent post-action VM readback") {
                    VStack(alignment: .leading, spacing: 5) {
                        LabeledContent("Gateway", value: finalObservation.observed.gateway.capitalized)
                        LabeledContent("Research", value: finalObservation.observed.research.capitalized)
                        LabeledContent("Target", value: finalObservation.observed.target.capitalized)
                        LabeledContent("Gateway uplink", value: finalObservation.observed.gatewayNet0.capitalized)
                        if let reachability = finalObservation.reachability {
                            LabeledContent("Gateway control", value: reachability.gateway.capitalized)
                            LabeledContent("Research control", value: reachability.research.capitalized)
                            LabeledContent("Target control", value: reachability.target.capitalized)
                        }
                        Text("Read back \(finalObservedAt.formatted(date: .omitted, time: .standard)). VM state alone does not prove boundary acceptance.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(8)
                }
            }
            HStack {
                Spacer()
                Button(result == nil ? "Cancel" : "Done") { dismiss() }
                    .disabled(busy)
                if result == nil {
                    Button(operation == .start ? "Start Stack" : "Stop Stack") {
                        Task { await execute() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(preflight?.status != "verified" || busy || error != nil)
                }
            }
        }
        .padding(24)
        .frame(width: 520)
        .task { await checkPreflight() }
        .task(id: busy) { await observeWhileBusy() }
    }

    private func checkPreflight() async {
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            preflight = try await Task.detached { try client.load("overview", as: HostStatus.self) }.value
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func execute() async {
        busy = true
        liveObservation = nil
        observedAt = nil
        phaseObservation = nil
        finalObservation = nil
        finalObservedAt = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            result = try await Task.detached { try client.lifecycle(operation.rawValue) }.value
        } catch {
            self.error = error.localizedDescription
        }
        if let observed = try? await Task.detached(operation: {
            try client.load("overview", as: HostStatus.self)
        }).value, observed.status == "verified" {
            finalObservation = observed
            finalObservedAt = Date()
        }
        busy = false
        await store.refresh()
    }

    private func observeWhileBusy() async {
        guard busy else { return }
        let client = CatalogClient(repositoryPath: repositoryPath)
        while busy && !Task.isCancelled {
            if let progress = try? await Task.detached(operation: {
                try client.lifecycleProgress()
            }).value, busy {
                phaseObservation = progress
            }
            if let status = try? await Task.detached(operation: {
                try client.load("overview", as: HostStatus.self)
            }).value, busy, status.status == "verified" {
                liveObservation = status
                observedAt = Date()
            }
            try? await Task.sleep(for: .seconds(3))
        }
    }

    private func phaseTitle(_ progress: LifecycleProgress) -> String {
        let target = (progress.target ?? "").capitalized
        switch progress.phase {
        case "preflight": return "Checking transition preconditions"
        case "vm_start": return "Starting \(target) VM"
        case "gateway_uplink": return "Connecting Gateway uplink"
        case "guest_readiness": return "Waiting for \(target) control reachability"
        case "guest_shutdown": return "Shutting down \(target) VM"
        case "time_sync": return "Synchronizing guest clocks"
        case "boundary_verification": return "Verifying containment boundaries"
        default: return "Host transition in progress"
        }
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
