import SwiftUI

struct MaintenanceView: View {
    let store: CatalogStore
    @Environment(\.openWindow) private var openWindow
    private let repositoryPath = ControlCenterPaths.repository
    @State private var checkingBoundaries = false
    @State private var boundaryResult: BoundaryVerificationResult?
    @State private var boundaryError: String?
    @State private var showingTimeSync = false
    @State private var checkingSafety = false
    @State private var safetyResult: SafetyAuditResult?
    @State private var safetyError: String?
    @State private var proposals: [MemoryProposal]?
    @State private var selectedProposal: MemoryProposal?
    @State private var proposalsError: String?
    @State private var loadingProposals = false
    @State private var confirmingPanic = false
    @State private var panicInProgress = false
    @State private var panicResult: PanicResult?
    @State private var panicError: String?
    @State private var confirmingIdentityReload = false
    @State private var reloadingIdentities = false
    @State private var identityReloadResult: IdentityReloadResult?
    @State private var identityReloadError: String?

    var body: some View {
        Form {
            Section("Read-only checks") {
                if let status = store.maintenance {
                    statusRow("Guest clocks", value: status.timeSync)
                    statusRow("Snapshot retention", value: status.snapshotPolicy)
                } else if let error = store.errors["maintenance"] {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } else {
                    ProgressView("Checking maintenance state…")
                }
                Button("Synchronize Guest Clocks…") { showingTimeSync = true }
                Button("Run Boundary Verification") { Task { await verify() } }
                    .disabled(checkingBoundaries)
                if checkingBoundaries { ProgressView("Checking all lab boundaries…") }
                if let boundaryResult {
                    Label("\(boundaryResult.passedChecks) passed · \(boundaryResult.failedChecks) failed · \(boundaryResult.gateNotices) gate notices",
                          systemImage: boundaryResult.status == "verified" ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .foregroundStyle(boundaryResult.status == "verified" ? .green : .orange)
                    if !boundaryResult.failureLabels.isEmpty {
                        ForEach(boundaryResult.failureLabels, id: \.self) { label in
                            Label(label, systemImage: "xmark.circle")
                                .textSelection(.enabled)
                        }
                        Text("The failed checks need investigation before boundary acceptance. Refresh status after any repair.")
                            .foregroundStyle(.secondary)
                    }
                }
                if let boundaryError {
                    Label(boundaryError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                Button("Run Safety Audit") { Task { await auditSafety() } }
                    .disabled(checkingSafety)
                if checkingSafety { ProgressView("Checking host, controller, boundaries, and off-host evidence…") }
                if let safetyResult {
                    Label(safetyResult.detail,
                          systemImage: safetyResult.verified ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .foregroundStyle(safetyResult.verified ? .green : .orange)
                    LabeledContent("Host-direct posture tier", value: String(safetyResult.hostDirectTier))
                }
                if let safetyError {
                    Label(safetyError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
            Section("Additional controls") {
                Button("Read Memory Proposals") { Task { await loadProposals() } }
                    .disabled(loadingProposals)
                if loadingProposals { ProgressView("Reading proposal metadata…") }
                if let proposals {
                    if proposals.isEmpty { Text("No pending proposals").foregroundStyle(.secondary) }
                    ForEach(proposals) { proposal in
                        Button {
                            selectedProposal = proposal
                        } label: {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(proposal.title).font(.headline)
                                Text("\(proposal.category) · \(proposal.status) · \(OperatorDate.display(proposal.createdAt))")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
                if let proposalsError {
                    Label(proposalsError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                Text("Proposal titles are untrusted suggestions. Select one to inspect its origin and digest.")
                    .foregroundStyle(.secondary)
            }
            Section("Direct administrator shells") {
                Text("These are emergency SSH paths outside the analysis session workflow. Each opens a separate terminal after a destination-specific review.")
                    .foregroundStyle(.secondary)
                Button("Open Research Administrator Shell…") { openWindow(id: "breakglass", value: "admin") }
                Button("Open Target Administrator Shell…") { openWindow(id: "breakglass", value: "target") }
            }
            Section("Host control identities") {
                Text("Reload the provisioning and control SSH keys from the Agents vault into their dedicated local agents. Key values stay out of the app response.")
                    .foregroundStyle(.secondary)
                Button("Reload Control Identities…") { confirmingIdentityReload = true }
                    .disabled(reloadingIdentities)
                if reloadingIdentities { ProgressView("Loading and checking both identities…") }
                if let identityReloadResult {
                    Label(identityReloadResult.status == "verified" ? "Both identities loaded" : "Identity reload needs attention",
                          systemImage: identityReloadResult.status == "verified" ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(identityReloadResult.status == "verified" ? .green : .orange)
                }
                if let identityReloadError {
                    Label(identityReloadError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
            }
            Section("Emergency containment") {
                Text("Hard stop Research and Target, then disconnect Gateway net0. This interrupts active work. The result is independently read back from Parallels.")
                    .foregroundStyle(.secondary)
                Button("Contain Sandbox Now…", role: .destructive) { confirmingPanic = true }
                    .disabled(panicInProgress)
                if panicInProgress { ProgressView("Stopping guests and checking uplink…") }
                if let panicResult {
                    Label(panicResult.status == "verified" ? "Sandbox containment verified" : "Containment incomplete; inspect VM state",
                          systemImage: panicResult.status == "verified" ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(panicResult.status == "verified" ? .green : .orange)
                    LabeledContent("Research", value: panicResult.research)
                    LabeledContent("Target", value: panicResult.target)
                    LabeledContent("Gateway net0", value: panicResult.gatewayNet0)
                }
                if let panicError {
                    Label(panicError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Maintenance")
        .sheet(isPresented: $showingTimeSync) {
            TimeSyncSheet(store: store)
        }
        .sheet(item: $selectedProposal) { proposal in
            MemoryProposalInspector(proposal: proposal)
        }
        .confirmationDialog("Contain the sandbox immediately?", isPresented: $confirmingPanic) {
            Button("Hard Stop Research and Target; Disconnect Gateway", role: .destructive) {
                Task { await containSandbox() }
            }
        } message: {
            Text("This ends active guest work and disconnects Gateway net0. Inspect the readback before taking another action.")
        }
        .confirmationDialog("Reload both host control identities?", isPresented: $confirmingIdentityReload) {
            Button("Reload Provisioning and Control Keys") { Task { await reloadIdentities() } }
        } message: {
            Text("The current identities in both local SSH agents will be replaced from the Agents vault.")
        }
    }

    private func statusRow(_ title: String, value: String) -> some View {
        LabeledContent(title) {
            Label(value.capitalized, systemImage: value == "verified" ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(value == "verified" ? .green : .orange)
        }
    }

    private func verify() async {
        checkingBoundaries = true
        boundaryResult = nil
        boundaryError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            boundaryResult = try await Task.detached {
                try client.verifyBoundaries()
            }.value
        } catch {
            boundaryError = error.localizedDescription
        }
        checkingBoundaries = false
    }

    private func auditSafety() async {
        checkingSafety = true
        safetyResult = nil
        safetyError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            safetyResult = try await Task.detached { try client.safetyAudit() }.value
        } catch {
            safetyError = error.localizedDescription
        }
        checkingSafety = false
    }

    private func loadProposals() async {
        loadingProposals = true
        proposalsError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            proposals = try await Task.detached { try client.memoryProposals() }.value
        } catch {
            proposalsError = error.localizedDescription
        }
        loadingProposals = false
    }

    private func containSandbox() async {
        panicInProgress = true
        panicResult = nil
        panicError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            panicResult = try await Task.detached { try client.panic() }.value
        } catch {
            panicError = "Containment outcome is unclear: \(error.localizedDescription). Refresh VM status before any retry."
        }
        panicInProgress = false
        await store.refresh()
    }

    private func reloadIdentities() async {
        reloadingIdentities = true
        identityReloadResult = nil
        identityReloadError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            identityReloadResult = try await Task.detached { try client.reloadControlIdentities() }.value
        } catch {
            identityReloadError = error.localizedDescription
        }
        reloadingIdentities = false
    }
}

private struct MemoryProposalInspector: View {
    let proposal: MemoryProposal
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section("Untrusted proposal") {
                Text(proposal.title).font(.headline)
                LabeledContent("Category", value: proposal.category)
                LabeledContent("Status", value: proposal.status)
                LabeledContent("Created", value: OperatorDate.display(proposal.createdAt))
            }
            Section("Origin and integrity") {
                Text("This was submitted by an analysis run for operator review. It has no authority to change host or guest memory.")
                    .foregroundStyle(.secondary)
                LabeledContent("Run ID", value: proposal.runID)
                LabeledContent("Proposal ID", value: proposal.id)
                LabeledContent("Authority", value: proposal.authority)
                LabeledContent("Content SHA-256", value: grouped(proposal.contentSHA256))
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
        .frame(minWidth: 540, minHeight: 370)
        .navigationTitle("Memory Proposal")
        .toolbar { Button("Close") { dismiss() } }
    }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.count - offset))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }
}

private struct TimeSyncSheet: View {
    let store: CatalogStore
    @Environment(\.dismiss) private var dismiss
    private let repositoryPath = ControlCenterPaths.repository
    @State private var status: HostStatus?
    @State private var error: String?
    @State private var result: TimeSyncResult?
    @State private var busy = false

    private var ready: Bool {
        guard let status else { return false }
        return status.status == "verified" && [status.observed.gateway, status.observed.research,
                                                status.observed.target].allSatisfy { $0 == "running" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Synchronize guest clocks").font(.title2.bold())
            Text("This changes the clocks of Gateway, Research, and Target. The host refuses the operation while a Claude run is active and checks all three clocks afterward.")
                .foregroundStyle(.secondary)
            if status == nil && error == nil { ProgressView("Checking VM state…") }
            if let status {
                LabeledContent("Gateway", value: status.observed.gateway)
                LabeledContent("Research", value: status.observed.research)
                LabeledContent("Target", value: status.observed.target)
            }
            if !ready && status != nil {
                Label("All three VMs must be running.", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            if busy { ProgressView("Synchronizing and independently checking clocks…") }
            if result != nil {
                Label("Guest clocks are within five seconds of the Mac.", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button(result == nil ? "Cancel" : "Done") { dismiss() }.disabled(busy)
                if result == nil {
                    Button("Synchronize Clocks") { Task { await apply() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(!ready || busy || error != nil)
                }
            }
        }
        .padding(24)
        .frame(width: 540)
        .task { await check() }
    }

    private func check() async {
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            status = try await Task.detached { try client.load("overview", as: HostStatus.self) }.value
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func apply() async {
        busy = true
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let checked = try await Task.detached { try client.applyTimeSync() }.value
            guard checked.status == "verified", checked.operation == "time-sync" else {
                throw CatalogError.invalidSchema
            }
            result = checked
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
        await store.refresh()
    }
}
