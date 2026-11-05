import SwiftUI
import SecureSandboxNativeSessionUIProtocol

struct NativeDeploymentControlView: View {
    let externallyBusy: Bool
    let onMutationFenceChanged: (Bool) -> Void
    let onCurrentHostReleaseChanged: (String?) -> Void
    let onProtectedStateChanged: () -> Void

    @State private var deploymentStatus: NativeDeploymentStatusQueryResult?
    @State private var catalogGate: NativeCatalogPromotionGateQueryResult?
    @State private var loading = false
    @State private var executing = false
    @State private var error: String?
    @State private var notice: String?
    @State private var planReview: DeploymentPlanReview?
    @State private var recoveryReview: DeploymentRecoveryReview?
    @State private var catalogRecoveryReview: CatalogRecoveryReview?

    private let catalogClient = CatalogClient(
        repositoryPath: ControlCenterPaths.repository
    )

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    Label("Protected native deployment", systemImage: "shippingbox.and.arrow.backward")
                        .font(.headline)
                    Spacer()
                    if loading || executing { ProgressView().controlSize(.small) }
                    Button("Refresh") { Task { await refresh() } }
                        .disabled(loading || executing || externallyBusy)
                }

                HStack(spacing: 18) {
                    stateFact(
                        "Gateway + Research",
                        value: deploymentStateTitle,
                        color: deploymentStateColor
                    )
                    stateFact(
                        "Catalog publication gate",
                        value: catalogGateTitle,
                        color: catalogGateColor
                    )
                    if let hostReleaseID = currentHostReleaseID {
                        stateFact(
                            "Current Host release",
                            value: hostReleaseID.groupedDigest,
                            color: .secondary,
                            monospaced: true
                        )
                    }
                    Spacer()
                }

                if let status = deploymentStatus?.status,
                   status.state == "recovery-required" {
                    Text(deploymentRecoveryDetail(status))
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if catalogGate?.gate.state == "invalid" {
                    Text("Catalog publication state is invalid. Native mutations remain fenced. There is no force-clear or bypass action.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                if let error {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
                if let notice {
                    Text(notice).font(.caption).foregroundStyle(.secondary)
                }

                HStack {
                    Text("Every plan is bound to the exact Host release, catalog, guest packages, predecessors, and bounded expiry. Download and install are never automatic.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if deploymentReady && catalogReady {
                        Button("Review Deployment…") {
                            Task { await prepareDeployment() }
                        }
                        .disabled(buttonsDisabled)
                    }
                    if deploymentStatus?.status.state == "recovery-required" {
                        Button("Review Deployment Recovery…") {
                            Task { await prepareDeploymentRecovery() }
                        }
                        .disabled(buttonsDisabled)
                    }
                    if catalogGate?.gate.state == "active" {
                        Button("Review Catalog Recovery…") {
                            prepareCatalogRecovery()
                        }
                        .disabled(buttonsDisabled)
                    }
                }
            }
            .padding(4)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .task {
            onMutationFenceChanged(true)
            onCurrentHostReleaseChanged(nil)
            await refresh()
        }
        .onDisappear {
            onMutationFenceChanged(true)
            onCurrentHostReleaseChanged(nil)
        }
        .sheet(item: $planReview) { review in
            NativeDeploymentPlanReviewSheet(
                query: review.query,
                onCancel: {
                    planReview = nil
                    publishMutationFence()
                },
                onAuthorize: { Task { await authorizeDeployment(review.query) } }
            )
        }
        .sheet(item: $recoveryReview) { review in
            NativeDeploymentRecoveryReviewSheet(
                query: review.query,
                onCancel: {
                    recoveryReview = nil
                    publishMutationFence()
                },
                onAuthorize: { action in
                    Task { await authorizeRecovery(action, query: review.query) }
                }
            )
        }
        .sheet(item: $catalogRecoveryReview) { review in
            NativeCatalogRecoveryReviewSheet(
                query: review.query,
                onCancel: {
                    catalogRecoveryReview = nil
                    publishMutationFence()
                },
                onRecover: { Task { await recoverCatalog(review.query) } }
            )
        }
    }

    private var buttonsDisabled: Bool {
        loading || executing || externallyBusy
    }

    private var deploymentReady: Bool {
        deploymentStatus?.status.state == "ready"
    }

    private var catalogReady: Bool { catalogGate?.gate.state == "ready" }

    private var mutationsMayProceed: Bool {
        !loading && !executing && error == nil
            && planReview == nil
            && recoveryReview == nil
            && catalogRecoveryReview == nil
            && deploymentReady && catalogReady
    }

    @MainActor private func publishMutationFence() {
        onMutationFenceChanged(!mutationsMayProceed)
    }

    private var currentHostReleaseID: String? {
        guard let deployment = deploymentStatus,
              let gate = catalogGate,
              deployment.currentHostReleaseID == gate.currentHostReleaseID
        else { return nil }
        return deployment.currentHostReleaseID
    }

    private var deploymentStateTitle: String {
        guard let status = deploymentStatus?.status else { return "Unavailable · fenced" }
        switch status.state {
        case "ready": return "Ready"
        case "recovery-required": return "Recovery required"
        default: return "Unsupported · fenced"
        }
    }

    private var deploymentStateColor: Color {
        deploymentReady ? .green : (deploymentStatus == nil ? .red : .orange)
    }

    private var catalogGateTitle: String {
        guard let gate = catalogGate?.gate else { return "Unavailable · fenced" }
        switch gate.state {
        case "ready": return "Ready"
        case "active": return "Recovery required"
        case "invalid": return "Invalid · fenced"
        default: return "Unsupported · fenced"
        }
    }

    private var catalogGateColor: Color {
        switch catalogGate?.gate.state {
        case "ready": .green
        case "active": .orange
        default: .red
        }
    }

    @ViewBuilder private func stateFact(
        _ title: String,
        value: String,
        color: Color,
        monospaced: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption2).foregroundStyle(.secondary)
            if monospaced {
                Text(value).font(.caption.monospaced()).foregroundStyle(color)
                    .textSelection(.enabled)
            } else {
                Text(value).font(.caption.weight(.semibold)).foregroundStyle(color)
            }
        }
    }

    private func deploymentRecoveryDetail(
        _ status: NativeDeploymentPublicStatus
    ) -> String {
        if status.phase == "state-invalid" {
            return "The deployment journal is invalid. The app will not offer resume, rollback, force-clear, or another deployment."
        }
        return "Exact deployment \(status.deploymentID ?? "unknown") stopped in phase \(status.phase ?? "unknown"). Review a fresh broker-admitted recovery plan before choosing an allowed action."
    }

    @MainActor private func refresh() async {
        guard !loading, !executing else { return }
        loading = true
        error = nil
        onMutationFenceChanged(true)
        onCurrentHostReleaseChanged(nil)
        planReview = nil
        recoveryReview = nil
        catalogRecoveryReview = nil
        do {
            let result = try await Task.detached {
                let deployment = try NativeDeploymentBrokerClient().status()
                let gate = try NativeCatalogRecoveryBrokerClient().gate()
                guard deployment.currentHostReleaseID == gate.currentHostReleaseID else {
                    throw NativeSessionBrokerError.rejected(
                        "native_control_host_release_changed"
                    )
                }
                return (deployment, gate)
            }.value
            deploymentStatus = result.0
            catalogGate = result.1
            onCurrentHostReleaseChanged(result.0.currentHostReleaseID)
        } catch {
            deploymentStatus = nil
            catalogGate = nil
            onCurrentHostReleaseChanged(nil)
            self.error = error.localizedDescription
        }
        loading = false
        onMutationFenceChanged(!mutationsMayProceed)
    }

    @MainActor private func prepareDeployment() async {
        guard !buttonsDisabled, mutationsMayProceed,
              let expectedHost = currentHostReleaseID else { return }
        executing = true
        error = nil
        onMutationFenceChanged(true)
        do {
            let result = try await Task.detached {
                try NativeDeploymentBrokerClient().plan()
            }.value
            guard result.currentHostReleaseID == expectedHost else {
                throw NativeSessionBrokerError.rejected(
                    "native_deployment_host_release_changed"
                )
            }
            planReview = DeploymentPlanReview(query: result)
        } catch { self.error = error.localizedDescription }
        executing = false
        onMutationFenceChanged(!mutationsMayProceed)
    }

    @MainActor private func authorizeDeployment(
        _ query: NativeDeploymentPlanQueryResult
    ) async {
        guard !executing else { return }
        planReview = nil
        executing = true
        error = nil
        onMutationFenceChanged(true)
        do {
            let response = query.response
            let terminal = try await Task.detached {
                try catalogClient.authorizeNativeDeployment(
                    action: "apply",
                    expectedSHA256: response.responseSHA256,
                    queryRequest: query.request,
                    canonicalQueryReply: query.canonicalReplyData,
                    expectedDeploymentID: response.plan.deploymentID,
                    expectedHostReleaseID: response.plan.hostReleaseID,
                    expectedPayloadContainerSHA256: response.payloadContainerSHA256
                )
            }.value
            notice = "Protected deployment committed with independent guest readback. Terminal \(terminal.recordSHA256.groupedDigest)."
            onProtectedStateChanged()
        } catch { self.error = error.localizedDescription }
        executing = false
        await refresh()
    }

    @MainActor private func prepareDeploymentRecovery() async {
        guard !buttonsDisabled,
              deploymentStatus?.status.state == "recovery-required",
              deploymentStatus?.status.phase != "state-invalid",
              let expectedJournal = deploymentStatus?.status.activeJournalSHA256,
              let expectedHost = currentHostReleaseID else { return }
        executing = true
        error = nil
        onMutationFenceChanged(true)
        do {
            let result = try await Task.detached {
                try NativeDeploymentBrokerClient().recoveryPlan()
            }.value
            guard result.currentHostReleaseID == expectedHost,
                  result.recoveryPlan.activeJournalSHA256 == expectedJournal
            else {
                throw NativeSessionBrokerError.rejected(
                    "native_deployment_recovery_state_changed"
                )
            }
            recoveryReview = DeploymentRecoveryReview(query: result)
        } catch { self.error = error.localizedDescription }
        executing = false
        onMutationFenceChanged(true)
    }

    @MainActor private func authorizeRecovery(
        _ action: String,
        query: NativeDeploymentRecoveryPlanQueryResult
    ) async {
        guard !executing,
              query.recoveryPlan.allowedActions.contains(action),
              ["resume", "rollback"].contains(action) else { return }
        recoveryReview = nil
        executing = true
        error = nil
        onMutationFenceChanged(true)
        do {
            let recovery = query.recoveryPlan
            let response = recovery.planResponse
            let terminal = try await Task.detached {
                try catalogClient.authorizeNativeDeployment(
                    action: action,
                    expectedSHA256: recovery.recoveryPlanSHA256,
                    queryRequest: query.request,
                    canonicalQueryReply: query.canonicalReplyData,
                    expectedDeploymentID: recovery.deploymentID,
                    expectedHostReleaseID: recovery.hostReleaseID,
                    expectedPayloadContainerSHA256: response.payloadContainerSHA256
                )
            }.value
            notice = "Exact deployment recovery \(terminal.phase) with independent guest readback. Terminal \(terminal.recordSHA256.groupedDigest)."
            onProtectedStateChanged()
        } catch { self.error = error.localizedDescription }
        executing = false
        await refresh()
    }

    @MainActor private func prepareCatalogRecovery() {
        guard !buttonsDisabled, catalogGate?.gate.state == "active",
              let catalogGate else { return }
        catalogRecoveryReview = CatalogRecoveryReview(query: catalogGate)
        onMutationFenceChanged(true)
    }

    @MainActor private func recoverCatalog(
        _ query: NativeCatalogPromotionGateQueryResult
    ) async {
        guard !executing, query.gate.state == "active" else { return }
        catalogRecoveryReview = nil
        executing = true
        error = nil
        onMutationFenceChanged(true)
        do {
            let result = try await Task.detached {
                try NativeCatalogRecoveryBrokerClient().recover(
                    expectedGateSHA256: query.gate.gateSHA256
                )
            }.value
            notice = "Exact catalog publication recovered from retained root authority. Terminal \(result.terminal.terminalSHA256.groupedDigest)."
            onProtectedStateChanged()
        } catch { self.error = error.localizedDescription }
        executing = false
        await refresh()
    }
}

private struct DeploymentPlanReview: Identifiable {
    let query: NativeDeploymentPlanQueryResult
    var id: String { query.response.plan.deploymentID }
}

private struct DeploymentRecoveryReview: Identifiable {
    let query: NativeDeploymentRecoveryPlanQueryResult
    var id: String { query.recoveryPlan.recoveryPlanSHA256 }
}

private struct CatalogRecoveryReview: Identifiable {
    let query: NativeCatalogPromotionGateQueryResult
    var id: String { query.gate.gateSHA256 }
}

private struct NativeDeploymentPlanReviewSheet: View {
    let query: NativeDeploymentPlanQueryResult
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Review Protected Native Deployment").font(.title2.bold())
            Text("Touch ID authorizes only this exact, expiring transaction. Gateway is installed first; Research remains lifecycle-fenced until both candidates are independently read back.")
                .foregroundStyle(.secondary)
            Form {
                Section("Authority") {
                    row("Deployment", query.response.plan.deploymentID)
                    row("Host release", query.response.plan.hostReleaseID.groupedDigest)
                    row("Catalog", query.response.plan.catalogSHA256.groupedDigest)
                    row("Plan", query.response.plan.planSHA256.groupedDigest)
                    row("Plan response", query.response.responseSHA256.groupedDigest)
                    row("Expires", expiry(query.response.plan.expiresAt))
                }
                Section("Candidate packages") {
                    row("Gateway", query.response.plan.gatewayPackageSHA256.groupedDigest)
                    row("Research", query.response.plan.researchPackageSHA256.groupedDigest)
                    row("Payload container", query.response.payloadContainerSHA256.groupedDigest)
                }
                Section("Exact predecessors") {
                    row("Gateway package", digest(query.response.plan.previousGatewayPackageSHA256))
                    row("Gateway status", query.response.plan.previousGatewayStatusSHA256.groupedDigest)
                    row("Research package", digest(query.response.plan.previousResearchPackageSHA256))
                    row("Research status", query.response.plan.previousResearchStatusSHA256.groupedDigest)
                }
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Touch ID & Deploy", role: .destructive, action: onAuthorize)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 650, minHeight: 610)
    }

    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label) { Text(value).font(.callout.monospaced()).textSelection(.enabled) }
    }

    private func digest(_ value: String?) -> String {
        value?.groupedDigest ?? "Exact absent/legacy predecessor"
    }

    private func expiry(_ value: Int) -> String {
        Date(timeIntervalSince1970: TimeInterval(value)).formatted(
            date: .abbreviated, time: .standard
        )
    }
}

private struct NativeDeploymentRecoveryReviewSheet: View {
    let query: NativeDeploymentRecoveryPlanQueryResult
    let onCancel: () -> Void
    let onAuthorize: (String) -> Void

    var body: some View {
        let recovery = query.recoveryPlan
        VStack(alignment: .leading, spacing: 14) {
            Text("Review Exact Deployment Recovery").font(.title2.bold())
            Text("The broker admitted only the actions shown below from the current durable journal and fresh independent guest observations. No force-clear or bypass exists.")
                .foregroundStyle(.secondary)
            Form {
                Section("Stopped transaction") {
                    row("Deployment", recovery.deploymentID)
                    row("Host release", recovery.hostReleaseID.groupedDigest)
                    row("Phase", recovery.phase)
                    row("Observed pair", recovery.observedPair)
                    row("Active journal", recovery.activeJournalSHA256.groupedDigest)
                    row("Recovery plan", recovery.recoveryPlanSHA256.groupedDigest)
                }
                Section("Candidate packages") {
                    row("Gateway", recovery.planResponse.plan.gatewayPackageSHA256.groupedDigest)
                    row("Research", recovery.planResponse.plan.researchPackageSHA256.groupedDigest)
                    row("Catalog", recovery.planResponse.plan.catalogSHA256.groupedDigest)
                    row("Payload container", recovery.planResponse.payloadContainerSHA256.groupedDigest)
                }
                Section("Independent observations") {
                    row("Gateway status", recovery.gatewayStatusSHA256?.groupedDigest ?? "Unavailable")
                    row("Research status", recovery.researchStatusSHA256?.groupedDigest ?? "Unavailable")
                }
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                if recovery.allowedActions.contains("rollback") {
                    Button("Touch ID & Roll Back", role: .destructive) {
                        onAuthorize("rollback")
                    }
                }
                if recovery.allowedActions.contains("resume") {
                    Button("Touch ID & Resume", role: .destructive) {
                        onAuthorize("resume")
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(minWidth: 650, minHeight: 560)
    }

    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label) { Text(value).font(.callout.monospaced()).textSelection(.enabled) }
    }
}

private struct NativeCatalogRecoveryReviewSheet: View {
    let query: NativeCatalogPromotionGateQueryResult
    let onCancel: () -> Void
    let onRecover: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Review Catalog Publication Recovery").font(.title2.bold())
            Text("This replays only the exact retained root-owned publication authority. It cannot select another catalog, Host release, or promotion, and it cannot clear an invalid gate.")
                .foregroundStyle(.secondary)
            Form {
                row("Current Host release", query.currentHostReleaseID.groupedDigest)
                row("Promotion", query.gate.activePromotionID ?? "Unavailable")
                row("Active state", query.gate.activeStateSHA256?.groupedDigest ?? "Unavailable")
                row("Gate", query.gate.gateSHA256.groupedDigest)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Recover Exact Publication", role: .destructive, action: onRecover)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 610, minHeight: 350)
    }

    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label) { Text(value).font(.callout.monospaced()).textSelection(.enabled) }
    }
}
