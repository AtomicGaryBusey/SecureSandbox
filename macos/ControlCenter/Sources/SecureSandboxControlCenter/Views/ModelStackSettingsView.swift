import SwiftUI
import SecureSandboxNativeSessionUIProtocol

struct ModelStackSettingsView: View {
    let harnessStore: HarnessStore
    @AppStorage("modelSettingsSurface") private var selectedSurface = "brokered"

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Model execution mode").font(.headline)
                    Text("This selects the settings surface only. Saving never changes live authority.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Mode", selection: $selectedSurface) {
                    Text("Brokered Provider Profile").tag("brokered")
                    Text("Native Vendor Harness + Model Stack").tag("native")
                }
                .pickerStyle(.segmented)
                .frame(width: 430)
            }
            .padding(.horizontal, 10)

            Divider()

            if selectedSurface == "native" {
                NativeVendorStacksSettingsView(harnessStore: harnessStore)
            } else {
                ModelProfilesSettingsView()
            }
        }
    }
}

private struct NativeVendorStacksSettingsView: View {
    let harnessStore: HarnessStore
    @State private var status: NativeVendorStackCatalogStatus?
    @State private var catalog: NativeVendorStackCatalog?
    @State private var persistedCatalog: NativeVendorStackCatalog?
    @State private var selectedID: String?
    @State private var publicStatus: NativeStackPublicCatalogStatus?
    @State private var inspections: [String: NativeStackInspection] = [:]
    @State private var sources: [SourceRecord] = []
    @State private var loading = false
    @State private var saving = false
    @State private var inspecting = false
    @State private var applying = false
    @State private var error: String?
    @State private var protectedError: String?
    @State private var notice: String?
    @State private var confirmingReload = false
    @State private var pendingActionPlan: NativeStackActionPlan?
    @State private var pendingProgramAttestationPlan: NativeProgramAttestationPlan?
    @State private var pendingPromotionPlan: NativeStackCatalogPromotionPlan?
    @State private var pendingSessionStart: NativeSessionStartIntent?
    @State private var pendingSessionPlan: NativeSessionPlan?
    @State private var projectionOriginalOperationID = ""
    @State private var pendingProjectionIdentityPlan:
        NativeProjectionIdentityRecoveryPlan?
    @State private var pendingProjectionReconciliationPlan:
        NativeProjectionReconciliationPlan?
    @State private var activeClaudeTerminal: NativeTerminalHandle?
    @State private var activeNativeSessionPlan: NativeSessionPlan?
    @State private var activeCodexHandle: NativeCodexUIHandle?
    @State private var activeCodexPlan: NativeSessionPlan?
    @State private var activeCodexReasoningEffort = "high"
    @State private var deploymentMutationsBlocked = true
    @State private var currentNativeHostReleaseID: String?

    private let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)

    var body: some View {
        VStack(spacing: 0) {
            NativeDeploymentControlView(
                externallyBusy: applying || saving,
                onMutationFenceChanged: { deploymentMutationsBlocked = $0 },
                onCurrentHostReleaseChanged: {
                    currentNativeHostReleaseID = $0
                },
                onProtectedStateChanged: {
                    Task { await refreshProtected() }
                }
            )
            .padding(10)

            Divider()

            HSplitView {
                VStack(spacing: 8) {
                    if let catalog {
                        List(catalog.stacks, selection: $selectedID) { stack in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(stack.displayName).fontWeight(.medium)
                                Text("\(stack.vendorID) · \(stack.harness.harnessID)")
                                    .font(.caption).foregroundStyle(.secondary)
                                Text(readinessTitle(for: stack.stackID))
                                    .font(.caption2)
                                    .foregroundStyle(readinessColor(for: stack.stackID))
                                if let live = liveStatus(for: stack.stackID) {
                                    Text("Live: \(live.activation.state) · \(live.authentication.state)")
                                        .font(.caption2)
                                        .foregroundStyle(live.activation.state == "active" ? .green : .secondary)
                                }
                            }
                            .tag(stack.stackID)
                        }
                        .listStyle(.sidebar)
                    } else if loading {
                        ProgressView("Loading native stacks…")
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        ContentUnavailableView("Native stacks unavailable", systemImage: "lock.shield")
                    }
                }
                .frame(minWidth: 230, idealWidth: 250, maxWidth: 290)

                if let binding = selectedStackBinding {
                    ScrollView {
                        NativeVendorStackEditor(
                            stack: binding,
                            admittedGenerations: admittedGenerations(for: binding.wrappedValue),
                            readiness: readiness(for: binding.wrappedValue.stackID),
                            operational: liveStatus(for: binding.wrappedValue.stackID),
                            protectedRevisionMatches: protectedRevisionMatches(
                                binding.wrappedValue.stackID
                            ),
                            busy: stackMutationBusy,
                            onAction: { action in Task { await prepareAction(action) } },
                            onProgramAttestation: {
                                Task { await prepareProgramAttestation() }
                            },
                            onStartSession: {
                                pendingSessionStart = NativeSessionStartIntent(
                                    stackID: binding.wrappedValue.stackID,
                                    displayName: binding.wrappedValue.displayName
                                )
                            },
                            onStageObservedBinding: { stageObservedBinding() }
                        )
                        .disabled(deploymentMutationsBlocked)
                    }
                    .frame(minWidth: 500)
                } else {
                    ContentUnavailableView("Select a native stack", systemImage: "lock.shield")
                        .frame(minWidth: 500)
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                if let error { Text(error).foregroundStyle(.red) }
                if let protectedError { Text(protectedError).foregroundStyle(.orange) }
                if let notice { Text(notice).foregroundStyle(.secondary) }
                if selectedStackBinding?.wrappedValue.vendorID == "openai" {
                    projectionRecoveryControls
                }
                HStack {
                    if let status {
                        Text("Staged \(status.catalogSHA256.groupedDigest)")
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                    if let publicStatus {
                        Text("Protected \(publicStatus.catalogSHA256.groupedDigest)")
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Spacer()
                    Button("Refresh Protected Status") {
                        Task { await refreshProtected() }
                    }
                    .disabled(loading || saving || inspecting || applying)
                    if canPromoteCatalog {
                        Button("Review & Admit Staged Catalog…") {
                            Task { await preparePromotion() }
                        }
                        .disabled(stackMutationBusy || loading)
                    }
                    Button("Reload") { requestReload() }
                        .disabled(loading || saving || inspecting || applying)
                    Button("Save Staged Settings") { Task { await save() } }
                        .disabled(catalog == nil || loading || stackMutationBusy)
                        .keyboardShortcut("s", modifiers: .command)
                }
            }
            .padding(10)
        }
        .task {
            if harnessStore.status == nil { await harnessStore.load() }
            if catalog == nil { await load() }
        }
        .alert("Discard Unsaved Native Stack Changes?", isPresented: $confirmingReload) {
            Button("Discard and Reload", role: .destructive) { Task { await load() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Reloading replaces every unsaved native-stack edit with the last staged settings.")
        }
        .sheet(item: $pendingActionPlan) { plan in
            NativeStackActionPlanSheet(
                plan: plan,
                onCancel: { pendingActionPlan = nil },
                onAuthorize: { Task { await authorizeAction(plan) } }
            )
        }
        .sheet(item: $pendingProgramAttestationPlan) { plan in
            NativeProgramAttestationPlanSheet(
                plan: plan,
                onCancel: { pendingProgramAttestationPlan = nil },
                onAuthorize: { Task { await authorizeProgramAttestation(plan) } }
            )
        }
        .sheet(item: $activeClaudeTerminal, onDismiss: {
            activeNativeSessionPlan = nil
            Task { await refreshProtected() }
        }) { handle in
            NativeClaudeTerminalView(
                handle: handle,
                title: handle.kind == "claude-login"
                    ? "Claude Code Sign-In" : "Claude Code Session",
                sessionPlan: handle.kind == "claude-session"
                    ? activeNativeSessionPlan : nil
            )
        }
        .sheet(item: $activeCodexHandle, onDismiss: {
            activeCodexPlan = nil
            Task { await refreshProtected() }
        }) { handle in
            if let plan = activeCodexPlan {
                NativeCodexSessionView(
                    handle: handle,
                    plan: plan,
                    reasoningEffort: activeCodexReasoningEffort
                )
            } else {
                ContentUnavailableView(
                    "Typed session authority unavailable",
                    systemImage: "exclamationmark.shield"
                )
            }
        }
        .sheet(item: $pendingSessionStart) { intent in
            NativeSessionStartSheet(
                intent: intent,
                sources: sources,
                onCancel: { pendingSessionStart = nil },
                onReview: { sourceID, leaseProfileID in
                    pendingSessionStart = nil
                    Task {
                        await prepareSessionStart(
                            stackID: intent.stackID,
                            sourceID: sourceID,
                            leaseProfileID: leaseProfileID
                        )
                    }
                }
            )
        }
        .sheet(item: $pendingSessionPlan) { plan in
            NativeSessionPlanSheet(
                plan: plan,
                sourceName: sourceName(plan.sourceID),
                onCancel: { pendingSessionPlan = nil },
                onAuthorize: { Task { await authorizeSessionStart(plan) } }
            )
        }
        .sheet(item: $pendingProjectionIdentityPlan) { plan in
            NativeProjectionIdentityRecoveryPlanSheet(
                plan: plan,
                onCancel: { pendingProjectionIdentityPlan = nil },
                onAuthorize: {
                    Task { await authorizeProjectionIdentityRecovery(plan) }
                }
            )
        }
        .sheet(item: $pendingProjectionReconciliationPlan) { plan in
            NativeProjectionReconciliationPlanSheet(
                plan: plan,
                onCancel: { pendingProjectionReconciliationPlan = nil },
                onAuthorize: {
                    Task { await authorizeProjectionReconciliation(plan) }
                }
            )
        }
        .sheet(item: $pendingPromotionPlan) { plan in
            NativeStackCatalogPromotionSheet(
                plan: plan,
                stacks: catalog?.stacks ?? [],
                onCancel: { pendingPromotionPlan = nil },
                onAuthorize: { Task { await authorizePromotion(plan) } }
            )
        }
    }

    private var selectedStackBinding: Binding<NativeVendorStack>? {
        guard let selectedID,
              let index = catalog?.stacks.firstIndex(where: { $0.stackID == selectedID }) else {
            return nil
        }
        return Binding(
            get: { catalog!.stacks[index] },
            set: { catalog!.stacks[index] = $0 }
        )
    }

    private var projectionRecoveryControls: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Label("Exact projection custody recovery", systemImage: "key.viewfinder")
                    .font(.caption.weight(.semibold))
                TextField(
                    "Original session operation ID",
                    text: $projectionOriginalOperationID
                )
                .textFieldStyle(.roundedBorder)
                .font(.caption.monospaced())
                .frame(minWidth: 285, idealWidth: 340)
                Button("Import Identity…") {
                    Task { await prepareProjectionIdentityRecovery() }
                }
                .disabled(applying || !projectionOriginalOperationIDIsValid)
                Button("Reconcile Closed Projection…") {
                    Task { await prepareProjectionReconciliation() }
                }
                .disabled(applying || !projectionOriginalOperationIDIsValid)
            }
            Text("Use the original start operation shown on the reviewed native session plan. Identity import is read-only and never clears custody. Reconciliation is a separate Touch ID ceremony and is available only after the Host independently proves the exact Research run absent and egress closed. Neither action has a bypass.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var projectionOriginalOperationIDIsValid: Bool {
        projectionOriginalOperationID.range(
            of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
            options: .regularExpression
        ) != nil
    }

    private func validateProjectionRecoveryPlan(
        stackID: String,
        stackSHA256: String,
        hostReleaseID: String
    ) throws {
        guard selectedID == stackID,
              projectionPlanUsesCurrentHost(hostReleaseID),
              publicStatus?.stacks.first(where: {
                  $0.stackID == stackID
              })?.stackSHA256 == stackSHA256,
              status?.catalogSHA256 == publicStatus?.catalogSHA256,
              !hasUnsavedChanges else {
            throw NativeSessionBrokerError.rejected(
                "native_projection_recovery_selected_authority_changed"
            )
        }
    }

    private func projectionPlanUsesCurrentHost(
        _ proposedHostReleaseID: String
    ) -> Bool {
        guard let currentNativeHostReleaseID,
              let historicalHostReleaseID = publicStatus?.hostReleaseID,
              let authority = try? NativeHostReleaseAuthority(
                  currentHostReleaseID: currentNativeHostReleaseID,
                  historicalPublicationHostReleaseID: historicalHostReleaseID
              ) else { return false }
        return (try? authority.requireCurrent(proposedHostReleaseID)) != nil
    }

    private func admittedGenerations(
        for stack: NativeVendorStack
    ) -> [HarnessProtectedGeneration] {
        (harnessStore.status?.protected.status?.generations ?? [])
            .filter {
                ["active", "retained"].contains($0.status)
                    && $0.vendorID == stack.vendorID
                    && $0.harnessID == stack.harness.harnessID
                    && $0.adapterID == stack.harness.adapterID
            }
            .sorted {
                if $0.releaseSequence != $1.releaseSequence {
                    return $0.releaseSequence > $1.releaseSequence
                }
                return $0.generationID < $1.generationID
            }
    }

    private var hasUnsavedChanges: Bool { catalog != persistedCatalog }

    private var stackMutationBusy: Bool {
        applying || inspecting || saving || deploymentMutationsBlocked
    }

    private var canPromoteCatalog: Bool {
        guard !deploymentMutationsBlocked, !hasUnsavedChanges,
              status?.source == "staged",
              let staged = status?.catalogSHA256,
              let protected = publicStatus?.catalogSHA256 else { return false }
        return staged != protected
    }

    private func protectedRevisionMatches(_ stackID: String) -> Bool {
        guard !hasUnsavedChanges,
              status?.catalogSHA256 == publicStatus?.catalogSHA256,
              let staged = status?.stacks.first(where: { $0.stack.stackID == stackID }),
              let protected = publicStatus?.stacks.first(where: { $0.stackID == stackID })
        else { return false }
        return staged.revisionSHA256 == protected.stackSHA256
            && inspections[stackID]?.status.stackSHA256 == protected.stackSHA256
    }

    private func liveStatus(for stackID: String) -> NativeStackOperationalStatus? {
        protectedRevisionMatches(stackID) ? inspections[stackID]?.status : nil
    }

    private func readiness(for stackID: String) -> NativeVendorStackReadiness? {
        guard !hasUnsavedChanges else { return nil }
        return status?.stacks.first(where: { $0.stack.stackID == stackID })?.readiness
    }

    private func readinessTitle(for stackID: String) -> String {
        guard let readiness = readiness(for: stackID) else { return "Draft changed · validation pending" }
        switch readiness.status {
        case "configuration-required": return "Configuration required"
        case "login-required": return "Vendor sign-in required"
        case "content-ready": return "Content complete · not activated"
        default: return "Unrecognized state"
        }
    }

    private func readinessColor(for stackID: String) -> Color {
        readiness(for: stackID)?.status == "content-ready" ? .secondary : .orange
    }

    @MainActor private func load() async {
        loading = true; error = nil; notice = nil
        do {
            let value = try await Task.detached { try client.nativeVendorStacks() }.value
            status = value
            catalog = value.catalog
            persistedCatalog = value.catalog
            selectedID = value.catalog.stacks.first?.stackID
            notice = value.source == "example"
                ? "Showing inert templates. Exact harness admission and vendor sign-in are still required."
                : "Loaded private staged settings. No native stack is activated by this screen."
        } catch { self.error = error.localizedDescription }
        loading = false
        await loadSources()
        await refreshProtected()
    }

    @MainActor private func loadSources() async {
        do {
            sources = try await Task.detached {
                try client.load("sources", as: [SourceRecord].self)
            }.value
        } catch {
            sources = []
        }
    }

    @MainActor private func save() async {
        guard !deploymentMutationsBlocked, var value = catalog else { return }
        saving = true; error = nil; notice = nil
        value.stacks.sort { $0.stackID < $1.stackID }
        do {
            let result = try await Task.detached { try client.saveNativeVendorStacks(value) }.value
            status = result
            catalog = result.catalog
            persistedCatalog = result.catalog
            selectedID = result.catalog.stacks.contains(where: { $0.stackID == selectedID })
                ? selectedID : result.catalog.stacks.first?.stackID
            notice = "Staged settings saved with mode 0600. Login, egress, and live authority are unchanged."
        } catch { self.error = error.localizedDescription }
        saving = false
    }

    @MainActor private func refreshProtected() async {
        guard !inspecting else { return }
        inspecting = true
        protectedError = nil
        do {
            let result = try await Task.detached { () -> (
                NativeStackPublicCatalogStatus, [String: NativeStackInspection]
            ) in
                let control = NativeStackControlClient()
                let publicStatus = try control.publicCatalogStatus()
                var inspections: [String: NativeStackInspection] = [:]
                for revision in publicStatus.stacks {
                    inspections[revision.stackID] = try control.inspect(
                        stackID: revision.stackID,
                        stackSHA256: revision.stackSHA256,
                        catalogSHA256: publicStatus.catalogSHA256
                    )
                }
                return (publicStatus, inspections)
            }.value
            publicStatus = result.0
            inspections = result.1
            if status?.catalogSHA256 != result.0.catalogSHA256 {
                notice = "Staged settings differ from protected authority. Review and admit the exact staged catalog before applying a live action."
            }
        } catch {
            publicStatus = nil
            inspections = [:]
            protectedError = error.localizedDescription
        }
        inspecting = false
    }

    @MainActor private func prepareAction(_ action: String) async {
        guard !deploymentMutationsBlocked, !applying,
              !hasUnsavedChanges, let selectedID,
              protectedRevisionMatches(selectedID),
              let inspection = inspections[selectedID] else {
            protectedError = "Save and admit the exact staged catalog, then refresh protected status before this action."
            return
        }
        applying = true
        error = nil
        do {
            let observedAccount = action == "binding-commit"
                ? inspection.status.accountBinding.accountSubjectSHA256 : nil
            let observedWorkspace = action == "binding-commit"
                ? inspection.status.accountBinding.workspaceSHA256 : nil
            let plan = try await Task.detached {
                try client.nativeStackActionPlan(
                    action: action,
                    stackID: selectedID,
                    inspection: inspection,
                    observedAccountSubjectSHA256: observedAccount,
                    observedWorkspaceSHA256: observedWorkspace
                )
            }.value
            pendingActionPlan = plan
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func authorizeAction(_ plan: NativeStackActionPlan) async {
        guard !deploymentMutationsBlocked, !applying else { return }
        pendingActionPlan = nil
        applying = true
        error = nil
        do {
            if plan.action == "signin-begin", plan.identity.vendorID == "anthropic" {
                let handle = try await Task.detached {
                    try client.authorizeNativeClaudeLogin(plan)
                }.value
                activeClaudeTerminal = handle
                notice = "Claude sign-in is attached directly to the protected broker. Closing the surface ends the one-use channel."
            } else {
                let receipt = try await Task.detached {
                    try client.authorizeNativeStackAction(plan)
                }.value
                notice = "\(actionTitle(receipt.action)) completed and was independently read back. Receipt \(receipt.receiptSHA256.groupedDigest)."
                await refreshProtected()
            }
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func prepareProgramAttestation() async {
        guard !deploymentMutationsBlocked, !applying,
              !hasUnsavedChanges, let selectedID,
              protectedRevisionMatches(selectedID),
              let inspection = inspections[selectedID],
              let publicStatus,
              status?.catalogSHA256 == publicStatus.catalogSHA256 else {
            protectedError = "Save and admit the exact staged catalog, then refresh protected status before declaring program enrollment."
            return
        }
        applying = true
        error = nil
        do {
            let plan = try await Task.detached {
                try client.nativeProgramAttestationPlan(
                    stackID: selectedID,
                    catalogSHA256: publicStatus.catalogSHA256,
                    inspection: inspection
                )
            }.value
            pendingProgramAttestationPlan = plan
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func authorizeProgramAttestation(
        _ plan: NativeProgramAttestationPlan
    ) async {
        guard !deploymentMutationsBlocked, !applying else { return }
        pendingProgramAttestationPlan = nil
        applying = true
        error = nil
        do {
            let result = try await Task.detached {
                try client.authorizeNativeProgramAttestation(plan)
            }.value
            notice = "External program enrollment was recorded as operator-declared—not provider-verified. Evidence \(result.evidenceSHA256.groupedDigest)."
            await refreshProtected()
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func prepareSessionStart(
        stackID: String, sourceID: String?, leaseProfileID: String
    ) async {
        guard !deploymentMutationsBlocked, !applying, !hasUnsavedChanges,
              protectedRevisionMatches(stackID),
              let revision = publicStatus?.stacks.first(where: {
                $0.stackID == stackID
              }),
              let catalogSHA256 = publicStatus?.catalogSHA256,
              let operational = inspections[stackID]?.status,
              operational.activation.state == "active",
              operational.liveRunCount == 0 else {
            protectedError = "The exact protected stack must be active, idle, and freshly inspected before planning a native session."
            return
        }
        if let sourceID, !sources.contains(where: { $0.id == sourceID }) {
            protectedError = "The selected registered source is no longer available."
            return
        }
        applying = true
        error = nil
        do {
            let request = try NativeSessionPlanRequest(
                action: .start,
                sessionID: UUID().uuidString.lowercased(),
                stackID: stackID,
                stackSHA256: revision.stackSHA256,
                catalogSHA256: catalogSHA256,
                sourceID: sourceID,
                resumeSessionID: nil,
                leaseProfileID: leaseProfileID
            )
            let plan = try await Task.detached {
                try NativeSessionPlanBrokerClient().plan(request)
            }.value
            pendingSessionPlan = plan
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func authorizeSessionStart(_ plan: NativeSessionPlan) async {
        guard !deploymentMutationsBlocked, !applying,
              plan.action == .start else { return }
        pendingSessionPlan = nil
        applying = true
        error = nil
        do {
            if plan.authority.vendorID == "anthropic" {
                let handle = try await Task.detached {
                    try client.authorizeNativeClaudeSessionStart(plan)
                }.value
                activeNativeSessionPlan = plan
                activeClaudeTerminal = handle
                notice = "The exact Claude session lease was authorized. The terminal is attached directly to the protected broker; closing it triggers teardown."
            } else {
                guard plan.authority.vendorID == "openai",
                      let stack = catalog?.stacks.first(where: {
                        $0.stackID == plan.stackID
                      }),
                      stack.model.modelID == plan.authority.modelID,
                      stack.model.settings.cyberAccess == "daybreak_blue",
                      let reasoning = stack.model.settings.reasoningEffort,
                      ["low", "medium", "high", "xhigh"].contains(reasoning)
                else {
                    throw NativeSessionBrokerError.rejected(
                        "native_codex_reviewed_settings_unavailable"
                    )
                }
                let settingsSHA256 = try CanonicalNativeJSON.digest([
                    "cyber_access": "daybreak_blue",
                    "reasoning_effort": reasoning,
                ])
                guard settingsSHA256 == plan.authority.modelSettingsSHA256 else {
                    throw NativeSessionBrokerError.rejected(
                        "native_codex_reviewed_settings_changed"
                    )
                }
                let handle = try await Task.detached {
                    try client.authorizeNativeCodexSessionStart(plan)
                }.value
                activeCodexPlan = plan
                activeCodexReasoningEffort = reasoning
                activeCodexHandle = handle
                projectionOriginalOperationID = plan.actionID
                notice = "The exact Codex session lease was authorized. The GUI accepts only the typed sanitized channel—never terminal bytes or raw app-server JSON."
            }
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func prepareProjectionIdentityRecovery() async {
        guard !deploymentMutationsBlocked, !applying,
              projectionOriginalOperationIDIsValid else { return }
        applying = true
        error = nil
        protectedError = nil
        do {
            let request = try NativeProjectionRecoveryPlanRequest(
                kind: .identityImport,
                originalOperationID: projectionOriginalOperationID
            )
            let plan = try await Task.detached {
                try NativeProjectionRecoveryBrokerClient().identityPlan(request)
            }.value
            try validateProjectionRecoveryPlan(
                stackID: plan.stackID,
                stackSHA256: plan.stackSHA256,
                hostReleaseID: plan.hostReleaseID
            )
            pendingProjectionIdentityPlan = plan
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func authorizeProjectionIdentityRecovery(
        _ plan: NativeProjectionIdentityRecoveryPlan
    ) async {
        guard !deploymentMutationsBlocked, !applying else { return }
        pendingProjectionIdentityPlan = nil
        applying = true
        error = nil
        do {
            try validateProjectionRecoveryPlan(
                stackID: plan.stackID,
                stackSHA256: plan.stackSHA256,
                hostReleaseID: plan.hostReleaseID
            )
            let result = try await Task.detached {
                try client.authorizeNativeProjectionIdentityRecovery(plan)
            }.value
            notice = "Exact projection identity imported read-only. Custody remains fail-closed; review the separate closure reconciliation next. Evidence \(result.identityEvidenceSHA256.groupedDigest)."
            await refreshProtected()
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func prepareProjectionReconciliation() async {
        guard !deploymentMutationsBlocked, !applying,
              projectionOriginalOperationIDIsValid else { return }
        applying = true
        error = nil
        protectedError = nil
        do {
            let request = try NativeProjectionRecoveryPlanRequest(
                kind: .reconciliation,
                originalOperationID: projectionOriginalOperationID
            )
            let plan = try await Task.detached {
                try NativeProjectionRecoveryBrokerClient()
                    .reconciliationPlan(request)
            }.value
            try validateProjectionRecoveryPlan(
                stackID: plan.stackID,
                stackSHA256: plan.stackSHA256,
                hostReleaseID: plan.hostReleaseID
            )
            pendingProjectionReconciliationPlan = plan
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func authorizeProjectionReconciliation(
        _ plan: NativeProjectionReconciliationPlan
    ) async {
        guard !deploymentMutationsBlocked, !applying else { return }
        pendingProjectionReconciliationPlan = nil
        applying = true
        error = nil
        do {
            try validateProjectionRecoveryPlan(
                stackID: plan.stackID,
                stackSHA256: plan.stackSHA256,
                hostReleaseID: plan.hostReleaseID
            )
            let result = try await Task.detached {
                try client.authorizeNativeProjectionReconciliation(plan)
            }.value
            projectionOriginalOperationID = ""
            notice = "Exact projection custody reconciled only after protected guest-absence, egress-closure, and consumer-identity proof. Evidence \(result.reconciliationEvidenceSHA256.groupedDigest)."
            await refreshProtected()
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func preparePromotion() async {
        guard !deploymentMutationsBlocked, !applying,
              canPromoteCatalog, let publicStatus,
              let stagedSHA256 = status?.catalogSHA256,
              let currentHostReleaseID = currentNativeHostReleaseID else {
            protectedError = "A saved staged catalog and verified protected predecessor are required."
            return
        }
        applying = true
        error = nil
        do {
            let plan = try await Task.detached {
                let gate = try NativeCatalogRecoveryBrokerClient().gate()
                guard gate.gate.state == "ready",
                      gate.currentHostReleaseID == currentHostReleaseID else {
                    throw NativeSessionBrokerError.rejected(
                        "native_catalog_current_host_changed"
                    )
                }
                return try client.nativeStackCatalogPromotionPlan(
                    publicStatus: publicStatus,
                    currentHostReleaseID: currentHostReleaseID,
                    expectedStagedCatalogSHA256: stagedSHA256
                )
            }.value
            pendingPromotionPlan = plan
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func authorizePromotion(
        _ plan: NativeStackCatalogPromotionPlan
    ) async {
        guard !deploymentMutationsBlocked, !applying else { return }
        pendingPromotionPlan = nil
        applying = true
        error = nil
        do {
            let receipt = try await Task.detached {
                try client.authorizeNativeStackCatalogPromotion(plan)
            }.value
            notice = "Protected catalog admitted. This did not authenticate, activate, or start a harness. Receipt \(receipt.receiptSHA256.groupedDigest)."
            await refreshProtected()
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func stageObservedBinding() {
        guard !deploymentMutationsBlocked, let selectedID,
              let inspection = inspections[selectedID],
              inspection.status.accountBinding.state == "observed",
              let account = inspection.status.accountBinding.accountSubjectSHA256,
              let workspace = inspection.status.accountBinding.workspaceSHA256,
              let index = catalog?.stacks.firstIndex(where: { $0.stackID == selectedID })
        else { return }
        catalog?.stacks[index].accountBinding.accountSubjectSHA256 = account
        catalog?.stacks[index].accountBinding.workspaceSHA256 = workspace
        notice = "Observed opaque provider bindings were copied into the inert draft. Save, review, and admit the changed catalog before binding live authority."
    }

    private func actionTitle(_ action: String) -> String {
        [
            "signin-begin": "Vendor sign-in",
            "binding-commit": "Account/workspace binding",
            "status-verify": "Native status verification",
            "entitlement-verify": "Program and model entitlement verification",
            "activate": "Stack activation",
            "rollback": "Stack rollback",
            "logout": "Vendor logout",
            "credential-destroy": "Credential destruction",
            "recover": "Fail-closed recovery",
        ][action] ?? action
    }

    private func sourceName(_ sourceID: String?) -> String? {
        guard let sourceID else { return nil }
        return sources.first(where: { $0.id == sourceID })?.repository
    }

    private func requestReload() {
        if hasUnsavedChanges {
            confirmingReload = true
        } else {
            Task { await load() }
        }
    }
}

private struct NativeVendorStackEditor: View {
    @Binding var stack: NativeVendorStack
    let admittedGenerations: [HarnessProtectedGeneration]
    let readiness: NativeVendorStackReadiness?
    let operational: NativeStackOperationalStatus?
    let protectedRevisionMatches: Bool
    let busy: Bool
    let onAction: (String) -> Void
    let onProgramAttestation: () -> Void
    let onStartSession: () -> Void
    let onStageObservedBinding: () -> Void

    var body: some View {
        Form {
            Section("Stack identity") {
                TextField("Display name", text: $stack.displayName)
                LabeledContent("Stack ID", value: stack.stackID)
                LabeledContent("Vendor", value: stack.vendorID)
                LabeledContent("Mode", value: stack.mode)
                LabeledContent("Network policy", value: stack.networkPolicyID)
            }

            Section("Official harness and authentication") {
                LabeledContent("Harness", value: stack.harness.harnessID)
                LabeledContent("Adapter", value: stack.harness.adapterID)
                Picker("Admitted generation", selection: $stack.harness.generationID) {
                    Text("Not selected").tag(String?.none)
                    ForEach(admittedGenerations) { generation in
                        Text(
                            "\(generation.version) · "
                                + generation.generationID.groupedDigest
                        )
                        .tag(Optional(generation.generationID))
                    }
                }
                if admittedGenerations.isEmpty {
                    Text("No active or retained generation matches this exact vendor, harness, and adapter. Admit one in the Harnesses tab first.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else {
                    Text("Only protected active/retained generations with this exact closed pairing are selectable. Selection stages a catalog change; it grants no execution authority.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Authentication", value: stack.authentication.mode)
                LabeledContent("Credential custody", value: stack.authentication.credentialCustody)
                Text("Harness, authentication, custody, and network policy form a closed reviewed pairing and cannot be recombined here.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Provider authority") {
                LabeledContent("Program", value: stack.accountBinding.programID)
                LabeledContent("Tier", value: stack.accountBinding.programTier)
                LabeledContent("Requirements", value: stack.accountBinding.programRequirementsVersion)
                LabeledContent("Account binding", value: digest(stack.accountBinding.accountSubjectSHA256))
                LabeledContent("Workspace binding", value: digest(stack.accountBinding.workspaceSHA256))
                if let operational {
                    LabeledContent("Live authentication", value: operational.authentication.state)
                    LabeledContent("Live binding", value: operational.accountBinding.state)
                    LabeledContent(
                        "Observed account", value: digest(operational.accountBinding.accountSubjectSHA256)
                    )
                    LabeledContent(
                        "Observed workspace", value: digest(operational.accountBinding.workspaceSHA256)
                    )
                    if operational.accountBinding.state == "observed",
                       (stack.accountBinding.accountSubjectSHA256
                        != operational.accountBinding.accountSubjectSHA256
                        || stack.accountBinding.workspaceSHA256
                        != operational.accountBinding.workspaceSHA256) {
                        Button("Stage Observed Opaque Binding", action: onStageObservedBinding)
                            .disabled(busy)
                    }
                } else {
                    LabeledContent(
                        "Live authority",
                        value: protectedRevisionMatches ? "Unavailable" : "Staged revision is not protected"
                    )
                }
                Text("Touch ID authorizes the SecureSandbox action; the vendor's own OAuth flow establishes provider identity. Raw provider identifiers and credentials never appear here.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Model") {
                if stack.vendorID == "openai" {
                    Picker("Model", selection: $stack.model.modelID) {
                        Text("GPT-6 Sol").tag("gpt-6-sol")
                        Text("GPT-6 Luna").tag("gpt-6-luna")
                        Text("GPT-6.1 Sol").tag("gpt-6.1-sol")
                    }
                    .onChange(of: stack.model.modelID) { _, modelID in
                        stack.model.modelName = switch modelID {
                        case "gpt-6-luna": "GPT-6 Luna"
                        case "gpt-6.1-sol": "GPT-6.1 Sol"
                        default: "GPT-6 Sol"
                        }
                    }
                    Picker("Reasoning effort", selection: optional($stack.model.settings.reasoningEffort, fallback: "high")) {
                        ForEach(["low", "medium", "high", "xhigh"], id: \.self) { Text($0).tag($0) }
                    }
                    LabeledContent("Cyber access", value: stack.model.settings.cyberAccess ?? "daybreak_blue")
                } else {
                    LabeledContent("Model", value: "\(stack.model.modelName) (\(stack.model.modelID))")
                    Picker("Effort", selection: optional($stack.model.settings.effort, fallback: "high")) {
                        ForEach(["low", "medium", "high"], id: \.self) { Text($0).tag($0) }
                    }
                }
                Text("A running session is permanently bound to this exact model and cannot call another installed model or harness.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Readiness") {
                LabeledContent("Content state", value: readiness?.status ?? "Draft changed · save to validate")
                if let readiness, !readiness.missing.isEmpty {
                    LabeledContent("Missing", value: readiness.missing.joined(separator: ", "))
                }
                Text("Content-ready is not authenticated, entitled, admitted, connected, or activated. Those are separate protected states.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Protected authority") {
                if let operational {
                    statusRow("Harness admission", operational.harness.state)
                    statusRow("Authentication", operational.authentication.state)
                    statusRow("Credential custody", operational.credentialCustody.state)
                    statusRow("Account / workspace", operational.accountBinding.state)
                    entitlementStatusRow(
                        "Program entitlement", operational.programEntitlement
                    )
                    entitlementStatusRow(
                        "Model entitlement", operational.modelEntitlement
                    )
                    statusRow("Network", operational.network.phase)
                    statusRow("Activation", operational.activation.state)
                    LabeledContent("Live runs", value: String(operational.liveRunCount))
                    if let fenceReason = operational.fenceReason {
                        LabeledContent("Fence reason", value: fenceReason)
                            .foregroundStyle(.orange)
                    }
                    Divider()
                    protectedActions(operational)
                } else {
                    Text("Save and admit the exact staged catalog, then refresh protected status. No live action is available while revisions differ or status is unverified.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
    }

    private var signInTitle: String {
        stack.vendorID == "anthropic" ? "Open Claude Code Sign-In…" : "Continue with ChatGPT…"
    }

    @ViewBuilder private func protectedActions(
        _ status: NativeStackOperationalStatus
    ) -> some View {
        HStack {
            Button(signInTitle) { onAction("signin-begin") }
                .disabled(busy || status.authentication.state != "signed-out"
                          || status.liveRunCount != 0)
            Button("Verify Native Status…") { onAction("status-verify") }
                .disabled(busy || status.authentication.state != "signed-in")
            Button("Declare Program Enrollment…", action: onProgramAttestation)
                .disabled(busy || status.authentication.state != "signed-in"
                          || status.accountBinding.state != "bound"
                          || status.liveRunCount != 0
                          || status.programEntitlement.assurance == "provider-enforced")
            Button("Verify Provider Entitlements…") { onAction("entitlement-verify") }
                .disabled(busy || status.authentication.state != "signed-in"
                          || status.accountBinding.state != "bound")
        }
        HStack {
            Button("Start Native Session…", action: onStartSession)
                .disabled(busy || status.activation.state != "active"
                          || status.liveRunCount != 0
                          || status.authentication.state != "signed-in"
                          || status.accountBinding.state != "bound"
                          || status.programEntitlement.state != "verified"
                          || status.modelEntitlement.state != "verified")
            Text("Session launch is a separate exact-plan and Touch ID ceremony.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        HStack {
            Button("Bind Observed Identity…") { onAction("binding-commit") }
                .disabled(busy || status.accountBinding.state != "observed"
                          || stack.accountBinding.accountSubjectSHA256
                            != status.accountBinding.accountSubjectSHA256
                          || stack.accountBinding.workspaceSHA256
                            != status.accountBinding.workspaceSHA256)
            Button("Activate Exact Stack…") { onAction("activate") }
                .disabled(busy || status.harness.state != "admitted"
                          || status.authentication.state != "signed-in"
                          || status.accountBinding.state != "bound"
                          || status.programEntitlement.state != "verified"
                          || status.modelEntitlement.state != "verified"
                          || status.activation.state == "active")
            Button("Recover Fenced Stack…") { onAction("recover") }
                .disabled(busy || !["fenced", "recovery-required"].contains(
                    status.activation.state
                ))
        }
        HStack {
            Button("Roll Back Stack…", role: .destructive) { onAction("rollback") }
                .disabled(busy || status.activation.state != "active")
            Button(stack.vendorID == "anthropic" ? "Log Out…" : "Disconnect…",
                   role: .destructive) { onAction("logout") }
                .disabled(busy || status.authentication.state != "signed-in")
            Button("Destroy Local Credentials…", role: .destructive) {
                onAction("credential-destroy")
            }
            .disabled(busy || status.liveRunCount != 0
                      || status.credentialCustody.state == "session-projected")
        }
        Text("Program declaration and provider verification are separate actions. Operator-declared means SecureSandbox recorded your reviewed statement; it never means the vendor verified it. Every ellipsis opens an exact-plan review. Touch ID has no password fallback.")
            .font(.caption).foregroundStyle(.secondary)
    }

    private func statusRow(_ label: String, _ value: String) -> some View {
        LabeledContent(label, value: value)
            .foregroundStyle(["ambiguous", "mismatch", "revoked", "fenced", "recovery-required"].contains(value) ? .orange : .primary)
    }

    @ViewBuilder private func entitlementStatusRow(
        _ label: String, _ status: NativeStackEntitlementStatus
    ) -> some View {
        LabeledContent(label) {
            VStack(alignment: .trailing, spacing: 2) {
                Text(status.state)
                Text(assuranceTitle(status.assurance))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func assuranceTitle(_ assurance: String) -> String {
        switch assurance {
        case "operator-external": "Operator-declared · not provider-verified"
        case "provider-enforced": "Provider-enforced"
        default: "No assurance"
        }
    }

    private func digest(_ value: String?) -> String {
        value?.groupedDigest ?? "Not bound"
    }

    private func optional(_ binding: Binding<String?>, fallback: String) -> Binding<String> {
        Binding(
            get: { binding.wrappedValue ?? fallback },
            set: { binding.wrappedValue = $0 }
        )
    }
}

extension NativeStackActionPlan: Identifiable {
    var id: String { actionID }
}

extension NativeStackCatalogPromotionPlan: Identifiable {
    var id: String { promotionID }
}

private struct NativeSessionStartIntent: Identifiable, Hashable {
    let stackID: String
    let displayName: String
    var id: String { stackID }
}

private struct NativeSessionStartSheet: View {
    let intent: NativeSessionStartIntent
    let sources: [SourceRecord]
    let onCancel: () -> Void
    let onReview: (String?, String) -> Void
    @State private var sourceID = ""
    @State private var leaseProfileID = "interactive"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Configure Native Session", systemImage: "lock.shield")
                .font(.title2.bold())
            Text(intent.displayName).font(.headline)
            Text("These are the only values supplied by the GUI. Protected Research independently measures the source manifest, persona, tool catalog, extension set, harness, model stack, and account authority before returning a reviewable plan.")
                .foregroundStyle(.secondary)

            Form {
                Picker("Registered source", selection: $sourceID) {
                    Text("No source").tag("")
                    ForEach(sources) { source in
                        Text(source.repository).tag(source.id)
                    }
                }
                Picker("Session lease", selection: $leaseProfileID) {
                    Text("Interactive · 1 hour").tag("interactive")
                    Text("Extended · 4 hours").tag("extended")
                }
                Text("The lease is a maximum lifetime, not permission to remain running. Closing the session surface triggers immediate teardown.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Build Exact Review Plan") {
                    onReview(sourceID.isEmpty ? nil : sourceID, leaseProfileID)
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 620, minHeight: 430)
        .interactiveDismissDisabled()
    }
}

struct NativeSessionPlanSheet: View {
    let plan: NativeSessionPlan
    let sourceName: String?
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(
                plan.action == .start
                    ? "Review Exact Native Session Start"
                    : "Review Exact Native Session Stop",
                systemImage: plan.action == .start ? "play.shield" : "stop.circle"
            )
            .font(.title2.bold())
            Text(plan.action == .start
                 ? "Touch ID authorizes one process, one measured runtime authority, and one bounded lease."
                 : "Touch ID authorizes teardown of this exact session authority and requires independent absence readback.")
                .foregroundStyle(.secondary)

            ScrollView {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    row(
                        plan.action == .start
                            ? "Start operation" : "Stop operation",
                        plan.actionID
                    )
                    row("Vendor / harness", "\(plan.authority.vendorID) / \(plan.authority.harnessID)")
                    row("Harness generation", plan.authority.harnessGenerationID.groupedDigest)
                    row("Harness executable", plan.authority.harnessExecutableSHA256.groupedDigest)
                    row("Harness adapter", plan.authority.harnessAdapterID)
                    row("Model", plan.authority.modelID)
                    row("Model settings", plan.authority.modelSettingsSHA256.groupedDigest)
                    row("Program / tier", "\(plan.authority.programID) / \(plan.authority.programTier)")
                    row("Requirements", plan.authority.programRequirementsVersion)
                    row("Network policy", plan.authority.networkPolicyID)
                    row("Session authority", plan.runtimeAuthoritySHA256.groupedDigest)
                    row("Session identity", plan.expectedSessionIDSHA256.groupedDigest)
                    row("Source", sourceTitle)
                    row("Source manifest", plan.authority.sourceManifestSHA256?.groupedDigest ?? "None")
                    row("Persona", plan.authority.personaSHA256.groupedDigest)
                    row("Outer-tool catalog", plan.authority.toolCatalogSHA256.groupedDigest)
                    row("Extension set", plan.authority.extensionSetSHA256.groupedDigest)
                    row("Lease", leaseTitle)
                    row("Stack revision", plan.stackSHA256.groupedDigest)
                    row("Protected catalog", plan.catalogSHA256.groupedDigest)
                    row("Protected status", plan.statusSHA256.groupedDigest)
                    row("Plan", plan.planSHA256.groupedDigest)
                    row(
                        "Expires",
                        Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
                            .formatted(date: .abbreviated, time: .standard)
                    )
                }
                .textSelection(.enabled)
            }

            Label(
                "Native mode gives the vendor harness credential authority and does not provide the Gateway's independent request-body enforcement. A session cannot switch model, harness, source, tools, or extensions.",
                systemImage: "exclamationmark.shield"
            )
            .foregroundStyle(.orange)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button(
                    plan.action == .start
                        ? "Authorize Start with Touch ID"
                        : "Authorize Stop with Touch ID",
                    role: plan.action == .stop ? .destructive : nil,
                    action: onAuthorize
                )
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 740, minHeight: 720)
        .interactiveDismissDisabled()
    }

    private var sourceTitle: String {
        guard plan.sourceID != nil else { return "No source" }
        return sourceName ?? "Selected registered source"
    }

    private var leaseTitle: String {
        switch plan.leaseProfileID {
        case "interactive": "Interactive · 1 hour maximum"
        case "extended": "Extended · 4 hours maximum"
        default: plan.action == .stop ? "Stop authority only" : "Invalid"
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced())
        }
    }
}

private struct NativeProjectionIdentityRecoveryPlanSheet: View {
    let plan: NativeProjectionIdentityRecoveryPlan
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Import Exact Projection Identity", systemImage: "person.text.rectangle")
                .font(.title2.bold())
            Text("Read-only identity recovery · custody remains fail-closed")
                .font(.headline)
                .foregroundStyle(.orange)
            Text("Touch ID authorizes the signed helper to disclose the exact content-free PID, start generation, executable digest, and session authority already committed for this one projection. This action cannot clear custody, restart a session, or release a credential.")
                .foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                row("Original operation", plan.originalOperationID)
                row("Recovery operation", plan.recoveryOperationID)
                row("Session", plan.sessionID)
                row("Session authority", plan.sessionAuthoritySHA256.groupedDigest)
                row("Stack", plan.stackID)
                row("Stack revision", plan.stackSHA256.groupedDigest)
                row("Host release", plan.hostReleaseID.groupedDigest)
                row("Plan", plan.planSHA256.groupedDigest)
                row(
                    "Expires",
                    Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
                        .formatted(date: .abbreviated, time: .standard)
                )
            }
            .textSelection(.enabled)
            Label(
                "A successful import only restores the Host journal's exact identity binding. Closure reconciliation remains a second, independently authorized action.",
                systemImage: "lock.shield"
            )
            .foregroundStyle(.orange)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Import Identity with Touch ID", action: onAuthorize)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 720, minHeight: 560)
        .interactiveDismissDisabled()
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced())
        }
    }
}

private struct NativeProjectionReconciliationPlanSheet: View {
    let plan: NativeProjectionReconciliationPlan
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Reconcile Exact Closed Projection", systemImage: "checkmark.shield")
                .font(.title2.bold())
            Text("Destructive custody terminalization · exact evidence required")
                .font(.headline)
                .foregroundStyle(.orange)
            Text("Touch ID clears only this helper ledger entry after the Host has independently proved the bound Research run absent and inference egress closed, and the helper has independently proved the exact consumer PID/start generation absent or reused.")
                .foregroundStyle(.secondary)
            ScrollView {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    row("Original operation", plan.originalOperationID)
                    row("Recovery operation", plan.recoveryOperationID)
                    row("Session", plan.sessionID)
                    row("Session authority", plan.sessionAuthoritySHA256.groupedDigest)
                    row("Stack", plan.stackID)
                    row("Stack revision", plan.stackSHA256.groupedDigest)
                    row("Consumer PID", String(plan.processIdentifier))
                    row(
                        "Consumer start generation",
                        String(plan.processStartTimeMicroseconds)
                    )
                    row(
                        "Consumer executable",
                        plan.consumerExecutableSHA256.groupedDigest
                    )
                    row(
                        "Guest absence evidence",
                        plan.guestAbsenceEvidenceSHA256.groupedDigest
                    )
                    row(
                        "Egress closure evidence",
                        plan.egressClosedEvidenceSHA256.groupedDigest
                    )
                    row("Host release", plan.hostReleaseID.groupedDigest)
                    row("Plan", plan.planSHA256.groupedDigest)
                    row(
                        "Expires",
                        Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
                            .formatted(date: .abbreviated, time: .standard)
                    )
                }
                .textSelection(.enabled)
            }
            Label(
                "PID absence or age alone is never authority. Any identity, evidence, release, expiry, or digest mismatch bricks this attempt with no bypass.",
                systemImage: "exclamationmark.shield"
            )
            .foregroundStyle(.orange)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button(
                    "Reconcile with Touch ID",
                    role: .destructive,
                    action: onAuthorize
                )
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 740, minHeight: 690)
        .interactiveDismissDisabled()
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced())
        }
    }
}

private struct NativeStackActionPlanSheet: View {
    let plan: NativeStackActionPlan
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Review Exact Protected Action", systemImage: "lock.shield")
                .font(.title2.bold())
            Text(actionTitle)
                .font(.headline)
            Text("Touch ID authorizes only this self-digested plan. It does not authenticate the vendor account and cannot be reused for a different stack or session.")
                .foregroundStyle(.secondary)

            ScrollView {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    row("Vendor", plan.identity.vendorID)
                    row("Harness", plan.identity.harnessID)
                    row("Harness generation", digest(plan.identity.harnessGenerationID))
                    row("Adapter", plan.identity.harnessAdapterID)
                    row("Authentication", plan.identity.authenticationMode)
                    row("Credential custody", plan.identity.credentialCustody)
                    row("Account", digest(plan.identity.accountSubjectSHA256))
                    row("Workspace", digest(plan.identity.workspaceSHA256))
                    row("Program / tier", "\(plan.identity.programID) / \(plan.identity.programTier)")
                    row("Requirements", plan.identity.programRequirementsVersion)
                    row("Model", plan.identity.modelID)
                    row("Model settings", plan.identity.modelSettingsSHA256.groupedDigest)
                    row("Network policy", plan.identity.networkPolicyID)
                    row("Network phase", plan.requestedNetworkPhase)
                    row("Stack revision", plan.identity.stackSHA256.groupedDigest)
                    row("Current status", plan.currentStatusSHA256.groupedDigest)
                    row("Plan", plan.planSHA256.groupedDigest)
                }
                .textSelection(.enabled)
            }

            if plan.impact.stopsBoundRuns || plan.impact.destroysCredentials {
                Label(impactText, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Authorize with Touch ID", action: onAuthorize)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 670, minHeight: 600)
        .interactiveDismissDisabled()
    }

    private var actionTitle: String {
        [
            "signin-begin": "Begin native vendor sign-in",
            "binding-commit": "Bind the observed account and workspace",
            "status-verify": "Verify native vendor status",
            "entitlement-verify": "Verify the exact program and model entitlement",
            "activate": "Activate the exact native stack",
            "rollback": "Roll back and deactivate the native stack",
            "logout": "Log out and revoke live native authority",
            "credential-destroy": "Destroy retained local credentials",
            "recover": "Recover into a fenced, closed state",
        ][plan.action] ?? plan.action
    }

    private var impactText: String {
        if plan.impact.destroysCredentials {
            return "This action irreversibly destroys the retained local vendor credential after stopping bound runs."
        }
        if plan.impact.stopsBoundRuns {
            return "This action stops every run bound to this exact stack before changing authority."
        }
        return "This action changes live authority."
    }

    private func digest(_ value: String?) -> String {
        value?.groupedDigest ?? "Not bound"
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced())
        }
    }
}

private struct NativeProgramAttestationPlanSheet: View {
    let plan: NativeProgramAttestationPlan
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Review External Program Declaration", systemImage: "person.badge.shield.checkmark")
                .font(.title2.bold())
            Text("This is an operator declaration, not provider verification.")
                .font(.headline)
                .foregroundStyle(.orange)
            Text("Touch ID records that you declared this exact external cyber-program enrollment for the displayed protected stack, opaque account and workspace bindings, requirements version, and harness generation. It cannot prove what the vendor has granted.")
                .foregroundStyle(.secondary)

            ScrollView {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    row("Program / tier", "\(plan.programID) / \(plan.programTier)")
                    row("Requirements", plan.programRequirementsVersion)
                    row("Assurance", "Operator-declared · not provider-verified")
                    row("Account binding", plan.accountSubjectSHA256.groupedDigest)
                    row("Workspace binding", plan.workspaceSHA256.groupedDigest)
                    row("Harness generation", plan.harnessGenerationID.groupedDigest)
                    row("Stack", plan.stackID)
                    row("Stack revision", plan.stackSHA256.groupedDigest)
                    row("Protected catalog", plan.catalogSHA256.groupedDigest)
                    row("Protected status", plan.statusSHA256.groupedDigest)
                    row("Plan", plan.planSHA256.groupedDigest)
                    row(
                        "Expires",
                        Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
                            .formatted(date: .abbreviated, time: .standard)
                    )
                }
                .textSelection(.enabled)
            }

            Label(
                "A later provider-enforced check remains a distinct action and may still reject this declaration.",
                systemImage: "exclamationmark.shield"
            )
            .foregroundStyle(.orange)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Declare with Touch ID", action: onAuthorize)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 700, minHeight: 590)
        .interactiveDismissDisabled()
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced())
        }
    }
}

private struct NativeStackCatalogPromotionSheet: View {
    let plan: NativeStackCatalogPromotionPlan
    let stacks: [NativeVendorStack]
    let onCancel: () -> Void
    let onAuthorize: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Admit Exact Native Stack Catalog", systemImage: "checkmark.shield")
                .font(.title2.bold())
            Text("This ceremony copies the reviewed staged catalog into root-owned protected state. It remains inert: no login, egress, activation, credential projection, or harness launch occurs.")
                .foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                row("Current protected catalog", plan.previousCatalogSHA256?.groupedDigest ?? "None")
                row("Proposed catalog", plan.catalogSHA256.groupedDigest)
                row("Host release", plan.hostReleaseID.groupedDigest)
                row("Plan", plan.planSHA256.groupedDigest)
            }
            .textSelection(.enabled)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(stacks.sorted(by: { $0.stackID < $1.stackID })) { stack in
                        GroupBox(stack.displayName) {
                            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 5) {
                                row("Stack", stack.stackID)
                                row("Vendor / harness", "\(stack.vendorID) / \(stack.harness.harnessID)")
                                row("Generation", stack.harness.generationID?.groupedDigest ?? "Not admitted")
                                row("Model", "\(stack.model.modelName) (\(stack.model.modelID))")
                                row("Account", stack.accountBinding.accountSubjectSHA256?.groupedDigest ?? "Not bound")
                                row("Workspace", stack.accountBinding.workspaceSHA256?.groupedDigest ?? "Not bound")
                                row("Program / tier", "\(stack.accountBinding.programID) / \(stack.accountBinding.programTier)")
                                row("Network policy", stack.networkPolicyID)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button("Admit with Touch ID", action: onAuthorize)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(minWidth: 720, minHeight: 650)
        .interactiveDismissDisabled()
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced())
        }
    }
}
