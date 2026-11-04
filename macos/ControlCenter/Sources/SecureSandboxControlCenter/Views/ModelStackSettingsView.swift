import SwiftUI

struct ModelStackSettingsView: View {
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
                NativeVendorStacksSettingsView()
            } else {
                ModelProfilesSettingsView()
            }
        }
    }
}

private struct NativeVendorStacksSettingsView: View {
    @State private var status: NativeVendorStackCatalogStatus?
    @State private var catalog: NativeVendorStackCatalog?
    @State private var persistedCatalog: NativeVendorStackCatalog?
    @State private var selectedID: String?
    @State private var publicStatus: NativeStackPublicCatalogStatus?
    @State private var inspections: [String: NativeStackInspection] = [:]
    @State private var loading = false
    @State private var saving = false
    @State private var inspecting = false
    @State private var applying = false
    @State private var error: String?
    @State private var protectedError: String?
    @State private var notice: String?
    @State private var confirmingReload = false
    @State private var pendingActionPlan: NativeStackActionPlan?
    @State private var pendingPromotionPlan: NativeStackCatalogPromotionPlan?

    private let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)

    var body: some View {
        VStack(spacing: 0) {
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
                            readiness: readiness(for: binding.wrappedValue.stackID),
                            operational: liveStatus(for: binding.wrappedValue.stackID),
                            protectedRevisionMatches: protectedRevisionMatches(
                                binding.wrappedValue.stackID
                            ),
                            busy: applying || inspecting || saving,
                            onAction: { action in Task { await prepareAction(action) } },
                            onStageObservedBinding: { stageObservedBinding() }
                        )
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
                        .disabled(loading || saving || inspecting || applying)
                    }
                    Button("Reload") { requestReload() }
                        .disabled(loading || saving || inspecting || applying)
                    Button("Save Staged Settings") { Task { await save() } }
                        .disabled(catalog == nil || loading || saving || applying)
                        .keyboardShortcut("s", modifiers: .command)
                }
            }
            .padding(10)
        }
        .task { if catalog == nil { await load() } }
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

    private var hasUnsavedChanges: Bool { catalog != persistedCatalog }

    private var canPromoteCatalog: Bool {
        guard !hasUnsavedChanges, status?.source == "staged",
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
        await refreshProtected()
    }

    @MainActor private func save() async {
        guard var value = catalog else { return }
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
        guard !applying, !hasUnsavedChanges, let selectedID,
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
        guard !applying else { return }
        pendingActionPlan = nil
        applying = true
        error = nil
        do {
            let receipt = try await Task.detached {
                try client.authorizeNativeStackAction(plan)
            }.value
            notice = "\(actionTitle(receipt.action)) completed and was independently read back. Receipt \(receipt.receiptSHA256.groupedDigest)."
            await refreshProtected()
        } catch { self.error = error.localizedDescription }
        applying = false
    }

    @MainActor private func preparePromotion() async {
        guard !applying, canPromoteCatalog, let publicStatus,
              let stagedSHA256 = status?.catalogSHA256 else {
            protectedError = "A saved staged catalog and verified protected predecessor are required."
            return
        }
        applying = true
        error = nil
        do {
            let plan = try await Task.detached {
                try client.nativeStackCatalogPromotionPlan(
                    publicStatus: publicStatus,
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
        guard !applying else { return }
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
        guard let selectedID,
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
    let readiness: NativeVendorStackReadiness?
    let operational: NativeStackOperationalStatus?
    let protectedRevisionMatches: Bool
    let busy: Bool
    let onAction: (String) -> Void
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
                LabeledContent("Admitted generation", value: digest(stack.harness.generationID))
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
                    }
                    .onChange(of: stack.model.modelID) { _, modelID in
                        stack.model.modelName = modelID == "gpt-6-luna" ? "GPT-6 Luna" : "GPT-6 Sol"
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
                    statusRow("Program entitlement", operational.programEntitlement.state)
                    statusRow("Model entitlement", operational.modelEntitlement.state)
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
            Button("Verify Program & Model…") { onAction("entitlement-verify") }
                .disabled(busy || status.authentication.state != "signed-in"
                          || status.accountBinding.state != "bound")
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
        Text("Every ellipsis opens an exact-plan review. Touch ID has no password fallback. Logout, rollback, recovery, and credential destruction stop bound runs and independently read back the closed network state.")
            .font(.caption).foregroundStyle(.secondary)
    }

    private func statusRow(_ label: String, _ value: String) -> some View {
        LabeledContent(label, value: value)
            .foregroundStyle(["ambiguous", "mismatch", "revoked", "fenced", "recovery-required"].contains(value) ? .orange : .primary)
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
